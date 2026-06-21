#!/usr/bin/env python3
"""
Dataset Merge & Validation Utility
===================================
Merges multiple session CSV files into a single master dataset,
validates schema consistency, audits data quality, and reports
label distributions.

Usage:
    python3 dataset_merge.py session1.csv session2.csv session3.csv --output dataset_master.csv
    python3 dataset_merge.py dataset_master.csv stealth.csv --output dataset_final.csv

Outputs:
    dataset_master.csv          — Full merge with meta_ columns (audit file)
    dataset_master_training.csv — meta_ columns stripped (DL-ready input)

Rationale XII.A: meta_ columns constitute data leakage if included as
model inputs — the training file MUST strip them.
"""

import sys
import os
import argparse
import csv
import math
from collections import Counter

# Import column definitions for schema validation
try:
    from traffic_capture import ALL_COLUMNS, META_COLUMNS, LABEL_COLUMNS
except ImportError:
    # Fallback if run from a different directory
    print("[WARN] Could not import from traffic_capture.py — using local column list for validation")
    ALL_COLUMNS = None
    META_COLUMNS = ['meta_window_id', 'meta_src_mac_oui', 'meta_device_name',
                    'meta_attack_tool', 'meta_attack_intensity', 'meta_mininet_event',
                    'meta_controller_load', 'meta_backlog_drops']
    LABEL_COLUMNS = ['label', 'attack_type', 'snort_sid']


def validate_schema(files):
    """Validate that all CSV files have identical column schemas.
    CRASHES on mismatch — never silently fills NaN."""
    schemas = {}
    for fpath in files:
        with open(fpath, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            header = next(reader)
            schemas[fpath] = header

    reference_file = files[0]
    reference_schema = schemas[reference_file]

    print(f"\n{'='*60}")
    print(f"  Schema Validation")
    print(f"{'='*60}")
    print(f"  Reference: {os.path.basename(reference_file)} ({len(reference_schema)} columns)")

    all_match = True
    for fpath, schema in schemas.items():
        if fpath == reference_file:
            continue
        if schema != reference_schema:
            all_match = False
            missing = set(reference_schema) - set(schema)
            extra = set(schema) - set(reference_schema)
            print(f"\n  ❌ MISMATCH: {os.path.basename(fpath)} ({len(schema)} columns)")
            if missing:
                print(f"     Missing columns: {sorted(missing)}")
            if extra:
                print(f"     Extra columns: {sorted(extra)}")
        else:
            print(f"  ✅ {os.path.basename(fpath)} — schema matches ({len(schema)} columns)")

    if not all_match:
        print(f"\n❌ FATAL: Schema mismatch detected. Cannot merge files with different columns.")
        print(f"   Fix the schema or regenerate the mismatched session(s).")
        sys.exit(1)

    # HARD schema guard against traffic_capture.py's ALL_COLUMNS (102 columns).
    # A stale/old-schema session (e.g. a leftover 50-column dataset.csv) must NOT
    # enter the merge — it silently corrupts the master via column misalignment
    # (attack_type ends up holding numeric feature values). Fail loudly.
    if ALL_COLUMNS is not None:
        if reference_schema != ALL_COLUMNS:
            missing_from_csv = set(ALL_COLUMNS) - set(reference_schema)
            extra_in_csv = set(reference_schema) - set(ALL_COLUMNS)
            print(f"\n  ❌ FATAL: schema does not match traffic_capture.py ALL_COLUMNS "
                  f"({len(reference_schema)} cols vs expected {len(ALL_COLUMNS)}).")
            if missing_from_csv:
                print(f"     Missing from CSV: {sorted(missing_from_csv)}")
            if extra_in_csv:
                print(f"     Extra in CSV: {sorted(extra_in_csv)}")
            if len(reference_schema) != len(ALL_COLUMNS):
                print("     A wrong column COUNT usually means a stale/old-schema "
                      "dataset.csv was captured into. Re-capture that session with the "
                      "current traffic_capture.py (it now auto-rotates old files) and retry.")
            sys.exit(1)
        print(f"  ✅ Schema matches traffic_capture.py ALL_COLUMNS ({len(ALL_COLUMNS)} columns)")
    else:
        # Fallback when traffic_capture.py is not importable: enforce the known
        # column count + presence of critical columns.
        EXPECTED_COUNT = 102
        critical = {'protocol', 'packets_per_second', 'attack_type', 'label', 'src_ip'}
        missing_critical = critical - set(reference_schema)
        if len(reference_schema) != EXPECTED_COUNT or missing_critical:
            print(f"\n  ❌ FATAL: schema check failed (count={len(reference_schema)}, "
                  f"expected {EXPECTED_COUNT}; missing critical cols: {sorted(missing_critical)}). "
                  f"Likely a stale/old-schema session — re-capture and retry.")
            sys.exit(1)
        print(f"  ✅ Column count OK ({len(reference_schema)}) and critical columns present")

    print()
    return reference_schema


def merge_files(files, schema, output_path):
    """Merge all CSV files into a single output, adding meta_session_id."""
    total_rows = 0
    all_rows = []

    for session_id, fpath in enumerate(files, start=1):
        session_name = os.path.splitext(os.path.basename(fpath))[0]
        with open(fpath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            session_rows = 0
            for row in reader:
                row['meta_session_id'] = session_id
                row['meta_session_name'] = session_name
                all_rows.append(row)
                session_rows += 1
            total_rows += session_rows
            print(f"  📄 {os.path.basename(fpath)}: {session_rows} rows (session {session_id})")

    # Write merged output
    output_columns = schema + ['meta_session_id', 'meta_session_name']
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=output_columns, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"\n  ✅ Merged {total_rows} total rows → {output_path}")
    return all_rows, output_columns


def audit_data_quality(rows, schema):
    """Check for NaN, inf, and empty values in numeric columns."""
    print(f"\n{'='*60}")
    print(f"  Data Quality Audit")
    print(f"{'='*60}")

    # Identify numeric columns (everything except known string columns)
    string_columns = {
        'timestamp', 'src_ip', 'dst_ip', 'protocol', 'attack_type', 'snort_sid',
        'meta_src_mac_oui', 'meta_device_name', 'meta_attack_tool',
        'meta_mininet_event', 'meta_session_name',
    }
    numeric_columns = [c for c in schema if c not in string_columns]

    nan_report = {}
    inf_report = {}
    empty_report = {}

    for col in numeric_columns:
        nan_count = 0
        inf_count = 0
        empty_count = 0
        for row in rows:
            val = row.get(col, '')
            if val == '' or val is None:
                empty_count += 1
            else:
                try:
                    fval = float(val)
                    if math.isnan(fval):
                        nan_count += 1
                    if math.isinf(fval):
                        inf_count += 1
                except (ValueError, TypeError):
                    pass  # Not numeric, skip

        if nan_count > 0:
            nan_report[col] = nan_count
        if inf_count > 0:
            inf_report[col] = inf_count
        if empty_count > 0:
            empty_report[col] = empty_count

    if nan_report:
        print(f"\n  ⚠ NaN values detected:")
        for col, count in sorted(nan_report.items()):
            print(f"     {col}: {count} NaN values")
    else:
        print(f"  ✅ No NaN values")

    if inf_report:
        print(f"\n  ⚠ Infinity values detected:")
        for col, count in sorted(inf_report.items()):
            print(f"     {col}: {count} inf values")
    else:
        print(f"  ✅ No infinity values")

    if empty_report:
        print(f"\n  ⚠ Empty cells in numeric columns:")
        for col, count in sorted(empty_report.items()):
            pct = round(100 * count / len(rows), 1)
            print(f"     {col}: {count} empty ({pct}%)")
    else:
        print(f"  ✅ No empty cells in numeric columns")

    return len(nan_report) == 0 and len(inf_report) == 0


def report_label_distribution(rows):
    """Report label distribution with per-attack-type row counts."""
    print(f"\n{'='*60}")
    print(f"  Label Distribution Report")
    print(f"{'='*60}")

    label_counts = Counter()
    attack_type_counts = Counter()
    label_attack_matrix = Counter()

    for row in rows:
        label = row.get('label', '?')
        attack = row.get('attack_type', 'unknown')
        label_counts[label] += 1
        attack_type_counts[attack] += 1
        label_attack_matrix[(label, attack)] += 1

    total = len(rows)
    print(f"\n  Total rows: {total}")
    print(f"\n  By label:")
    for label in sorted(label_counts.keys()):
        count = label_counts[label]
        pct = round(100 * count / total, 1)
        label_name = {
            '0': 'normal', '1': 'known_attack (Snort)', '2': 'behavioral_anomaly'
        }.get(str(label), f'label_{label}')
        print(f"     Label {label} ({label_name}): {count} rows ({pct}%)")

    print(f"\n  By attack type:")
    for attack in sorted(attack_type_counts.keys()):
        count = attack_type_counts[attack]
        pct = round(100 * count / total, 1)
        status = ""
        if attack != 'normal' and count < 50:
            status = " ⚠ CRITICALLY LOW — run more sessions for this type"
        elif attack != 'normal' and count < 200:
            status = " ⚠ LOW — consider supplemental collection"
        print(f"     {attack}: {count} rows ({pct}%){status}")

    # Normal vs attack ratio
    normal_count = sum(1 for r in rows if r.get('label', '0') == '0')
    attack_count = total - normal_count
    print(f"\n  Normal/Attack split: {normal_count}/{attack_count} "
          f"({round(100*normal_count/total, 1)}%/{round(100*attack_count/total, 1)}%)")

    if attack_count > 0:
        ratio = round(normal_count / attack_count, 2)
        print(f"  Imbalance ratio: {ratio}:1")
        if ratio > 5:
            print(f"  ⚠ Significant imbalance — consider oversampling attack rows or using class weights")


def create_training_file(input_path, output_path, schema):
    """Strip meta_ columns and label ID columns to create DL-ready training file.
    Rationale XII.A: Including meta_ columns would constitute data leakage."""
    meta_cols = [c for c in schema if c.startswith('meta_')]
    keep_cols = [c for c in schema if c not in meta_cols]
    # Also add meta_session_id/name for removal
    meta_cols.extend(['meta_session_id', 'meta_session_name'])

    with open(input_path, 'r', encoding='utf-8') as fin:
        reader = csv.DictReader(fin)
        # Filter columns
        train_cols = [c for c in reader.fieldnames if c not in meta_cols]

        with open(output_path, 'w', newline='', encoding='utf-8') as fout:
            writer = csv.DictWriter(fout, fieldnames=train_cols, extrasaction='ignore')
            writer.writeheader()
            rows_written = 0
            for row in reader:
                writer.writerow(row)
                rows_written += 1

    stripped_count = len(meta_cols)
    print(f"\n  ✅ Training file: {output_path}")
    print(f"     {rows_written} rows, {len(train_cols)} columns "
          f"({stripped_count} meta columns stripped)")
    print(f"     Stripped: {sorted(set(meta_cols) & set(schema + ['meta_session_id', 'meta_session_name']))}")


def main():
    parser = argparse.ArgumentParser(
        description='Merge and validate session CSV files for DL training',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 dataset_merge.py session1.csv session2.csv session3.csv --output dataset_master.csv
  python3 dataset_merge.py dataset_master.csv stealth.csv --output dataset_final.csv
        """
    )
    parser.add_argument('files', nargs='+', help='Session CSV files to merge')
    parser.add_argument('--output', '-o', default='dataset_master.csv',
                       help='Output merged CSV path (default: dataset_master.csv)')
    args = parser.parse_args()

    # Validate files exist
    for fpath in args.files:
        if not os.path.exists(fpath):
            print(f"❌ File not found: {fpath}")
            sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  Dataset Merge & Validation Tool")
    print(f"  Input files: {len(args.files)}")
    print(f"{'='*60}")

    # 1. Schema validation
    schema = validate_schema(args.files)

    # 2. Merge
    print(f"{'='*60}")
    print(f"  Merging Sessions")
    print(f"{'='*60}")
    rows, output_columns = merge_files(args.files, schema, args.output)

    # 3. Data quality audit
    audit_ok = audit_data_quality(rows, schema)

    # 4. Label distribution
    report_label_distribution(rows)

    # 5. Create training file (meta stripped)
    training_path = args.output.replace('.csv', '_training.csv')
    print(f"\n{'='*60}")
    print(f"  Creating Training File")
    print(f"{'='*60}")
    create_training_file(args.output, training_path, schema)

    # Summary
    print(f"\n{'='*60}")
    print(f"  Summary")
    print(f"{'='*60}")
    print(f"  Master file:   {args.output}")
    print(f"  Training file: {training_path}")
    print(f"  Total rows:    {len(rows)}")
    print(f"  Data quality:  {'✅ PASS' if audit_ok else '⚠ ISSUES FOUND'}")
    print(f"{'='*60}\n")


if __name__ == '__main__':
    main()
