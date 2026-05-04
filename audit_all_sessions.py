import pandas as pd
import os

ds_dir = r"d:\4th Year\Graduation Project\data\GP\results\datasets"

for f in sorted(os.listdir(ds_dir)):
    if not f.endswith('.csv'):
        continue
    path = os.path.join(ds_dir, f)
    df = pd.read_csv(path, low_memory=False)
    print(f"\n{'='*70}")
    print(f"FILE: {f}")
    print(f"  Rows: {len(df):,}  |  Columns: {len(df.columns)}")
    print(f"\n  LABEL DISTRIBUTION:")
    for lbl, cnt in df['label'].value_counts().items():
        print(f"    label={lbl}: {cnt:,} ({100*cnt/len(df):.1f}%)")
    print(f"\n  ATTACK TYPE DISTRIBUTION:")
    for atype, cnt in df['attack_type'].value_counts().items():
        print(f"    {atype}: {cnt:,}")
    
    # Check attack types by source IP
    attack = df[df['label'] > 0]
    if len(attack) > 0:
        print(f"\n  ATTACK TYPE × SOURCE IP:")
        grouped = attack.groupby(['attack_type', 'src_ip']).size().reset_index(name='count')
        for _, row in grouped.iterrows():
            print(f"    {row['attack_type']:35s} from {row['src_ip']:12s} = {row['count']:,}")
    
    # Check victim-blaming
    victims_flagged = False
    for ip, name in [('10.0.0.4', 'h2'), ('10.0.0.5', 'TempSensor'), ('10.0.0.2', 'sta2'), ('10.0.0.1', 'sta1')]:
        flagged = df[(df['src_ip'] == ip) & (df['label'] > 0)]
        if len(flagged) > 0:
            victims_flagged = True
            print(f"  ⚠ VICTIM-BLAME: {name} ({ip}) has {len(flagged)} attack rows: {flagged['attack_type'].value_counts().to_dict()}")
    if not victims_flagged and len(attack) > 0:
        print(f"  ✅ No victim-blaming detected")
    
    # Meta attack tool
    meta_tools = df['meta_attack_tool'].value_counts()
    if len(meta_tools) > 1 or (len(meta_tools) == 1 and meta_tools.index[0] != 'none'):
        print(f"\n  META ATTACK TOOL:")
        for tool, cnt in meta_tools.items():
            print(f"    {tool}: {cnt:,}")
    
    # Rows per window stats
    by_window = df.groupby('meta_window_id').size()
    print(f"\n  ROWS PER WINDOW: min={by_window.min()}, max={by_window.max()}, median={by_window.median():.0f}, mean={by_window.mean():.1f}")
    big_windows = by_window[by_window > 200]
    if len(big_windows) > 0:
        print(f"  ⚠ {len(big_windows)} windows with >200 rows (possible flow explosion)")

    # Protocol cross-contamination check
    if len(attack) > 0:
        cross = attack.groupby(['attack_type', 'protocol']).size().reset_index(name='count')
        suspicious = []
        for _, row in cross.iterrows():
            at, proto = row['attack_type'], row['protocol']
            if at == 'SYN Flood' and proto not in ('TCP',):
                suspicious.append(f"{at}+{proto}={row['count']}")
            elif at == 'ICMP Flood' and proto not in ('ICMP',):
                suspicious.append(f"{at}+{proto}={row['count']}")
            elif at == 'UDP Flood' and proto not in ('UDP',):
                suspicious.append(f"{at}+{proto}={row['count']}")
            elif at == 'Control Plane Saturation' and proto not in ('UDP',):
                suspicious.append(f"{at}+{proto}={row['count']}")
        if suspicious:
            print(f"  ⚠ CROSS-PROTOCOL CONTAMINATION: {', '.join(suspicious)}")
        else:
            print(f"  ✅ No cross-protocol contamination")
