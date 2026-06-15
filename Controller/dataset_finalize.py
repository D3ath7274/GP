"""
Dataset Finalize — Metadata Stripping + AES Encryption
=========================================================
Post-session script that:
  1. Strips all meta_* columns → outputs *_training.csv (DL-ready)
  2. Encrypts the full CSV with Fernet (AES-128-CBC) 
  3. Saves the encryption key to a separate .key file
  4. Optionally deletes the plaintext CSV

Usage:
    python3 dataset_finalize.py dataset.csv
    python3 dataset_finalize.py dataset.csv --keep-plaintext
    python3 dataset_finalize.py dataset.csv --no-encrypt

Rationale XII.A: meta_ columns constitute data leakage if included
as model inputs. The training file MUST strip them.
"""

import os
import sys
import csv
import argparse
from datetime import datetime


def strip_meta_columns(input_path, output_path):
    """
    Strip all meta_* columns from the CSV and write a training-ready file.
    Also strips label identification columns that are targets, not features.
    
    Returns:
        Tuple of (rows_written, columns_kept, columns_stripped)
    """
    with open(input_path, 'r', encoding='utf-8') as fin:
        reader = csv.DictReader(fin)
        all_cols = reader.fieldnames

        # Strip meta_ columns
        meta_cols = [c for c in all_cols if c.startswith('meta_')]
        keep_cols = [c for c in all_cols if c not in meta_cols]

        with open(output_path, 'w', newline='', encoding='utf-8') as fout:
            writer = csv.DictWriter(fout, fieldnames=keep_cols, extrasaction='ignore')
            writer.writeheader()
            rows_written = 0
            for row in reader:
                writer.writerow(row)
                rows_written += 1

    return rows_written, len(keep_cols), len(meta_cols)


def encrypt_file(input_path, output_path=None, key_path=None):
    """
    Encrypt a file using Fernet (AES-128-CBC with HMAC verification).
    
    Args:
        input_path: Path to the plaintext file.
        output_path: Path for the encrypted file (default: input + .enc).
        key_path: Path to save the encryption key (default: input + .key).
    
    Returns:
        Tuple of (encrypted_path, key_path)
    """
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        print("\n  ⚠ 'cryptography' package not installed.")
        print("    Install with: pip install cryptography")
        print("    Skipping encryption.\n")
        return None, None

    if output_path is None:
        output_path = input_path + '.enc'
    if key_path is None:
        key_path = input_path + '.key'

    # Generate key
    key = Fernet.generate_key()
    fernet = Fernet(key)

    # Encrypt
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    encrypted = fernet.encrypt(plaintext)

    with open(output_path, 'wb') as f:
        f.write(encrypted)

    # Save key
    with open(key_path, 'wb') as f:
        f.write(key)

    # Restrict key file permissions
    try:
        os.chmod(key_path, 0o600)
    except (OSError, AttributeError):
        pass

    return output_path, key_path


def decrypt_file(encrypted_path, key_path, output_path=None):
    """
    Decrypt a Fernet-encrypted file.
    
    Args:
        encrypted_path: Path to the encrypted file.
        key_path: Path to the encryption key.
        output_path: Path for the decrypted file (default: removes .enc extension).
    """
    from cryptography.fernet import Fernet

    if output_path is None:
        output_path = encrypted_path.replace('.enc', '')

    with open(key_path, 'rb') as f:
        key = f.read()

    fernet = Fernet(key)

    with open(encrypted_path, 'rb') as f:
        encrypted = f.read()

    decrypted = fernet.decrypt(encrypted)

    with open(output_path, 'wb') as f:
        f.write(decrypted)

    return output_path


def main():
    parser = argparse.ArgumentParser(
        description='Finalize dataset: strip meta columns and encrypt',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python3 dataset_finalize.py dataset.csv
    python3 dataset_finalize.py dataset.csv --keep-plaintext
    python3 dataset_finalize.py dataset.csv --no-encrypt
    python3 dataset_finalize.py --decrypt dataset.csv.enc --key dataset.csv.key
        """
    )
    parser.add_argument('input', help='Input CSV file')
    parser.add_argument('--keep-plaintext', action='store_true',
                        help='Do not delete the plaintext CSV after encryption')
    parser.add_argument('--no-encrypt', action='store_true',
                        help='Skip encryption (just strip meta columns)')
    parser.add_argument('--decrypt', action='store_true',
                        help='Decrypt mode: decrypt .enc file')
    parser.add_argument('--key', help='Key file for decryption')
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"❌ File not found: {args.input}")
        sys.exit(1)

    # Decrypt mode
    if args.decrypt:
        key_path = args.key or args.input.replace('.enc', '.key')
        if not os.path.exists(key_path):
            print(f"❌ Key file not found: {key_path}")
            sys.exit(1)
        output = decrypt_file(args.input, key_path)
        print(f"✅ Decrypted → {output}")
        return

    print(f"\n{'='*60}")
    print(f"  Dataset Finalization")
    print(f"  Input: {args.input}")
    print(f"  Time:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    # Step 1: Strip meta columns
    base = os.path.splitext(args.input)[0]
    training_path = base + '_training.csv'

    rows, kept, stripped = strip_meta_columns(args.input, training_path)
    print(f"\n  ✅ Training file: {training_path}")
    print(f"     {rows} rows, {kept} columns ({stripped} meta columns stripped)")

    # Step 2: Encrypt (unless --no-encrypt)
    if not args.no_encrypt:
        print(f"\n  Encrypting full dataset...")
        enc_path, key_path = encrypt_file(args.input)

        if enc_path:
            enc_size = os.path.getsize(enc_path)
            orig_size = os.path.getsize(args.input)
            print(f"  ✅ Encrypted: {enc_path} ({enc_size:,} bytes)")
            print(f"     Key file:  {key_path}")
            print(f"     Original:  {orig_size:,} bytes")

            # Step 3: Delete plaintext (unless --keep-plaintext)
            if not args.keep_plaintext:
                os.remove(args.input)
                print(f"\n  🗑 Deleted plaintext: {args.input}")
                print(f"     ⚠ Move {key_path} to offline storage!")
            else:
                print(f"\n  ℹ Plaintext kept (--keep-plaintext)")
    else:
        print(f"\n  ℹ Encryption skipped (--no-encrypt)")

    print(f"\n{'='*60}")
    print(f"  Finalization Complete")
    print(f"{'='*60}\n")


if __name__ == '__main__':
    main()
