#!/usr/bin/env python3
"""
FinCipher AI — CLI Backup and Disaster Recovery Utility
Usage:
  python scripts/backup_and_recovery.py --create [--desc "Description"]
  python scripts/backup_and_recovery.py --list
  python scripts/backup_and_recovery.py --verify <backup_id>
  python scripts/backup_and_recovery.py --restore <backup_id>
"""

import sys
import os
import argparse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.engine.backup_manager import backup_manager


def main():
    parser = argparse.ArgumentParser(description="FinCipher AI Backup and Disaster Recovery Utility")
    parser.add_argument("--create", action="store_true", help="Create a new snapshot backup")
    parser.add_argument("--desc", type=str, default="Manual CLI backup", help="Backup description")
    parser.add_argument("--list", action="store_true", help="List all available backups")
    parser.add_argument("--verify", type=str, metavar="BACKUP_ID", help="Verify integrity checksum of backup")
    parser.add_argument("--restore", type=str, metavar="BACKUP_ID", help="Restore database from verified backup")

    args = parser.parse_args()

    if args.create:
        print("[*] Initiating snapshot backup...")
        res = backup_manager.create_backup(description=args.desc)
        print(f"[+] Backup successfully generated: {res['backup_id']}")
        print(f"    File: {res['archive_filename']} ({res['archive_size_bytes']:,} bytes)")
        print(f"    SHA-256 Checksum: {res['sha256_checksum']}")

    elif args.list:
        backups = backup_manager.list_backups()
        print(f"\n[*] Discovered {len(backups)} backup archive(s):\n")
        print(f"{'Backup ID':<26} {'Created (UTC)':<22} {'Size':<12} {'Status':<10}")
        print("-" * 72)
        for b in backups:
            sz = f"{b.get('archive_size_bytes', 0):,} B"
            print(f"{b['backup_id']:<26} {b.get('created_at', ''):<22} {sz:<12} {b.get('status', 'UNKNOWN'):<10}")
        print()

    elif args.verify:
        print(f"[*] Verifying cryptographic integrity for {args.verify}...")
        res = backup_manager.verify_backup(args.verify)
        if res.get("valid"):
            print(f"[+] Checksum VERIFIED INTACT: {res['calculated_checksum']}")
        else:
            print(f"[-] Integrity FAILED: {res.get('error', 'Checksum mismatch')}")
            sys.exit(1)

    elif args.restore:
        print(f"[*] Restoring system state from {args.restore}...")
        res = backup_manager.restore_backup(args.restore)
        print(f"[+] Restore complete! Restored components: {', '.join(res.get('components_restored', []))}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
