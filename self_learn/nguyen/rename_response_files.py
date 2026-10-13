#!/usr/bin/env python3
"""
Script to rename response analysis files to shorter, more readable names.

This script renames all JSON and MD files in the final_response directory
from long names like:
- covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges_2020-08-05020926_response_analysis.json
- covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges_2020-08-05020926_threat_report.md

To shorter names:
- response_analysis.json
- threat_report.md
"""

import os
import sys
from pathlib import Path
from typing import List, Tuple


def find_response_files(base_dir: str) -> List[Tuple[str, str, str]]:
    """
    Find all response analysis files that need to be renamed.
    
    Args:
        base_dir: Base directory to search (e.g., 'final_response')
        
    Returns:
        List of tuples: (file_path, new_json_name, new_md_name)
    """
    files_to_rename = []
    base_path = Path(base_dir)
    
    if not base_path.exists():
        print(f"[ERROR] Base directory '{base_dir}' does not exist!")
        return files_to_rename
    
    # Walk through all subdirectories
    for root, dirs, files in os.walk(base_path):
        root_path = Path(root)
        
        # Look for JSON and MD files with the old naming pattern
        json_files = [f for f in files if f.endswith('_response_analysis.json')]
        md_files = [f for f in files if f.endswith('_threat_report.md')]
        
        # Process JSON files
        for json_file in json_files:
            json_path = root_path / json_file
            new_json_name = "response_analysis.json"
            new_md_name = "threat_report.md"
            files_to_rename.append((str(json_path), new_json_name, new_md_name))
        
        # Process MD files
        for md_file in md_files:
            md_path = root_path / md_file
            new_json_name = "response_analysis.json"
            new_md_name = "threat_report.md"
            files_to_rename.append((str(md_path), new_json_name, new_md_name))
    
    return files_to_rename


def rename_files(files_to_rename: List[Tuple[str, str, str]], dry_run: bool = True) -> None:
    """
    Rename the files to shorter names.
    
    Args:
        files_to_rename: List of files to rename
        dry_run: If True, only show what would be renamed without actually doing it
    """
    if not files_to_rename:
        print("[INFO] No files found that need renaming.")
        return
    
    print(f"[INFO] Found {len(files_to_rename)} files to rename.")
    
    if dry_run:
        print("\n[DRY RUN] Files that would be renamed:")
    else:
        print("\n[RENAMING] Renaming files:")
    
    success_count = 0
    error_count = 0
    
    for file_path, new_json_name, new_md_name in files_to_rename:
        try:
            old_path = Path(file_path)
            new_name = new_json_name if file_path.endswith('.json') else new_md_name
            new_path = old_path.parent / new_name
            
            if dry_run:
                print(f"  {old_path.name} -> {new_name}")
            else:
                # Check if target file already exists
                if new_path.exists():
                    print(f"  [SKIP] {old_path.name} -> {new_name} (target already exists)")
                    continue
                
                # Rename the file
                old_path.rename(new_path)
                print(f"  [OK] {old_path.name} -> {new_name}")
                success_count += 1
                
        except Exception as e:
            print(f"  [ERROR] Failed to rename {file_path}: {e}")
            error_count += 1
    
    if not dry_run:
        print(f"\n[SUMMARY] Renamed {success_count} files successfully, {error_count} errors.")


def main():
    """Main function to handle command line arguments and execute renaming."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Rename response analysis files to shorter names",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python rename_response_files.py                    # Dry run (show what would be renamed)
  python rename_response_files.py --execute         # Actually rename the files
  python rename_response_files.py --dir custom_dir  # Use custom directory
        """
    )
    
    parser.add_argument(
        '--dir', 
        default='final_response',
        help='Base directory to search for files (default: final_response)'
    )
    
    parser.add_argument(
        '--execute',
        action='store_true',
        help='Actually rename files (default is dry run)'
    )
    
    args = parser.parse_args()
    
    print(f"[INFO] Searching for response files in: {args.dir}")
    
    # Find files to rename
    files_to_rename = find_response_files(args.dir)
    
    if not files_to_rename:
        print("[INFO] No files found that need renaming.")
        return
    
    # Show what we found
    print(f"[INFO] Found {len(files_to_rename)} files that match the old naming pattern.")
    
    # Rename files (dry run or actual)
    rename_files(files_to_rename, dry_run=not args.execute)
    
    if not args.execute:
        print("\n[INFO] This was a dry run. Use --execute to actually rename the files.")
        print("Example: python rename_response_files.py --execute")


if __name__ == "__main__":
    main()
