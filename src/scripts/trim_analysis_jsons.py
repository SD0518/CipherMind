import argparse
import json
import os
import re
from typing import Any, Dict


TIMESTAMP_REGEX = re.compile(r"_(\d{8}_\d{6})\.json$")
# Capture kind and timestamp anywhere in the filename, like ..._analysis_YYYYMMDD_HHMMSS.json
KIND_TS_INFIX_REGEX = re.compile(r"(analysis|iterations|messages)_(\d{8}_\d{6})\.json$", re.IGNORECASE)


def extract_timestamp_from_filename(filename: str) -> str:
    match = TIMESTAMP_REGEX.search(filename)
    return match.group(1) if match else ""


def remove_name_keys(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: remove_name_keys(v) for k, v in obj.items() if k != "name"}
    if isinstance(obj, list):
        return [remove_name_keys(v) for v in obj]
    return obj


def reduce_payload(original: Any, filename: str) -> Dict[str, Any]:
    cleaned = remove_name_keys(original)
    timestamp = extract_timestamp_from_filename(filename)

    if isinstance(cleaned, dict):
        result: Dict[str, Any] = {}
        if "function" in cleaned:
            result["function"] = cleaned["function"]
        if "analysis" in cleaned:
            result["analysis"] = cleaned["analysis"]

        if not result:
            # If this is an analysis file (by name), wrap the content as analysis
            if "analysis" in os.path.basename(filename):
                result = {"analysis": cleaned}
            else:
                # For other files, keep only top-level function if available in nested items
                result = {"analysis": cleaned}

    else:
        # Non-dict JSON (e.g., list). Treat as analysis content.
        result = {"analysis": cleaned}

    if timestamp:
        result["timestamp"] = timestamp
    return result


def compute_new_basename(filename: str) -> str | None:
    base = os.path.basename(filename)
    m = KIND_TS_INFIX_REGEX.search(base)
    if not m:
        return None
    kind = m.group(1).lower()
    ts = m.group(2)
    return f"{kind}_{ts}.json"


def safe_rename(path: str, new_basename: str) -> str:
    directory = os.path.dirname(path)
    target = os.path.join(directory, new_basename)
    if os.path.abspath(path) == os.path.abspath(target):
        return path
    if not os.path.exists(target):
        os.replace(path, target)
        return target
    stem, ext = os.path.splitext(new_basename)
    counter = 1
    while True:
        candidate = os.path.join(directory, f"{stem}_{counter}{ext}")
        if not os.path.exists(candidate):
            os.replace(path, candidate)
            return candidate
        counter += 1


def process_file(path: str, do_rename: bool) -> str:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    reduced = reduce_payload(data, os.path.basename(path))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(reduced, f, ensure_ascii=False, indent=2)
        f.write("\n")
    if do_rename:
        new_base = compute_new_basename(path)
        if new_base:
            path = safe_rename(path, new_base)
    print(f"Processed: {os.path.basename(path)}")
    return path


def process_directory(target_dir: str, do_rename: bool) -> None:
    if not os.path.isdir(target_dir):
        raise FileNotFoundError(f"Directory not found: {target_dir}")

    for root, _dirs, files in os.walk(target_dir):
        for entry in files:
            if not entry.lower().endswith(".json"):
                continue
            path = os.path.join(root, entry)
            try:
                process_file(path, do_rename)
            except Exception as e:
                print(f"Failed: {os.path.relpath(path, start=target_dir)}: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Trim JSONs to keep only function, analysis, and timestamp; remove name fields. Recurses directories.")
    parser.add_argument(
        "--path",
        help="A file or directory path to process. If omitted, defaults to the bitsadmin analysis dir.",
    )
    parser.add_argument("--no-rename", action="store_true", help="Do not rename files to kind_timestamp.json")
    args = parser.parse_args()
    default_dir = os.path.join(
        "mordor_dataset",
        "eval_output",
        "analysis",
    )
    target = args.path or default_dir
    if os.path.isdir(target):
        process_directory(target, do_rename=not args.no_rename)
    elif os.path.isfile(target):
        process_file(target, do_rename=not args.no_rename)
    else:
        raise FileNotFoundError(f"Path not found: {target}")


if __name__ == "__main__":
    main()


