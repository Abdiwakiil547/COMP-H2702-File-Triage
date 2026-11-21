
"""File triage program using SHA-256 hashes."""

import argparse
import csv
import hashlib
import json
from pathlib import Path
from datetime import datetime


def load_references(path):
    references = {}

    try:
        with open(path, "r", encoding="utf-8-sig", newline="") as file:
            reader = csv.DictReader(file)

            if not reader.fieldnames:
                raise ValueError("Reference CSV is empty")

            if "sha256" not in reader.fieldnames or "label" not in reader.fieldnames:
                raise ValueError("Reference CSV needs sha256 and label columns")

            for row in reader:
                file_hash = (row.get("sha256") or "").strip().lower()
                label = (row.get("label") or "").strip()

                # Check that each reference contains a valid SHA-256 hash.
                if len(file_hash) != 64:
                    raise ValueError("Invalid SHA-256 in reference CSV")

                for character in file_hash:
                    if character not in "0123456789abcdef":
                        raise ValueError("Invalid SHA-256 in reference CSV")

                if file_hash in references:
                    raise ValueError("Duplicate SHA-256 in reference CSV")

                references[file_hash] = label

    except (OSError, UnicodeError, csv.Error, ValueError) as error:
        raise ValueError("Could not load reference data: " + str(error))

    return references


def hash_file(path):
    # SHA-256 creates a fingerprint from the file's contents.
    hash_value = hashlib.sha256()

    with open(path, "rb") as file:
        while True:
            data = file.read(65536)

            if not data:
                break

            hash_value.update(data)

    return hash_value.hexdigest()


def analyse_folder(folder, references, reference_path, output_path):
    results = []
    errors = []

    for path in sorted(folder.iterdir()):
        if not path.is_file():
            continue

        # Skip the teaching README, reference CSV and generated report.
        if path.name.lower() == "readme.txt":
            continue

        if path.resolve() == reference_path.resolve():
            continue

        if path.resolve() == output_path.resolve():
            continue

        try:
            details = path.stat()
            file_hash = hash_file(path)

            status = "UNKNOWN"
            label = ""

            if file_hash in references:
                status = "KNOWN"
                label = references[file_hash]

            modified_time = datetime.fromtimestamp(details.st_mtime)
            modified_time = modified_time.astimezone().isoformat(timespec="seconds")

            file_result = {
                "filename": path.name,
                "extension": path.suffix.lower() or "(none)",
                "size_bytes": details.st_size,
                "modified": modified_time,
                "sha256": file_hash,
                "status": status,
                "reference_label": label
            }

            results.append(file_result)

        except OSError as error:
            errors.append(path.name + ": " + str(error))

    return results, errors


def find_duplicates(results):
    # Files with the same hash have matching contents.
    hashes = {}
    duplicates = []

    for item in results:
        file_hash = item["sha256"]
        filename = item["filename"]

        if file_hash not in hashes:
            hashes[file_hash] = []

        hashes[file_hash].append(filename)

    for file_hash in hashes:
        filenames = hashes[file_hash]

        if len(filenames) > 1:
            duplicates.append({
                "sha256": file_hash,
                "files": filenames
            })

    return duplicates


def generate_report(results, errors, folder, duplicates, output):
    known = 0
    unknown = 0

    for item in results:
        if item["status"] == "KNOWN":
            known += 1
        else:
            unknown += 1

    report = {
        "folder": str(folder.resolve()),
        "total_files": len(results),
        "known": known,
        "unknown": unknown,
        "files": results,
        "duplicate_groups": duplicates,
        "errors": errors,
        "interpretation": [
            "A matching SHA-256 shows that file content matches a reference hash. It does not prove the file is safe.",
            "UNKNOWN means the hash was not found in the reference CSV. It does not prove the file is malicious.",
            "Files with the same SHA-256 have matching contents, even when their filenames are different."
        ]
    }

    output.parent.mkdir(parents=True, exist_ok=True)

    with open(output, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    print(f"Analysed {len(results)} files: {known} KNOWN, {unknown} UNKNOWN")

    for item in results:
        print(
            f'{item["filename"]}: {item["status"]} | '
            f'{item["size_bytes"]} bytes | {item["sha256"]}'
        )

    for group in duplicates:
        print("DUPLICATE CONTENT:", ", ".join(group["files"]))

    for error in errors:
        print("FILE ERROR:", error)

    print(f"Report saved: {output}")

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Analyse local files using SHA-256"
    )

    parser.add_argument("folder", nargs="?", default="samples")
    parser.add_argument("--references", default="samples/hashes_reference.csv")
    parser.add_argument("--output", default="output/triage_report.json")

    args = parser.parse_args()

    folder = Path(args.folder)
    reference_path = Path(args.references)
    output_path = Path(args.output)

    if not folder.is_dir():
        parser.error("Input folder does not exist: " + str(folder))

    try:
        references = load_references(reference_path)
        results, errors = analyse_folder(
            folder, references, reference_path, output_path
        )

        duplicates = find_duplicates(results)

        generate_report(
            results, errors, folder, duplicates, output_path
        )

    except (OSError, ValueError) as error:
        parser.exit(1, "ERROR: " + str(error) + "\n")


if __name__ == "__main__":
    main()
