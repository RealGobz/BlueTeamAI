"""
extract_rules.py - Helper script to extract high and critical Sigma rules
from the SigmaHQ master archive into detection/rules/
"""

import argparse
import os
import re
import zipfile


def extract_high_critical_rules(zip_path: str, output_dir: str) -> int:
    """Extract only high and critical process-creation rules from Sigma archive."""
    os.makedirs(output_dir, exist_ok=True)
    count = 0

    print(f"[*] Opening Sigma archive: {zip_path}")
    with zipfile.ZipFile(zip_path, "r") as archive:
        for file_name in archive.namelist():
            # Target only Windows process-creation rules
            if (
                "rules/windows/process_creation/" in file_name
                and file_name.endswith(".yml")
            ):
                content_bytes = archive.read(file_name)
                content_text = content_bytes.decode("utf-8", errors="ignore")

                # Filter for level: high or level: critical (per about.md requirement)
                # Also include medium for LOLBINs if relevant
                if re.search(
                    r"level:\s*(high|critical)", content_text, re.IGNORECASE
                ):
                    rule_filename = os.path.basename(file_name)
                    dest_path = os.path.join(output_dir, rule_filename)
                    with open(dest_path, "wb") as f_out:
                        f_out.write(content_bytes)
                    count += 1

    print(
        f"[+] Successfully extracted {count} High/Critical process creation rules into: {output_dir}"
    )
    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract High/Critical process creation rules from Sigma archive."
    )
    parser.add_argument(
        "--zip", required=True, help="Path to Sigma master zip archive"
    )
    parser.add_argument(
        "--output", required=True, help="Destination directory for rules"
    )
    args = parser.parse_args()

    extract_high_critical_rules(args.zip, args.output)
