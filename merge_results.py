import json
import csv
from pathlib import Path

BASE_DIR = Path.cwd()

SEMGREP_DIR = BASE_DIR / "results" / "semgrep"
BANDIT_DIR = BASE_DIR / "results" / "bandit"

OUTPUT_DIR = BASE_DIR / "results_csv"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def parse_semgrep(repo_name):
    file = SEMGREP_DIR / f"{repo_name}.json"
    rows = []

    if not file.exists():
        return rows

    try:
        data = json.load(open(file, encoding="utf-8"))

        for result in data.get("results", []):
            severity = result.get("extra", {}).get("severity", "UNKNOWN")
            rule_id = result.get("check_id", "N/A")
            message = result.get("extra", {}).get("message", "")
            cwes = result.get("extra", {}).get("metadata", {}).get("cwe", [])

            cwe_value = ",".join(cwes) if cwes else "N/A"

            rows.append([
                "Semgrep",
                severity,
                rule_id,
                cwe_value,
                message
            ])
    except Exception as e:
        print(f"[Semgrep Parse Error] {repo_name}: {e}")

    return rows


def parse_bandit(repo_name):
    file = BANDIT_DIR / f"{repo_name}.json"
    rows = []

    if not file.exists():
        return rows

    try:
        data = json.load(open(file, encoding="utf-8"))

        for result in data.get("results", []):
            severity = result.get("issue_severity", "UNKNOWN")
            rule_id = result.get("test_id", "N/A")
            message = result.get("issue_text", "")

            rows.append([
                "Bandit",
                severity,
                rule_id,
                "N/A",
                message
            ])
    except Exception as e:
        print(f"[Bandit Parse Error] {repo_name}: {e}")

    return rows


def main():
    # 🔥 Get all repos from semgrep results
    semgrep_files = list(SEMGREP_DIR.glob("*.json"))

    if not semgrep_files:
        print("No scan results found.")
        return

    for file in semgrep_files:
        repo_name = file.stem

        semgrep_rows = parse_semgrep(repo_name)
        bandit_rows = parse_bandit(repo_name)

        all_rows = semgrep_rows + bandit_rows

        output_file = OUTPUT_DIR / f"{repo_name}.csv"

        with open(output_file, "w", newline="", encoding="utf-8") as f_csv:
            writer = csv.writer(f_csv)

            writer.writerow([
                "Tool",
                "Severity",
                "Rule_ID",
                "CWE",
                "Description"
            ])

            writer.writerows(all_rows)

        print(f"Created CSV for {repo_name}")


if __name__ == "__main__":
    main()