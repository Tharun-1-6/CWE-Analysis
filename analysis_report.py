import csv
from pathlib import Path
from collections import Counter

BASE_DIR = Path.cwd()
CSV_DIR = BASE_DIR / "results_csv"


def main():
    csv_files = list(CSV_DIR.glob("*.csv"))

    if not csv_files:
        print("No CSVs found.")
        return

    global_stats = {
        "repos": 0,
        "findings": 0,
        "semgrep": 0,
        "bandit": 0,
        "severity": Counter(),
        "cwe": Counter()
    }

    for file in csv_files:
        global_stats["repos"] += 1

        with open(file, encoding="utf-8") as f:
            reader = csv.DictReader(f)

            for row in reader:
                global_stats["findings"] += 1

                if row["Tool"] == "Semgrep":
                    global_stats["semgrep"] += 1
                elif row["Tool"] == "Bandit":
                    global_stats["bandit"] += 1

                global_stats["severity"][row["Severity"]] += 1

                if row["CWE"] != "N/A":
                    for c in row["CWE"].split(","):
                        global_stats["cwe"][c.strip()] += 1

    # 🔥 Prepare output
    output_lines = []

    output_lines.append("================ FINAL DATASET STATS ================")
    output_lines.append(f"Total Repositories: {global_stats['repos']}")
    output_lines.append(f"Total Findings: {global_stats['findings']}")

    output_lines.append("\nTool Distribution:")
    output_lines.append(f"  Semgrep: {global_stats['semgrep']}")
    output_lines.append(f"  Bandit: {global_stats['bandit']}")

    output_lines.append("\nSeverity Distribution:")
    for k, v in global_stats["severity"].items():
        output_lines.append(f"  {k}: {v}")

    output_lines.append("\nTop 10 CWEs:")
    for c, n in global_stats["cwe"].most_common(10):
        output_lines.append(f"  {c}: {n}")

    output_lines.append("===================================================")

    # 🔥 Print to terminal
    for line in output_lines:
        print(line)

    # 🔥 Save to TXT file
    with open("final_analysis.txt", "w", encoding="utf-8") as f:
        for line in output_lines:
            f.write(line + "\n")

    print("\n📄 Saved report to final_analysis.txt")


if __name__ == "__main__":
    main()