import subprocess
import json
import shutil
import csv
from pathlib import Path

BASE_DIR = Path.cwd()
BANDIT_DIR = BASE_DIR / "results" / "bandit"
REPO_DIR = BASE_DIR / "repos"

BANDIT_DIR.mkdir(parents=True, exist_ok=True)
REPO_DIR.mkdir(exist_ok=True)

SUMMARY_FILE = REPO_DIR / "repos_summary.csv"

if not SUMMARY_FILE.exists():
    with open(SUMMARY_FILE, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(["Repo", "Risk", "Total_Findings"])


def run_bandit(repo_name, repo_path, semgrep_file):
    bandit_file = BANDIT_DIR / f"{repo_name}.json"

    # ✅ Skip if already processed
    if SUMMARY_FILE.exists():
        with open(SUMMARY_FILE, encoding="utf-8") as f:
            if repo_name in f.read():
                print(f"[Bandit] {repo_name} already processed. Skipping.")
                return

    def is_high():
        try:
            data = json.load(open(semgrep_file))
            for r in data.get("results", []):
                if r.get("extra", {}).get("severity") in ["ERROR", "WARNING"]:
                    return True
        except:
            pass
        return False

    def count(file):
        try:
            data = json.load(open(file))
            return len(data.get("results", []))
        except:
            return 0

    # Low risk
    if not is_high():
        with open(SUMMARY_FILE, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([repo_name, "Low", 0])

        shutil.rmtree(repo_path, ignore_errors=True)
        return

    # High risk → run bandit
    subprocess.run(f"bandit -r {repo_path} -f json -o {bandit_file}", shell=True)

    total = count(semgrep_file) + count(bandit_file)

    with open(SUMMARY_FILE, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([repo_name, "High", total])

    # ✅ delete repo immediately
    shutil.rmtree(repo_path, ignore_errors=True)