from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from semgrep_scan import run_semgrep
from bandit_scan import run_bandit

MAX_WORKERS = 6


def process_repo(repo):
    try:
        repo_name = repo.split("/")[-1].replace(".git", "")

        # ✅ Skip if already processed
        if Path(f"results_csv/{repo_name}.csv").exists():
            print(f"Skipping {repo_name} (already done)")
            return

        print(f"\nProcessing: {repo}")

        repo_name, repo_path, semgrep_file = run_semgrep(repo)
        run_bandit(repo_name, repo_path, semgrep_file)

    except Exception as e:
        print(f"Error processing {repo}: {e}")


def main():
    print("\n📂 Using repo list: repos.txt")

    with open("repos.txt", encoding="utf-8") as f:
        repos = [r.strip() for r in f if r.strip()]

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        executor.map(process_repo, repos)

    print("\n✅ Scanning completed")

    import subprocess, sys
    subprocess.run([sys.executable, "merge_results.py"])
    subprocess.run([sys.executable, "analysis_report.py"])


if __name__ == "__main__":
    main()