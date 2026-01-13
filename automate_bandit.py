import os
import subprocess

BASE_DIR = os.getcwd()
CLONE_DIR = os.path.join(BASE_DIR, "cloned_repos")
RESULTS_DIR = os.path.join(BASE_DIR, "results")

os.makedirs(CLONE_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

with open("repos.txt", "r") as f:
    repos = [line.strip() for line in f if line.strip()]

for repo_url in repos:
    repo_name = repo_url.split("/")[-1].replace(".git", "")
    repo_path = os.path.join(CLONE_DIR, repo_name)
    output_file = os.path.join(RESULTS_DIR, f"{repo_name}_bandit.json")

    print(f"\n🔍 Processing repo: {repo_name}")

    # Clone repo
    if not os.path.exists(repo_path):
        print("📥 Cloning repository...")
        subprocess.run(["git", "clone", repo_url, repo_path])
    else:
        print("✅ Repo already cloned, skipping clone.")

    # Run Bandit (DO NOT crash on findings)
    print("🛡 Running Bandit scan...")
    result = subprocess.run(
        [
            "bandit",
            "-r",
            repo_path,
            "-f",
            "json",
            "-o",
            output_file
        ],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        print("✅ No security issues found.")
    elif result.returncode == 1:
        print("⚠️ Security issues found (expected). Report saved.")
    else:
        print("❌ Bandit execution error:")
        print(result.stderr)

print("\n🎯 Automation completed for all repositories.")
