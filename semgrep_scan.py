import subprocess
from pathlib import Path

BASE_DIR = Path.cwd()

SEMGREP_DIR = BASE_DIR / "results" / "semgrep"
CLONE_DIR = BASE_DIR / "cloned"

SEMGREP_DIR.mkdir(parents=True, exist_ok=True)
CLONE_DIR.mkdir(exist_ok=True)


def run_semgrep(repo_url):
    repo_name = repo_url.split("/")[-1].replace(".git", "")
    repo_path = CLONE_DIR / repo_name
    semgrep_file = SEMGREP_DIR / f"{repo_name}.json"

    print(f"\n[Semgrep] {repo_name}")
    print(f"[DEBUG] Cloning into: {repo_path}")

    # ✅ Skip if already scanned
    if semgrep_file.exists():
        print("[Semgrep] Already scanned. Skipping clone.")
        return repo_name, repo_path, semgrep_file

    # Clone into cloned/
    subprocess.run(
        f"git clone --depth 1 {repo_url} \"{repo_path}\"",
        shell=True
    )

    # Run Semgrep
    subprocess.run(
        f"semgrep --config p/default "
        f"--json -o \"{semgrep_file}\" "
        f"\"{repo_path}\" "
        f"--disable-version-check",
        shell=True
    )

    return repo_name, repo_path, semgrep_file