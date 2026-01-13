import json
import os

RESULTS_DIR = "results"
CLONED_REPOS_DIR = "cloned_repos"

SEVERITY_WEIGHTS = {
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 5
}

def calculate_loc(repo_path):
    loc = 0
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if line.strip() and not line.strip().startswith("#"):
                                loc += 1
                except Exception:
                    pass
    return loc


def analyze_bandit_report(json_path, repo_path):
    with open(json_path, "r") as f:
        data = json.load(f)

    severity_count = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    cwe_set = set()

    for issue in data.get("results", []):
        severity = issue.get("issue_severity", "LOW")
        cwe = issue.get("issue_cwe")

        if severity in severity_count:
            severity_count[severity] += 1

        if cwe and "id" in cwe:
            cwe_set.add(f"CWE-{cwe['id']}")

    vulnerability_score = sum(
        severity_count[s] * SEVERITY_WEIGHTS[s] for s in severity_count
    )

    loc = calculate_loc(repo_path)

    density = vulnerability_score / loc if loc > 0 else 0

    return severity_count, sorted(cwe_set), vulnerability_score, loc, density


def main():
    print("\n🔐 Automated CWE Vulnerability Analysis (With LOC & Density)\n")

    for file_name in os.listdir(RESULTS_DIR):
        if not file_name.endswith(".json"):
            continue

        repo_name = file_name.replace("_bandit.json", "")
        json_path = os.path.join(RESULTS_DIR, file_name)
        repo_path = os.path.join(CLONED_REPOS_DIR, repo_name)

        if not os.path.exists(repo_path):
            print(f"⚠️ Repo folder missing for {repo_name}, skipping.")
            continue

        severity_count, cwes, score, loc, density = analyze_bandit_report(
            json_path, repo_path
        )

        print(f"📦 Repository: {repo_name}")
        print(f"   Python LOC              : {loc}")
        print(f"   Vulnerabilities:")
        print(f"     HIGH   : {severity_count['HIGH']}")
        print(f"     MEDIUM : {severity_count['MEDIUM']}")
        print(f"     LOW    : {severity_count['LOW']}")
        print(f"   CWE IDs Found           : {', '.join(cwes) if cwes else 'None'}")
        print(f"   Vulnerability Score     : {score}")
        print(f"   Vulnerability Density   : {density:.6f}")
        print("-" * 60)


if __name__ == "__main__":
    main()
