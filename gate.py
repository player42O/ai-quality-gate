"""Quality gate (Mission 1 placeholder).

Reads the PR diff and FAILS if any added line contains the marker below.
Later missions replace this check with a Claude AI audit + severity rules.
"""
import subprocess
import sys

# Built from two parts so this file doesn't trip its own gate.
MARKER = "DO_NOT" + "_MERGE"


def added_lines(base_branch):
    """Return (file, line) for every line the PR adds compared to the base branch."""
    diff = subprocess.run(
        ["git", "diff", f"origin/{base_branch}...HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout

    current_file = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            current_file = line[6:]  # strip "+++ b/"
        elif line.startswith("+"):
            yield current_file, line[1:]


def main():
    base_branch = sys.argv[1]
    findings = [(f, text) for f, text in added_lines(base_branch) if MARKER in text]

    if findings:
        print(f"FAIL: {len(findings)} finding(s)")
        for f, text in findings:
            print(f"  {f}: {text.strip()}")
        sys.exit(1)

    print("PASS: no findings")


if __name__ == "__main__":
    main()
