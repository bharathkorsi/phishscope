import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parent

steps = [
    ("Validate email analysis", "tests/validate_email_analysis.py"),
    ("Analyze sample emails", "src/analyze_email.py"),
    ("Build HTML report", "src/generate_report.py"),
]

for title, script in steps:
    print(f"\n--- {title} ---", flush=True)
    subprocess.run(
        [sys.executable, str(PROJECT / script)],
        cwd=PROJECT,
        check=True
    )

print("\nPhishScope demo completed successfully.")
print("Report: reports/email-triage-report.html")
