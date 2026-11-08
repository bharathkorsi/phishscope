import hashlib
import json
import sys
import tempfile
from email.message import EmailMessage
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT / "src"))

from analyze_email import analyze_email


def make_email(sender, reply_to=None, subject="Team update", body="Hello Alex."):
    message = EmailMessage()
    message["From"] = sender
    message["To"] = "alex@company.example"
    message["Subject"] = subject
    if reply_to:
        message["Reply-To"] = reply_to
    message.set_content(body)
    return message


def codes(result):
    return {finding["code"] for finding in result["findings"]}


checks = []


def check(name, condition):
    checks.append({"name": name, "passed": bool(condition)})
    print(f"{'PASS' if condition else 'FAIL'}: {name}")


ordinary = analyze_email(PROJECT / "sample-emails" / "ordinary-demo.eml")
suspicious = analyze_email(PROJECT / "sample-emails" / "suspicious-demo.eml")

check("Ordinary sample has no configured indicators",
      codes(ordinary) == set())

check("Suspicious sample has the expected indicators",
      codes(suspicious) == {
          "REPLY_TO_DOMAIN_MISMATCH", "URGENCY_LANGUAGE"
      })

check("Sample URL is extracted and defanged",
      suspicious["urls_defanged"] == [
          "hxxps://account-check[.]example/verify"
      ])

payload = b"Fictional invoice for security training. No executable content.\n"
check("Attachment hash matches its known contents",
      len(suspicious["attachments"]) == 1
      and suspicious["attachments"][0]["sha256"]
      == hashlib.sha256(payload).hexdigest())

with tempfile.TemporaryDirectory() as folder:
    path = Path(folder) / "test.eml"

    def analyze(message):
        path.write_bytes(message.as_bytes())
        return analyze_email(path)

    result = analyze(make_email(
        "team@COMPANY.example", "team@company.example"
    ))
    check("Domain comparison ignores capitalization",
          codes(result) == set())

    result = analyze(make_email("team@company.example"))
    check("Missing optional Reply-To does not create a mismatch",
          codes(result) == set())

    result = analyze(make_email(
        "team@company.example", "team@company.example",
        subject="Urgent: meeting room change"
    ))
    check("Legitimate urgency is a review indicator",
          codes(result) == {"URGENCY_LANGUAGE"}
          and result["assessment"]
          == "Review indicators identified; maliciousness undetermined.")

    result = analyze(make_email(
        "team@company.example",
        body="https://portal.example/help https://portal.example/help"
    ))
    check("Repeated URL is reported once",
          result["urls_defanged"] == ["hxxps://portal[.]example/help"])

    result = analyze(make_email(
        "team@company.example", body="The unsurged project is resuspended."
    ))
    check("Partial words do not trigger urgency matching",
          codes(result) == set())

    message = make_email("team@company.example")
    del message["From"]
    result = analyze(message)
    check("Missing sender domain is reported",
          codes(result) == {"MISSING_SENDER_DOMAIN"})

passed = sum(item["passed"] for item in checks)
report = PROJECT / "reports" / "email-validation.json"
report.write_text(
    json.dumps({
        "total": len(checks),
        "passed": passed,
        "failed": len(checks) - passed,
        "checks": checks
    }, indent=2) + "\n",
    encoding="utf-8"
)

print(f"\nPassed: {passed}/{len(checks)}")
print("Saved: reports/email-validation.json")
sys.exit(0 if passed == len(checks) else 1)
