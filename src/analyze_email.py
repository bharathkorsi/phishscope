import hashlib
import json
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent


def domain(address):
    parsed = parseaddr(str(address or ""))[1]
    return parsed.rsplit("@", 1)[1].casefold() if "@" in parsed else ""


def defang(url):
    return (
        url.replace("https://", "hxxps://")
        .replace("http://", "hxxp://")
        .replace(".", "[.]")
    )


def analyze_email(path):
    raw = path.read_bytes()
    message = BytesParser(policy=policy.default).parsebytes(raw)

    sender = str(message.get("From", ""))
    reply_to = str(message.get("Reply-To", ""))
    subject = str(message.get("Subject", ""))

    bodies = []
    attachments = []

    for part in message.walk():
        if part.is_multipart():
            continue

        if part.get_content_disposition() == "attachment" or part.get_filename():
            content = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": part.get_filename() or "(unnamed)",
                "content_type": part.get_content_type(),
                "size_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest()
            })
        elif part.get_content_type() == "text/plain":
            bodies.append(part.get_content())

    body = "\n".join(bodies)
    urls = sorted(set(
        match.rstrip(".,;!?)")
        for match in re.findall(r'https?://[^\s<>"\']+', body)
    ))

    findings = []

    if not domain(sender):
        findings.append({
            "code": "MISSING_SENDER_DOMAIN",
            "reason": "A sender domain could not be extracted."
        })

    if reply_to and domain(sender) and domain(reply_to):
        if domain(sender) != domain(reply_to):
            findings.append({
                "code": "REPLY_TO_DOMAIN_MISMATCH",
                "reason": "Sender and Reply-To domains differ; verify the context."
            })

    urgency_terms = [
        term for term in ("urgent", "immediately", "suspended")
        if re.search(r"\b" + term + r"\b", subject + "\n" + body, re.I)
    ]

    if urgency_terms:
        findings.append({
            "code": "URGENCY_LANGUAGE",
            "reason": "Review urgency wording: " + ", ".join(urgency_terms)
        })

    return {
        "file": path.name,
        "email_sha256": hashlib.sha256(raw).hexdigest(),
        "sender": sender,
        "reply_to": reply_to,
        "subject": subject,
        "urls_defanged": [defang(url) for url in urls],
        "attachments": attachments,
        "findings": findings,
        "assessment": (
            "Review indicators identified; maliciousness undetermined."
            if findings else
            "No configured indicators identified; safety not established."
        ),
        "limitations": [
            "Only plain-text body URLs are extracted.",
            "SPF, DKIM, and DMARC are not verified.",
            "No reputation lookups or attachment execution are performed.",
            "Domain mismatch and urgency can occur in legitimate emails."
        ]
    }


def main():
    paths = sorted((PROJECT / "sample-emails").glob("*.eml"))
    if not paths:
        raise SystemExit("No .eml files found in sample-emails.")

    reports = PROJECT / "reports"
    reports.mkdir(exist_ok=True)

    for path in paths:
        result = analyze_email(path)
        output = reports / f"{path.stem}-analysis.json"
        output.write_text(
            json.dumps(result, indent=2) + "\n",
            encoding="utf-8"
        )

        print(f"\nEmail: {path.name}")
        print(f"Review indicators: {len(result['findings'])}")
        print(f"URLs extracted: {len(result['urls_defanged'])}")
        print(f"Attachments hashed: {len(result['attachments'])}")
        print(f"Assessment: {result['assessment']}")
        print(f"Saved: reports/{output.name}")


if __name__ == "__main__":
    main()
