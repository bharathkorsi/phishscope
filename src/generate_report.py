import html
import json
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
REPORTS = PROJECT / "reports"


def escape(value):
    return html.escape(str(value), quote=True)


def main():
    paths = sorted(REPORTS.glob("*-analysis.json"))
    if not paths:
        raise SystemExit("Run src/analyze_email.py first.")

    validation = json.loads(
        (REPORTS / "email-validation.json").read_text(encoding="utf-8")
    )

    cards = []

    for path in paths:
        report = json.loads(path.read_text(encoding="utf-8"))

        findings = "".join(
            f"<li><strong>{escape(item['code'])}</strong>"
            f"<br>{escape(item['reason'])}</li>"
            for item in report["findings"]
        ) or "<li>No configured indicators identified.</li>"

        urls = "".join(
            f"<li><code>{escape(url)}</code></li>"
            for url in report["urls_defanged"]
        ) or "<li>No plain-text HTTP(S) URLs extracted.</li>"

        attachments = "".join(
            "<tr>"
            f"<td>{escape(item['filename'])}</td>"
            f"<td>{escape(item['content_type'])}</td>"
            f"<td>{escape(item['size_bytes'])}</td>"
            f"<td><code>{escape(item['sha256'])}</code></td>"
            "</tr>"
            for item in report["attachments"]
        )

        attachment_section = (
            "<div class='scroll'><table><thead><tr>"
            "<th>Filename</th><th>Type</th><th>Bytes</th><th>SHA-256</th>"
            "</tr></thead><tbody>"
            + attachments + "</tbody></table></div>"
            if attachments else "<p>No attachments identified.</p>"
        )

        badge = (
            "REVIEW INDICATORS FOUND"
            if report["findings"] else "NO CONFIGURED INDICATORS"
        )

        cards.append(f"""
<section>
  <span class="badge">{badge}</span>
  <h2>{escape(report['file'])}</h2>
  <dl>
    <dt>Subject</dt><dd>{escape(report['subject'])}</dd>
    <dt>From</dt><dd>{escape(report['sender'])}</dd>
    <dt>Reply-To</dt><dd>{escape(report['reply_to'] or '(not provided)')}</dd>
  </dl>
  <h3>Review indicators</h3>
  <ul>{findings}</ul>
  <h3>Extracted URLs — defanged</h3>
  <ul>{urls}</ul>
  <h3>Attachment metadata</h3>
  {attachment_section}
  <p class="assessment">{escape(report['assessment'])}</p>
  <details>
    <summary>Email file SHA-256</summary>
    <code>{escape(report['email_sha256'])}</code>
  </details>
</section>
""")

    page = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishScope — Email Triage Report</title>
<style>
* { box-sizing: border-box; }
body {
  margin: 0; background: #101827; color: #e5edf7;
  font: 16px/1.6 system-ui, sans-serif;
}
main { max-width: 1100px; margin: auto; padding: 32px 20px; }
h1 { font-size: 38px; margin-bottom: 4px; }
.subtitle, footer { color: #b6c5d8; }
.stats { display: flex; flex-wrap: wrap; gap: 16px; margin: 24px 0; }
.stat, section {
  background: #1a2638; border: 1px solid #34465f;
  border-radius: 12px; padding: 22px;
}
.stat { flex: 1; min-width: 170px; }
.stat strong { display: block; font-size: 28px; color: #78e2ce; }
section { margin-bottom: 24px; }
.badge {
  display: inline-block; background: #33425b; color: #e5edf7;
  padding: 4px 12px; border-radius: 20px; font-size: 12px;
}
dt { font-weight: bold; color: #b6c5d8; }
dd { margin: 0 0 10px; overflow-wrap: anywhere; }
li { margin-bottom: 12px; }
code { overflow-wrap: anywhere; }
.scroll { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 10px; border-bottom: 1px solid #34465f; }
td:last-child { min-width: 220px; }
.assessment { border-left: 3px solid #ffdb8d; padding-left: 12px; }
</style>
</head>
<body><main>
<h1>PhishScope</h1>
<p class="subtitle">Python automation for evidence-based email triage</p>
"""

    page += f"""
<div class="stats">
  <div class="stat"><strong>{len(paths)}</strong>Emails analyzed</div>
  <div class="stat">
    <strong>{escape(validation['passed'])}/{escape(validation['total'])}</strong>
    Saved validation results
  </div>
  <div class="stat"><strong>Offline</strong>Local file analysis</div>
</div>
"""

    page += "".join(cards)
    page += """
<footer>
<p>Demonstration uses fictional emails. Findings are review indicators;
absence of findings does not establish safety.</p>
<p>Plain-text body URL extraction only. SPF, DKIM, DMARC, HTML links,
and reputation are not assessed. Attachment hashes identify content;
they do not determine maliciousness.</p>
<p>Built from saved analysis and validation files. Rerun analysis,
validation, and report generation before sharing updated results.</p>
</footer>
</main></body></html>
"""

    output = REPORTS / "email-triage-report.html"
    output.write_text(page, encoding="utf-8")
    print(f"Created: {output.relative_to(PROJECT)}")


if __name__ == "__main__":
    main()
