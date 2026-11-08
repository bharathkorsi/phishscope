# PhishScope 🔎

Automate email triage with explainable findings.

A Python prototype that analyzes saved email files, identifies
selected review indicators, extracts URLs, hashes attachments,
and generates JSON and HTML reports.

## Features

- Batch analysis of local .eml files.
- Sender and Reply-To domain comparison.
- Detection of selected urgency words.
- Plain-text HTTP(S) URL extraction and deduplication.
- Defanged URLs displayed as text.
- SHA-256 hashes for email files and attachment contents.
- HTML-escaped report values.
- Ten automated validation checks.

## Run the Demo

Uses Python's standard library. No external packages required.
Developed and tested locally with Python 3.14.

From the project folder:

    python3 run_demo.py

Open the report on macOS:

    open reports/email-triage-report.html

The workflow validates the analyzer, processes sample emails,
and builds the HTML report. It stops if a step fails.

## Fictional Demo Results

| Sample | Review indicators | URLs | Attachments |
| --- | --- | --- | --- |
| ordinary-demo.eml | 0 | 0 | 0 |
| suspicious-demo.eml | 2 | 1 | 1 |

The suspicious sample contains a Reply-To domain mismatch
and urgency language. These indicators require context;
they do not establish that an email is malicious.

## Explore the Evidence

- [Email analyzer](src/analyze_email.py)
- [Validation script](tests/validate_email_analysis.py)
- [Validation results](reports/email-validation.json)
- [Ordinary email analysis](reports/ordinary-demo-analysis.json)
- [Suspicious email analysis](reports/suspicious-demo-analysis.json)
- [HTML report source — download to view](reports/email-triage-report.html)
- [Sample emails](sample-emails/)
- [Demo runner](run_demo.py)

## Limitations

- Uses fictional emails for demonstration.
- Only plain-text body URLs are extracted.
- SPF, DKIM, and DMARC are not verified.
- No URL reputation checks or attachment execution.
- Attachment hashes identify content, not maliciousness.
- Legitimate emails can contain urgency or differing domains.
- No findings does not mean an email is safe.
- Malformed messages and unusual encodings need broader testing.
- Reports are overwritten on reruns.
- The HTML report includes all saved *-analysis.json files;
  reports from removed samples may remain until removed separately.

## Planned Improvements

- HTML link extraction.
- Stronger handling of malformed messages.
- Configurable checks and input paths.
- Report freshness tracking.
- Optional reputation enrichment.
