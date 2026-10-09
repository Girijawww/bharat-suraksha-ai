# Bharat Suraksha AI

**A multilingual digital-safety educational prototype** that checks pasted messages or screenshots for a small set of common warning patterns. It is designed to encourage users to pause and verify independently—not to make a definitive fraud verdict.

## Features
- Paste a message or upload a screenshot (choose one at a time).
- Rule-based warning indicators with explanations.
- English, Tamil, and Hindi result/UI display; detection coverage is limited, especially for mixed-language and romanised text.
- Optional screenshot OCR through Tesseract; English is the only OCR language guaranteed by the included Dockerfile. Tamil/Hindi OCR require the matching Tesseract language data.
- URLs are not fetched or opened; displayed URLs are defanged.
- Input limits, image checks, JSON error responses, and basic security headers.
- Simulated examples and automated tests.

## Run locally

Python 3.10+ is recommended.

```bash
python -m venv .venv
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. The app binds to localhost for local development.

## Run tests

The test suite uses Python's built-in `unittest`, so it can run without installing pytest:

```bash
python -m unittest discover -s tests -v
```

Optional pytest support: `python -m pip install -r requirements-dev.txt` then `python -m pytest -q`.

## Screenshot OCR

OCR needs both the Python packages above and the separate Tesseract executable. If Tesseract is missing, text-paste mode still works.

- **Windows:** install Tesseract OCR, then ensure `tesseract.exe` is on PATH.
- **macOS:** with Homebrew, `brew install tesseract`.
- **Ubuntu/Debian:** `sudo apt-get install tesseract-ocr tesseract-ocr-eng`.
- **Tamil/Hindi OCR:** install the matching `tam` / `hin` language data too. If unavailable, OCR may fall back to English and be inaccurate.

OCR behavior depends on your OS installation; test with non-sensitive screenshots only.

## Deployment

For a Linux host that supports Python web apps, install dependencies plus Gunicorn and use:

```bash
pip install -r requirements.txt gunicorn
gunicorn --bind 0.0.0.0:$PORT app:app
```

A `Procfile` is included for compatible hosts. A `Dockerfile` is included as an alternative. Free hosting tiers and deployment providers change; configure the deployment using your chosen provider's current instructions. Do not claim a public deployment until you have tested the deployed URL.

## Limitations and safety

- The analyzer is a small rule-based prototype, not a trained AI model and not an official cybercrime service.
- It can miss scams, flag harmless messages, and misunderstand language, spelling, context, sarcasm, or mixed scripts.
- Selecting Tamil/Hindi changes the UI and explanations; it does **not** mean complete understanding of all Tamil/Hindi messages. Rule coverage is limited.
- Link-structure clues are not proof of maliciousness. The app does not visit links or verify the sender.
- Results are advisory only. Verify through an official app/site or contact method you find independently.
- Never enter real passwords, OTPs, PINs, card details, or private messages.
- Tamil/Hindi wording should be reviewed by fluent speakers before public deployment.

## Project layout

- `app.py` — Flask routes, upload validation and JSON errors
- `analyzer.py` — rules, link parsing and optional OCR
- `templates/index.html` — accessible web UI
- `static/i18n.js` — UI translations
- `tests/` — automated checks
- `sample_data/` — simulated examples only
- `docs/` — architecture and privacy notes

## GitHub upload

1. Create a **public** repository named `bharat-suraksha-ai` (or choose private if required).
2. Upload the contents of this project folder, not the ZIP file itself.
3. Ensure `README.md`, `LICENSE`, `requirements.txt`, `app.py`, `analyzer.py`, `templates/`, `static/`, `tests/`, `docs/`, and `sample_data/` appear at the repository root.
4. Never upload `.env`, private messages, credentials, or real screenshots.
5. Run the app and tests before submitting the repository link to the hackathon form.
