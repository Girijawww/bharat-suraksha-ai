# Architecture

Browser UI (HTML/CSS/JavaScript) → Flask `/api/analyze` endpoint → rule-based analysis and optional local Tesseract OCR → advisory result. The app does not fetch submitted URLs. Detection rules are transparent but limited; false positives and false negatives are expected. The display language is English, Tamil, or Hindi. Rule coverage is limited and does not imply full multilingual understanding.
