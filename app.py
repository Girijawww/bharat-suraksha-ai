import os
from flask import Flask, render_template, request, jsonify
from werkzeug.exceptions import RequestEntityTooLarge
from analyzer import analyze_message, extract_text_from_image, MAX_TEXT_CHARS

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "bmp"}
ERRORS = {
 "empty_input":"Please paste a message or upload a screenshot.",
 "both_inputs":"Please choose either pasted text or a screenshot, not both.",
 "text_too_long":f"Message exceeds the {MAX_TEXT_CHARS}-character limit.",
 "file_too_large":"Upload is too large (maximum 5 MB).",
 "unsupported_file_type":"Unsupported file type. Use PNG, JPEG, WebP or BMP.",
 "empty_file":"The uploaded file is empty.", "invalid_image":"The file is not a readable image or may be corrupt.",
 "image_dimensions":"The image has too many pixels. Please upload a smaller screenshot.",
 "ocr_unavailable":"Screenshot reading is unavailable because Tesseract or its Python package is not installed. Paste the text instead.",
 "ocr_language_missing":"No usable Tesseract language data is installed. Paste the text instead.",
 "ocr_failed":"Screenshot reading failed or timed out. Try a smaller image or paste the text.",
 "no_text_found":"No readable text was found in the image. Try a clearer screenshot or paste the text.",
 "malformed_request":"The request could not be understood. Reload the page and try again.",
}
def error(key, status=400): return jsonify({"error": ERRORS.get(key, ERRORS["malformed_request"]), "error_code": key}), status
@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response
@app.errorhandler(RequestEntityTooLarge)
def too_large(_): return error("file_too_large", 413)
@app.errorhandler(404)
def not_found(_): return error("malformed_request", 404) if request.path.startswith("/api/") else ("Not found", 404)
@app.route("/health")
def health(): return jsonify({"status":"ok"})
@app.route("/")
def index(): return render_template("index.html")
@app.post("/api/analyze")
def analyze():
    lang = request.form.get("language", "en")
    if lang not in {"en", "ta", "hi"}: lang = "en"
    text = (request.form.get("text") or "").strip()
    image = request.files.get("image")
    has_image = bool(image and image.filename)
    if text and has_image: return error("both_inputs")
    if text:
        if len(text) > MAX_TEXT_CHARS: return error("text_too_long")
    elif has_image:
        if not image.filename: return error("empty_file")
        ext = image.filename.rsplit(".", 1)[-1].lower() if "." in image.filename else ""
        if ext not in ALLOWED_EXTENSIONS: return error("unsupported_file_type")
        if not image or image.content_length == 0: return error("empty_file")
        try:
            text, fallback = extract_text_from_image(image, lang)
            if not text.strip(): return error("no_text_found")
        except (ValueError, RuntimeError) as exc:
            code = str(exc) if str(exc) in ERRORS else "invalid_image"
            return error(code)
        if len(text) > MAX_TEXT_CHARS: text = text[:MAX_TEXT_CHARS]
    else: return error("empty_input")
    result = analyze_message(text, lang)
    # Never echo the submitted text or OCR contents back to the browser.
    if has_image and 'fallback' in locals() and fallback:
        result["ocr_note"] = "Requested OCR language data is missing; screenshot was read using English if available. Results may be inaccurate."
    return jsonify(result)
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG", "0") == "1")
