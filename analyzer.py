"""Transparent, rule-based scam-warning prototype. Advisory only; not a fraud classifier."""
import re
from urllib.parse import urlsplit

MAX_TEXT_CHARS = 12000
URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']{3,300}")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "rebrand.ly"}

# Patterns deliberately look for requests/actions rather than isolated words like OTP/pay/claim.
RULES = [
    ("credential_request", [
        r"\b(?:share|send|tell|enter|submit|provide|confirm)\b.{0,45}\b(?:otp|one[- ]time password|pin|password|cvv|card number|banking details)\b",
        r"\b(?:otp|one[- ]time password|pin|password|cvv)\b.{0,35}\b(?:share|send|enter|submit|provide|tell us)\b",
        r"(?:ओटीपी|ओटिपी|पासवर्ड|पिन).{0,25}(?:बताएं|भेजें|साझा करें|डालें|दर्ज करें)",
        r"(?:OTP|கடவுச்சொல்|ரகசியக் குறியீடு|பின்).{0,35}(?:பகிர|அனுப்பு|உள்ளிட|தெரிவிக்க)",
    ]),
    ("urgency_pressure", [
        r"\b(?:account|card|service)\b.{0,35}\b(?:blocked|suspended|closed|deactivated)\b",
        r"\b(?:act now|immediately|urgent|last warning|within \d+ (?:minutes?|hours?))\b",
        r"(?:खाता|कार्ड|सेवा).{0,25}(?:बंद|ब्लॉक|निलंबित).{0,25}(?:होगा|कर दिया जाएगा|कर देंगे)",
        r"(?:கணக்கு|சேவை).{0,25}(?:முடக்க|நிறுத்த).{0,25}(?:ப்படும்|விடுவோம்)",
    ]),
    ("payment_request", [
        r"\b(?:pay|send|transfer)\b.{0,35}\b(?:fee|deposit|money|rupees?|rs\.?|upi)\b",
        r"\b(?:processing|release|verification|delivery) fee\b",
        r"(?:शुल्क|फीस|जमा राशि).{0,30}(?:भेजें|भुगतान|जमा करें|ट्रांसफर)",
        r"(?:கட்டணம்|பணம்).{0,30}(?:செலுத்த|அனுப்பு|பரிமாற்ற)",
    ]),
    ("prize_lure", [
        r"\b(?:you have won|you are the winner|claim your (?:prize|reward)|won a prize|lottery winner)\b",
        r"(?:आपने|आप).{0,25}(?:इनाम|लॉटरी|पुरस्कार).{0,20}(?:जीता|जीते|जीतें|पाने)",
        r"(?:பரிசு|வெகுமதி).{0,25}(?:வென்ற|பெற்றுள்ளீர்கள்|பெற கிளிக்)",
    ]),
    ("impersonation_pressure", [
        r"\b(?:digital arrest|arrest warrant|police case|tax raid|customs case)\b",
        r"(?:पुलिस|सीबीआई|आयकर विभाग).{0,35}(?:गिरफ्तार|डिजिटल अरेस्ट|मामला दर्ज)",
        r"(?:காவல்துறை|வரித்துறை).{0,35}(?:கைது|வழக்கு|டிஜிட்டல் கைது)",
    ]),
    ("link_pressure", [
        r"\b(?:click|open|tap|visit)\b.{0,35}\b(?:link|below|here|verify|update|claim)\b",
        r"\b(?:click|open|tap|visit)\b.{0,35}(?:https?://|www\.)",
        r"\b(?:verify|update|unlock)\b.{0,30}\b(?:account|kyc|details)\b.{0,35}\b(?:link|click|open)\b",
        r"(?:लिंक|यहाँ क्लिक).{0,25}(?:खोलें|क्लिक|सत्यापित)",
        r"(?:இணைப்பு|கிளிக்).{0,25}(?:திற|சரிபார்|உறுதிப்படுத்து)",
    ]),
    ("unknown_app_request", [
        r"\b(?:install|download)\b.{0,40}\b(?:apk|anydesk|teamviewer|remote access|screen sharing)\b",
        r"(?:ऐप|एपीके).{0,25}(?:इंस्टॉल|डाउनलोड).{0,25}(?:करें|करो)",
        r"(?:செயலி|APK).{0,25}(?:நிறுவ|பதிவிறக்க)",
    ]),
]
INDICATOR_TEXT = {
 "en": {
  "credential_request": ("Request to share a secret credential", "The wording may ask someone to share or enter an OTP, PIN, password or similar secret."),
  "urgency_pressure": ("Urgency or threat", "The message may pressure the reader to act quickly or threaten account/service loss."),
  "payment_request": ("Unusual payment request", "The wording may request a fee or money transfer in a context worth independently checking."),
  "prize_lure": ("Prize or reward claim", "The message appears to promise a prize or reward. Unexpected wins deserve independent verification."),
  "impersonation_pressure": ("Authority or legal threat", "The message may invoke police, tax or legal threats. Verify using contact details you find independently."),
  "link_pressure": ("Pressure to use a link", "The message may push the reader to open a link. Use the official app or type the known website yourself."),
  "unknown_app_request": ("Unknown or remote-access app request", "The message may ask you to install an APK or remote-access tool. Do not install unexpected apps."),
 },
 "ta": {
  "credential_request": ("ரகசிய விவரங்களைப் பகிரக் கோருதல்", "OTP, PIN அல்லது கடவுச்சொல்லைப் பகிர/உள்ளிடச் சொல்வது போல் உள்ளது."),
  "urgency_pressure": ("அவசர அழுத்தம் அல்லது அச்சுறுத்தல்", "விரைவாகச் செயல்படச் சொல்லும் அழுத்தம் அல்லது கணக்கு முடக்கப்படும் அச்சுறுத்தல் இருக்கலாம்."),
  "payment_request": ("சந்தேகத்திற்குரிய பணக் கோரிக்கை", "கட்டணம் அல்லது பணப் பரிமாற்றம் கேட்கப்படலாம்; தனியாகச் சரிபார்க்கவும்."),
  "prize_lure": ("பரிசு/வெகுமதி வாக்குறுதி", "எதிர்பாராத பரிசு வாக்குறுதியை அதிகாரப்பூர்வ வழியில் சரிபார்க்கவும்."),
  "impersonation_pressure": ("அதிகாரி/சட்ட அச்சுறுத்தல்", "காவல் அல்லது வரித்துறை அச்சுறுத்தல் இருக்கலாம்; நீங்களே கண்ட தொடர்பு வழியில் சரிபார்க்கவும்."),
  "link_pressure": ("இணைப்பைத் திறக்க அழுத்தம்", "இணைப்பைத் திறக்கச் சொல்லப்படலாம். அதிகாரப்பூர்வ செயலி அல்லது தளத்தை நீங்களே திறக்கவும்."),
  "unknown_app_request": ("தெரியாத செயலியை நிறுவக் கோருதல்", "எதிர்பாராத APK அல்லது தொலைநிலை அணுகல் செயலியை நிறுவ வேண்டாம்."),
 },
 "hi": {
  "credential_request": ("गोपनीय जानकारी साझा करने की माँग", "संदेश OTP, PIN या पासवर्ड साझा करने या दर्ज करने को कह सकता है."),
  "urgency_pressure": ("जल्दबाज़ी या धमकी", "संदेश जल्दी कार्रवाई करने का दबाव या खाता बंद होने की धमकी दे सकता है."),
  "payment_request": ("असामान्य भुगतान की माँग", "शुल्क या पैसे भेजने की माँग हो सकती है; स्वतंत्र रूप से पुष्टि करें."),
  "prize_lure": ("इनाम या रिवॉर्ड का दावा", "अप्रत्याशित इनाम के दावे की आधिकारिक माध्यम से पुष्टि करें."),
  "impersonation_pressure": ("अधिकारी या कानूनी धमकी", "पुलिस या कर विभाग की धमकी हो सकती है; स्वयं खोजे गए संपर्क से पुष्टि करें."),
  "link_pressure": ("लिंक खोलने का दबाव", "लिंक खोलने को कहा जा सकता है. आधिकारिक ऐप खोलें या वेबसाइट स्वयं टाइप करें."),
  "unknown_app_request": ("अज्ञात ऐप इंस्टॉल करने की माँग", "अनपेक्षित APK या रिमोट-एक्सेस ऐप इंस्टॉल न करें."),
 }
}
UI = {
 "en": {"none":"No configured warning indicators detected", "verify":"Verify independently", "warning":"Several warning patterns detected", "explain":"These are rule-based clues, not proof of fraud. A message with no detected clues is not guaranteed safe.", "guidance":"Do not share OTPs, PINs, passwords or card details. Do not open unexpected links or install apps from messages. Verify using the official app/site or a trusted contact you find yourself.", "disclaimer":"Educational prototype only. The message and screenshot are processed for this request and are not intentionally stored by this app."},
 "ta": {"none":"எச்சரிக்கை அறிகுறிகள் கண்டறியப்படவில்லை", "verify":"தனியாகச் சரிபார்க்கவும்", "warning":"பல எச்சரிக்கை வடிவங்கள் கண்டறியப்பட்டன", "explain":"இவை விதி அடிப்படையிலான குறிப்புகள் மட்டுமே; மோசடிக்கான நிரூபணம் அல்ல. அறிகுறிகள் இல்லாதது பாதுகாப்பு உறுதி அல்ல.", "guidance":"OTP, PIN, கடவுச்சொல் அல்லது அட்டை விவரங்களைப் பகிர வேண்டாம். எதிர்பாராத இணைப்புகளைத் திறக்கவோ செயலிகளை நிறுவவோ வேண்டாம். அதிகாரப்பூர்வ செயலி/தளம் அல்லது நம்பகமான தொடர்பு வழியில் சரிபார்க்கவும்.", "disclaimer":"கல்வி நோக்கிலான முன்மாதிரி மட்டுமே. இந்தச் செயலி கோரிக்கைக்காக செய்தி/படத்தைச் செயலாக்குகிறது; திட்டமிட்டு சேமிப்பதில்லை."},
 "hi": {"none":"कोई कॉन्फ़िगर किया गया चेतावनी संकेत नहीं मिला", "verify":"स्वतंत्र रूप से पुष्टि करें", "warning":"कई चेतावनी पैटर्न मिले", "explain":"ये नियम-आधारित संकेत हैं, धोखाधड़ी का प्रमाण नहीं। कोई संकेत न मिलना सुरक्षा की गारंटी नहीं है।", "guidance":"OTP, PIN, पासवर्ड या कार्ड विवरण साझा न करें। अनपेक्षित लिंक न खोलें और संदेश से ऐप इंस्टॉल न करें। आधिकारिक ऐप/वेबसाइट या स्वयं खोजे गए भरोसेमंद संपर्क से पुष्टि करें।", "disclaimer":"केवल शैक्षिक प्रोटोटाइप। ऐप अनुरोध के लिए संदेश/छवि संसाधित करता है और जानबूझकर उसे संग्रहीत नहीं करता।"}
}

def _links(text):
    out = []
    for raw in URL_RE.findall(text)[:5]:
        cleaned = raw.rstrip(".,!?;:)]}")
        candidate = cleaned if "://" in cleaned else "http://" + cleaned
        try:
            p = urlsplit(candidate)
            host = (p.hostname or "").lower().strip(".")
            flags = []
            if host in SHORTENERS: flags.append("URL shortener hides the destination")
            if p.username or p.password or "@" in p.netloc: flags.append("URL contains user-info or @ syntax")
            if host.startswith("xn--") or ".xn--" in host: flags.append("Encoded domain characters (xn--) present")
            if host.count(".") >= 4: flags.append("Many subdomain levels")
            if p.scheme == "http": flags.append("Uses http rather than https")
            out.append({"display": cleaned.replace(".", "[.]", 1), "flags": flags})
        except ValueError:
            out.append({"display": cleaned.replace(".", "[.]", 1), "flags": ["URL could not be parsed"]})
    return out

def analyze_message(text, lang="en"):
    lang = lang if lang in UI else "en"
    text = str(text or "")[:MAX_TEXT_CHARS]
    indicators = []
    for key, patterns in RULES:
        matched = any(re.search(p, text, re.IGNORECASE) for p in patterns)
        # Safety reminders saying not to share credentials should not be mistaken for requests.
        if key == "credential_request" and re.search(
            r"\b(?:do not|don't|never)\s+(?:share|send|provide|give|enter)\b.{0,45}\b(?:otp|one[- ]time password|pin|password|cvv|card number)\b",
            text, re.IGNORECASE):
            matched = False
        if matched:
            label, explanation = INDICATOR_TEXT[lang][key]
            indicators.append({"id": key, "label": label, "explanation": explanation})
    links = _links(text)
    for link in links:
        for flag in link["flags"]:
            # URL structure is a reason to verify, not a fraud verdict.
            link.setdefault("note", "The link was not opened or fetched. Structural clues alone cannot determine safety.")
    if len(indicators) >= 3: level_key = "warning"
    elif indicators or any(x["flags"] for x in links): level_key = "verify"
    else: level_key = "none"
    return {"language": lang, "level": UI[lang][level_key], "level_key": level_key,
            "indicators": indicators, "links": links,
            "explanation": UI[lang]["explain"], "guidance": UI[lang]["guidance"],
            "disclaimer": UI[lang]["disclaimer"], "truncated": len(str(text)) >= MAX_TEXT_CHARS}

def extract_text_from_image(file_storage, lang="en"):
    try:
        import pytesseract
        from PIL import Image, UnidentifiedImageError
    except ImportError as exc:
        raise RuntimeError("ocr_unavailable") from exc
    try:
        image = Image.open(file_storage.stream)
        image.verify()
        file_storage.stream.seek(0)
        image = Image.open(file_storage.stream)
        if image.width * image.height > 20_000_000:
            raise ValueError("image_dimensions")
        image = image.convert("RGB")
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("invalid_image") from exc
    langs = {"en":"eng", "ta":"tam", "hi":"hin"}
    try:
        available = set(pytesseract.get_languages(config=""))
        wanted = langs.get(lang, "eng")
        if wanted not in available:
            if "eng" not in available: raise RuntimeError("ocr_language_missing")
            wanted = "eng"
        result = pytesseract.image_to_string(image, lang=wanted, timeout=12).strip()
        return result, (wanted != langs.get(lang, "eng"))
    except RuntimeError as exc:
        if str(exc) in {"ocr_language_missing", "ocr_unavailable"}: raise
        raise RuntimeError("ocr_failed") from exc
    except Exception as exc:
        raise RuntimeError("ocr_failed") from exc
