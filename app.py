from flask import Flask, render_template, request, jsonify
import requests
import io
from PIL import Image, ImageOps, ImageEnhance
import re
from bs4 import BeautifulSoup

app = Flask(__name__)

# ==============================================================================
# 1. MASSIVE THREAT DATABASE (BLACKLIST - SCAMS)
# ==============================================================================

IMPERSONATION_TARGETS = {
    # Streaming & Social
    "netflix": "Netflix", "amazon": "Amazon", "prime video": "Amazon Prime", "disney": "Disney+",
    "hotstar": "Disney+ Hotstar", "spotify": "Spotify", "youtube": "YouTube",
    "facebook": "Meta/Facebook", "instagram": "Instagram", "whatsapp": "WhatsApp", 
    "snapchat": "Snapchat", "telegram": "Telegram", "linkedin": "LinkedIn", "twitter": "X (Twitter)",
    
    # Global Finance
    "paypal": "PayPal", "venmo": "Venmo", "cashapp": "CashApp", "western union": "Western Union",
    "binance": "Binance", "coinbase": "Coinbase", "trust wallet": "Trust Wallet", "metamask": "MetaMask",
    
    # Indian Banks
    "sbi": "SBI Bank", "hdfc": "HDFC Bank", "icici": "ICICI Bank", "axis": "Axis Bank", "pnb": "Punjab National Bank",
    "kotak": "Kotak Mahindra", "bob": "Bank of Baroda", "canara": "Canara Bank", "indusind": "IndusInd Bank",
    "idfc": "IDFC First Bank", "yes bank": "Yes Bank", "union bank": "Union Bank of India",
    
    # Indian Payments & Services
    "paytm": "Paytm", "phonepe": "PhonePe", "gpay": "Google Pay", "bajaj finserv": "Bajaj Finance",
    "muthoot": "Muthoot Finance", "epfo": "EPFO", "lic": "LIC India", "cred": "CRED",
    
    # Indian Shopping & Delivery
    "flipkart": "Flipkart", "meesho": "Meesho", "myntra": "Myntra", "ajio": "Ajio", "nykaa": "Nykaa",
    "zomato": "Zomato", "swiggy": "Swiggy", "blinkit": "Blinkit", "zepto": "Zepto", "bigbasket": "BigBasket",
    "jiomart": "JioMart", "dmart": "DMart", "ola": "Ola Cabs", "uber": "Uber", "rapido": "Rapido",
    
    # Entertainment & Ticketing
    "bookmyshow": "BookMyShow", "pvr": "PVR Cinemas", "inox": "INOX", "cinepolis": "Cinepolis",
    "paytm insider": "Paytm Insider", "ticketnew": "TicketNew",
    
    # Tech & Govt
    "apple id": "Apple", "icloud": "Apple", "microsoft": "Microsoft", "google": "Google",
    "zoom": "Zoom", "dropbox": "Dropbox", "adobe": "Adobe", "norton": "Norton", "mcafee": "McAfee",
    "geek squad": "Geek Squad", "fedex": "FedEx", "dhl": "DHL", "usps": "USPS", "ups": "UPS", 
    "indiapost": "India Post", "bluedart": "BlueDart", "delhivery": "Delhivery",
    "jio": "Jio Telecom", "airtel": "Airtel", "vi": "Vodafone Idea", "bsnl": "BSNL",
    "uidai": "Aadhaar", "irctc": "Indian Railways", "incometax": "Income Tax Dept", 
    "parivahan": "Transport Ministry", "passport": "Passport Seva", "digilocker": "DigiLocker",
    "sebi": "SEBI", "rbi": "RBI", "police": "Police Dept", "cbi": "CBI", "customs": "Customs Dept"
}

SENSITIVE_WARNINGS = [
    "otp for", "otp is", "one time password", "verification code", "valid for", 
    "generated at", "do not share this code", "code is", "auth code", "login code",
    "secret code", "withdrawl code", "transaction password", "cvv", "pin number"
]

# --- INDIAN HIGH-FREQUENCY SCAMS ---

URGENT_PANIC_SCAMS = [
    "within 24 hours", "within 24hr", "immediately", "urgent action", "avoid deactivation",
    "account will be close", "will be closed", "service stopped", "access restricted",
    "block your account", "suspend your account", "action required", "compliance pending",
    "kyc incomplete", "submit immediately", "last reminder", "final notice", "electricity disconnection",
    "pay right away", "overdue and unsettled"
]

DIGITAL_ARREST_SCAMS = [
    "package seized", "drugs found", "illegal items", "customs officials", "narcotics bureau",
    "cbi investigation", "mumbai police", "delhi police", "cyber crime cell", "arrest warrant",
    "money laundering case", "adhaar misuse", "skype statement", "video call statement",
    "digital arrest", "stay online", "do not disconnect", "police verification pending",
    "court summon", "legal notice issued", "case registered against you", "crime branch"
]

POLICE_CHALLAN_SCAMS = [
    "challan pending", "parivahan", "court notice", "lok adalat", "traffic police", 
    "fine unpaid", "legal action", "virtual court", "epolice", "traffic violation",
    "vehicle seized", "pay fine immediately", "fir registered", "police case", "e-challan",
    "click to pay fine", "fine is overdue", "unsettled", "supplementary fees", 
    "enforcement procedures", "traffic fine", "steer clear",
    "traffic rto challan", "your traffic rto"
]

INDIAN_JOB_SCAMS = [
    "part time job", "work from home", "like youtube videos", "telegram task", "prepaid task", 
    "daily salary", "hr manager", "hiring for amazon", "investment start", "crypto trading", 
    "mall review", "google map review", "hotel review", "daily income", "weekly payout",
    "no experience needed", "work from mobile", "data entry job", "filling job", "sms sending job",
    "online job fraud", "higher wages", "better employment", "false hope", "job promise",
    "rating task", "review task"
]

INDIAN_BANKING_SCAMS = [
    "kyc pending", "update your pan", "account blocked", "netbanking blocked", 
    "adhar link", "pan card expired", "submit kyc", "dear customer your account", 
    "debit card blocked", "credit card points", "redeem points", "reward points expiring",
    "bank account suspended", "kyc verification", "sim verification", "paytm kyc",
    "credit limit increase", "lifetime free card", "cibil score check", "loan approved",
    "pf claim rejected", "uan activation", "epfo kyc", "pension stopped",
    "demat fraud", "depository fraud", "e-wallet fraud", "fraud call", "vishing", 
    "sim swap", "debit card fraud", "credit card fraud",
    "bank a/c will be close", "account will be closed", "complete your verification",
    "unauthorized use", "withdrawing funds", "card information", "purchase detected"
]

UPI_LOTTERY_SCAMS = [
    "cashback received", "phonepe reward", "gpay reward", "kbc winner", "kaun banega crorepati", 
    "lottery number", "jio lucky", "ipl winner", "scan to receive", "enter pin", 
    "refund processed", "money sent successfully", "scratch card", "better luck next time",
    "you won", "congratulations winner", "paytm cashback", "wallet refund", 
    "prime minister yojana", "pm scheme", "free laptop", "scholarship approved", "ration card update",
    "ayushman bharat upgrade", "e-shram card bonus",
    "congratulations", "you have been selected", "lucky draw", "claim your prize", 
    "spin the wheel", "jackpot winner", "winning notification"
]

ENTERTAINMENT_REFUND_SCAMS = [
    "ticket refund", "refund approved", "click to receive refund", "movie cancelled",
    "show cancelled", "booking failed", "amount deducted twice", "double deduction",
    "scan to get refund", "refund initiated", "receive your refund", "cancellation charges",
    "bookmyshow support", "pvr support", "refund link", "money debited but ticket not booked"
]

WRONG_RECHARGE_SCAMS = [
    "wrong number recharge", "recharge refund", "sent money by mistake", "please return money",
    "refund my recharge", "accidentally sent", "return the amount", "mistake transaction"
]

INDIAN_DOC_SCAMS = [
    "aadhaar suspended", "biometric locked", "update aadhaar immediately", "aadhaar address update", 
    "download e-aadhaar", "aadhaar verification failed", "link mobile to aadhaar", "aadhaar kyc required",
    "document update required", "upload proof of identity", "aadhaar services suspended",
    "needs biometrics update", "needs document update", "avoid deactivation", "update to continue",
    "pan card inoperative", "pan inoperative", "link pan with aadhaar", "pan aadhaar link", 
    "penalty for pan", "pan verification failed", "pan card blocked", "income tax penalty",
    "pan invalid", "pan record missing",
    "voter id not verified", "digital voter id", "voter card blocked", "ration card cancelled", 
    "ration suspended", "add member to ration card", "ration subsidy stopped",
    "tax refund approved", "income tax refund", "itr processed", "click to claim refund", 
    "outstanding tax demand", "pay tax arrears", "gst registration cancelled", "gstin blocked",
    "passport dispatch halted", "police verification failed", "passport file on hold", 
    "visa appointment cancelled", "immigration error"
]

INDIAN_TECH_SCAMS = [
    "5g upgrade", "sim block", "esim activation", "port sim", "kyc sim", 
    "airtel verification", "jio verification", "vi verification", 
    "recharge successful", "plan expired", "validity expired", "upgrade to 5g",
    "sim swap", "esim request"
]

# --- GLOBAL & TECHNICAL SCAMS ---

APK_MALWARE_SCAMS = [
    "download apk", "install apk", "apk file", "android package", "unknown source",
    "update.apk", "bonus.apk", "reward.apk", "beta version apk", "app-release.apk",
    "mod apk", "cracked apk", "premium unlocked", "pro version apk", "download link attached",
    "install this application", "challan.apk", "traffic challan apk", "parivahan apk", 
    "traffic fine apk", "epolice apk", "court notice apk",
    "your traffic rto challan", "challan rs", ".apk", "3.5 mb"
]

VIRUS_TROJAN_SCAMS = [
    "computer virus", "trojan horse", "worm detected", "malicious program", "backdoor entry",
    "replicate themselves", "damage your files", "alter data", "destructive program",
    "genuine application", "access your system", "steal confidential information",
    "ransomware", "encrypt files", "files encrypted", "demand ransom", "restore data", 
    "decrypt your files", "pay ransom", "bitcoin ransom", "lock your computer"
]

FAKE_APP_SCAMS = [
    "whatsapp gold", "whatsapp plus", "gold version", "upgrade to gold", "premium whatsapp",
    "whatsapp pink", "gb whatsapp", "download update", "new version available", 
    "update whatsapp now", "unlimited access", "free upgrade", "exclusive features",
    "install this app", "apk download", "install new version", "martinelli video"
]

CRYPTO_MINING_SCAMS = [
    "cryptojacking", "mining malware", "cloud mining scam", "generate cryptocurrency", 
    "stealing resources", "infected machines", "high power consumption", "mining pool",
    "wear and tear", "computing power"
]

HACKING_TERRORISM_SCAMS = [
    "threaten unity", "integrity of india", "sovereignty of india", "strike terror", 
    "denial of access", "penetrate system", "unauthorised access", "damage to computer",
    "disrupt supplies", "critical information infrastructure", "tampering with documents",
    "website defacement", "email hacking", "data breach", "wrongful loss", "delete information",
    "alter information", "diminish value", "exceeding authorised access"
]

IDENTITY_THEFT_SCAMS = [
    "identity theft", "impersonation act", "electronic signature theft", "password theft",
    "unique identification feature", "fraudulently making use", "dishonestly making use",
    "fake profile", "impersonating profile", "identity fraud"
]

SOCIAL_MEDIA_CRIMES = [
    "cheating by impersonation", "cyber bullying", "cyber stalking", "sexting", 
    "intimidating email", "impersonating email", "matrimonial fraud", "groom wanted", 
    "bride wanted", "profile hacking", "provocative speech", "incitement to offence", 
    "unlawful acts", "defamation"
]

INVESTMENT_SCAMS = [
    "stock tip", "guaranteed profit", "upper circuit", "ipo allotment", "institutional account",
    "foreign institutional investor", "fii trading", "block trade", "double your money",
    "whatsapp investment group", "telegram trading group", "sebi registered analyst",
    "profit sharing", "no loss strategy", "high return", "daily income trading",
    "pump and dump", "crypto giveaway", "guaranteed high returns"
]

SEXTORTION_SCAMS = [
    "video call recording", "nude video", "uploaded to youtube", "send to your contacts",
    "social reputation", "delete the video", "cyber police complaint", "pay to remove",
    "video viral", "recorded your screen", "sexually explicit", "lascivious", 
    "prurient interest", "deprave and corrupt", "section 67", "section 67a"
]

CRYPTO_SCAMS = [
    "airdrop claim", "connect wallet", "seed phrase", "validate wallet", "synchronize wallet",
    "gas fees", "fake usdt", "crypto mining pool", "hashrate", "mining withdrawal",
    "trust wallet support", "metamask support"
]

GLOBAL_DELIVERY_SCAMS = [
    "delivery attempt failed", "package pending", "shipping fee", "customs duty", 
    "incomplete address", "redelivery", "address confirmation", "package on hold",
    "unable to deliver", "return to sender", "track your package", "shipment issue"
]

GLOBAL_FINANCE_SCAMS = [
    "irs tax refund", "hmrc refund", "unusual sign-in activity", "verify your identity", 
    "apple id locked", "netflix payment failed", "paypal limited", "social security suspended",
    "unauthorized transaction", "payment declined", "card charged", "subscription expired",
    "renew subscription", "account limited", "secure your account", "invoice attached",
    "receipt for your order", "purchase confirmed", "cloud storage full", "icloud full",
    "view your bill", "invoice available", "bill is due", "payment overdue", 
    "ceo request", "wire transfer", "confidential project", "change vendor details",
    "business email compromise", "email takeover"
]

GLOBAL_RELATIONSHIP_SCAMS = [
    "romance", "military doctor", "send money for ticket", "diplomat", "consignment box", 
    "inheritance", "fund transfer", "next of kin", "trust fund", "widow", "orphan",
    "my darling", "my love", "soulmate", "send gift card", "steam card", "please help me"
]

GLOBAL_TECH_SUPPORT = [
    "microsoft support", "windows defender expired", "computer infected", "call this number", 
    "virus detected", "trojan alert", "firewall breach", "hacker detected", 
    "ip compromised", "system critical", "contact support immediately", "toll free"
]

SOCIAL_SCAMS = [
    "broke my phone", "temporary number", "new number", "lost my phone", "this is mom", 
    "this is dad", "accident", "hospital", "urgent surgery", "send money", "borrow money", 
    "pay you back", "send me $", "taxi fare", "uber", "gas money", "grindr", "tinder", 
    "meet up", "gift card", "steam card", "apple card", "google play card", 
    "help me", "emergency", "jail", "bail money", "lawyer fee", "stuck at airport",
    "voicemail received", "listen to voicemail", "video call missed",
    "my secretary", "assistant gave", "wrong number", "saved in my contacts", 
    "acquaintance", "fate", "destiny", "nice to meet you", "kindly and friendly", 
    "stored your number", "manager gave me", "assistant saved"
]

OTP_PHISHING_SCAMS = [
    "otp for purchase", "otp for transaction", "debited from your account", 
    "if not you", "call to cancel", "call support", "transaction detected", 
    "refund code", "stop transaction", "did you attempt", "unusual login", 
    "share this code", "verification code for amazon", "verification code for flipkart",
    "amount deducted", "request to pay", "approve request"
]

INDIAN_UTILITY_SCAMS = [
    "electricity power", "disconnect tonight", "bill not update", "electricity officer", 
    "contact officer", "light bill", "power cut", "meter disconnect", "bill unpaid",
    "previous month bill", "bses alert", "tata power", "adani electricity",
    "gas connection", "subsidy pending", "indane gas", "bharat gas"
]

# --- T. URL THREATS ---
SUSPICIOUS_DOMAINS = [
    "bit.ly", "tinyurl", "ngrok", "is.gd", ".xyz", "top", "club", "g00gle", "paypa1", 
    "amaz0n", "hotmail", "gmail", "outlook", "yahoo", "blogspot", "weebly", "wix", 
    "duckdns", "serveo", "pastebin", "ipfs", "glitch.me", "firebaseapp", 
    "nrsc.gov.in", "bhuvan-app", "lnk.ink", "link.ink", "short.url"
]
BAD_URL_KEYWORDS = [
    "kyc", "bank-update", "secure-login", "account-verify", "bonus", "claim", "free", 
    "gift", "support", "help-desk", "service", "login", "signin", "wallet", "connect", 
    "validate", "confirm", "unlock", "update-pan", "adhaar-link", "rewards", "itr-refund"
]

# ==============================================================================
# 2. WHITELIST DATABASES (OFFICIAL & SAFE CONTEXT)
# ==============================================================================

# --- A. OFFICIAL DOMAIN WHITELIST ---
OFFICIAL_DOMAINS = [
    # GOVT & ID
    "uidai.gov.in", "myaadhaar.uidai.gov.in", "incometax.gov.in", "parivahan.gov.in", 
    "passportindia.gov.in", "epfindia.gov.in", "pmkisan.gov.in", "cybercrime.gov.in",
    "ncs.gov.in", "digilocker.gov.in", "nvsp.in", "eci.gov.in", "indianrail.gov.in", "irctc.co.in",
    "echallan.parivahan.gov.in",
    
    # BANKS (India)
    "onlinesbi.sbi", "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "kotak.com", "pnbindia.in", "bankofbaroda.in", "canarabank.com", "unionbankofindia.co.in",
    "indusind.com", "idfcfirstbank.com", "rbi.org.in", "yesbank.in", "bandhanbank.com",
    
    # PAYMENTS & APPS
    "paytm.com", "phonepe.com", "google.com/pay", "bhimupi.org.in", "npci.org.in",
    "paypal.com", "cred.club", "razorpay.com", "billdesk.com",
    
    # SHOPPING, FOOD & DELIVERY
    "amazon.in", "amazon.com", "flipkart.com", "myntra.com", "ajio.com", "meesho.com",
    "nykaa.com", "tatacliq.com", "jiomart.com", "dmart.in",
    "zomato.com", "swiggy.com", "blinkit.com", "zeptonow.com", "bigbasket.com",
    "bluedart.com", "delhivery.com", "indiapost.gov.in",
    
    # TRAVEL & TRANSPORT
    "olacabs.com", "uber.com", "rapido.bike", "makemytrip.com", "goibibo.com", "yatra.com",
    "indigo.in", "airindia.com", "spicejet.com", "akasaair.com", "redbus.in",
    "bookmyshow.com", "pvrcinemas.com", 
    
    # TELECOM & SERVICES
    "jio.com", "airtel.in", "myvi.in", "bsnl.co.in", "actcorp.in", "hathway.com",
    "licindia.in", "policybazaar.com",
    
    # TECH
    "microsoft.com", "apple.com", "google.com", "facebook.com", "instagram.com", 
    "whatsapp.com", "twitter.com", "linkedin.com", "youtube.com"
]

# --- B. SAFE PATTERNS (CONTEXT WHITELIST) ---
SAFE_PATTERNS = {
    "BANKING_INFO": [
        "credited to", "deposited in", "statement generated", "balance is", "transaction successful", 
        "thank you for banking", "received from", "sent to", "payment received", "auto-pay scheduled"
    ],
    "JOB_SAFE": [
        "application received", "interview scheduled", "position filled", "thank you for applying",
        "resume review", "job alert", "offer letter attached", "joining date"
    ],
    "SOCIAL_SAFE": [
        "happy birthday", "congratulations on your", "get well soon", "good morning", 
        "see you later", "call me when", "let's meet", "are you free", "happy anniversary",
        "merry christmas", "happy diwali", "happy new year", "best wishes", "hey, how are you",
        "can i call you", "lunch today"
    ],
    "SHIPPING_SAFE": [
        "out for delivery", "delivered successfully", "handed over", "order placed", 
        "invoice generated", "receipt for", "order confirmation", "arriving today"
    ],
    "TICKET_SAFE": [
        "booking confirmed", "enjoy the show", "tickets attached", "seat number",
        "audi", "screen", "showtime", "booking id", "tickets reserved"
    ]
}

# ==============================================================================
# 3. ACTIVE LINK INSPECTOR
# ==============================================================================
def inspect_link(url):
    risks = []
    score_add = 0
    if not url.startswith(('http://', 'https://')): url = 'http://' + url
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(max_retries=1)
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    try:
        response = session.get(url, timeout=(2, 3), allow_redirects=True)
        if response.history:
            final_url = response.url
            risks.append(f"⚠️ **Redirection:** Link redirects to '{final_url}'")
            if ".apk" in final_url:
                 risks.append("⛔ **Malware Alert:** Redirected to an App download (.apk)")
                 score_add += 5
        if response.status_code != 200:
            risks.append(f"⚠️ **Suspicious:** Site returned Error {response.status_code} (Likely taken down).")
            score_add += 2 
        soup = BeautifulSoup(response.text, 'html.parser')
        if soup.title:
            title = soup.title.string.strip()[:50]
            risks.append(f"ℹ️ **Page Title:** '{title}'")
            if "index of" in title.lower() or "wordpress" in title.lower():
                risks.append("❌ **Unsafe:** Title indicates a cheap/hacked setup.")
                score_add += 2
    except requests.exceptions.Timeout:
        risks.append("⚠️ **Timeout:** Site is too slow or unresponsive (Suspicious).")
        score_add += 2
    except requests.exceptions.TooManyRedirects:
        risks.append("❌ **Loop:** Site redirects too many times (Trap).")
        score_add += 2
    except requests.exceptions.RequestException:
        risks.append("⚠️ **Connection Failed:** Could not verify link (Potential Risk).")
        score_add += 2
    finally:
        session.close()
    return risks, score_add

# ==============================================================================
# 4. MAIN ANALYSIS ENGINE (UNIVERSAL VALIDATION)
# ==============================================================================
def get_threat_analysis(text, source_type):
    # --- 1. NEW: HANDLE OCR FAILURES FIRST ---
    # If the OCR failed, stop here. Do NOT check for scams, just report the error.
    if text.startswith("System:") or "API Limit Reached" in text:
        return {
            "verdict": "ERROR: UNABLE TO READ",
            "color": "warning", # Yellow/Orange
            "score": 0,
            "flags": ["⚠️ **OCR Failed:** The system could not read the text in this image.",
                      "ℹ️ **Reason:** Image might be blurry, dark, or the free API key is busy.",
                      "👉 **Action:** Please type the text manually or try again later."]
        }

    score = 0
    flags = []
    text_lower = text.lower()
    is_safe_source = False
    detected_threat_type = None

    # --- PART A: WHITELIST CHECK ---
    for safe_domain in OFFICIAL_DOMAINS:
        if safe_domain in text_lower:
            is_safe_source = True
            flags.append(f"✅ **Verified Source:** Message contains official domain '{safe_domain}'.")
            score -= 5
            break

    # --- PART B: LINK EXTRACTION ---
    link_pattern = r'(?:https?://|www\.)\S+'
    urls = re.findall(link_pattern, text)

    # --- PART C: IMPERSONATION DETECTION ---
    detected_impersonation = []
    for keyword, company in IMPERSONATION_TARGETS.items():
        if re.search(r'\b' + re.escape(keyword) + r'\b', text_lower):
            if company not in detected_impersonation:
                detected_impersonation.append(company)
                if not is_safe_source: score += 1 
    if detected_impersonation and not is_safe_source:
         flags.append(f"🏢 **Entity Detection:** Message mentions {', '.join(detected_impersonation)}.")
         flags.append(f"⚠️ **Warning:** Verify this is truly from their official app/number.")

    # --- PART D: SAFE CONTEXT CHECK ---
    for category, patterns in SAFE_PATTERNS.items():
        for phrase in patterns:
            if phrase in text_lower:
                score -= 3 
                flags.append(f"✅ **Likely Safe:** Context appears to be legitimate ({category}).")
                break

    # --- PART E: THREAT PATTERN MATCHING ---
    for phrase in SENSITIVE_WARNINGS:
        if phrase in text_lower:
            score += 1 
            flags.append(f"🔒 **Security Alert:** Message contains SENSITIVE CODE ('{phrase}'). **DO NOT SHARE** this with anyone.")
            break 
            
    for phrase in URGENT_PANIC_SCAMS:
        if phrase in text_lower:
            score += 3
            flags.append(f"⚠️ PANIC TRIGGER: Urgent action demanded ('{phrase}')")

    threat_lists = [
        (DIGITAL_ARREST_SCAMS, 5, "🚨 **DIGITAL ARREST SCAM:** Fake Police/Customs threat detected", "Police/Legal"),
        (POLICE_CHALLAN_SCAMS, 2, "⚠️ GOV IMPOSTER: Fake Challan/Legal notice", "Traffic Challan"),
        (VIRUS_TROJAN_SCAMS, 5, "⛔ **MALWARE ALERT:** Virus/Trojan/Worm threat detected", "Tech Support"),
        (IDENTITY_THEFT_SCAMS, 5, "🚨 **IDENTITY THEFT:** Impersonation/Signature fraud detected", "Identity"),
        (HACKING_TERRORISM_SCAMS, 5, "🚨 **CYBER TERRORISM/HACKING:** Critical infrastructure/Unity threat detected", "Terrorism"),
        (SOCIAL_MEDIA_CRIMES, 3, "⚠️ SOCIAL CRIME: Harassment/Impersonation/Matrimonial fraud", "Social Media"),
        (CRYPTO_MINING_SCAMS, 3, "⚠️ CRYPTOJACKING: Unauthorized mining threat", "Crypto"),
        (FAKE_APP_SCAMS, 4, "❌ FAKE APP SCAM: Malicious software promotion detected", "Fake App"),
        (INVESTMENT_SCAMS, 3, "⚠️ INVESTMENT FRAUD: Suspicious high-return scheme", "Investment"),
        (SEXTORTION_SCAMS, 5, "⛔ **SEXTORTION ALERT:** Blackmail/Obscenity threat detected", "Extortion"),
        (CRYPTO_SCAMS, 3, "⚠️ CRYPTO SCAM: Wallet/Airdrop fraud detected", "Crypto"),
        (INDIAN_DOC_SCAMS, 4, "❌ GOV DOC SCAM: Official Identity Fraud detected", "Govt Document"),
        (OTP_PHISHING_SCAMS, 3, "⚠️ OTP/PANIC SCAM: Fake transaction or panic trigger", "Banking/OTP"),
        (INDIAN_BANKING_SCAMS, 3, "❌ BANK SCAM (India): Panic tactic detected", "Banking"),
        (INDIAN_UTILITY_SCAMS, 4, "❌ UTILITY SCAM: Fake disconnection threat", "Utility Bill"),
        (UPI_LOTTERY_SCAMS, 3, "⚠️ UPI/SCHEME FRAUD: Fake Reward/Lottery claim", "Lottery/Reward"),
        (INDIAN_JOB_SCAMS, 2, "⚠️ JOB SCAM: Suspicious work offer", "Job Offer"),
        (INDIAN_TECH_SCAMS, 3, "⚠️ TECH SCAM: Sim/5G Fraud attempt", "Telecom"),
        (GLOBAL_DELIVERY_SCAMS, 2, "📦 DELIVERY SCAM: Fake shipping notification", "Delivery"),
        (GLOBAL_FINANCE_SCAMS, 3, "💳 PHISHING: Tax/Account Suspicious Activity", "Financial"),
        (GLOBAL_RELATIONSHIP_SCAMS, 3, "💔 RELATIONSHIP SCAM: Trust/Money trick detected", "Romance"),
        (GLOBAL_TECH_SUPPORT, 4, "💻 TECH SUPPORT SCAM: Fake Virus Alert", "Tech Support"),
        (SOCIAL_SCAMS, 3, "⚠️ SOCIAL ENGINEERING: Emergency/Money trick detected", "Social"),
        (ENTERTAINMENT_REFUND_SCAMS, 3, "⚠️ REFUND FRAUD: Suspicious ticket/booking refund claim", "Refund/Booking"),
        (WRONG_RECHARGE_SCAMS, 2, "⚠️ PAYMENT FRAUD: Suspicious request to return money", "Payment/Recharge"),
        
        # --- ENSURE APK SCAMS ARE HERE ---
        (APK_MALWARE_SCAMS, 5, "⛔ MALWARE ALERT: Suspicious APK download detected", "Malicious App")
    ]

    for pattern_list, risk_score, message, context_tag in threat_lists:
        for phrase in pattern_list:
            if phrase in text_lower:
                score += risk_score
                detected_threat_type = context_tag
                flags.append(f"{message} ('{phrase}')")

    if "enter pin" in text_lower:
        score += 5
        flags.append("⛔ CRITICAL: Asking for PIN to 'receive' money is 100% SCAM.")

    # --- PART F: LINK SCANNING & SCORING ---
    if urls:
        flags.append(f"🔗 **Scan:** Found {len(urls)} link(s) in message.")
        for url in urls:
            url_lower = url.lower()
            
            if ".apk" in url_lower:
                score += 5
                flags.append(f"⛔ MALWARE: Link ends in .apk")
            if re.search(r'http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                score += 4
                flags.append(f"❌ DANGEROUS: IP Address URL.")
            
            if not is_safe_source:
                for domain in SUSPICIOUS_DOMAINS:
                    if domain in url_lower:
                        score += 2
                        flags.append(f"⚠️ Suspicious Domain: '{domain}'")
                for keyword in BAD_URL_KEYWORDS:
                    if keyword in url_lower:
                        score += 2
                        flags.append(f"⚠️ Suspicious keyword in URL: '{keyword}'")

            if source_type == 'manual' and not is_safe_source:
                insp_flags, insp_score = inspect_link(url)
                score += insp_score
                flags.extend(insp_flags)

    # --- PART G: UNIVERSAL VALIDATION RULE (The Fix) ---
    # If ANY threat type is detected AND there is a link AND it's not Official:
    # Flag it as a CRITICAL MISMATCH automatically.
    if urls and not is_safe_source:
        score += 5
        # Dynamic, context-aware error message
        if detected_threat_type:
            flags.append(f"⛔ CRITICAL: This message appears to be about **{detected_threat_type}**, but the link provided does NOT match our official records for that category.")
        else:
            flags.append("⛔ CRITICAL POLICY: The link provided is NOT an official government or banking domain. We treat all unverified links as high risk.")

    # --- FINAL VERDICT LOGIC ---
    if is_safe_source and score > 0:
        score = max(0, score - 5)

    final_score = min(score, 10)
    
    if final_score <= 0:
        verdict = "SAFE"
        color = "safe"
        if final_score < 0: final_score = 0 
    elif 1 <= final_score <= 4:
        verdict = "SUSPICIOUS"
        color = "suspicious"
    else:
        verdict = "SCAM DETECTED"
        color = "danger"

    return {"verdict": verdict, "color": color, "score": final_score, "flags": flags}

# ==============================================================================
# 5. NEW OCR HELPER (Handles Dark Mode & Inversion)
# ==============================================================================
def ocr_space_file(image_file, api_key='helloworld', language='eng'):
    """
    Sends image to OCR.space API. 
    Includes pre-processing to handle Dark Mode screenshots (Inverts colors).
    """
    try:
        # --- A. LOAD & PRE-PROCESS IMAGE ---
        img = Image.open(image_file)
        
        # Convert to RGB (fixes transparency issues)
        if img.mode != 'RGB':
            img = img.convert('RGB')

        # --- B. DETECT DARK MODE ---
        # Calculate average brightness
        grayscale = img.convert('L')
        histogram = grayscale.histogram()
        pixels = sum(histogram)
        total_brightness = sum([i * h for i, h in enumerate(histogram)])
        avg_brightness = total_brightness / pixels

        # If brightness is low (< 100), it is likely Dark Mode -> INVERT IT
        if avg_brightness < 100:
            print("Dark mode detected. Inverting image colors for better OCR...")
            img = ImageOps.invert(img)
            # Boost contrast slightly
            enhancer = ImageEnhance.Contrast(img)
            img = enhancer.enhance(1.5)

        # --- C. SAVE TO MEMORY ---
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='JPEG')
        img_buffer.seek(0)

        # --- D. SEND TO API ---
        payload = {
            'apikey': api_key,
            'language': language,
            'isOverlayRequired': False,
            'scale': True,        # Important for screenshots
            'OCREngine': 2        # Engine 2 is better for numbers/messy text
        }
        
        files = {'file': ('processed_image.jpg', img_buffer, 'image/jpeg')}
        
        response = requests.post('https://api.ocr.space/parse/image',
                                 files=files,
                                 data=payload,
                                 timeout=20)

        # --- E. HANDLE RESULT ---
        result = response.json()
        
        if result.get('IsErroredOnProcessing'):
            return ""  # Return empty string on error
        
        parsed_results = result.get('ParsedResults')
        if parsed_results and parsed_results[0].get('ParsedText'):
            return parsed_results[0]['ParsedText']
        else:
            return ""

    except Exception as e:
        print(f"OCR Error: {e}")
        return ""

# ==============================================================================
# 6. FLASK ROUTES
# ==============================================================================
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/extract_text', methods=['POST'])
def extract_text():
    if 'image' not in request.files: return jsonify({'error': 'No file uploaded'})
    
    files = request.files.getlist('image')
    
    if not files or files[0].filename == '': return jsonify({'error': 'No file selected'})
    
    extracted_texts = []
    
    try:
        for file in files:
            # Use the NEW robust OCR function instead of the old loop
            text = ocr_space_file(file)
            
            if text:
                extracted_texts.append(text)

        # Join all extracted text
        full_text = "\n\n--- [NEXT IMAGE] ---\n\n".join(extracted_texts)

        if not full_text.strip():
            # Keep specific failure message for user debugging
            full_text = "System: No readable text found or API Limit Reached. \n\nAnalysis: Please check internet connection."
            
        return jsonify({'text': full_text})

    except Exception as e: 
        return jsonify({'error': f"Network/API Error: {str(e)}"})

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    text = data.get('text', '')
    source = data.get('source', 'manual') 
    
    if not text.strip(): return jsonify({'error': 'No text'})
    
    result = get_threat_analysis(text, source)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, threaded=True, port=5000)