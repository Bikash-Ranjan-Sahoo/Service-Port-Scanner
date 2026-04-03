# ============================================================
# IntelliPort - AI Risk Predictor Module
# File: ai_predictor.py
# Purpose: Load trained model and predict risk for each port
# ============================================================

import pickle   # Load saved model files
import os       # Check if files exist

# -------------------------------------------------------
# RISK DEFINITIONS
# Maps risk level numbers to display information
# -------------------------------------------------------
RISK_INFO = {
    0: {
        "label":       "Safe",
        "emoji":       "🟢",
        "color":       "#00c853",   # Green
        "description": "This port appears safe and uses secure protocols.",
    },
    1: {
        "label":       "Suspicious",
        "emoji":       "🟡",
        "color":       "#ffd600",   # Yellow
        "description": "This port may pose a risk. Monitor it closely.",
    },
    2: {
        "label":       "Dangerous",
        "emoji":       "🔴",
        "color":       "#d50000",   # Red
        "description": "This port is high risk! Immediate action recommended.",
    },
}

# -------------------------------------------------------
# RECOMMENDATION DATABASE
# Specific security advice for known risky ports
# -------------------------------------------------------
RECOMMENDATIONS = {
    21:    "❌ Close FTP (port 21). Use SFTP or FTPS instead.",
    20:    "❌ Close FTP-DATA (port 20). Use SFTP instead.",
    23:    "❌ Disable Telnet immediately. Use SSH (port 22) instead.",
    135:   "⚠️  Block MSRPC from external access. Common attack vector.",
    137:   "⚠️  Block NetBIOS. Not needed for internet-facing systems.",
    138:   "⚠️  Block NetBIOS Datagram. Disable if not on local network.",
    139:   "⚠️  Block NetBIOS Session. Use SMB over TCP/IP instead.",
    445:   "❌ Block SMB (port 445) from internet! Vulnerable to ransomware (WannaCry).",
    512:   "❌ Disable REXEC. It transmits credentials in plaintext.",
    513:   "❌ Disable RLOGIN. Replace with SSH immediately.",
    1080:  "⚠️  Close SOCKS proxy if not intentionally set up.",
    1433:  "⚠️  Restrict MSSQL access. Never expose to public internet.",
    1521:  "⚠️  Restrict Oracle DB access. Use firewall rules.",
    2049:  "⚠️  NFS should NOT be exposed to the internet.",
    3306:  "⚠️  Restrict MySQL. Bind to localhost unless remote access needed.",
    3389:  "⚠️  RDP is frequently attacked. Use VPN + disable if unused.",
    4444:  "🚨 Port 4444 is used by Metasploit! Investigate immediately.",
    5900:  "❌ VNC is insecure over internet. Use SSH tunnel instead.",
    5985:  "⚠️  Restrict WinRM access. Not for public-facing servers.",
    6379:  "❌ Redis has no auth by default! Bind to localhost only.",
    9200:  "❌ Elasticsearch is open! Add authentication immediately.",
    27017: "❌ MongoDB is open! Vulnerable to data theft. Add auth.",
    22:    "✅ SSH is secure. Ensure key-based auth is enabled.",
    80:    "✅ HTTP is fine for web. Consider redirecting to HTTPS.",
    443:   "✅ HTTPS is secure. Ensure TLS 1.2+ is used.",
    8443:  "✅ HTTPS-ALT is secure. Check certificate validity.",
}


# -------------------------------------------------------
# CLASS: AIPredictor
# Loads the trained model and predicts risk levels
# -------------------------------------------------------
class AIPredictor:

    def __init__(self):
        """Initialize and load the trained model files."""
        self.model    = None
        self.encoders = None
        self.loaded   = False
        self._load_model()

    def _load_model(self):
        """Load model and encoders from .pkl files."""
        model_path    = "intelliport_model.pkl"
        encoders_path = "intelliport_encoders.pkl"

        # Check both files exist
        if not os.path.exists(model_path) or not os.path.exists(encoders_path):
            print("[AI] WARNING: Model files not found. Using rule-based fallback.")
            return

        try:
            # Load the trained Random Forest model
            with open(model_path, "rb") as f:
                self.model = pickle.load(f)

            # Load the text encoders
            with open(encoders_path, "rb") as f:
                self.encoders = pickle.load(f)

            self.loaded = True
            print("[AI] Model loaded successfully ✓")

        except Exception as e:
            print(f"[AI] Error loading model: {e}. Using fallback.")

    def predict(self, port, protocol, status):
        """
        Predict the risk level for a given port.

        Parameters:
        - port     : Port number (e.g., 21)
        - protocol : 'TCP' or 'UDP'
        - status   : 'open', 'closed', or 'filtered'

        Returns:
        - Dictionary with risk_level, label, color, emoji,
          description, and recommendation
        """

        # Closed/filtered ports are generally safe
        if status in ("closed", "filtered"):
            risk_level = 0
        elif self.loaded:
            # Use AI model to predict
            risk_level = self._ai_predict(port, protocol, status)
        else:
            # Fallback: rule-based prediction
            risk_level = self._rule_based_predict(port, status)

        # Get display info
        info = RISK_INFO[risk_level].copy()
        info["risk_level"]     = risk_level
        info["recommendation"] = RECOMMENDATIONS.get(
            port,
            self._default_recommendation(risk_level)
        )

        return info

    def _ai_predict(self, port, protocol, status):
        """Use the trained Random Forest model to predict risk."""
        try:
            # Encode text values to numbers
            proto_enc  = self.encoders["protocol"].transform([protocol])[0]
            status_enc = self.encoders["status"].transform([status])[0]

            # Prepare input for the model
            features = [[port, proto_enc, status_enc]]

            # Get prediction (0, 1, or 2)
            prediction = self.model.predict(features)[0]
            return int(prediction)

        except Exception:
            # If AI fails, use rule-based fallback
            return self._rule_based_predict(port, status)

    def _rule_based_predict(self, port, status):
        """
        Simple rule-based fallback if AI model is unavailable.
        Based on known dangerous ports.
        """
        DANGEROUS_PORTS   = {21, 20, 23, 135, 137, 138, 139, 445,
                              512, 513, 1080, 1433, 1521, 2049,
                              3389, 4444, 5900, 5985, 6379, 9200, 27017}
        SUSPICIOUS_PORTS  = {25, 53, 69, 110, 111, 119, 143, 161,
                              514, 515, 631, 873, 1723, 2121, 3306,
                              5432, 6667, 8080, 8888}

        if status == "open":
            if port in DANGEROUS_PORTS:
                return 2   # Dangerous
            elif port in SUSPICIOUS_PORTS:
                return 1   # Suspicious
            else:
                return 0   # Safe
        else:
            return 0       # Closed/filtered = safe

    def _default_recommendation(self, risk_level):
        """Return a generic recommendation based on risk level."""
        if risk_level == 0:
            return "✅ No action required. Port appears secure."
        elif risk_level == 1:
            return "⚠️  Monitor this port. Restrict access if not needed."
        else:
            return "❌ Review this port urgently. Consider closing or restricting it."

    def calculate_threat_score(self, results):
        """
        Calculate an overall threat score (0-100) for all scan results.

        Logic:
        - Each dangerous open port  = +15 points
        - Each suspicious open port = +7 points
        - Score is capped at 100
        """
        score = 0
        for r in results:
            if r.get("status") == "open":
                risk = r.get("risk_level", 0)
                if risk == 2:
                    score += 15
                elif risk == 1:
                    score += 7

        return min(score, 100)   # Cap at 100

    def get_threat_label(self, score):
        """Return a label and color for the threat score."""
        if score >= 70:
            return "CRITICAL RISK", "#d50000"
        elif score >= 45:
            return "HIGH RISK", "#ff6d00"
        elif score >= 25:
            return "MEDIUM RISK", "#ffd600"
        elif score >= 10:
            return "LOW RISK", "#64dd17"
        else:
            return "SECURE", "#00c853"
