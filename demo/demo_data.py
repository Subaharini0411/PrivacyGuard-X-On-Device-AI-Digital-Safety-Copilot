"""
PrivacyGuard X - Synthetic Demo Data Generator
Provides strictly synthetic, non-real test samples for demonstration and evaluation.
NEVER contains real personal information or live API secrets.
All records are explicitly labelled: DEMO DATA — NOT REAL CREDENTIALS.
"""

import io
from PIL import Image, ImageDraw, ImageFont


DEMO_DISCLAIMER = "Demo Mode — synthetic data only. NOT REAL CREDENTIALS."

DEMO_CODE = """# DEMO DATA — NOT REAL CREDENTIALS
import os
import psycopg2

# Configuration setup for internal staging service
ENV = "staging"
DEBUG_MODE = True

# WARNING: Credentials should be externalized
OPENAI_API_KEY = "sk-proj-demo987349182347192847129384712398demo"
AWS_ACCESS_KEY_ID = "AKIAEXAMPLE12345678"
DATABASE_URL = "postgresql://db_admin:demo_super_secret_password_2026@192.168.1.140:5432/finance_db"
JWT_SECRET = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkRlbW8gVXNlciIsImlhdCI6MTUxNjIzOTAyMn0.demo_signature_hash_xyz"

def get_connection():
    print(f"Connecting to {DATABASE_URL}...")
    return psycopg2.connect(DATABASE_URL)
"""

DEMO_TEXT = """DEMO DATA — NOT REAL CREDENTIALS
Confidential Internal Memo - Project Apollo Launch

Team,
Please find below the updated contact directory and onboarding credentials for the new security auditors.

Contact Coordinator:
Email: elena.rodriguez@example-corp.internal
Direct Line: +1 415-555-0188
Physical Office: 450 Innovation Boulevard, Tech Park, Suite 400
Employee Badge ID: EMP-90421
Internal Wiki: http://wiki.apollo.internal/dev-portal

Please do not share these details outside the engineering group.
"""

DEMO_DOCUMENT = """DEMO DATA — NOT REAL CREDENTIALS
==================================================
HP SNAPDRAGON PRIVACY DEMO AUDIT REPORT
==================================================
Department: Security Operations & AI Testing
Date: October 2026
Classification: Restricted (Synthetic Sample)

1. SYSTEM ADMINISTRATOR DETAILS
Primary Contact: david.miller@example-solutions.com
Desk Phone: +1 206-555-0144
SSN Reference (Demo): 999-12-3456
Student / Intern ID: STU-88219

2. STAGING PAYMENT GATEWAY TEST CARD
Cardholder Name: Synthetic Demo Test User
Test Card Number: 4532 0150 1234 5671
Card Type: Visa Test Verification
Status: Active Sandbox

3. INFRASTRUCTURE ENDPOINTS
Internal Subnet: 10.240.12.88
Gateway Router: 192.168.1.1
Database Password: password = "demo_root_password_987#"
==================================================
"""

DEMO_URL = "http://192.168.1.55:8080/admin/dashboard?token=demo_auth_session_9948271&user=demo_admin"

DEMO_CLEAN_TEXT = """Meeting Notes - Architecture Review
Discussion regarding on-device AI acceleration on Snapdragon hardware.
The team agreed to prioritize local inference using Qualcomm Hexagon NPU to ensure zero data leaves the user's laptop.
Next sync is scheduled for Thursday at 2:00 PM.
Documentation is accessible in the public open source repository.
"""


def generate_demo_image() -> bytes:
    """
    Dynamically generates a synthetic screenshot image containing demo credentials
    and clear visual watermarks. Returns PNG image bytes.
    """
    width = 850
    height = 420
    # Sleek dark background
    image = Image.new("RGB", (width, height), color="#0f172a")
    draw = ImageDraw.Draw(image)

    # Window title bar (Mac/Windows style)
    draw.rectangle([0, 0, width, 40], fill="#1e293b")
    draw.ellipse([15, 13, 27, 25], fill="#ef4444")
    draw.ellipse([35, 13, 47, 25], fill="#f59e0b")
    draw.ellipse([55, 13, 67, 25], fill="#10b981")
    draw.text((80, 12), "config.env — DEMO SYNTHETIC SCREENSHOT (NOT REAL CREDENTIALS)", fill="#94a3b8")

    # Banner
    draw.rectangle([20, 55, width - 20, 85], fill="#312e81", outline="#6366f1")
    draw.text((30, 62), "⚠️ DEMO MODE — SYNTHETIC CREDENTIALS FOR TESTING ONLY", fill="#c7d2fe")

    # Code / Content lines
    lines = [
        ("# Project Environment Secrets (Synthetic Demonstration)", "#64748b"),
        ("API_KEY=\"sk-proj-demo987349182347192847129384712398demo\"", "#f43f5e"),
        ("USER_EMAIL=\"sarah.jenkins@company.com\"", "#38bdf8"),
        ("SUPPORT_PHONE=\"+1 415-555-0199\"", "#a855f7"),
        ("DATABASE_URL=\"postgresql://admin:super_secret_pw@192.168.1.105:5432/db\"", "#fb923c"),
        ("EMPLOYEE_ID=\"EMP-84920\"", "#34d399"),
        ("STRIPE_KEY=\"pk_test_sample_sandbox_gateway_token\"", "#f43f5e"),
    ]

    y = 110
    for text_line, color in lines:
        draw.text((35, y), text_line, fill=color)
        y += 40

    buf = io.BytesIO()
    image.save(buf, format="PNG")
    return buf.getvalue()
