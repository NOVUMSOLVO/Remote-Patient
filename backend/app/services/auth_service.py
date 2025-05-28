"""
Authentication service for handling user login, registration, and 2FA.
"""
import pyotp
import qrcode
from io import BytesIO
import base64

def generate_otp_secret():
    """Generate a new OTP secret for a user."""
    return pyotp.random_base32()

def verify_otp(secret, code):
    """
    Verify a TOTP code against a secret.
    
    Args:
        secret: The user's OTP secret
        code: The code to verify
        
    Returns:
        bool: True if the code is valid, False otherwise
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

def generate_qr_code(secret, email):
    """
    Generate a QR code for the user to scan with their authenticator app.
    
    Args:
        secret: The user's OTP secret
        email: The user's email address
        
    Returns:
        str: Base64 encoded QR code image
    """
    # Create a provisioning URI for the user
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name="Remote Patient"
    )
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    
    # Create an image from the QR code
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert the image to base64
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    img_str = base64.b64encode(buffer.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"