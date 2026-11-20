"""
Email

Rowanholt sends one kind of email: the reset-access link someone asked for from Forgot password
(auth/reset_access.py). A minimal SMTP sender on the standard library, configured with
ROWANHOLT_SMTP_HOST, _PORT, _USERNAME, _PASSWORD, _FROM and _STARTTLS (on by default; port 465 is
TLS from the start). Without a host and a sender address, nothing is sent and Forgot password says to
ask an administrator. The link is always at ROWANHOLT_PUBLIC_URL (routes_simple._forgot_password_offered).
"""

import logging
import smtplib
import ssl
from email.message import EmailMessage

try:
    from .config import settings
except ImportError:
    from config import settings

logger = logging.getLogger(__name__)

TIMEOUT = 20  # seconds


def configured() -> bool:
    """Whether email can be sent: a server to send through and an address to send from."""
    return bool(settings.rowanholt_smtp_host and settings.rowanholt_smtp_from)


def send(to: str, subject: str, body: str) -> None:
    """Send a plain-text email; raises on failure (smtplib.SMTPException, OSError)."""
    message = EmailMessage()
    message["From"] = settings.rowanholt_smtp_from
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)
    context = ssl.create_default_context()
    host, port = settings.rowanholt_smtp_host, settings.rowanholt_smtp_port
    if port == 465:
        smtp = smtplib.SMTP_SSL(host, port, timeout=TIMEOUT, context=context)
    else:
        smtp = smtplib.SMTP(host, port, timeout=TIMEOUT)
    with smtp:
        if port != 465 and settings.rowanholt_smtp_starttls:
            smtp.starttls(context=context)
        if settings.rowanholt_smtp_username:
            smtp.login(settings.rowanholt_smtp_username, settings.rowanholt_smtp_password)
        smtp.send_message(message)


def send_reset_link(to: str, username: str, link: str, hours: int) -> None:
    """Email a self-service reset-access link. Runs after the answer has gone (a background task), so
    a failure is logged, not raised: the answer mustn't say whether an account matched."""
    body = (f"Someone asked to reset access to the Rowanholt account {username}.\n\n"
            f"If it was you, open this link within {hours} hours to choose a new password and set up a new "
            f"authenticator. It works once:\n\n  {link}\n\n"
            "If it wasn't you, ignore this email: your password and authenticator keep working, and the "
            "link expires on its own.\n")
    try:
        send(to, "Reset your Rowanholt access", body)
    except (smtplib.SMTPException, OSError) as exc:
        logger.error("Could not email a reset-access link for %s: %s", username, exc)
