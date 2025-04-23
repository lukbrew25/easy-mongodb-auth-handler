import smtplib
from email.mime.text import MIMEText

def send_verification_email(mail_server, mail_port, mail_username, mail_password, recipient_email, verification_code):
    if not all([mail_server, mail_port, mail_username, mail_password]):
        raise ValueError("Mail server settings are incomplete or missing.")

    subject = "Your Verification Code"
    body = f"Your verification code is: {verification_code}"
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = mail_username
    msg["To"] = recipient_email

    try:
        with smtplib.SMTP(mail_server, mail_port) as server:
            server.starttls()
            server.login(mail_username, mail_password)
            server.sendmail(mail_username, recipient_email, msg.as_string())
    except Exception as e:
        raise RuntimeError(f"Failed to send email: {e}")