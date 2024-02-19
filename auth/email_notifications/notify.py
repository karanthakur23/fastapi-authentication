import os
from dotenv import load_dotenv
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
import logging
import ssl

logger = logging.getLogger("uvicorn")
load_dotenv()
SENDER_GMAIL = os.environ["SENDER_GMAIL"]
SENDER_GMAIL_PASSWORD = os.environ["SENDER_GMAIL_PASSWORD"]
dirname = os.path.dirname(__file__)
templates_folder = os.path.join(dirname, '../templates')

conf = ConnectionConfig(
    MAIL_USERNAME = SENDER_GMAIL,
    MAIL_PASSWORD = SENDER_GMAIL_PASSWORD,
    MAIL_FROM = SENDER_GMAIL,
    MAIL_PORT = 587,
    MAIL_SERVER = "smtp.gmail.com",
    MAIL_FROM_NAME="Admin",
    MAIL_STARTTLS = True,
    MAIL_SSL_TLS = False,
    USE_CREDENTIALS = True,
    VALIDATE_CERTS = False,
    TEMPLATE_FOLDER = templates_folder,
)

async def send_reset_password_mail(recipient_email, user, url, expire_in_minutes):
    template_body = {
        'user': user,
        'url': url,
        'expire_in_minutes': expire_in_minutes
    }
    try:
        message = MessageSchema(
            subject = "Forgot Passsword Reset Mail",
            recipients = [recipient_email],
            template_body = template_body,
            subtype = MessageType.html
        )
        fm = FastMail(conf)
        await fm.send_message(message, template_name="reset_password_email.html")
    except Exception as e:
        logger.error("Something went wrong in password reset email")
        logger.error(str(e))
