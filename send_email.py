import smtplib
from termcolor import colored
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from mail_config import SMTP_SERVER, SMTP_PORT, SENDER_EMAIL, SENDER_PASSWORD, RECIPIENT_EMAIL

error_log = []
def send_email(subject, body):
    try:
        message = MIMEMultipart()
        message['From'] = SENDER_EMAIL
        message['To'] = RECIPIENT_EMAIL
        message['Subject'] = subject

        message.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(message)
            print(colored(f"[EMAIL] Email sent successfully!", "light_magenta"))
    except Exception as e:
        error_log.append(f"[ERROR] Error sending email: {e}")
        if error_log:
            with open("error_log.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")

