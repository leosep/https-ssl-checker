import ssl
import smtplib
import logging
import os
import socket
import io
from datetime import datetime
from urllib.parse import urlparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import parsedate_to_datetime
def load_urls(filename):
    try:
        with open(filename, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        return urls
    except FileNotFoundError:
        logging.error(f"File {filename} not found")
        return []
    except Exception as e:
        logging.error(f"Error reading {filename}: {e}")
        return []

def load_emails(filename):
    try:
        with open(filename, 'r') as f:
            emails = [line.strip() for line in f if line.strip()]
        return emails
    except FileNotFoundError:
        logging.error(f"File {filename} not found")
        return []
    except Exception as e:
        logging.error(f"Error reading {filename}: {e}")
        return []
def check_ssl_certificate(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443

        # Create SSL context with verification
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        # Connect and wrap socket
        sock = socket.create_connection((hostname, port))
        ssl_sock = context.wrap_socket(sock, server_hostname=hostname)

        # Get certificate info
        cert = ssl_sock.getpeercert()

        # Check expiry
        not_after_str = cert['notAfter']
        not_after = parsedate_to_datetime(not_after_str)
        now = datetime.utcnow().replace(tzinfo=not_after.tzinfo)
        if now > not_after:
            logging.warning(f"Certificate for {url} is expired (expired on {not_after})")
            ssl_sock.close()
            return False

        ssl_sock.close()
        logging.info(f"Certificate for {url} is valid")
        return True

    except ssl.SSLError as e:
        logging.warning(f"Certificate for {url} is invalid: {e}")
        return False
    except Exception as e:
        logging.error(f"Error checking certificate for {url}: {e}")
        return False

def send_notification_email(emails, bad_certificates):
    try:
        smtp_server = 'smtp.example.com'
        smtp_port = 587
        smtp_username = 'your-email@example.com'
        smtp_password = 'your-password'

        msg = MIMEMultipart()
        msg['From'] = smtp_username
        msg['To'] = ', '.join(emails)
        msg['Subject'] = 'Alerta de Certificado SSL'

        body = f"Los siguientes sitios web tienen certificados SSL inválidos:\n\n" + "\n".join(bad_certificates)
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_username, smtp_password)
        text = msg.as_string()
        server.sendmail(smtp_username, emails, text)
        server.quit()

        logging.info("Notification email sent successfully")
    except Exception as e:
        logging.error(f"Failed to send notification email: {e}")
# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    # Load URLs and emails
    urls = load_urls('websites.txt')
    emails = load_emails('emails.txt')

    if not urls:
        logging.error("No URLs found in websites.txt")
        return

    if not emails:
        logging.error("No emails found in emails.txt")
        return

    bad_certificates = []

    for url in urls:
        if not check_ssl_certificate(url):
            bad_certificates.append(url)

    if bad_certificates:
        send_notification_email(emails, bad_certificates)
        logging.info(f"Notification sent for {len(bad_certificates)} bad certificates")
    else:
        logging.info("All certificates are valid")

if __name__ == "__main__":
    main()