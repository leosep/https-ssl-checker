import ssl
import smtplib
import logging
import os
import socket
import io
from datetime import datetime
from urllib.parse import urlparse
from urllib.request import urlopen
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import parsedate_to_datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from cryptography.x509.ocsp import OCSPRequestBuilder, OCSPResponse, OCSPResponseStatus
from cryptography.hazmat.primitives import serialization
import requests
from urllib.request import urlopen
import urllib.parse
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
        now = datetime.now(not_after.tzinfo)
        if now > not_after:
            logging.warning(f"Certificate for {url} is expired (expired on {not_after})")
            ssl_sock.close()
            return False

        # Check if certificate is self-signed
        cert_der = ssl_sock.getpeercert(binary_form=True)
        cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
        if cert_obj.subject == cert_obj.issuer:
            logging.warning(f"Certificate for {url} is self-signed (not issued by a trusted CA)")
            ssl_sock.close()
            return False

        # Check for certificate revocation using OCSP
        try:
            aia = cert_obj.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            ocsp_url = None
            issuer_url = None
            for desc in aia.value:
                if desc.access_method == AuthorityInformationAccessOID.OCSP:
                    ocsp_url = desc.access_location.value
                elif desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                    issuer_url = desc.access_location.value
            if ocsp_url and issuer_url:
                # Fetch issuer certificate
                issuer_response = requests.get(issuer_url, timeout=10)
                if issuer_response.status_code == 200:
                    issuer_cert = x509.load_der_x509_certificate(issuer_response.content, default_backend())
                    builder = OCSPRequestBuilder()
                    request = builder.add_certificate(cert_obj, issuer_cert, default_backend()).build()
                    ocsp_resp = requests.post(ocsp_url, data=request.public_bytes(serialization.Encoding.DER), headers={'Content-Type': 'application/ocsp-request'}, timeout=10)
                    if ocsp_resp.status_code == 200:
                        ocsp_response = OCSPResponse.load_der(ocsp_resp.content)
                        if ocsp_response.certificate_status == OCSPResponseStatus.GOOD:
                            logging.info(f"OCSP check passed for {url}")
                        elif ocsp_response.certificate_status == OCSPResponseStatus.REVOKED:
                            logging.warning(f"Certificate for {url} is revoked according to OCSP")
                            ssl_sock.close()
                            return False
                        else:
                            logging.warning(f"OCSP status unknown for {url}")
                    else:
                        logging.warning(f"OCSP request failed for {url}: {ocsp_resp.status_code}")
                else:
                    logging.warning(f"Failed to fetch issuer certificate for {url}: {issuer_response.status_code}")
            else:
                logging.warning(f"No OCSP or issuer URL found for {url}")
        except Exception as e:
            logging.warning(f"OCSP check failed for {url}: {e}")

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
        smtp_server = 'x'
        smtp_port = 587
        smtp_username = 'x'
        smtp_password = 'x'

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
