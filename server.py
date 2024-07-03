import re
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class Server:
    def __init__(self, ca_cert_file, crl_file, port=12345):
        self.ca_cert_file = ca_cert_file
        self.crl_file = crl_file
        self.crl = None
        self.ca_cert = None
        self.port = port
        self.load_crl()
        self.load_ca_cert()
        self.get_server_certificate()

    def load_ca_cert(self):
        with open(self.ca_cert_file, "rb") as f:
            ca_cert_data = f.read()
        self.ca_cert = x509.load_pem_x509_certificate(ca_cert_data, default_backend())

    def get_server_certificate(self):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        context = ssl.create_default_context(cafile=self.ca_cert_file)

        # Connect to the server
        with socket.create_connection(('localhost', 8888)) as sock:
            with context.wrap_socket(sock, server_hostname='localhost') as ssock:
                print("Connected to the server.")

                # Send a request for a certificate
                name_bytes = b'Server'
                ssock.sendall(name_bytes)

                ssock.sendall(key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PublicFormat.SubjectPublicKeyInfo))
                # Receive the certificate
                cert_data = ssock.recv(4096)
                # Save the certificate to a file with .cert extension
                with open("server_cert.crt", "wb") as cert_file:
                    cert_file.write(cert_data)

                with open("server_key.key", "wb") as key_file:
                    key_file.write(key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()))

                print("Server Certificate received'.")

    def load_crl(self):
        with open(self.crl_file, "rb") as f:
            crl_data = f.read()
        self.crl = x509.load_pem_x509_crl(crl_data, default_backend())

    def verify_cert(self, cert_data):
        try:
            valid = self.verify_certificate_chain(cert_data.decode())
            return valid

        except Exception as e:
            print("Certificate verification failed:", e)
            return False

    def check_expire(self,certificate):
        # Access the not_valid_before and not_valid_after attributes
        not_valid_before = certificate.not_valid_before_utc
        not_valid_after = certificate.not_valid_after_utc

        current_time = datetime.now()

        # Convert offset-aware datetime objects to naive datetime objects
        not_valid_before = not_valid_before.replace(tzinfo=None)
        not_valid_after = not_valid_after.replace(tzinfo=None)

        # Check if the certificate is expired or not yet valid
        if not_valid_before <= current_time <= not_valid_after:
            return False  # Certificate is valid
        else:
            return True  # Certificate is expired or not yet valid

    def start(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_verify_locations(cafile=self.ca_cert_file)
        context.load_cert_chain(certfile='server_cert.crt', keyfile='server_key.key')
        context.verify_mode = ssl.CERT_OPTIONAL

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as server_socket:
            server_socket.bind(("localhost", self.port))
            server_socket.listen(1)
            print(f"Server is listening on port {self.port}...")
            while True:
                conn, addr = server_socket.accept()
                with context.wrap_socket(conn, server_side=True) as ssl_socket:
                    print("Connection from:", addr)
                    cert_data = ssl_socket.recv(4096*2)
                    print("Received certificate from client.")

                    if self.verify_cert(cert_data):
                        ssl_socket.send("Valid certificate ✅".encode())
                    else:
                        ssl_socket.send("Invalid certificate ❌".encode())

    def get_cert_chain(self, cert_file):
        # Use regular expression to find certificates
        cert_list = re.findall(r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', cert_file, re.DOTALL)
        cert_list = [f'-----BEGIN CERTIFICATE-----{s}-----END CERTIFICATE-----' for s in cert_list]
        certificates = [x509.load_pem_x509_certificate(cert.encode(), default_backend()) for cert in cert_list]
        return certificates

    def verify_certificate_chain(self, crt):
        cert_chain = self.get_cert_chain(crt)
        for i in range(len(cert_chain)):
            cert = cert_chain[i]
            if i < len(cert_chain) - 1:
                issuer_cert = cert_chain[i + 1]
            try:
                if cert.issuer == self.ca_cert.subject:
                    self.ca_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(),
                                                     cert.signature_hash_algorithm)
                elif i < len(cert_chain)-1:
                    issuer_public_key = issuer_cert.public_key()
                    issuer_public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        cert.signature_hash_algorithm,
                    )
                expired = self.check_expire(cert)
                revoked = self.crl.get_revoked_certificate_by_serial_number(cert.serial_number)
                if revoked is not None or expired:
                    raise Exception("invalid")
                print(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,'✅')
            except Exception as e:
                print(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, '❌')
                print("Certificate chain verification failed:", e)
                return False

        print("Certificate chain verification successful")
        return True


def main():
    server = Server("ca.crt", "list.crl")
    server.start()


if __name__ == "__main__":
    main()
