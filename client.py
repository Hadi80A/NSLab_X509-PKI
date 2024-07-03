import socket
import ssl

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class Client:
    def __init__(self,ca_cert_file):
        self.name = ''
        self.host = 'localhost'
        self.ra_port = 8888
        self.server_port = 12345
        self.ca_cert_file = ca_cert_file
        self.server_hostname = 'Server'

    def set_name(self, name):
        self.name = name

    def verify_cert(self,cert):
        context = ssl.create_default_context(cafile=self.ca_cert_file)

        # Connect to the server
        with socket.create_connection((self.host, self.server_port)) as sock:
            # Wrap the socket with SSL/TLS
            with context.wrap_socket(sock, server_hostname=self.server_hostname) as ssock:
                # cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
                ssock.sendall(cert)

                cert_data = ssock.recv(4096)

                print(cert_data.decode())
    def send_cert_request(self):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Create an SSL context with the CA file
        context = ssl.create_default_context(cafile=self.ca_cert_file)

        # Connect to the server
        with socket.create_connection((self.host, self.ra_port)) as sock:
            # Wrap the socket with SSL/TLS
            with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                print("Connected to the RA")

                # Send a request for a certificate
                name_bytes = self.name.encode()
                ssock.sendall(name_bytes)

                ssock.sendall(key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))
                # Receive the certificate
                cert_data = ssock.recv(4096)
                crt= cert_data.decode()
                error= f'{self.name} not registered'
                if crt ==error:
                    print(error)
                    return
                # Print the certificate
                print("Received certificate:")
                print(crt)

                # Save the certificate to a file with .cert extension
                with open("user_cert.crt", "wb") as cert_file:
                    cert_file.write(cert_data)

                with open("user_key.key", "wb") as key_file:
                    key_file.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()))

                print("Certificate received and saved to 'user_cert.crt'.")
