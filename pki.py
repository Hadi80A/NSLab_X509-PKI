import socket
import ssl
import os
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend


class CertificateAuthority:
    def __init__(self, key_file, cert_file):
        self.key_file = key_file
        self.cert_file = cert_file
        self.cert = None
        self.key = None
        self.load_certificate()

    def ensure_ca_certificate(self):
        if not os.path.exists('ca.key') or not os.path.exists('ca.crt'):
            self.generate_ca_key_and_cert()
            print("CA Key and Certificate generated.")

    def load_certificate(self):
        self.ensure_ca_certificate()
        if os.path.exists(self.cert_file):
            with open(self.cert_file, 'rb') as f:
                self.cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                self.key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    def generate_ca_key_and_cert(self):
        # Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Create a certificate subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"My CA"),
        ])

        # Create a self-signed certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(subject)
        builder = builder.not_valid_before(datetime.datetime.utcnow())
        builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(private_key.public_key())
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        # Write private key to a file
        with open(self.key_file, "wb") as key_file:
            key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Write certificate to a file
        with open(self.cert_file, "wb") as cert_file:
            cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))

    def generate_certificate(self, subject_name,public_key_pem, valid_days=365):
        if self.cert is None or self.key is None:
            raise ValueError("CA certificate or key is not loaded")
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
        # Create a certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ])
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(self.cert.subject)
        builder = builder.not_valid_before(datetime.datetime.utcnow())
        builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=valid_days))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        certificate = builder.sign(private_key=self.key, algorithm=hashes.SHA256(), backend=default_backend())

        return certificate


class CertificateRevocationList:
    def __init__(self, issuer_cert, issuer_private_key,crl_file):
        self.issuer_cert = issuer_cert
        self.issuer_private_key = issuer_private_key
        self.crl = self.load_crl(crl_file)

    def create_crl(self, revoked_certificates):
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.issuer_cert.subject)
        builder = builder.last_update(datetime.datetime.utcnow())
        builder = builder.next_update(datetime.datetime.utcnow() + datetime.timedelta(days=7))

        for revoked_cert in revoked_certificates:
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(revoked_cert.serial_number)
                .revocation_date(revoked_cert.revocation_date)
                .build()
            )

        self.crl = builder.sign(
            private_key=self.issuer_private_key, algorithm=hashes.SHA256(), backend=default_backend()
        )

        with open(crl_file, "wb") as f:
            f.write(self.crl.public_bytes(serialization.Encoding.PEM))

    def load_crl(self,crl_file):
        if not os.path.exists(crl_file):
            # invalid_serial=0x51a62b92c3dd63bce63a30266a77cf9abf3a290c
            # revoked= x509.RevokedCertificateBuilder().serial_number(invalid_serial).revocation_date(time=datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)).build()
            # self.create_crl([revoked])
            self.create_crl([])
        with open(crl_file, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read(), default_backend())
        return crl

    def is_revoked(self, cert_to_check):
        for revoked_cert in self.crl:
            if revoked_cert.serial_number == cert_to_check.serial_number:
                return True

        return False



class RegistrationAuthority:
    def __init__(self, host, port, ca_cert_file,ca_key_file, crl_file, ca):
        self.host = host
        self.port = port
        self.ca_cert_file = ca_cert_file
        self.ca_key_file = ca_key_file
        self.crl_file = crl_file
        self.ca = ca
        self.ca_cert = None
        self.ca_key = None
        self.crl = None
        self.context = None
        self.ra_cert_file = 'ra.crt'
        self.ra_key_file = 'ra.key'
        self.load_ca_certificate()
        self.load_crl()
        self.setup_ra_context()
        self.user_list=['hadi','ali','changiz','Server']

    def load_ca_certificate(self):
        if os.path.exists(self.ca_cert_file):
            with open(self.ca_cert_file, 'rb') as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        if os.path.exists(self.ca_key_file):
            with open(self.ca_key_file, 'rb') as f:
                self.ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    def load_crl(self):
        self.crl = CertificateRevocationList(self.ca_cert,self.ca_key,self.crl_file)

    def setup_ra_context(self):
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.verify_mode = ssl.CERT_OPTIONAL
        self.ensure_ra_certificate()
        self.context.load_cert_chain(certfile=self.ra_cert_file, keyfile=self.ra_key_file)
        self.context.load_verify_locations(cafile=self.ca_cert_file)

    def ensure_ra_certificate(self):
        if not os.path.exists(self.ra_cert_file) or not os.path.exists(self.ra_key_file):
            self.generate_ra_certificate()

    def generate_ra_certificate(self):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        certificate= self.ca.generate_certificate("localhost",key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))
        with open(self.ra_cert_file, "wb") as cert_file:
            cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))

        with open(self.ra_key_file, "wb") as key_file:
            key_file.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print("ra Key and Certificate generated.")

    def handle_client(self, conn):
        conn = self.context.wrap_socket(conn, server_side=True)
        try:
            data = conn.recv(1024)
            pu_key = conn.recv(4096)
            if data:
                user = data.decode()
                print("Received request from client:", user)
                if user not in self.user_list:
                    conn.sendall(f"{user} not registered".encode())
                    print("not registered")
                    return

                # Generate a certificate for the user
                user_cert = self.ca.generate_certificate(user,pu_key)

                conn.sendall(user_cert.public_bytes(serialization.Encoding.PEM))
                print('certificate send')
        except Exception as e:
            print("Error handling client:", e)
        finally:
            conn.close()

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen(1)
            print(f"ra listening on {self.host}:{self.port}")
            while True:
                conn, addr = s.accept()
                print('Connected by', addr)
                self.handle_client(conn)


ca = CertificateAuthority('ca.key', 'ca.crt')

crl_file = 'list.crl'
ra = RegistrationAuthority('localhost', 8888, 'ca.crt','ca.key', crl_file, ca)
ra.start()
