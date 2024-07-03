from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import serialization

def certificate_info(cert_path):
    """
    Returns a dictionary containing certificate information
    """
    try:
        # Load certificate from file
        with open(cert_path, 'rb') as cert_file:
            cert_data = cert_file.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Extract certificate information
        info = {
            "issuer": cert.issuer.rfc4514_string(),
            "subject": cert.subject.rfc4514_string(),
            "serial_number": cert.serial_number,
            "not_before": cert.not_valid_before_utc,
            "not_after": cert.not_valid_after_utc,
            "signature_algorithm": cert.signature_algorithm_oid,
            "signature_hash_algorithm": cert.signature_hash_algorithm.name,
            "public_key": cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }

        # Extract extensions
        extensions = []
        for extension in cert.extensions:
            extensions.append({
                "name": extension.oid._name,
                "oid": extension.oid.dotted_string,
                "value": extension.value
            })
        if len(extensions)>0 :
            info["extensions"] = extensions

        return info

    except Exception as e:
        return {"error": str(e)}

