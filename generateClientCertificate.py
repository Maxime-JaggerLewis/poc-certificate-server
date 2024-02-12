from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, BestAvailableEncryption
from datetime import datetime, timedelta

def main():
    ca_password = b"passwordEnBytes"
    
    # Load the existing CA private key and certificate
    with open("./ca/ca.key", "rb") as key_file:
        ca_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=ca_password,
            backend=default_backend()
        )


    with open("./ca/ca.crt", "rb") as cert_file:
        ca_cert = x509.load_pem_x509_certificate(
            cert_file.read(),
            default_backend()
        )

    # Generate a key pair and a certificate signing request (CSR) for the end entity
    end_entity_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "MyOrganization"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "www.example.com"),
    ])

    csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("www.example.com"),
        ]),
        critical=False,
    ).sign(
        end_entity_private_key, hashes.SHA256(), default_backend()
    )

    # Sign the end entity certificate with the existing CA
    end_entity_cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(
        ca_private_key, hashes.SHA256(), default_backend()
    )
    
    
    client_key_bytes = end_entity_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        
    client_cert_bytes = end_entity_cert.public_bytes(serialization.Encoding.PEM)
    
    print(client_key_bytes)
    print(client_cert_bytes)

main()