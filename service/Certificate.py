from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import OpenSSL
from OpenSSL import crypto
import datetime
import subprocess
import os
import sys
import logging

logging.basicConfig(level=logging.DEBUG)

class Certificate:
    def __init__(self, root_path):
        self.directory_path = root_path
        pass
    
    def generateAbsolutePath(self, path):
        abs_path = os.path.join(self.directory_path, path)
        return os.path.abspath(abs_path)
    
    def createCertificate(self, iccid):
        bash_path = os.path.join(self.directory_path, "bash", "generate_client_crt.sh")
        subprocess.run(["bash", bash_path] + [iccid], check=True)
    
    def checkCertificateValidity(self, cert_path):
        try:
            with open(self.generateAbsolutePath(cert_path), 'rb') as cert_file:
                cert_data = cert_file.read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())

                # Obtient les dates de début et de fin de validité du certificat
                valid_from = cert.not_valid_before
                valid_to = cert.not_valid_after

                # Vérifie la validité du certificat
                current_time = datetime.datetime.now()
                if valid_from <= current_time <= valid_to:
                    print("Le certificat est valide.")
                    print("Date de début de validité:", valid_from)
                    print("Date de fin de validité:", valid_to)
                    return True
                else:
                    print("Le certificat n'est pas valide.")
                    print("Date de début de validité:", valid_from)
                    print("Date de fin de validité:", valid_to)
                    return False

        except Exception as e:
            print("Une erreur s'est produite lors de la vérification du certificat :", str(e))
            return False
    
    def checkCertificateWithKey(self, cert_path, key_path):
        try:
            # Charger le certificat depuis le fichier
            with open(self.generateAbsolutePath(cert_path), 'rb') as cert_file:
                cert_data = cert_file.read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())

            # Charger la clé privée depuis le fichier
            with open(self.generateAbsolutePath(key_path), 'rb') as key_file:
                key_data = key_file.read()
                private_key = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())

            # Extraire la clé publique à partir du certificat
            cert_public_key = cert.public_key()
            prv_public_key = private_key.public_key()

            cpub = cert_public_key.public_bytes(serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            pkpub = prv_public_key.public_bytes(serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

            # Vérifier la correspondance entre la clé publique du certificat et la clé privée
            if cpub == pkpub:
                print("La clé privée correspond au certificat.")
                return True
            else:
                print("La clé privée NE correspond PAS au certificat.")
                return False

        except Exception as e:
            print("Une erreur s'est produite lors de la vérification de la correspondance :", str(e))   
            return False
        
         
    def checkCertificateWithCA(self, client_path, ca_path):
        # Charger le certificat de l'autorité de certification (CA)
        with open(self.generateAbsolutePath(ca_path), 'rb') as f:
            ca_cert_data = f.read()
            ca_cert = x509.load_pem_x509_certificate(ca_cert_data, default_backend())

        # Charger le certificat client
        with open(self.generateAbsolutePath(client_path), 'rb') as f:
            client_cert_data = f.read()
            client_cert = x509.load_pem_x509_certificate(client_cert_data, default_backend())

        # Vérifier la signature du certificat client avec la clé publique du CA
        try:            
            ca_cert.public_key().verify(
                client_cert.signature,
                client_cert.tbs_certificate_bytes,
                padding=padding.PKCS1v15(),
                algorithm=client_cert.signature_hash_algorithm,
            )
            print('Le certificat client est valide.')
            return True
        except Exception as e:
            logging.exception("exception : %s", e)
            print(f'Le certificat client n\'est pas valide. Erreur : {e}')
            return False

    
    def getCertificateInfo(self, cert_path):
        try:
            # Charger le certificat depuis le fichier
            with open(self.generateAbsolutePath(cert_path), 'rb') as cert_file:
                cert_data = cert_file.read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())

                # Récupérer des informations du certificat
                subject = cert.subject
                issuer = cert.issuer
                not_valid_before = cert.not_valid_before
                not_valid_after = cert.not_valid_after
                serial_number = cert.serial_number
                thumbprint = cert.fingerprint(hashes.SHA256())

                # Extraire les extensions du certificat
                extensions = cert.extensions

                # Afficher les informations des extensions
                for extension in extensions:
                    print(f"Nom de l'extension: {extension.oid}")
                    print(f"Valeur de l'extension: {extension.value}")
                
                result = {
                    "subject": subject,
                    "issuer": issuer,
                    "not_valid_before": not_valid_before,
                    "not_valid_after": not_valid_after,
                    "serial_number": serial_number,
                    "extensions": extensions,
                    "empreinte": thumbprint.hex() 
                    }
                
                print(result)
                
                return result

        except Exception as e:
            print("Une erreur s'est produite lors de la récupération des informations du certificat :", str(e))
            return None