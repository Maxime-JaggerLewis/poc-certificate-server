import os
import sys
from service.Certificate import Certificate


def main():
    directory = os.path.dirname(os.path.realpath(__file__))
    if (len(sys.argv) < 2):
        exit(-1)
    iccid = str(sys.argv[1])
    
    chemin_certificat = os.path.join("crt", iccid, "client.crt")
    chemin_cle_privee = os.path.join("crt", iccid,"client.key")
    chemin_ca = os.path.join("ca", "ca.crt")
    
    certificate = Certificate(directory)
    print("---------- Create certificate --------------")
    certificate.createCertificate(iccid)
    print("---------- Check validity --------------")
    certificate.checkCertificateValidity(chemin_certificat)
    print("---------- Check validity with key --------------")
    certificate.checkCertificateWithKey(chemin_certificat, chemin_cle_privee)
    print("---------- Check validity with CA --------------")
    certificate.checkCertificateWithCA(chemin_certificat, chemin_ca)
    print("---------- Check certificate info --------------")
    certificate.getCertificateInfo(chemin_certificat)
    

main()