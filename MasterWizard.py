
import keyring
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

def CreateECCKeypair():
    privateKey = ec.generate_private_key(ec.SECP256R1())
    publicKey = privateKey.public_key()

    pemPrivate = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  
    )
    with open("MasterECCPrivateKey.pem", "wb") as f:
        f.write(pemPrivate)
        
    pemPublic = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("MasterECCPublicKey.pem", "wb") as f:
        f.write(pemPublic)
    return privateKey, publicKey

def WizardInitialisation(masterPassword):
    ph = PasswordHasher()
    keyring.set_password("Decentralised-File-System", "master", ph.hash(masterPassword))

    CreateECCKeypair()

password = input("Password : ")
WizardInitialisation(password)