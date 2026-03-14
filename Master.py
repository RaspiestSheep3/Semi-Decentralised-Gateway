import os
import sys
import json
import base64
import logging
import keyring
import colorlog
from argon2 import PasswordHasher
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519

#Global variables
privateKey, publicKey = None, None

#Logging setup
logFormatter = colorlog.ColoredFormatter(
            "%(log_color)s%(levelname)s: %(message)s",
            log_colors={
                "DEBUG": "cyan",
                "INFO": "green",
                "WARNING": "yellow",
                "ERROR": "red",
                "CRITICAL": "bold_red",
            },
        )

consoleLogHandler = logging.StreamHandler()
consoleLogHandler.setFormatter(logFormatter)
consoleLogHandler.setLevel(logging.DEBUG)

# General handler
with open(f"MasterGeneral.log", "w") as f:
    f.write("") #Clearing file
generalLogHandler = logging.FileHandler(f"MasterGeneral.log")
generalLogHandler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
generalLogHandler.setLevel(logging.DEBUG) 

#Error handler
with open(f"MasterErrors.log", "w") as f:
    f.write("")
errorLogHandler = logging.FileHandler(f"MasterErrors.log")
errorLogHandler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
errorLogHandler.setLevel(logging.ERROR)  

#Creating logger
logger = logging.getLogger("colorLogger")
logger.setLevel(logging.DEBUG)

# Adding handlers to the logger
logger.addHandler(consoleLogHandler) 
logger.addHandler(generalLogHandler)    
logger.addHandler(errorLogHandler) 

#Keypair generation
def CreateUserCertificate(name : str, ID : str, title : str, publicKeyPath : str, permissions : list, expiryDate : str, algorithmUsed : str, issuerID : str, issueDate : str, serial : int, version : int):
    permissionsDict = dict()
    
    for permission in permissions:
        permissionsDict[permission[0]] = permission[1]
        
    with open(publicKeyPath, "rb") as f:
        pemPublic = f.read()

    publicKey = serialization.load_pem_public_key(pemPublic)

    publicDer = publicKey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    publicKeyBytesB64 = base64.b64encode(publicDer).decode()
    
    userDict = {
        "Name" : name,
        "ID" : ID,
        "Title" : title,
        "Public Key" : publicKeyBytesB64,
        "Permissions" : permissionsDict,
        "Expiry Date" : expiryDate,
        "Algorithm Used" : algorithmUsed,
        "Issuer" : issuerID,
        "Issue Date" : issueDate,
        "Serial" : serial,
        "Certificate Version" : version
    }
    
    #Signing the user
    signatureBytes = privateKey.sign(
        json.dumps(userDict).encode(),
        ec.ECDSA(hashes.SHA256())
    )
    
    userDict["Signature"] = base64.b64encode(signatureBytes).decode()
    with open(f"User{secure_filename(ID)}Certificate.json", "w") as f:
        json.dump(userDict, f, indent=4)

def CreateResourceCertificate(name : str, ID : str, publicKeyPath : str, algorithmUsed : str, issuerID : str, issueDate : str, expiryDate : str, serial : int, version : int, ):
    
    with open(publicKeyPath, "rb") as f:
        pemPublic = f.read()

    publicKey = serialization.load_pem_public_key(pemPublic)

    publicDer = publicKey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    publicKeyBytesB64 = base64.b64encode(publicDer).decode()
    
    resourceDict = {
        "Name" : name,
        "ID" : ID,
        "Public Key" : publicKeyBytesB64,
        "Algorithm Used" : algorithmUsed,
        "Issuer" : issuerID,
        "Issue Date" : issueDate,
        "Expiry" : expiryDate,
        "Serial" : serial,
        "Certificate Version" : version,
    }
    
    signatureBytes = privateKey.sign(
        json.dumps(resourceDict).encode(),
        ec.ECDSA(hashes.SHA256())
    )
    
    resourceDict["Signature"] = base64.b64encode(signatureBytes).decode()
    with open(f"Resource{secure_filename(ID)}Certificate.json", "w") as f:
        json.dump(resourceDict, f, indent=4)

if(not os.path.exists("MasterECCPrivateKey.pem")):
   logger.critical("No keypair exists!")
else:
    with open("MasterECCPrivateKey.pem", "rb") as f:
        privateKey = serialization.load_pem_private_key(
            f.read(),
            password=None 
        )
        
    with open("MasterECCPublicKey.pem", "rb") as f:
        publicKey = serialization.load_pem_public_key(f.read())

def CreateLogKey():
    if(os.path.exists("MasterLogPrivateKey.key")):
        print(f"Exists")
        with open("MasterLogPrivateKey.key", "rb") as f:
            privateKey = x25519.X25519PrivateKey.from_private_bytes(f.read())

        with open("MasterLogPublicKey.key", "rb") as f:
            publicKey = x25519.X25519PublicKey.from_public_bytes(f.read())
        
    else:
        privateKey = x25519.X25519PrivateKey.generate()
        publicKey = privateKey.public_key()

        # Save private key
        with open("MasterLogPrivateKey.key", "wb") as f:
            f.write(
                privateKey.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        # Save public key
        with open("MasterLogPublicKey.key", "wb") as f:
            f.write(
                publicKey.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            )
    
    return privateKey, publicKey

def DecodeLog(logPath):
    with open(logPath, "r") as f:

        lines = f.readlines()
        
        ephemeralKeyLine = lines.pop(0).strip().split(" - ")
        ephemeralPublicKey = x25519.X25519PublicKey.from_public_bytes(base64.b64decode(ephemeralKeyLine[1]))
        sharedSecret = logPrivateKey.exchange(ephemeralPublicKey)
        derivedKey = AESGCM(HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"Log Encryption"
        ).derive(sharedSecret))
        
        for line in lines:
            if(line == "\n"):
                continue
            line = line.strip().split(" - ")
            nonce = base64.b64decode(line[0])
            ciphertext = base64.b64decode(line[1])
            print(derivedKey.decrypt(nonce, ciphertext, None).decode())

def CreateClientLogin(clientID, clientPassword):
    ph = PasswordHasher()
    keyring.set_password("Decentralised-File-System", clientID, ph.hash(clientPassword))

def AttemptMasterLogin(password):
    passwordHash = keyring.get_password("Decentralised-File-System", "master")
    ph = PasswordHasher()
    ph.verify(passwordHash, password)

#Test certificate creation
"""CreateUserCertificate("John Smith", 
    "JohnSmith1", 
    "Head Engineer", 
    "ExampleB64", 
    [["Engineering LVL1", "WRITE"],["Engineering LVL2", "WRITE"],["Management LVL1", "READ"]], 
    "01/01/30", 
    "ECDSA",
    "RS3",
    "29/12/25",
    12345,
    1)

CreateResourceCertificate(
    "Management Resource",
    "ManagementResource1",
    "Example2B64",
    "ECDSA",
    "RS3",
    "29/12/25",
    "01/01/30",
    12345,
    1)

"""

logPrivateKey, logPublicKey = CreateLogKey()

#WizardInitialisation("TestMasterPassword")

#CreateClientLogin("JohnSmith1", "John123")
AttemptMasterLogin("T")

#DecodeLog("Resource1FileInfo.txt")

"""CreateUserCertificate(
    "John Smith", 
    "JohnSmith1", 
    "Head Engineer", 
    "C:\\Users\\iniga\\OneDrive\\Programming\\Gateway\\NonePublicKey.pem", 
    [["Engineering LVL1", "WRITE"],["Engineering LVL2", "WRITE"],["Management LVL1", "READ"]], 
    "01/01/30", 
    "ECDSA",
    "RS3",
    "29/12/25",
    12345,
    1)

CreateResourceCertificate(
    "Management Resource",
    "ManagementResource1",
    "C:\\Users\\iniga\\OneDrive\\Programming\\Gateway\\ResourceECCPublicKey.pem",
    "ECDSA",
    "RS3",
    "29/12/25",
    "01/01/30",
    12345,
    1)"""