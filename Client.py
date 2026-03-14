#Imports
import os
import json
import socket
import base64
import logging
import keyring
import colorlog
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#Constants
INCOMING_CONNECTION_HOST = "0.0.0.0"
INCOMING_CONNECTION_PORT = 12346
SERVER_CONNECTION_PORT = 12345
MASTER_PUBLIC_KEY_PEM = "MasterECCPublicKey.pem"

#Runtime variables
userID = None
certPath = None

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
with open(f"ClientGeneral.log", "w") as f:
    f.write("") #Clearing file
generalLogHandler = logging.FileHandler(f"ClientGeneral.log")
generalLogHandler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
generalLogHandler.setLevel(logging.DEBUG) 

#Error handler
with open(f"ClientErrors.log", "w") as f:
    f.write("")
errorLogHandler = logging.FileHandler(f"ClientErrors.log")
errorLogHandler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
errorLogHandler.setLevel(logging.ERROR)  

#Creating logger
logger = logging.getLogger("colorLogger")
logger.setLevel(logging.DEBUG)

# Adding handlers to the logger
logger.addHandler(consoleLogHandler) 
logger.addHandler(generalLogHandler)    
logger.addHandler(errorLogHandler) 

def IncrementNonce(oldNonce : bytes, increment : int):
    try:
        oldNonceInt = int.from_bytes(oldNonce, byteorder="big")
        oldNonceInt = (oldNonceInt + increment) % (1 << 96) #Wraparound
        nonce = oldNonceInt.to_bytes(12, byteorder="big")
        return nonce
    except Exception as e:
        logger.error(f"Error {e} in IncrementNonce", exc_info=True)

#Keypair generation
def CreateECCKeypair():
    global privateKey, publicKey, privateKeyBytes, publicKeyBytes
    
    privateKey = ec.generate_private_key(ec.SECP256R1())
    publicKey = privateKey.public_key()

    pemPrivate = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  
    )
    with open(f"{userID}PrivateKey.pem", "wb") as f:
        f.write(pemPrivate)
        
    pemPublic = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"{userID}PublicKey.pem", "wb") as f:
        f.write(pemPublic)
        
    privateKeyBytes = privateKey.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
    publicKeyBytes = publicKey.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    ) 

#Setting up a connection to the Resource

def ConnectToResource(privateEphemeralKey, publicEphemeralKeyBytes): 
    global userID
    resourceSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    resourceSocket.connect(("127.0.0.1", SERVER_CONNECTION_PORT))
    
    ephemeralKeyData = json.dumps({"Type" : "Client-Resource Ephemeral Key Transmission", "publicEphemeralKey" : base64.b64encode(publicEphemeralKeyBytes).decode()})
    resourceSocket.send(ephemeralKeyData.encode().ljust(1024, b"\0"))
    receivedMessage = json.loads(resourceSocket.recv(512).rstrip(b"\0").decode())
    logger.debug(receivedMessage)

    #Creating the shared secret
    serverEphemeralPublicKey = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), 
        base64.b64decode(receivedMessage["publicEphemeralKey"])
    )
    ephemeralSecret = privateEphemeralKey.exchange(ec.ECDH(), serverEphemeralPublicKey)

    #Deriving an AES key
    serverAESKey = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"Client-Resource Handshake",
    ).derive(ephemeralSecret)

    aes = AESGCM(serverAESKey) 
    
    #Loading in the cert info 
    with open(certPath, "r") as fileHandle:
        certInfo = json.loads(fileHandle.read())
    
    userID = certInfo["ID"]

    #Transmission of cert
    nonce = os.urandom(12)
    clientCertInfoEncrypted = aes.encrypt(nonce, json.dumps(certInfo).encode(), None)
    
    resourceSocket.send(nonce)
    resourceSocket.send(clientCertInfoEncrypted.ljust(2048, b"\0"))
           
    #Receiving cert
    resourceCertInfoEncrypted = resourceSocket.recv(2048).rstrip(b"\0")
    resourceCertInfo = json.loads(aes.decrypt(IncrementNonce(nonce, 1), resourceCertInfoEncrypted, None).decode())
    
    #Signature test
    signature = resourceCertInfo.pop("Signature")
    
    with open(MASTER_PUBLIC_KEY_PEM, "rb") as f:
        masterKey = serialization.load_pem_public_key(f.read())

    try:
        masterKey.verify(
            base64.b64decode(signature),
            json.dumps(resourceCertInfo).encode(),
            ec.ECDSA(hashes.SHA256())   
        )
        logger.debug("Signature valid")
    except Exception as e:
        logger.error(f"Invalid signature : {e}")
        return
        
    #Getting our session token  
    sessionTokenEncrypted = resourceSocket.recv(1024).rstrip(b"\0")
    sessionToken = json.loads(aes.decrypt(IncrementNonce(nonce, 2), sessionTokenEncrypted, None).decode())   
    
    print(f"sessionToken : {sessionToken}")
    
    #Closing the socket
    resourceSocket.shutdown(socket.SHUT_RDWR)
    resourceSocket.close()
    
    return aes, sessionToken

def RequestFileFromResource(aes, sessionToken, fileID):
    #Defining the connection
    resourceSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    resourceSocket.connect(("127.0.0.1", SERVER_CONNECTION_PORT))
    
    #Filing the request
    requestNonce = os.urandom(12)
    request = {"Nonce" : base64.b64encode(requestNonce).decode(), 
               "ID" : userID,
               "Type" : "File Request", 
               "Token" : base64.b64encode(aes.encrypt(requestNonce, json.dumps(sessionToken).encode(), None)).decode(), 
               "FileID" : base64.b64encode(aes.encrypt(IncrementNonce(requestNonce, 1), fileID.encode(), None)).decode()}

    resourceSocket.send(json.dumps(request).encode().ljust(1024, b"\0"))
    
    #Getting the return metadata
    resourceReturnMetadataEncrypted = resourceSocket.recv(1024).rstrip(b"\0")
    resourceReturnMetadata = json.loads(aes.decrypt(IncrementNonce(requestNonce, 2), resourceReturnMetadataEncrypted, None).decode())
    logger.info(f"Resource Return Metadata : {resourceReturnMetadata}")
    if(resourceReturnMetadata["Status"] != "Allowed"):
        logger.warning(f"File access denied - returning")
        return
    
    fileSize = resourceReturnMetadata["Metadata"]["Size"]
    bytesToReceive = fileSize
    incrementCounter = 3
    with open(fileID, "wb") as f:
        while(bytesToReceive > 0):
            encryptedBlock = resourceSocket.recv(min(bytesToReceive + 16, 65536 + 16))
            logger.debug(f"Length : {len(encryptedBlock)}")
            decryptedBlock = aes.decrypt(IncrementNonce(requestNonce, incrementCounter), encryptedBlock, None)
            f.write(decryptedBlock)
            bytesToReceive -= len(decryptedBlock)
            incrementCounter += 1
    
    logger.info(f"All blocks received - now closing")
    resourceSocket.shutdown(socket.SHUT_RDWR)
    resourceSocket.close() 

def UploadFileToResource(aes, sessionToken, filePath):
    resourceSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    resourceSocket.connect(("127.0.0.1", SERVER_CONNECTION_PORT))
    
    fileID = os.path.basename(filePath)
    fileSize = os.path.getsize(filePath)
    #Filing the request
    requestNonce = os.urandom(12)
    request = {"Nonce" : base64.b64encode(requestNonce).decode(), 
                "ID" : userID,
                "Type" : "File Upload Request", 
                "Token" : base64.b64encode(aes.encrypt(requestNonce, json.dumps(sessionToken).encode(), None)).decode(), 
                "FileID" : base64.b64encode(aes.encrypt(IncrementNonce(requestNonce, 1), fileID.encode(), None)).decode(),
                "File Size" : base64.b64encode(aes.encrypt(IncrementNonce(requestNonce, 2), fileSize.to_bytes(64, "big"), None)).decode()}

    resourceSocket.send(json.dumps(request).encode().ljust(1024, b"\0"))
    #Getting the return metadata
    resourceReturnMetadataEncrypted = resourceSocket.recv(1024).rstrip(b"\0")
    resourceReturnMetadata = json.loads(aes.decrypt(IncrementNonce(requestNonce, 3), resourceReturnMetadataEncrypted, None).decode())
    logger.info(f"Resource Return Metadata : {resourceReturnMetadata}")
    if(resourceReturnMetadata["Status"] != "Allowed"):
        logger.warning(f"File upload denied - returning")
        return

    bytesSent = 0
    nonceCounter = 4
    
    logger.debug(f"File path : {filePath}")
    
    print(f"Filesize : {fileSize}, {os.path.getsize(filePath)}, bS : {bytesSent}")
    
    with open(filePath, "rb") as f:
        while(bytesSent < fileSize):
            decryptedBlock = f.read(min(65536, fileSize - bytesSent))
            encryptedBlock = aes.encrypt(IncrementNonce(requestNonce, nonceCounter), decryptedBlock, None)
            print(f"Encrypt len : {len(encryptedBlock)}, decrypt len : {len(decryptedBlock)}")
            resourceSocket.send(encryptedBlock)
            bytesSent += min(65536, fileSize - bytesSent)
            nonceCounter += 1   
        
def DeleteFileFromResource(aes, sessionToken, fileID):
    #Defining the connection
    resourceSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    resourceSocket.connect(("127.0.0.1", SERVER_CONNECTION_PORT))
    
    #Filing the request
    requestNonce = os.urandom(12)
    request = {"Nonce" : base64.b64encode(requestNonce).decode(), 
               "ID" : userID,
               "Type" : "File Deletion Request", 
               "Token" : base64.b64encode(aes.encrypt(requestNonce, json.dumps(sessionToken).encode(), None)).decode(), 
               "FileID" : base64.b64encode(aes.encrypt(IncrementNonce(requestNonce, 1), fileID.encode(), None)).decode()}

    resourceSocket.send(json.dumps(request).encode().ljust(1024, b"\0"))
    
    #Getting the return metadata
    resourceReturnMetadataEncrypted = resourceSocket.recv(1024).rstrip(b"\0")
    resourceReturnMetadata = json.loads(aes.decrypt(IncrementNonce(requestNonce, 2), resourceReturnMetadataEncrypted, None).decode())
    logger.info(f"Resource Return Metadata : {resourceReturnMetadata}")
    if(resourceReturnMetadata["Status"] != "Allowed"):
        logger.warning(f"File deletion denied - returning")
    
    resourceSocket.shutdown(socket.SHUT_RDWR)
    resourceSocket.close() 

#Ephemeral Key Creation
def CreateEphemeralECCKeypair():
    privateEphemeralKey = ec.generate_private_key(ec.SECP256R1())
    publicEphemeralKey = privateEphemeralKey.public_key()
    
    privateEphemeralKeyBytes = privateEphemeralKey.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
    )
    
    publicEphemeralKeyBytes = publicEphemeralKey.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    return privateEphemeralKey, publicEphemeralKey, privateEphemeralKeyBytes, publicEphemeralKeyBytes

def LoginUser(username, password):
    global certPath
    passwordKeyring = keyring.get_password("Decentralised-File-System", username)
    ph = PasswordHasher()
    try:
        (ph.verify(passwordKeyring, password))
    except:
        logger.warning("Login Failed")
        return
    
    certPath = os.path.join(os.getcwd(), f"User{username}Certificate.json")

resourceSocket, aes, privateKey, publicKey, privateKeyBytes, publicKeyBytes = None, None, None, None, None, None

def Start():
    global resourceSocket, aes, privateKey, publicKey, privateKeyBytes, publicKeyBytes
    
    #ECC setup
    if(os.path.exists(f"{userID}PrivateKey.pem") and os.path.exists(f"{userID}PublicKey.pem")):
        with open(f"{userID}PrivateKey.pem", "rb") as f:
            privateKey = serialization.load_pem_private_key(
                f.read(),
                password=None 
            )
                
        with open(f"{userID}PublicKey.pem", "rb") as f:
            publicKey = serialization.load_pem_public_key(f.read())
        
        privateKeyBytes = privateKey.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        publicKeyBytes = publicKey.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        ) 
    else:
        CreateECCKeypair()
    
    #Resrouce ephmeral pair
    privateEphemeralKey, _, _, publicEphemeralKeyBytes = CreateEphemeralECCKeypair()
    aes, sessionToken = ConnectToResource(privateEphemeralKey, publicEphemeralKeyBytes)
    #RequestFileFromResource(aes, sessionToken, "StunTest.py")
    #UploadFileToResource(aes, sessionToken, "C:\\Users\\iniga\\OneDrive\\Programming\\StunTest.py")
    DeleteFileFromResource(aes, sessionToken, "StunTest.py")

LoginUser("JohnSmith1", "John123")
Start()
