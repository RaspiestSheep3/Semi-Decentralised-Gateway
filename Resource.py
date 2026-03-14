#Imports
import os
import json
import socket
import base64
import logging
import sqlite3
import colorlog
import threading
from time import sleep
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timezone, timedelta, date
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec, x25519

#Constants
INCOMING_CONNECTION_HOST = "0.0.0.0"
INCOMING_CONNECTION_PORT = 12345
RESOURCE_LABEL = "Resource1"
CERT_PATH = "ResourceManagementResource1Certificate.json"
MASTER_PUBLIC_KEY_PEM = "MasterECCPublicKey.pem"
SESSION_TOKEN_EXPIRY_TIME = timedelta(minutes=30)

#Runtime variables
loadedAES = dict()
privateKey, privateKeyBytes, publicKey, publicKeyBytes = None, None, None, None
masterKey = None
logKey = None

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
with open(f"ResourceGeneral.log", "w") as f:
    f.write("") #Clearing file
generalLogHandler = logging.FileHandler(f"ResourceGeneral.log")
generalLogHandler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
generalLogHandler.setLevel(logging.DEBUG) 

#Error handler
with open(f"ResourceErrors.log", "w") as f:
    f.write("")
errorLogHandler = logging.FileHandler(f"ResourceErrors.log")
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
    with open("ResourceECCPrivateKey.pem", "wb") as f:
        f.write(pemPrivate)
        
    pemPublic = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("ResourceECCPublicKey.pem", "wb") as f:
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

def LoadLogEncryptor():
    with open("MasterLogPublicKey.key", "rb") as f:
        masterPublicKey = x25519.X25519PublicKey.from_public_bytes(f.read())
    
     # Generate ephemeral key
    ephemeralPrivateKey = x25519.X25519PrivateKey.generate()
    ephemeralPublicKey = ephemeralPrivateKey.public_key()

    # Derive shared secret
    sharedSecret = ephemeralPrivateKey.exchange(masterPublicKey)

    # Derive AES-256 key
    derivedKey = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"Log Encryption"
    ).derive(sharedSecret)
    
    with open(f"{RESOURCE_LABEL}FileInfo.txt", "w") as f:
       f.write(f"Ephemeral Public Key - {base64.b64encode(ephemeralPublicKey.public_bytes_raw()).decode()}\n")
    
    return AESGCM(derivedKey)

def AddEncryptedLog(level : str, messageToLog : str):
    message = f"{datetime.now(timezone.utc).strftime("%Y-%m-%d %H-%M-%S")} {level} : {messageToLog}".encode()
    
    nonce = os.urandom(12)
    ciphertext = logKey.encrypt(nonce, message, None)
    with open(f"{RESOURCE_LABEL}FileInfo.txt", "a") as f:
        f.write(f"{base64.b64encode(nonce).decode()} - {base64.b64encode(ciphertext).decode()}\n")
    

def Start():
    global privateKey, privateKeyBytes, publicKey, publicKeyBytes, masterKey, logKey
    #Listening for information
    
    logKey = LoadLogEncryptor()
    
    with open(MASTER_PUBLIC_KEY_PEM, "rb") as f:
        masterKey = serialization.load_pem_public_key(f.read())
    
    incomingConnectionSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    incomingConnectionSocket.bind((INCOMING_CONNECTION_HOST, INCOMING_CONNECTION_PORT))
    incomingConnectionSocket.listen(5)
    
    if(os.path.isfile(f"{RESOURCE_LABEL}ECCPrivateKey.pem") and os.path.isfile(f"{RESOURCE_LABEL}ECCPublicKey.pem")):
        with open(f"{RESOURCE_LABEL}ECCPrivateKey.pem", "rb") as f:
            privateKey = serialization.load_pem_private_key(
                f.read(),
                password=None 
            )
                
        with open(f"{RESOURCE_LABEL}ECCPublicKey.pem", "rb") as f:
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

    logger.info("WAITING FOR REQUESTS")
    while True:
        clientSocket, addr = incomingConnectionSocket.accept()
        threading.Thread(target=HandleClient, args=(clientSocket,)).start()

def HandleClient(clientSocket):
    global loadedAES
    
    receivedMessage = json.loads(clientSocket.recv(1024).rstrip(b"\0").decode())
    if(receivedMessage["Type"] == "Client-Resource Ephemeral Key Transmission"):
        privateEphemeralKey, publicEphemeralKey = CreateEphemeralECCKey()
        privateEphemeralKeyBytes = privateEphemeralKey.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        publicEphemeralKeyBytes = publicEphemeralKey.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        ephemeralKeyData = json.dumps({"Type" : "Client-Resource Ephemeral Key Transmission Response", "publicEphemeralKey" : base64.b64encode(publicEphemeralKeyBytes).decode()})
        clientSocket.send(ephemeralKeyData.encode().ljust(512, b"\0"))

        #Creating the shared secret
        clientEphemeralPublicKey = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), 
            base64.b64decode(receivedMessage["publicEphemeralKey"])
        )
        ephemeralSecret = privateEphemeralKey.exchange(ec.ECDH(), clientEphemeralPublicKey)

        #Deriving an AES key
        clientAESKey = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"Client-Resource Handshake",
        ).derive(ephemeralSecret)
        
        #Receiving the dummy attempt login
        aes = AESGCM(clientAESKey)
        
        #Receiving cert
        nonce = clientSocket.recv(12)
        clientCertInfoEncrypted = clientSocket.recv(2048).rstrip(b"\0")
        clientCertInfo = json.loads(aes.decrypt(nonce, clientCertInfoEncrypted, None).decode())
        
        #Signature test
        signature = clientCertInfo.pop("Signature")

        #Cert expiry check
        clientCertExpiryTimeSplit = clientCertInfo["Expiry Date"].split("/")
        clientCertExpiryTime = date(int("20" + clientCertExpiryTimeSplit[2]), int(clientCertExpiryTimeSplit[1]), int(clientCertExpiryTimeSplit[0]))
        if(clientCertExpiryTime < date.today()):
            AddEncryptedLog("WARNING", f"Client {clientCertInfo["ID"]} is signing in with an expired cert")
            return

        try:
            masterKey.verify(
                base64.b64decode(signature),
                json.dumps(clientCertInfo).encode(),
                ec.ECDSA(hashes.SHA256())   
            )
            logger.debug("Signature valid")
        except Exception as e:
            logger.error(f"Invalid signature : {e}")
            return

        #Sending our cert
        returnNonce = IncrementNonce(nonce, 1)
        
        with open(CERT_PATH, "r") as fileHandle:
            certInfo = json.loads(fileHandle.read())

        #Transmission of cert
        resourceCertInfoEncrypted = aes.encrypt(returnNonce, json.dumps(certInfo).encode(), None)
        
        clientSocket.send(resourceCertInfoEncrypted.ljust(2048, b"\0"))
        
        #Sending a session token 
        #My goal is to minimise the size of this for effiency 
        #TODO : Check that they are loaded in on correct time before issuing tokens
        
        sessionToken = {
            "ID" : clientCertInfo["ID"],
            "Issuer" : certInfo["ID"],
            "Permissions" : clientCertInfo["Permissions"],
            "Expiry Time" : int((datetime.now(timezone.utc) + SESSION_TOKEN_EXPIRY_TIME).timestamp())
        }
        
        #Signing the token
        signatureBytes = privateKey.sign(
            json.dumps(sessionToken).encode(),
            ec.ECDSA(hashes.SHA256())
        )
        
        sessionToken["Signature"] = base64.b64encode(signatureBytes).decode()
        
        #Returning back the session token 
        sessionTokenEncrypted = aes.encrypt(IncrementNonce(returnNonce, 1), json.dumps(sessionToken).encode(), None)
        clientSocket.send(sessionTokenEncrypted.ljust(1024, b"\0"))
        
        logger.debug(f"session token : {sessionToken}")
        
        loadedAES[clientCertInfo["ID"]] = aes
    elif(receivedMessage["Type"] == "File Request"):
        requestNonce = base64.b64decode(receivedMessage["Nonce"])
        aes = loadedAES[receivedMessage["ID"]]
        userToken = json.loads(aes.decrypt(requestNonce, base64.b64decode(receivedMessage["Token"]), None).decode())
        fileID = aes.decrypt(IncrementNonce(requestNonce, 1), base64.b64decode(receivedMessage["FileID"]), None).decode()

        #Checking the signature is intact
        signatureRaw = base64.b64decode(userToken["Signature"])
        
        userToken.pop("Signature")
        
        try:
            publicKey.verify(
                signatureRaw,
                json.dumps(userToken).encode(),
                ec.ECDSA(hashes.SHA256())
            )
        
            logger.debug("Signature correct")
        
        except InvalidSignature:
            logger.warning("Signature invalid")
            return
        
        #Checking the timestamp on the token
        if(int(datetime.now(timezone.utc).timestamp()) > userToken["Expiry Time"]):
            logger.warning(f"Time expired on token")
            return
        
        #Checking if the user has correct level permissions for the file they are requesting
        conn = sqlite3.connect(f"{RESOURCE_LABEL}.db")
        cursor = conn.cursor()
        cursor.execute("""SELECT * FROM resourceFiles WHERE fileLabel = ?""", (fileID,))
        row = cursor.fetchone()
        
        status = "Not Allowed"
        metadata = None
        if(row != None):
            acceptedLevels = row[2].split(", ")
            logger.debug(f"Levels : {acceptedLevels}, {userToken["Permissions"]}")
            for level in (userToken["Permissions"]):
                if(level in acceptedLevels):
                    status = "Allowed"
                    break
        
            if(status == "Allowed"):
                metadata = {"Size" : os.path.getsize(row[1])}
        else:
            logger.debug(f"row : {row}, levels : {acceptedLevels}")
                
        #TODO : Send a response with status and metadata if relevant
        requestResponse = {"Status" : status, "Metadata" : metadata}
        requestResponseEncrypted = aes.encrypt(IncrementNonce(requestNonce, 2), json.dumps(requestResponse).encode(), None)
        clientSocket.send(requestResponseEncrypted.ljust(1024, b"\0"))
        
        #Sending the data
        if(status == "Allowed"):
            filePath = row[1]
            fileSize = os.path.getsize(filePath)
            bytesSent = 0
            nonceCounter = 3
            
            logger.debug(f"File path : {filePath}")
            
            with open(filePath, "rb") as f:
                while(bytesSent < fileSize):
                    decryptedBlock = f.read(min(65536, fileSize - bytesSent))
                    encryptedBlock = aes.encrypt(IncrementNonce(requestNonce, nonceCounter), decryptedBlock, None)
                    print(f"Encrypt len : {len(encryptedBlock)}")
                    clientSocket.send(encryptedBlock)
                    bytesSent += min(65536, fileSize - bytesSent)
                    nonceCounter += 1   
        
            logger.info(f"All blocks sent")
            AddEncryptedLog("INFO", f"SUCCESS : {userToken["ID"]} requested {fileID} - successful delivery")
        else:
            AddEncryptedLog("INFO", f"FAILURE : {userToken["ID"]} requested {fileID} - insufficient permissions")
    elif(receivedMessage["Type"] == "File Deletion Request"):
        requestNonce = base64.b64decode(receivedMessage["Nonce"])
        aes = loadedAES[receivedMessage["ID"]]
        userToken = json.loads(aes.decrypt(requestNonce, base64.b64decode(receivedMessage["Token"]), None).decode())
        fileID = aes.decrypt(IncrementNonce(requestNonce, 1), base64.b64decode(receivedMessage["FileID"]), None).decode()

        #Checking the signature is intact
        signatureRaw = base64.b64decode(userToken["Signature"])
        
        userToken.pop("Signature")
        
        try:
            publicKey.verify(
                signatureRaw,
                json.dumps(userToken).encode(),
                ec.ECDSA(hashes.SHA256())
            )
        
            logger.debug("Signature correct")
        
        except InvalidSignature:
            logger.warning("Signature invalid")
            return
        
        #Checking the timestamp on the token
        if(int(datetime.now(timezone.utc).timestamp()) > userToken["Expiry Time"]):
            logger.warning(f"Time expired on token")
            return
        
        #Checking if the user has correct level permissions for the file they are requesting
        conn = sqlite3.connect(f"{RESOURCE_LABEL}.db")
        cursor = conn.cursor()
        cursor.execute("""SELECT * FROM resourceFiles WHERE fileLabel = ?""", (fileID,))
        row = cursor.fetchone()
        
        status = "Not Allowed"
        metadata = None
        if(row != None):
            acceptedLevels = row[2].split(", ")
            logger.debug(f"Levels : {acceptedLevels}, {userToken["Permissions"]}")
            for level in (userToken["Permissions"]):
                if(level in acceptedLevels and userToken["Permissions"][level] == "WRITE"):
                    status = "Allowed"
                    break
        
            if(status == "Allowed"):
                metadata = {}
        else:
            logger.warning(f"row : {row}, levels : {userToken["Permissions"]}")
                
        requestResponse = {"Status" : status, "Metadata" : metadata}
        requestResponseEncrypted = aes.encrypt(IncrementNonce(requestNonce, 2), json.dumps(requestResponse).encode(), None)
        clientSocket.send(requestResponseEncrypted.ljust(1024, b"\0"))
        if(status != "Allowed"):
            AddEncryptedLog("INFO", f"FAILURE : {userToken["ID"]} requested deletion of {fileID} - insufficient permissions")
            return
        
        #Deleting the file off the system
        cursor.execute("""DELETE FROM resourceFiles WHERE fileLabel = ?""", (fileID,))
        conn.commit()
        os.remove(row[1])
        AddEncryptedLog("INFO", f"SUCESS : {userToken["ID"]} requested deletion of {fileID}")
        
    elif(receivedMessage["Type"] == "File Upload Request"):
        requestNonce = base64.b64decode(receivedMessage["Nonce"])
        aes = loadedAES[receivedMessage["ID"]]
        userToken = json.loads(aes.decrypt(requestNonce, base64.b64decode(receivedMessage["Token"]), None).decode())
        fileID = aes.decrypt(IncrementNonce(requestNonce, 1), base64.b64decode(receivedMessage["FileID"]), None).decode()

        #Checking the signature is intact
        signatureRaw = base64.b64decode(userToken["Signature"])
        
        userToken.pop("Signature")
        
        try:
            publicKey.verify(
                signatureRaw,
                json.dumps(userToken).encode(),
                ec.ECDSA(hashes.SHA256())
            )
        
            logger.debug("Signature correct")
        
        except InvalidSignature:
            logger.warning("Signature invalid")
            return
        
        #Checking the timestamp on the token
        if(int(datetime.now(timezone.utc).timestamp()) > userToken["Expiry Time"]):
            logger.warning(f"Time expired on token")
            return
        
        #Checking if the user has correct level permissions for the file they are requesting
        conn = sqlite3.connect(f"{RESOURCE_LABEL}.db")
        cursor = conn.cursor()
        cursor.execute("""SELECT * FROM resourceFiles WHERE fileLabel = ?""", (fileID,))
        row = cursor.fetchone()
        
        status = "Not Allowed"
        metadata = None
        if(row != None):
            acceptedLevels = row[2].split(", ")
            logger.debug(f"Levels : {acceptedLevels}, {userToken["Permissions"]}")
            for level in (userToken["Permissions"]):
                if(level in acceptedLevels and userToken["Permissions"][level] == "WRITE"):
                    status = "Allowed"
                    break
        
            if(status == "Allowed"):
                metadata = {}
        else:
            logger.warning(f"row : {row}, levels : {userToken["Permissions"]}")
                
        requestResponse = {"Status" : status, "Metadata" : metadata}
        requestResponseEncrypted = aes.encrypt(IncrementNonce(requestNonce, 3), json.dumps(requestResponse).encode(), None)
        clientSocket.send(requestResponseEncrypted.ljust(1024, b"\0"))
        if(status != "Allowed"):
            AddEncryptedLog("INFO", f"FAILURE : {userToken["ID"]} requested upload of {fileID} - insufficient permissions")
            return
        
        fileSize = int.from_bytes(aes.decrypt(IncrementNonce(requestNonce, 2), base64.b64decode(receivedMessage["File Size"]), None), byteorder="big")
        bytesToReceive = fileSize
        logger.debug(f"File Size : {fileSize}")
        
        sleep(0.5)
        
        incrementCounter = 4
        with open(row[1], "wb") as f:
            while(bytesToReceive > 0):
                encryptedBlock = clientSocket.recv(min(bytesToReceive + 16, 65536 + 16))
                logger.debug(f"Length : {len(encryptedBlock)}")
                decryptedBlock = aes.decrypt(IncrementNonce(requestNonce, incrementCounter), encryptedBlock, None)
                f.write(decryptedBlock)
                bytesToReceive -= len(decryptedBlock)
                incrementCounter += 1
        
        logger.info(f"All blocks received - now closing")
        AddEncryptedLog("INFO", f"SUCESS : {userToken["ID"]} requested upload of {fileID}")
        
    #Closing the socket
    clientSocket.shutdown(socket.SHUT_RDWR)
    clientSocket.close()
    
    logger.debug(f"Socket closed")

def CreateEphemeralECCKey():
    privateEphemeralKey = ec.generate_private_key(ec.SECP256R1())
    publicEphemeralKey = privateEphemeralKey.public_key()
    
    return privateEphemeralKey, publicEphemeralKey

def AssignFilesToSQL(acceptedLevels : list, filePath : str = None, folderPath : str = None):
    #This function can be called to bulk add files in a folder to the SQL   
    acceptedLevels = "|".join(acceptedLevels)
    
    conn = sqlite3.connect(f"{RESOURCE_LABEL}.db")
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS resourceFiles (
      fileLabel TEXT PRIMARY KEY,
      filePath TEXT NOT NULL UNIQUE,
      acceptedLevels TEXT NOT NULL  
    ) """)
    conn.commit()
    
    if(filePath):
        #Solo insert
        fileName = os.path.basename(filePath)
        cursor.execute("""
        INSERT INTO resourceFiles (
            fileLabel, filePath, acceptedLevels
        ) VALUES (?,?,?)
        """, (fileName, filePath, acceptedLevels))
        conn.commit()
    
    else:
        #Bulk insert
        rows = []
        
        filePaths = os.listdir(folderPath)
        for filePath in filePaths:
            fullPath = os.path.join(folderPath, filePath)
            if(os.path.isdir(fullPath)):
                AssignFilesToSQL(acceptedLevels.split("|"), None, fullPath)
            else:
                rows.append((filePath, fullPath,acceptedLevels))
        
        cursor.executemany("""
        INSERT INTO resourceFiles (
            fileLabel, filePath, acceptedLevels
        ) VALUES (?,?,?)
        """, rows)
        conn.commit()
    
    conn.close()

#AssignFilesToSQL(["Engineering LVL1, Engineering LVL2"], None, r"C:\Users\iniga\OneDrive\Programming\Testing")    
Start()
#AssignFilesToSQL(["Engineering LVL1"], "C:\\Users\\iniga\\OneDrive\\Programming\\StunTest.py")