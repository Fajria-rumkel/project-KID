from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from typing import List
import os
from datetime import datetime
import json
import base64
import secrets
import hashlib
from typing import Dict

# Crypto imports - PASTIKAN TIDAK ADA TYPO
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

app = FastAPI(title="Punk Records", version="1.0")

# Database
keys_db: Dict[str, str] = {}
messages_db: List[Dict] = []

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health check
@app.get("/")
def root():
    return {"message": "Punk Records API - Pythagoras B+", "docs": "/docs"}

@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.now().isoformat()}

# 1. MULTI-USER: Store public key
@app.post("/store")
def store_key(username: str, public_key: str):
    if username in keys_db:
        return {"error": "User exists", "code": 400}
    
    keys_db[username] = public_key
    
    # Save to file (multi-user storage)
    with open("users.txt", "a") as f:
        f.write(f"{username}:{public_key[:50]}...\n")
    
    return {
        "message": "User registered",
        "user": username,
        "total_users": len(keys_db),
        "timestamp": datetime.now().isoformat()
    }

# 2. INTEGRITY CHECK: Verify signature
@app.post("/verify")
def verify_sig(username: str, message: str, signature: str):
    if username not in keys_db:
        return {"error": "User not found", "code": 404}
    
    # Simulate signature verification
    try:
        # Create hash of message
        msg_hash = hashlib.sha256(message.encode()).hexdigest()
        
        # Simple check (in real use, verify with actual public key)
        if signature == msg_hash or signature == "valid_signature_demo":
            return {
                "verified": True,
                "integrity": "HIGH",
                "message": "✓ Integrity verified",
                "algorithm": "SHA256"
            }
        else:
            return {
                "verified": False,
                "integrity": "LOW",
                "message": "✗ Integrity check failed"
            }
    except Exception as e:
        return {
            "verified": False,
            "integrity": "UNKNOWN",
            "error": str(e)
        }

# 3. VARIASI CIPHER: Relay encrypted message
@app.post("/relay")
def relay_message(
    sender: str,
    receiver: str,
    message: str,
    cipher_type: str = "aes"  # aes, base64, hybrid
):
    if receiver not in keys_db:
        return {"error": "Receiver not found", "code": 404}
    
    # Choose cipher type
    if cipher_type == "aes":
        # AES-256-CBC (Symmetric)
        key = secrets.token_bytes(32)  # 256-bit
        iv = secrets.token_bytes(16)
        
        # Pad message
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(message.encode()) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded) + encryptor.finalize()
        
        result = {
            "cipher_type": "AES-256-CBC (Symmetric)",
            "ciphertext": base64.b64encode(encrypted).decode(),
            "key": base64.b64encode(key).decode(),
            "iv": base64.b64encode(iv).decode()
        }
        
    elif cipher_type == "hybrid":
        # Hybrid: ECDH key exchange + AES
        # Generate ephemeral key
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        
        # Simulate encryption
        simple_encrypted = base64.b64encode(message.encode()).decode()
        
        result = {
            "cipher_type": "ECDH+AES (Hybrid)",
            "ciphertext": simple_encrypted,
            "ephemeral_public_key": "simulated_key",
            "algorithm": "Hybrid encryption demo"
        }
        
    else:
        # Base64 only (no real encryption)
        result = {
            "cipher_type": "BASE64 (Encoding only)",
            "ciphertext": base64.b64encode(message.encode()).decode(),
            "warning": "No actual encryption applied"
        }
    
    # Store message
    msg_id = secrets.token_hex(8)
    msg_record = {
        "id": msg_id,
        "from": sender,
        "to": receiver,
        "cipher": cipher_type,
        "timestamp": datetime.now().isoformat(),
        "data": result
    }
    
    messages_db.append(msg_record)
    
    return {
        "status": "Message relayed",
        "message_id": msg_id,
        "receiver": receiver,
        "cipher_used": cipher_type,
        "encryption_details": result,
        "total_messages": len(messages_db)
    }

# Helper endpoints
@app.get("/users")
def list_users():
    return {
        "users": list(keys_db.keys()),
        "count": len(keys_db),
        "timestamp": datetime.now().isoformat()
    }

@app.get("/messages")
def get_messages():
    return {
        "messages": messages_db,
        "count": len(messages_db)
    }

# PDF endpoint (from template)
@app.post("/upload-pdf")
async def upload_pdf(file: UploadFile = File(...)):
    return {
        "message": "PDF uploaded (demo)",
        "filename": file.filename,
        "content_type": file.content_type
    }