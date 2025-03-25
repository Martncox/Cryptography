import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

# Generate Bob's RSA Key Pair
bob_key = RSA.generate(2048)
bob_private_key = bob_key.export_key()
bob_public_key = bob_key.publickey().export_key()

# AES Helper Functions
def AES_encrypt(text, key):
    cipher = AES.new(key, AES.MODE_ECB)
    pad_length = 16 - (len(text) % 16)
    text += chr(pad_length) * pad_length
    encrypted_bytes = cipher.encrypt(text.encode())
    return base64.b64encode(encrypted_bytes).decode()

def AES_decrypt(encrypted_text, key):
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_bytes = cipher.decrypt(base64.b64decode(encrypted_text))
        text = decrypted_bytes.decode()
        pad_length = ord(text[-1])
        return text[:-pad_length]
    except Exception as e:
        return "[ERROR] Decryption failed! Message may have been tampered with."

# Server Setup
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('127.0.0.1', 12345)
server_socket.bind(server_address)
server_socket.listen(5)

print("\n[Bob] Waiting for a connection...")
client_socket, client_address = server_socket.accept()
print(f"\n[Bob] Connected to Alice (or Mallory) from {client_address}")

input("\n[Bob] Press Enter to send my RSA Public Key to Alice...")
client_socket.sendall(bob_public_key)
print("\n[Bob] Sent my Public Key to Alice.")

input("\n[Bob] Press Enter to receive Alice’s public key...")
alice_public_key_pem = client_socket.recv(1024)
alice_public_key = RSA.import_key(alice_public_key_pem)
print("\n[Bob] Received Alice's Public Key.")

# Step 3: Receive and Decrypt AES Session Key + Signature
input("\n[Bob] Press Enter to receive encrypted session key + signature...")
data = client_socket.recv(512)  # 256 bytes for encrypted session key + 256 bytes for signature
encrypted_session_key = data[:256]
signature = data[256:]

# Step 4: Decrypt AES Session Key
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(bob_private_key))
session_key = cipher_rsa.decrypt(encrypted_session_key)

# **Ensure AES Key is Exactly 16 Bytes**
session_key = session_key[:16]
print(f"\n[Bob] Successfully decrypted the AES session key: {session_key.hex()}")

# Step 5: Verify Digital Signature
input("\n[Bob] Press Enter to verify Alice’s signature...")
hash_obj = SHA256.new(session_key)
try:
    pkcs1_15.new(alice_public_key).verify(hash_obj, signature)
    print("\n[Bob] Signature verification **SUCCESSFUL**! The session key is authentic.")
except (ValueError, TypeError):
    print("\n[Bob] Signature verification **FAILED**! Connection aborted.")
    client_socket.close()
    exit()

input("\n[Bob] Press Enter to start encrypted communication...")
print("\n[Bob] Secure session established. Messages are now encrypted.")

# Secure Communication
try:
    while True:
        encrypted_message = client_socket.recv(1024).decode()
        if not encrypted_message:
            break
        
        decrypted_message = AES_decrypt(encrypted_message, session_key)
        print(f"\n[Bob] Received Encrypted Message: {encrypted_message}")
        print(f"[Bob] Decrypted Message from Alice: {decrypted_message}")

        response = input("\n[Bob] Type your response: ")
        encrypted_response = AES_encrypt(response, session_key)
        client_socket.sendall(encrypted_response.encode())

except Exception as e:
    print("[ERROR] Bob encountered an error:", e)

finally:
    client_socket.close()
    print("\n[Bob] Connection closed.")
