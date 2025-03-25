import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

# Generate Alice's RSA Key Pair
alice_key = RSA.generate(2048)
alice_private_key = alice_key.export_key()
alice_public_key = alice_key.publickey().export_key()

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

# **Alice Connects to Mallory Instead of Bob**
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
mallory_address = ('127.0.0.1', 12344)  # **Mallory's MITM Port**
client_socket.connect(mallory_address)

print("\n[Alice] Connecting to Bob (really Mallory)...")
input("\n[Alice] Press Enter to receive Bob’s public key...")

# Step 1: Receive Bob's Public Key (from Mallory, thinking it's Bob)
bob_public_key_pem = client_socket.recv(1024)
bob_public_key = RSA.import_key(bob_public_key_pem)
print("\n[Alice] Received Bob's Public Key.")

input("\n[Alice] Press Enter to send my public key to Bob...")
client_socket.sendall(alice_public_key)
print("\n[Alice] Sent my Public Key to Bob.")

# Step 3: Generate AES Session Key
session_key = b'16_byte_secret_k'  # **Ensure exactly 16 bytes**
print(f"\n[Alice] Generated AES session key: {session_key.hex()}")

input("\n[Alice] Press Enter to sign and encrypt the session key...")

# Step 4: Sign Session Key
hash_obj = SHA256.new(session_key)
signature = pkcs1_15.new(RSA.import_key(alice_private_key)).sign(hash_obj)
print("\n[Alice] Signed the session key.")

# Step 5: Encrypt Session Key with Bob’s Public Key
cipher_rsa = PKCS1_OAEP.new(bob_public_key)
encrypted_session_key = cipher_rsa.encrypt(session_key)

# Step 6: Send Encrypted Session Key + Signature to Bob
client_socket.sendall(encrypted_session_key + signature)
print("\n[Alice] Sent encrypted session key and signature to Bob.")

input("\n[Alice] Press Enter to start secure communication...")
print("\n[Alice] Secure session established. Messages are now encrypted.")

# Secure Communication
try:
    while True:
        message = input("\n[Alice] Enter a message (or '.' to quit): ")
        if message == ".":
            break
        
        encrypted_message = AES_encrypt(message, session_key)
        client_socket.sendall(encrypted_message.encode())

        encrypted_ack = client_socket.recv(1024).decode()
        decrypted_ack = AES_decrypt(encrypted_ack, session_key)
        print("\n[Alice] Received response:", decrypted_ack)

except Exception as e:
    print("[ERROR] Alice encountered an error:", e)

finally:
    client_socket.close()
    print("\n[Alice] Disconnected.")
