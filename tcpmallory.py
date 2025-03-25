import socket
from Crypto.PublicKey import RSA
import base64

# Mallory’s MITM Setup
MALLORY_HOST = '127.0.0.1'
MALLORY_PORT = 12344  # **Alice Connects Here**
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345  # **Mallory Connects to Bob**

mallory_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
mallory_server.bind((MALLORY_HOST, MALLORY_PORT))
mallory_server.listen(1)

print(f"\n[Mallory] Waiting for Alice to connect...")
client_socket, client_address = mallory_server.accept()
print(f"\n[Mallory] Alice connected from {client_address}")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.connect((SERVER_HOST, SERVER_PORT))
print("\n[Mallory] Connected to Bob.")

# Step 1: Intercept Bob's Public Key
server_public_key = server_socket.recv(1024)
client_socket.sendall(server_public_key)
print("\n[Mallory] Forwarded Bob’s Public Key to Alice.")

# Step 2: Intercept Alice’s Public Key
alice_public_key_pem = client_socket.recv(1024)
server_socket.sendall(alice_public_key_pem)
print("\n[Mallory] Forwarded Alice’s Public Key to Bob.")

# Step 3: Intercept Encrypted Session Key + Signature
data = client_socket.recv(512)
server_socket.sendall(data)
print("\n[Mallory] Intercepted encrypted session key but CAN’T DECRYPT IT.")

print("\n[Mallory] Secure session established, but I am BLIND to messages!\n")

# **Intercept Messages But Modify Them**
try:
    while True:
        # **Intercept Alice’s Encrypted Message**
        encrypted_message_from_client = client_socket.recv(1024).decode()
        if not encrypted_message_from_client:
            break

        print(f"\n[Mallory] Intercepted Encrypted Message from Alice: {encrypted_message_from_client}")
        modified_encrypted_message = input("[Mallory] Modify the encrypted message (or press Enter to forward unchanged): ")
        if modified_encrypted_message.strip() == "":
            modified_encrypted_message = encrypted_message_from_client  # Forward unchanged
        input("\n[Mallory] Press Enter to forward message to Bob...")
        server_socket.sendall(modified_encrypted_message.encode())

        # **Intercept Bob’s Encrypted Response**
        encrypted_response = server_socket.recv(1024).decode()
        if not encrypted_response:
            break

        print(f"\n[Mallory] Intercepted Encrypted Response from Bob: {encrypted_response}")
        modified_encrypted_response = input("[Mallory] Modify the encrypted response (or press Enter to forward unchanged): ")
        if modified_encrypted_response.strip() == "":
            modified_encrypted_response = encrypted_response  # Forward unchanged
        input("\n[Mallory] Press Enter to forward response to Alice...")
        client_socket.sendall(modified_encrypted_response.encode())

except Exception as e:
    print("[ERROR] Mallory encountered an error during communication:", e)

finally:
    client_socket.close()
    server_socket.close()
    mallory_server.close()
    print("\n[Mallory] MITM Attack Failed! Messages remain encrypted.")
