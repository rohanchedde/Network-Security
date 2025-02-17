# 500952269
# 501123581

import socket
import os
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Shared Symmetric Key (KAB)
KAB = b"thisiskey1234567"  # 16 bytes for AES-128

def encrypt_message(message, key):
    """ Encrypt message using AES-CBC """
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_msg = cipher.encrypt(pad(message.encode(), AES.block_size))
    return iv + encrypted_msg  # Send IV along with encrypted message

def decrypt_message(encrypted_message, key):
    """ Decrypt message using AES-CBC """
    iv = encrypted_message[:16]
    encrypted_msg = encrypted_message[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_msg), AES.block_size).decode()

def bob():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 5000))
    server_socket.listen(1)
    print("Bob (Server) is listening...")

    conn, addr = server_socket.accept()
    print(f"Connection established with Alice ({addr})")

    # (1) Receive Message 1: Alice -> Bob
    data = conn.recv(1024)
    message1 = json.loads(data.decode())
    alice_id = message1["ID"]
    nonce_A = message1["Nonce"]
    print(f"\nReceived Message 1: {message1}")

    # (2) Send Message 2: Bob -> Alice
    nonce_B = os.urandom(8).hex()  # Generate random nonce NB
    msg_to_encrypt = json.dumps({"ID": "Bob", "Nonce_A": nonce_A})
    encrypted_msg = encrypt_message(msg_to_encrypt, KAB)

    message2 = {"Nonce_B": nonce_B, "Encrypted": encrypted_msg.hex()}
    conn.send(json.dumps(message2).encode())
    print(f"\nSent Message 2: {message2}")

    # (3) Receive Message 3: Alice -> Bob
    data = conn.recv(1024)
    message3 = json.loads(data.decode())
    print(f"\nReceived Message 3: {message3}")

    decrypted_msg3 = decrypt_message(bytes.fromhex(message3["Encrypted"]), KAB)
    print(f"\nDecrypted Message 3: {decrypted_msg3}")

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    bob()
