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

def alice():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 5000))
    print("Alice (Client) is connected to Bob.")

    # (1) Send Message 1: Alice -> Bob
    nonce_A = os.urandom(8).hex()  # Generate random nonce NA
    message1 = {"ID": "Alice", "Nonce": nonce_A}
    client_socket.send(json.dumps(message1).encode())
    print(f"\nSent Message 1: {message1}")

    # (2) Receive Message 2: Bob -> Alice
    data = client_socket.recv(1024)
    message2 = json.loads(data.decode())
    print(f"\nReceived Message 2: {message2}")

    decrypted_msg2 = decrypt_message(bytes.fromhex(message2["Encrypted"]), KAB)
    print(f"\nDecrypted Message 2: {decrypted_msg2}")

    # (3) Send Message 3: Alice -> Bob
    msg_to_encrypt = json.dumps({"ID": "Alice", "Nonce_B": message2["Nonce_B"]})
    encrypted_msg = encrypt_message(msg_to_encrypt, KAB)

    message3 = {"Encrypted": encrypted_msg.hex()}
    client_socket.send(json.dumps(message3).encode())
    print(f"\nSent Message 3: {message3}")

    client_socket.close()

if __name__ == "__main__":
    alice()
