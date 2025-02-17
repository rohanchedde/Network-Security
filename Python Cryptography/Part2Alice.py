import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

# Generate RSA key pair
def generate_key_pair():
    key = RSA.generate(2048)
    return key

# Generate nonce A
def generate_nonce():
    return str(get_random_bytes(4).hex())

# Encrypt data using RSA public key
def encrypt_rsa(data, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher.encrypt(data.encode())
    return base64.b64encode(encrypted_data).decode()

# Decrypt data using RSA private key
def decrypt_rsa(encrypted_data, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data))
    return decrypted_data.decode()

# Client code
def connect_to_server():
    # Generate client's RSA key pair
    client_key_pair = generate_key_pair()
    private_key = client_key_pair
    public_key = client_key_pair.publickey()

    # Create a client socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 2048))
    print("Connected to Bob!")

    try:
        #Send client's public key to server
        client_public_key_pem = public_key.export_key()
        client_socket.send(client_public_key_pem)
        print("Sent Bob's public key to server.")

        #Receive server's public key
        server_public_key_pem = client_socket.recv(4096)
        server_public_key = RSA.import_key(server_public_key_pem)
        print("Received Bob's public key.")

        #Send client's ID & Nonce (Na) to server
        client_id = "Alice"
        nonce_a = generate_nonce()
        print(f"Sending to server: ID = {client_id}, NA = {nonce_a}")

        client_socket.send(client_id.encode())
        client_socket.send(nonce_a.encode())

        #Receive server’s Nonce and encrypted response
        nonce_b = client_socket.recv(4096).decode()
        encrypted_response = client_socket.recv(4096).decode()
        print(f"Received from Bob: NB = {nonce_b}")
        print(f"Encrypted Message 2: {encrypted_response}")

        #Decrypt server's response
        decrypted_message = decrypt_rsa(encrypted_response, private_key)
        print(f"Decrypted Message 2: {decrypted_message}")

        # Step 6: Verify Nonce A
        if nonce_a not in decrypted_message:
            print("Authentication failed at step 2!")
            client_socket.close()
            return

        # Step 7: Encrypt response (client's ID & Nb) using server's Public Key
        response_message = f"client||{nonce_b}"
        encrypted_response_message = encrypt_rsa(response_message, server_public_key)
        client_socket.send(encrypted_response_message.encode())
        print("Sent final encrypted message to server.")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()
        print("Connection closed.")

if __name__ == "__main__":
    connect_to_server()