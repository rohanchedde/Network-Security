import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

# Generate RSA key pair
def generate_key_pair():
    key = RSA.generate(2048)
    return key

# Generate nonce B
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

# Server code
def start_server():
    # Generate server's RSA key pair
    server_key_pair = generate_key_pair()
    private_key = server_key_pair
    public_key = server_key_pair.publickey()

    # Create a server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 2048))
    server_socket.listen(1)
    print("Server is waiting for client...")

    # Accept client connection
    client_socket, addr = server_socket.accept()
    print("Connected to client!")

    try:
        #Receive client's public key
        client_public_key_pem = client_socket.recv(4096)
        client_public_key = RSA.import_key(client_public_key_pem)
        print("Received Alice's public key.")

        #Send server's public key to client
        server_public_key_pem = public_key.export_key()
        client_socket.send(server_public_key_pem)
        print("Sent Bob's public key to Alice.")

        #Receive client's ID & Nonce (Na)
        client_id = client_socket.recv(4096).decode()
        nonce_a = client_socket.recv(4096).decode()
        print(f"Received from Alice: ID = {client_id}, Na = {nonce_a}")

        #Generate server's Nonce (Nb)
        nonce_b = generate_nonce()
        print(f"Generated Nb: {nonce_b}")

        #Encrypt response (server's ID & Na) using client's Public Key
        message = f"Bob||{nonce_a}"
        encrypted_message = encrypt_rsa(message, client_public_key)

        #Send N_B and encrypted message to client
        client_socket.send(nonce_b.encode())
        client_socket.send(encrypted_message.encode())
        print("Sent Nb and encrypted message to client.")

        #Receive client’s final encrypted response
        encrypted_response = client_socket.recv(4096).decode()
        decrypted_response = decrypt_rsa(encrypted_response, private_key)
        print(f"Decrypted Message 3: {decrypted_response}")

        #Verify Nonce B
        if nonce_b in decrypted_response:
            print("Authentication successful")
        else:
            print("Authentication failed")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()
        server_socket.close()
        print("Connection closed.")

if __name__ == "__main__":
    start_server()