# 500952269
# 501123581

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
import time

# Step 1: Generate RSA key pair for Alice
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Step 2: Sign the message with Alice's private key
def sign_message(private_key, message):
    signature = private_key.sign(
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Step 3: Verify the signature with Alice's public key
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print("Signature verification failed:", e)
        return False

# Step 4: Prevent replay attack by adding a timestamp
def add_timestamp(message):
    timestamp = str(int(time.time())).encode()
    return message + b"||" + timestamp

def extract_timestamp(timestamped_message):
    return timestamped_message.split(b"||")[0], timestamped_message.split(b"||")[1]

# Main program
if __name__ == "__main__":
    # Alice's key pair
    private_key, public_key = generate_key_pair()

    # Original message
    message = b"Hello Bob, this is Alice! How are you?"

    # Add timestamp to prevent replay attack
    timestamped_message = add_timestamp(message)
    print("Timestamped message:", timestamped_message)

    # Alice signs the timestamped message
    signature = sign_message(private_key, timestamped_message)
    print("Signature:", signature.hex())

    # Bob receives the message and signature
    received_message = timestamped_message
    received_signature = signature

    # Verify the signature
    is_verified = verify_signature(public_key, received_message, received_signature)
    if is_verified:
        print("Signature verified successfully!")
        # Extract the original message and timestamp
        original_message, timestamp = extract_timestamp(received_message)
        print("Original message:", original_message.decode())
        print("Timestamp:", timestamp.decode())
    else:
        print("Signature verification failed!")