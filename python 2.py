import random
import string
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.exceptions import InvalidKey

def generate_key():
    """Generate a key and save it to a file."""
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)
    return key

def load_key():
    """Load the key from the file."""
    try:
        with open("key.key", "rb") as key_file:
            key = key_file.read()
        return key
    except FileNotFoundError:
        print("Key file not found. Generating a new key...")
        key = generate_key()
        return key

def encrypt_message(message):
    """Encrypt a message using the key."""
    try:
        # Convert the message to a bytes object
        message_bytes = message.encode()
        key = load_key()
        f = Fernet(key)
        encrypted_message = f.encrypt(message_bytes)
        return encrypted_message
    except InvalidKey as e:
        print("Error: Invalid key. {}".format(e))
        return None

def decrypt_message(encrypted_message):
    """Decrypt a message using the key."""
    try:
        # Read the key from the file
        key = load_key()
        # Create a Fernet object with the key
        f = Fernet(key)
        # Decrypt the message
        decrypted_message = f.decrypt(encrypted_message)
        return decrypted_message.decode()
    except InvalidToken as e:
        print("Error: Invalid token. {}".format(e))
        return None

def custom_encode(bytes_data):
    symbols = string.ascii_letters + string.digits + "!@#$%^&*()_+[]{}|;:,.<>?/"
    return ''.join(random.choice(symbols) for _ in range(10))

# Example usage
message = input("Enter a message to encrypt: ")
encrypted_message = encrypt_message(message)
if encrypted_message:
    custom_encoded_encrypted_message = custom_encode(encrypted_message)
    
    print("Encrypted message:", custom_encoded_encrypted_message)

    decrypted_message = decrypt_message(encrypted_message)
    print("Decrypted message:", decrypted_message)
else:
    print("Failed to encrypt the message.")

    