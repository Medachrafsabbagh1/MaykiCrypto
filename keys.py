from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

def generate_key_and_save(filename, key_length):
    # Generate a new key of the specified length
    key = Fernet.generate_key()

    # Truncate or pad the key to the desired length
    key = key[:key_length] if len(key) >= key_length else key + b'\0' * (key_length - len(key))

    # Display the key
    print(f"Clé générée : {key.decode()}")

    # Store the key in a text file
    with open(filename, 'wb') as file:
        file.write(key)

if __name__ == "__main__":
    key_filename = "key.txt"
    key_length = 32  # Choose the desired key length (16, 24, or 32 bytes)
    generate_key_and_save(key_filename, key_length)

