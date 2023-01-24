import getpass
import os
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

def encrypt_folder(path, password):
    # Check if key and salt files exist
    key_path = os.path.join(path, 'key.key')
    salt_path = os.path.join(path, 'salt.key')
    if not os.path.exists(salt_path):
        # Generate a random salt if it doesn't
        salt = os.urandom(16)
        # Save the salt to a file
        with open(salt_path, 'wb') as f:
            f.write(salt)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256,
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        # Derive a key from the password
        key = base64.urlsafe_b64encode(kdf.derive(password))
        # Save the key to a file
        with open(key_path, 'wb') as f:
            f.write(key)
    else:
        # if exists read the key from the file
        with open(key_path, 'rb') as f:
            key = f.read()

    fernet = Fernet(key)
    # Walk through all files in the folder and encrypt them
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, "rb") as f:
                data = f.read()
            if file != "key.key" and file != "salt.key":
                encrypted_data = fernet.encrypt(data)
                # Add the .encrypted extension to the file name
                new_file_path = file_path + ".encrypted"
                with open(new_file_path, "wb") as f:
                    f.write(encrypted_data)
                # Remove the original file
                os.remove(file_path)

def decrypt_folder(path, password):
    # Read the key from the key.key file
    key_path = os.path.join(path, 'key.key')
    with open(key_path, 'rb') as f:
        key = f.read()

    fernet = Fernet(key)
    # Walk through all files in the folder and decrypt them
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith(".encrypted"):
                file_path = os.path.join(root, file)
                with open(file_path, "rb") as f:
                    data = f.read()
                decrypted_data = fernet.decrypt(data)
                # Remove the .encrypted extension from the file name
                new_file_path = os.path.splitext(file_path)[0]
                with open(new_file_path, "wb") as f:
                    f.write(decrypted_data)
                # Remove the original encrypted file
                os.remove(file_path)


if len(sys.argv) != 2:
    print("This script takes only one parameter: Foldername")
else:
    # Get folder from arguments
    folder = sys.argv[1]
    # Ask the user for the folder password
    password = getpass.getpass("Enter the password: ").encode()

    # Check if the folder is already encrypted
    encrypted = False
    current_directory = os.getcwd()
    path = current_directory + "/" + folder
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith(".encrypted"):
                encrypted = True
                break
        if encrypted:
            break

    # Encrypt or decrypt the folder based on whether it is already encrypted
    if encrypted:
        decrypt_folder(path, password)
        print("The folder was successfully decrypted.")
    else:
        encrypt_folder(path, password)
        print("The folder was successfully encrypted.")