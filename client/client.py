import socket
import json
import os
import bcrypt
import hashlib
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from testpdf import testpdf

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432

# Utility functions for encryption and decryption
def encrypt_file(file_path):
    key = os.urandom(32)  # Generate a random 256-bit key
    iv = os.urandom(12)   # Generate a random 12-byte IV for AES-GCM
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return key, iv, ciphertext, encryptor.tag

def decrypt_file(ciphertext, key, iv, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def generate_key_pair(username):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_filename = f"{username}_private_key.pem"
    with open(private_key_filename, "wb") as f:
        f.write(private_pem)
    print(f"[INFO] Private key saved to {private_key_filename}")

    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_pem


def connect_to_server():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))
    return client_socket

def send_file(client_socket, filepath, expiration_minutes, max_downloads, is_public):
    try:
        filename = os.path.basename(filepath)

        #test for malicious file
        ismal=testpdf(filepath)
        if(ismal[0]!='no'):
            print("Malicious file detected")
            return
        else:
            print('success')

        # Compute file identifier (based on plaintext file data)
        with open(filepath, 'rb') as f:
            plaintext = f.read()
        file_identifier = hashlib.sha256(plaintext).hexdigest()[:48]  # Consistent identifier for same content
        print(f"[DEBUG] File identifier computed: {file_identifier}")

        # Encrypt the file
        key, iv, ciphertext, tag = encrypt_file(filepath)

        # Save the symmetric key for future decryption
        with open(f"{file_identifier}_key.txt", "w") as key_file:
            key_file.write(key.hex())
        print(f"[INFO] Symmetric key saved to {file_identifier}_key.txt")

        # Send metadata
        client_socket.send(filename.encode())
        time.sleep(0.1)
        client_socket.send(str(expiration_minutes).encode())
        time.sleep(0.1)
        client_socket.send(str(max_downloads).encode())
        time.sleep(0.1)
        client_socket.send(file_identifier.encode())  # Send file identifier
        time.sleep(0.1)

        # Send encryption details and encrypted file
        client_socket.send(iv)  # Send IV
        time.sleep(0.1)
        client_socket.send(tag)  # Send the authentication tag
        time.sleep(0.1)
        for i in range(0, len(ciphertext), 1048576):
            client_socket.send(ciphertext[i:i + 1048576])
        time.sleep(0.1)
        client_socket.send(b'EOF')
        time.sleep(0.1)
        client_socket.send("true".encode() if is_public else "false".encode())

        # Get upload response
        upload_response = client_socket.recv(1024).decode(errors='ignore')
        print(upload_response)
    except Exception as e:
        print(f"[ERROR] Error in send_file: {e}")

def receive_file(client_socket, file_identifier):
    try:
        client_socket.send(file_identifier.encode())
        response = client_socket.recv(1024)
        if response == b"START":
            iv = client_socket.recv(12)  # Receive the IV
            tag = client_socket.recv(16)  # Receive the authentication tag
            filename = client_socket.recv(1024).decode(errors='ignore')

            save_path = input("Enter location to save (press Enter for current directory): ").strip()
            if not save_path:
                save_location = os.path.join(os.getcwd(), filename)
            else:
                if not os.path.exists(save_path):
                    print(f"[ERROR] Directory {save_path} does not exist.")
                    return
                save_location = os.path.join(save_path, filename)

            ciphertext = b""
            while True:
                data = client_socket.recv(1048576)
                if b"EOF" in data:
                    ciphertext += data[:data.index(b"EOF")]
                    break
                ciphertext += data

            # Ask for the symmetric key
            key_file_path = f"{file_identifier}_key.txt"
            try:
                with open(key_file_path, "r") as key_file:
                    key = bytes.fromhex(key_file.read().strip())
                    print(f"[INFO] Symmetric key loaded from {key_file_path}")
            except FileNotFoundError:
                key = input("Enter the symmetric key for decryption: ").encode()

            plaintext = decrypt_file(ciphertext, key, iv, tag)

            with open(save_location, 'wb') as f:
                f.write(plaintext)
            print(f"[SUCCESS] File saved to: {save_location}")
        else:
            print(response.decode(errors='ignore'))
    except Exception as e:
        print(f"[ERROR] Error in receive_file: {e}")


def main():
    while True:
        choice = input("Do you want to log in, sign up, Anonymous or exit? (login/signup/Anonymous/exit): ").lower()

        if choice == "exit":
            break

        client_socket = connect_to_server()

        if choice == "signup":
            client_socket.send("signup".encode())
            time.sleep(0.1)
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

            public_key = generate_key_pair(username)
            print("[DEBUG] Sending signup data to server.")  # Generate RSA key pair
            client_socket.send(username.encode())
            time.sleep(0.1)
            client_socket.send(hashed_password)
            time.sleep(0.1)
            client_socket.send(public_key)
            time.sleep(0.1)
            print("[DEBUG] Signup data sent.")  # Send public key to server

            response = client_socket.recv(1024).decode(errors='ignore')
            print(response)
            client_socket.close()

        elif choice == "anonymous":
            client_socket.send("anonymous".encode())
            response = client_socket.recv(1024).decode(errors='ignore')
            print(response)
            while True:
                action = input("Choose an action (list-public/download/exit): ").lower()
                client_socket.send(action.encode())
                if action == "list-public":
                    response = client_socket.recv(4096).decode(errors='ignore')
                    try:
                        files = json.loads(response)
                        if not files:
                            print("No public files found.")
                        else:
                            for file in files:
                                print("\nPublic File Details:")
                                for key, value in file.items():
                                    print(f"{key}: {value}")

                    except json.JSONDecodeError:
                        print(response)
                    
                elif action == "download":
                    file_identifier = input("Enter the file identifier to download: ")
                    receive_file(client_socket, file_identifier)
                
                elif action == "exit":
                    break


                

        elif choice == "login":
            client_socket.send("login".encode())
            username = input("Enter your username: ")
            password = input("Enter your password: ")

            client_socket.send(username.encode())
            client_socket.send(password.encode())

            auth_response = client_socket.recv(1024).decode(errors='ignore')
            print(auth_response)

            if "successful" in auth_response.lower():
                print("[SUCCESS] Authentication successful! You are now connected to the server.")

                while True:
                    action = input("Choose an action (upload/download/list-uploaded/list-shared/send-to/download-shared/exit): ")

                    if action == "exit":
                        client_socket.send("exit".encode())
                        break

                    client_socket.send(action.encode())

                    if action == "upload":
                        filepath = input("Enter the file path to upload: ")
                        if not os.path.exists(filepath):
                            print("[ERROR] File does not exist.")
                            continue

                        expiration_minutes = int(input("Enter expiration time in minutes: "))
                        max_downloads = int(input("Enter maximum number of downloads (0 for unlimited): "))
                        is_public = input("Make this file public? (yes/no): ").strip().lower() == "yes"
                        send_file(client_socket, filepath, expiration_minutes, max_downloads, is_public)

                    elif action == "download":
                        file_identifier = input("Enter the file identifier to download: ")
                        receive_file(client_socket, file_identifier)

                    elif action == "list-uploaded" or action == "list-shared":
                        time.sleep(0.1)
                        response = client_socket.recv(4096).decode(errors='ignore')
                        try:
                            files = json.loads(response)
                            if not files:
                                print("No files found.")
                            else:
                                for file in files:
                                    print("\nFile Details:")
                                    for key, value in file.items():
                                        print(f"{key}: {value}")
                        except json.JSONDecodeError:
                            print(response)

                    elif action == "send-to":
                        recipient = input("Enter recipient's username: ")
                        file_id = input("Enter file identifier: ")
                        client_socket.send(recipient.encode())  # Send recipient username
                        time.sleep(0.1)
                        client_socket.send(file_id.encode())  # Send file identifier
                        time.sleep(0.1)            
                        key_file = f"{file_id}_key.txt"
                        try:
                            with open(key_file, "r") as f:
                                symmetric_key = bytes.fromhex(f.read().strip())
                            print(f"[DEBUG] Symmetric key loaded from {key_file}.")
                        except FileNotFoundError:
                            print(f"[ERROR] Symmetric key file not found for file identifier: {file_id}")
                            client_socket.send(b"[ERROR] Missing symmetric key.")
                            return   
                        try:
                            recipient_public_key_pem = client_socket.recv(4096).decode('utf-8')
                            if "ERROR" in recipient_public_key_pem:  
                                print("[ERROR] Unable to fetch the recipient's public key.")
                                return  
                            print("[DEBUG] Recipient's public key received.")
                        except Exception as e:
                            print(f"[ERROR] Failed to fetch recipient's public key: {e}")
                            return
                        try:
                            from cryptography.hazmat.primitives.asymmetric import padding
                            from cryptography.hazmat.primitives import hashes, serialization
                            recipient_public_key = serialization.load_pem_public_key(
                                recipient_public_key_pem.encode('utf-8'),
                                backend=default_backend()
                            )
                            encrypted_key = recipient_public_key.encrypt(
                                symmetric_key,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
                            print("[DEBUG] Symmetric key encrypted with recipient's public key.")
                        except Exception as e:
                            print(f"[ERROR] Failed to encrypt the symmetric key: {e}")
                            return
                         
                        try:
                            client_socket.send(encrypted_key)  # Send the encrypted symmetric key
                            print("[DEBUG] Encrypted symmetric key sent to the server.")
                            response = client_socket.recv(1024).decode(errors='ignore')
                            print(response)  # Display server's response
                        except Exception as e:
                            print(f"[ERROR] Failed to send encrypted key: {e}")


                    elif action == "download-shared":
                        file_id = input("Enter the file identifier to download: ")
                        client_socket.send(file_id.encode())
                        encrypted_key = client_socket.recv(4096)
                        print("[DEBUG] Encrypted symmetric key received.")
                        private_key_file = f"{username}_private_key.pem"
                        from cryptography.hazmat.primitives import serialization
                        try:
                            with open(private_key_file, "rb") as key_file:
                                private_key = serialization.load_pem_private_key(
                                    key_file.read(),
                                    password=None,
                                    backend=default_backend()
                                    )
                            print("[DEBUG] Private key loaded successfully.")
                        except FileNotFoundError:
                            print("[ERROR] Private key file not found.")
                            return
                        from cryptography.hazmat.primitives.asymmetric import padding
                        from cryptography.hazmat.primitives import hashes
                        try:
                            symmetric_key = private_key.decrypt(
                                encrypted_key,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
                            print("[DEBUG] Symmetric key decrypted successfully.")
                        except Exception as e:
                            print(f"[ERROR] Failed to decrypt symmetric key: {e}")
                            return
                        iv = client_socket.recv(12)
                        tag = client_socket.recv(16)
                        filename = client_socket.recv(1024).decode(errors='ignore')
                        ciphertext = b""
                        while True:
                            chunk = client_socket.recv(1048576)
                            if b"EOF" in chunk:
                                ciphertext += chunk[:chunk.index(b"EOF")]
                                break
                            ciphertext += chunk
                        plaintext = decrypt_file(ciphertext, symmetric_key, iv, tag)
                        save_path = input("Enter location to save the file (press Enter for current directory): ").strip()
                        if not save_path:
                            save_path = os.getcwd()
                        save_location = os.path.join(save_path, filename)
                        with open(save_location, "wb") as f:
                            f.write(plaintext)
                        print(f"[SUCCESS] File saved to: {save_location}")
                        

            client_socket.close()

if __name__ == "__main__":
    main()
