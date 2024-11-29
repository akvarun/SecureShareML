import socket
import threading
import mysql.connector
import bcrypt
import hashlib
import json
from datetime import datetime, timedelta
import time
from cryptography.fernet import Fernet
import os

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432
ADDRESS = (SERVER_HOST, SERVER_PORT)

# Database connection settings
db_config = {
    'user': 'vak',
    'password': 'asdf',
    'host': 'localhost',
    'database': 'secure_file_sharing'
}

KEY_FILE = "fernet_key.key"

def initialize_fernet_key():
    """Initialize the Fernet key, generating it only if the server is running for the first time."""
    if os.path.exists(KEY_FILE):
        # The server is restarting
        print("Key file exists. Server is restarting.")
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
        print("Fernet key loaded successfully!")
    else:
        # The server is running for the first time
        print("Key file not found. Server is running for the first time.")
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        print("Fernet key generated and saved successfully!")

    return Fernet(key)

fernet = initialize_fernet_key()


def list_public_files():
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT file_identifier, filename, upload_timestamp, expiration_time 
            FROM files 
            WHERE is_public = TRUE AND expiration_time > NOW()
        """)
        files = cursor.fetchall()
        for file in files:
            file['upload_timestamp'] = file['upload_timestamp'].isoformat()
            file['expiration_time'] = file['expiration_time'].isoformat()
        return json.dumps(files)
    except Exception as e:
        print(f"[ERROR] Failed to fetch public files: {e}")
        return json.dumps([])
    finally:
        cursor.close()
        conn.close()


def get_public_file_from_db(file_identifier):
    """Retrieve the encrypted file, IV, and tag for a public file identifier."""
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(buffered=True)
    try:
        # Execute the query to fetch public file details
        cursor.execute("""
            SELECT f.encrypted_data, f.iv, f.tag, f.filename, f.download_count, f.max_downloads
            FROM files f
            WHERE f.file_identifier = %s AND f.is_public = 1 AND f.expiration_time > NOW();
        """, (file_identifier,))
        
        result = cursor.fetchone()

        if not result:
            # File not found or expired
            print(f"No file found or expired for identifier: {file_identifier}")
            return None, None, None, None

        # Unpack results
        server_encrypted_data, iv, tag, filename, download_count, max_downloads = result

        # Decrypt the encrypted data
        try:
            encrypted_data = fernet.decrypt(server_encrypted_data)
            print("Decryption successful")
        except Exception as decrypt_error:
            print(f"[ERROR] Decryption failed: {decrypt_error}")
            return None, None, None, None

        # Check max_downloads and download_count
        if max_downloads == 0 or download_count < max_downloads:
            # Update download count
            cursor.execute(
                "UPDATE files SET download_count = download_count + 1 WHERE file_identifier = %s",
                (file_identifier,)
            )
            conn.commit()
            print(f"Updated download count for file: {file_identifier}")
            return encrypted_data, iv, tag, filename
        else:
            # Download limit reached
            print(f"[DEBUG] Download limit reached for public file: {file_identifier}")
            return None, None, None, None
    except Exception as e:
        print(f"[ERROR] Error in get_public_file_from_db: {e}")
        return None, None, None, None
    finally:
        cursor.close()
        conn.close()



def add_user_to_db(username, hashed_password, public_key):
    """Add a new user along with their public key."""
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password, public_key) VALUES (%s, %s, %s)", 
                       (username, hashed_password, public_key))
        conn.commit()
    except mysql.connector.IntegrityError:
        return False
    finally:
        cursor.close()
        conn.close()
    return True

def save_file_to_db(file_identifier, filename, encrypted_data, iv, tag, owner_id, expiration_minutes, max_downloads, is_public):
    """Store encrypted file data, IV, and authentication tag in the database."""
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    try:
        # Check if the file with the same identifier already exists for the user
        cursor.execute(
            "SELECT id FROM files WHERE file_identifier = %s AND owner_id = %s",
            (file_identifier, owner_id)
        )
        existing_file = cursor.fetchone()
        if existing_file:
            print(f"[DEBUG] Duplicate file detected: {file_identifier} for user_id {owner_id}")
            return None, True  # File already exists
        
        server_encrypted_data = fernet.encrypt(encrypted_data)

        # Calculate expiration time and insert the new file record
        expiration_time = datetime.now() + timedelta(minutes=expiration_minutes)
        cursor.execute(
            """
            INSERT INTO files (file_identifier, filename, encrypted_data, iv, tag, owner_id, expiration_time, max_downloads, download_count, is_public)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (file_identifier, filename, server_encrypted_data, iv, tag, owner_id, expiration_time, max_downloads, 0, is_public)
        )
        conn.commit()
        print(f"[DEBUG] File inserted: {file_identifier}")
        return file_identifier, False  # File saved successfully
    finally:
        cursor.close()
        conn.close()


def get_uploaded_files(user_id):
    """Fetch all files uploaded by the user."""
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT f.file_identifier, f.filename, f.upload_timestamp, f.expiration_time, f.download_count, f.max_downloads,
                   GROUP_CONCAT(u.username) as shared_with
            FROM files f
            LEFT JOIN shared_files sf ON f.id = sf.file_id
            LEFT JOIN users u ON sf.shared_with_user_id = u.id
            WHERE f.owner_id = %s AND f.expiration_time > NOW()
            GROUP BY f.id
            ORDER BY f.upload_timestamp DESC
        """, (user_id,))
        files = cursor.fetchall()
        for file in files:
            file['upload_timestamp'] = file['upload_timestamp'].isoformat()
            file['expiration_time'] = file['expiration_time'].isoformat()
        return json.dumps(files)
    except Exception as e:
        print(f"[ERROR] Failed to fetch uploaded files: {e}")
        return json.dumps([])
    finally:
        cursor.close()
        conn.close()

def get_shared_files(user_id):
    """Fetch all files shared with the user."""
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT f.file_identifier, f.filename, f.upload_timestamp, f.expiration_time, f.download_count, f.max_downloads,
                   u.username as shared_by
            FROM files f
            JOIN shared_files sf ON f.id = sf.file_id
            JOIN users u ON f.owner_id = u.id
            WHERE sf.shared_with_user_id = %s AND f.expiration_time > NOW()
            ORDER BY f.upload_timestamp DESC
        """, (user_id,))
        files = cursor.fetchall()
        for file in files:
            file['upload_timestamp'] = file['upload_timestamp'].isoformat()
            file['expiration_time'] = file['expiration_time'].isoformat()
        return json.dumps(files)
    except Exception as e:
        print(f"[ERROR] Failed to fetch shared files: {e}")
        return json.dumps([])
    finally:
        cursor.close()
        conn.close()

def get_file_from_db(file_identifier, user_id):
    """Retrieve the encrypted file, IV, and tag for a given file identifier."""
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(buffered=True)
    try:
        cursor.execute("""
            SELECT f.encrypted_data, f.iv, f.tag, f.filename, f.download_count, f.max_downloads
            FROM files f
            LEFT JOIN shared_files sf ON f.id = sf.file_id
            WHERE f.file_identifier = %s AND (f.owner_id = %s OR sf.shared_with_user_id = %s)
            AND f.expiration_time > NOW()
        """, (file_identifier, user_id, user_id))
        result = cursor.fetchone()

        if not result:
            # File not found or not shared with the user
            return None, None, None, None

        # Unpack results
        server_encrypted_data, iv, tag, filename, download_count, max_downloads = result
        encrypted_data = fernet.decrypt(server_encrypted_data)


        # Check max_downloads and download_count
        if max_downloads == 0 or download_count < max_downloads:
            # Update download count
            cursor.execute(
                "UPDATE files SET download_count = download_count + 1 WHERE file_identifier = %s",
                (file_identifier,)
            )
            conn.commit()
            return encrypted_data, iv, tag, filename
        else:
            # Download limit reached
            print(f"[DEBUG] Download limit reached for file: {file_identifier}")
            return None, None, None, None
    except Exception as e:
        print(f"[ERROR] Error in get_file_from_db: {e}")
        return None, None, None, None
    finally:
        cursor.close()
        conn.close()


def get_user_id(username):
    """Retrieve the user ID for a given username."""
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    return result[0] if result else None

def authenticate(username, password):
    """Authenticate the user using username and password."""
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("SELECT id, password FROM users WHERE username = %s", (username,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    if result and bcrypt.checkpw(password.encode(), result[1].encode()):
        print(f"Authentication result for {username}: True")
        return result[0]
    print(f"Authentication result for {username}: False")
    return None

def share_file(sender_id, recipient_username, file_identifier, encrypted_key):
    """Share a file by storing the encrypted symmetric key for the recipient."""
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id FROM files WHERE file_identifier = %s AND owner_id = %s", 
                       (file_identifier, sender_id))
        file_result = cursor.fetchone()
        if not file_result:
            return False

        recipient_id = get_user_id(recipient_username)
        if not recipient_id:
            return False

        cursor.execute("""
            INSERT INTO shared_files (file_id, shared_with_user_id, encrypted_key)
            VALUES (%s, %s, %s)
        """, (file_result[0], recipient_id, encrypted_key))
        conn.commit()
        return True
    finally:
        cursor.close()
        conn.close()

def cleanup_expired_files():
    """Clean up expired or fully downloaded files."""
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(buffered=True)
    try:
        cursor.execute("""
            DELETE FROM files
            WHERE expiration_time < NOW() OR (max_downloads > 0 AND download_count >= max_downloads)
        """)
        conn.commit()
        print(f"Cleaned up {cursor.rowcount} expired or fully downloaded files.")
    finally:
        cursor.close()
        conn.close()

def handle_client(client_socket, client_address):
    """Handle individual client connections."""
    print(f"New connection from {client_address}")
    try:
        choice = client_socket.recv(1024).decode(errors='ignore')
        print(f"[DEBUG] Received choice: {choice}")
        if choice == "signup":
            username = client_socket.recv(1024).decode(errors='ignore')
            print(f"[DEBUG] Username received: {username}")
            hashed_password = client_socket.recv(1024).decode(errors='ignore')
            print(f"[DEBUG] Password hash received: {hashed_password[:50]}...")
            public_key = client_socket.recv(4096).decode(errors='ignore')  # Receive public key
            print(f"[DEBUG] Received signup data: username={username}, public_key={public_key[:50]}...")

            if add_user_to_db(username, hashed_password, public_key):
                client_socket.send("Sign-up successful! You can now log in with your credentials.".encode())
            else:
                client_socket.send("Username already taken. Please try a different one.".encode())

        elif choice == "anonymous":
            client_socket.send("Logged in as anonymous. You can only access public files.".encode())
            print(f"{client_address} logged in as anonymous.")
            while True:
                action = client_socket.recv(1024).decode(errors='ignore')
                if action == "list-public":
                    response = list_public_files()
                    client_socket.sendall(response.encode())
                elif action == "download":
                    file_identifier = client_socket.recv(1024).decode(errors='ignore')
                    encrypted_data, iv, tag, filename = get_public_file_from_db(file_identifier)
                    if encrypted_data:
                        client_socket.send(b"START")
                        client_socket.send(iv)
                        time.sleep(0.1)
                        client_socket.send(tag)
                        time.sleep(0.1)
                        client_socket.send(filename.encode())
                        time.sleep(0.1)
                        for i in range(0, len(encrypted_data), 1048576):
                            client_socket.send(encrypted_data[i:i + 1048576])
                        client_socket.send(b"EOF")
                    else:
                        client_socket.send("[ERROR] File not found or expired.".encode())

                elif action == "exit":
                    break


        
        elif choice == "login":
            username = client_socket.recv(1024).decode(errors='ignore')
            password = client_socket.recv(1024).decode(errors='ignore')
            user_id = authenticate(username, password)
            if user_id:
                client_socket.send("Authentication successful".encode())
                print(f"{client_address} authenticated as {username}")
                while True:
                    action = client_socket.recv(1024).decode(errors='ignore')
                    if action == "upload":
                        filename = client_socket.recv(1024).decode(errors='ignore')
                        expiration_minutes = int(client_socket.recv(1024).decode(errors='ignore'))
                        max_downloads = int(client_socket.recv(1024).decode(errors='ignore'))
                        file_identifier = client_socket.recv(1024).decode(errors='ignore')
                        iv = client_socket.recv(12)  # Receive IV
                        tag = client_socket.recv(16)  # Receive authentication tag
                        encrypted_data = b""
                        while True:
                            chunk = client_socket.recv(1048576)
                            if b"EOF" in chunk:
                                encrypted_data += chunk[:chunk.index(b"EOF")]
                                break
                            encrypted_data += chunk
                        is_public = client_socket.recv(1024).decode(errors='ignore') == "true"
                        file_id, is_duplicate = save_file_to_db(file_identifier, filename, encrypted_data, iv, tag, user_id, expiration_minutes, max_downloads, is_public)
                        if is_duplicate:
                            client_socket.send(f"[ERROR] File '{filename}' already exists in the database. Identifier: {file_identifier}".encode())
                        else:
                            client_socket.send(f"File uploaded successfully. Identifier: {file_identifier}".encode())
                    elif action == "download":
                        file_identifier = client_socket.recv(1024).decode(errors='ignore')
                        encrypted_data, iv, tag, filename = get_file_from_db(file_identifier, user_id)
                        if encrypted_data:
                            client_socket.send(b"START")
                            client_socket.send(iv)
                            time.sleep(0.1)
                            client_socket.send(tag)
                            time.sleep(0.1)
                            client_socket.send(filename.encode())
                            time.sleep(0.1)
                            for i in range(0, len(encrypted_data), 1048576):
                                client_socket.send(encrypted_data[i:i + 1048576])
                            client_socket.send(b"EOF")
                        else:
                            client_socket.send("[ERROR] File not found or expired.".encode())
                    elif action == "list-uploaded":
                        print("[DEBUG] Handling 'list-uploaded' request.")
                        response = get_uploaded_files(user_id)
                        client_socket.sendall(response.encode())
                    elif action == "list-shared":
                        print("[DEBUG] Handling 'list-shared' request.")
                        response = get_shared_files(user_id)
                        client_socket.sendall(response.encode())
                    elif action == "send-to":
                        print("[DEBUG] Handling 'send-to' request.")
                        recipient_username = client_socket.recv(1024).decode(errors='ignore')
                        print(f"[DEBUG] Recipient username: {recipient_username}")
                        file_identifier = client_socket.recv(1024).decode(errors='ignore')
                        print(f"[DEBUG] File identifier: {file_identifier}")
                        conn = mysql.connector.connect(**db_config)
                        cursor = conn.cursor()
                        try:
                            cursor.execute("SELECT public_key FROM users WHERE username = %s", (recipient_username,))
                            result = cursor.fetchone()
                            if not result:
                                client_socket.send("[ERROR] Recipient username not found.".encode())
                                print("[ERROR] Public key request failed: Recipient not found.")
                                return
                            recipient_public_key = result[0]
                            print(f"[DEBUG] Public key retrieved: {recipient_public_key[:50]}...")
                            client_socket.send(recipient_public_key.encode('utf-8'))
                        except Exception as e:
                            print(f"[ERROR] Failed to fetch recipient's public key: {e}")
                            client_socket.send("[ERROR] Failed to fetch recipient's public key.".encode())
                            return
                        finally:
                            cursor.close()
                            conn.close()
                        encrypted_key = client_socket.recv(4096)
                        print(f"[DEBUG] Received encrypted key: {encrypted_key} (Length: {len(encrypted_key)})")

                        if share_file(user_id, recipient_username, file_identifier, encrypted_key):
                            client_socket.send("File shared successfully.".encode())
                        else:
                            client_socket.send("Failed to share file.".encode())


                    elif action == "exit":
                        break
                    elif action == "download-shared":
                        print("[DEBUG] Handling 'download-shared' request.")
                        file_id = client_socket.recv(1024).decode(errors='ignore')
                        
                        conn = mysql.connector.connect(**db_config)
                        cursor = conn.cursor()
                        try:
                            cursor.execute("""
            SELECT f.encrypted_data, f.iv, f.tag, f.filename, sf.encrypted_key
            FROM files f
            JOIN shared_files sf ON f.id = sf.file_id
            WHERE f.file_identifier = %s AND sf.shared_with_user_id = %s
        """, (file_id, user_id))
                            result = cursor.fetchone()
                            if result:
                                server_encrypted_data, iv, tag, filename, encrypted_key = result
                                encrypted_data = fernet.decrypt(server_encrypted_data)
                                print(f"[DEBUG] Encrypted key from DB: {encrypted_key} (Length: {len(encrypted_key)})")
                                client_socket.send(encrypted_key)
                                client_socket.send(iv)
                                time.sleep(0.1)
                                client_socket.send(tag)  # Send authentication tag
                                time.sleep(0.1)
                                client_socket.send(filename.encode())  # Send filename
                                time.sleep(0.1)
                                for i in range(0, len(encrypted_data), 1048576):
                                    client_socket.send(encrypted_data[i:i + 1048576])
                                client_socket.send(b"EOF")
                                print("[DEBUG] Shared file sent successfully.")
                            else:
                                client_socket.send("[ERROR] File not found or not shared with you.".encode())
                        except Exception as e:
                            print(f"[ERROR] Failed to handle 'download-shared': {e}")
                            client_socket.send("[ERROR] Failed to retrieve the shared file.".encode())
                        
            else:
                client_socket.send("Authentication failed.".encode())
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        client_socket.close()

# Server initialization
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(ADDRESS)
server_socket.listen()
print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")

# Start cleanup thread
cleanup_thread = threading.Thread(target=lambda: (cleanup_expired_files(), time.sleep(3600)))
cleanup_thread.daemon = True
cleanup_thread.start()

try:
    while True:
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()
except KeyboardInterrupt:
    print("\nServer is shutting down.")
finally:
    server_socket.close()
