import socket
import json
from cryptography.fernet import Fernet

class FileClient:
    def __init__(self, config_file):
        with open(config_file) as f:
            self.config = json.load(f)
        self.server_address = (self.config['server_host'], self.config['server_port'])
        self.client_key = Fernet.generate_key()
        
    def encrypt_file(self, file_data):
        f = Fernet(self.client_key)
        return f.encrypt(file_data)
    
    def decrypt_file(self, encrypted_data):
        f = Fernet(self.client_key)
        return f.decrypt(encrypted_data)
    
    def upload(self, file_path, expiration):
        # Read file, encrypt, send to server
        pass
    
    def download(self, file_id):
        # Request file from server, decrypt
        pass
    
    def list_uploaded(self):
        # Request list of uploaded files from server
        pass
    
    def list_available(self):
        # Request list of available files from server
        pass
    
    def send_to(self, file_id, recipient):
        # Send request to server to share file
        pass

if __name__ == "__main__":
    import sys
    client = FileClient('client-cfg.json')
    command = sys.argv[1]
    if command == 'upload':
        client.upload(sys.argv[2], int(sys.argv[3]))
    elif command == 'download':
        client.download(sys.argv[2])
    elif command == 'list-uploaded':
        client.list_uploaded()
    elif command == 'list-available':
        client.list_available()
    elif command == 'send-to':
        client.send_to(sys.argv[2], sys.argv[3])
