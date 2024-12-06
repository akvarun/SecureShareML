# Secure File Sharing System with Machine Learning-Based Malware Detection

This project implements a secure file sharing system that ensures data confidentiality, integrity, and authenticity while incorporating real-time malware detection and storage optimization. The system is designed to handle both authenticated and anonymous users, making it versatile for a variety of use cases.

---

## Features

### 1. **Security Measures**
- **End-to-End Encryption**: 
  - AES-GCM (AES-256) for file encryption/decryption.
  - RSA for secure key sharing between users.
  - Fernet encryption for files stored on the server (encryption at rest).
- **Password Security**: 
  - bcrypt hashing for secure storage of user passwords.
- **Access Control**:
  - Public/private file attributes with expiration times and download limits.

### 2. **Malware Detection**
- **Real-Time Protection**:
  - Uses a Random Forest model to detect malicious files during upload.
  - Trained on the Contagio PDF dataset, achieving 99.90% accuracy with a false negative rate of 0.13%.

### 3. **Storage Optimization**
- **Deduplication**:
  - Identifies duplicate files using SHA-256 hashing and prevents redundant uploads.
  - Achieved up to 35% storage savings during testing.

### 4. **Anonymous User Support**
- Allows anonymous users to list and download public files securely without requiring authentication.
- Ensures privacy while adhering to file expiration policies and download limits.

---

## System Architecture

The system follows a client-server model with the following components:

### 1. **Server**
- **Technologies Used**:
  - Python
  - MySQL
- **Responsibilities**:
  - User authentication and session handling.
  - File encryption, decryption, and storage.
  - File sharing and enforcing access control policies.

### 2. **Client**
- **Technologies Used**:
  - Python
- **Responsibilities**:
  - File upload/download with client-side encryption and decryption.
  - Deduplication using SHA-256 hashing.
  - Support for anonymous access to public files.

### 3. **Database**
- **Technologies Used**:
  - MySQL
- **Responsibilities**:
  - Stores hashed user credentials, encrypted file content, metadata, and sharing information.

---

## Prerequisites

- Python 3.8+
- MySQL Server
- Required Python Libraries:
  - `bcrypt`
  - `cryptography`
  - `scikit-learn`
  - `mysql-connector-python`

