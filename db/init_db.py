import mysql.connector

# Database connection settings
db_config = {
    'user': 'vak',
    'password': 'asdf',
    'host': 'localhost',
    'database': 'secure_file_sharing'
}

def initialize_database():
    # Connect to MySQL server without specifying a database (to create the database if needed)
    conn = mysql.connector.connect(
        user=db_config['user'],
        password=db_config['password'],
        host=db_config['host']
    )
    cursor = conn.cursor()
    
    # Create the database if it doesn't exist
    cursor.execute("CREATE DATABASE IF NOT EXISTS secure_file_sharing")
    print("Database 'secure_file_sharing' created or already exists.")
    conn.close()

    # Reconnect to the database to create tables
    db_config_with_db = db_config.copy()
    db_config_with_db['database'] = 'secure_file_sharing'
    conn = mysql.connector.connect(**db_config_with_db)
    cursor = conn.cursor()

    # Create the users table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(100) NOT NULL,
            public_key TEXT NOT NULL  -- Column to store the user's public key
        )
    ''')
    print("Table 'users' created or already exists.")

    # Create the files table with expiration_time, max_downloads, and encryption details
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INT AUTO_INCREMENT PRIMARY KEY,
            filename VARCHAR(100) NOT NULL,
            encrypted_data LONGBLOB NOT NULL,  -- Encrypted file data
            iv BLOB NOT NULL,                 -- Initialization vector (IV) for AES encryption
            tag BLOB NOT NULL,                -- Authentication tag for AES encryption
            owner_id INT NOT NULL,
            upload_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            file_identifier CHAR(48) NOT NULL,
            expiration_time TIMESTAMP NOT NULL,
            download_count INT DEFAULT 0,
            max_downloads INT NOT NULL DEFAULT 0,
            is_public BOOLEAN DEFAULT FALSE,
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    print("Table 'files' created or already exists.")

    # Create the shared_files table with encrypted key column
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS shared_files (
            id INT AUTO_INCREMENT PRIMARY KEY,
            file_id INT NOT NULL,
            shared_with_user_id INT NOT NULL,
            encrypted_key BLOB NOT NULL,      -- Encrypted symmetric key for file sharing
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY (shared_with_user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    print("Table 'shared_files' created or already exists.")

    conn.commit()
    cursor.close()
    conn.close()
    print("Database and tables initialized successfully.")

if __name__ == "__main__":
    initialize_database()
