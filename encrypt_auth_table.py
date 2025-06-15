import mysql.connector
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import getpass
import sys
from tabulate import tabulate  # For nice table display

# Configuration - replace with your actual database credentials
DB_CONFIG = {
    'host': 'localhost',
    'user': 'your_username',
    'password': 'your_password',
    'database': 'your_database'
}

# Encryption key (in production, store this securely)
def get_encryption_key():
    try:
        with open('encryption.key', 'rb') as f:
            return f.read()
    except FileNotFoundError:
        # Generate a new key if none exists
        key = get_random_bytes(32)  # AES-256
        with open('encryption.key', 'wb') as f:
            f.write(key)
        print("Generated new encryption key")
        return key

# CBC Encryption function
def encrypt_cbc(plaintext, key):
    if plaintext is None:
        return None
    
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Generate random IV
    iv = get_random_bytes(AES.block_size)
    
    # Create cipher and encrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    # Combine IV and ciphertext and encode to base64
    encrypted = base64.b64encode(iv + ciphertext).decode('utf-8')
    return encrypted

# CBC Decryption function
def decrypt_cbc(ciphertext, key):
    if ciphertext is None:
        return None
    
    # Decode base64 data
    raw_data = base64.b64decode(ciphertext)
    
    # Extract IV and actual ciphertext
    iv = raw_data[:AES.block_size]
    actual_ciphertext = raw_data[AES.block_size:]
    
    # Create cipher and decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(actual_ciphertext)
    decrypted = unpad(decrypted_padded, AES.block_size).decode('utf-8')
    return decrypted

# Function to check if the auth_table exists
def check_table_exists(cursor):
    cursor.execute("SHOW TABLES LIKE 'auth_table'")
    return cursor.fetchone() is not None

# Function to create auth_table if it doesn't exist
def create_auth_table(cursor):
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS auth_table (
        id INT AUTO_INCREMENT PRIMARY KEY,
        timestamp DATETIME,
        source_ip VARCHAR(50),
        username VARCHAR(50),
        status VARCHAR(20),
        pwd_length INT,
        source_ip_encrypted TEXT,
        username_encrypted TEXT,
        status_encrypted TEXT
    )
    ''')
    print("Created auth_table")

# Function to populate sample data if table is empty
def populate_sample_data(connection):
    cursor = connection.cursor()
    
    # Check if table is empty
    cursor.execute("SELECT COUNT(*) FROM auth_table")
    count = cursor.fetchone()[0]
    
    if count == 0:
        # Insert sample data
        sample_data = [
            ('2025-06-12 17:38:16', '106.251.104.146', 'admin', 'success', 344),
            ('2025-06-12 17:38:16', '63.16.140.27', 'admin', 'success', 344),
            ('2025-06-12 17:38:17', '87.242.236.35', 'root', 'success', 344),
            ('2025-06-12 17:38:17', '6.45.76.6', 'root', 'success', 344),
            ('2025-06-12 17:38:18', '240.74.128.5', 'admin', 'success', 344)
        ]
        
        cursor.executemany('''
        INSERT INTO auth_table (timestamp, source_ip, username, status, pwd_length)
        VALUES (%s, %s, %s, %s, %s)
        ''', sample_data)
        
        connection.commit()
        print(f"Inserted {len(sample_data)} sample records")
    
    cursor.close()

# Function to encrypt data
def encrypt_table_data(connection, encryption_key):
    cursor = connection.cursor(dictionary=True)
    update_cursor = connection.cursor()
    
    # Get all records from auth table
    cursor.execute("SELECT * FROM auth_table")
    rows = cursor.fetchall()
    
    counter = 0
    # Encrypt each row and update the table
    for row in rows:
        # Encrypt sensitive fields
        source_ip_encrypted = encrypt_cbc(row['source_ip'], encryption_key)
        username_encrypted = encrypt_cbc(row['username'], encryption_key)
        status_encrypted = encrypt_cbc(row['status'], encryption_key)
        
        # Update the record with encrypted values
        update_cursor.execute(
            """UPDATE auth_table 
               SET source_ip_encrypted = %s, 
                   username_encrypted = %s, 
                   status_encrypted = %s 
               WHERE id = %s""",
            (source_ip_encrypted, username_encrypted, status_encrypted, row['id'])
        )
        counter += 1
    
    # Commit changes
    connection.commit()
    print(f"Encrypted {counter} records in auth_table")
    
    update_cursor.close()
    cursor.close()

# Function to display the table before and after encryption
def display_table(connection, encryption_key=None):
    cursor = connection.cursor(dictionary=True)
    
    # Get records from auth table
    cursor.execute("""
    SELECT id, timestamp, source_ip, source_ip_encrypted, 
           username, username_encrypted,
           status, status_encrypted, pwd_length
    FROM auth_table LIMIT 5
    """)
    rows = cursor.fetchall()
    
    # Display original data
    print("\n--- Original Data ---")
    headers = ["ID", "Timestamp", "Source IP", "Username", "Status", "PWD Length"]
    table_data = []
    for row in rows:
        table_data.append([
            row['id'],
            row['timestamp'],
            row['source_ip'],
            row['username'],
            row['status'],
            row['pwd_length']
        ])
    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    # Display encrypted data
    print("\n--- Encrypted Data ---")
    headers = ["ID", "Timestamp", "Encrypted IP", "Encrypted Username", "Encrypted Status", "PWD Length"]
    table_data = []
    for row in rows:
        table_data.append([
            row['id'],
            row['timestamp'],
            row['source_ip_encrypted'][:20] + "..." if row['source_ip_encrypted'] else None,
            row['username_encrypted'][:20] + "..." if row['username_encrypted'] else None,
            row['status_encrypted'][:20] + "..." if row['status_encrypted'] else None,
            row['pwd_length']
        ])
    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    # If encryption key is provided, display decrypted data
    if encryption_key:
        print("\n--- Decrypted Data ---")
        headers = ["ID", "Timestamp", "Decrypted IP", "Decrypted Username", "Decrypted Status", "PWD Length"]
        table_data = []
        for row in rows:
            decrypted_ip = decrypt_cbc(row['source_ip_encrypted'], encryption_key) if row['source_ip_encrypted'] else None
            decrypted_username = decrypt_cbc(row['username_encrypted'], encryption_key) if row['username_encrypted'] else None
            decrypted_status = decrypt_cbc(row['status_encrypted'], encryption_key) if row['status_encrypted'] else None
            
            table_data.append([
                row['id'],
                row['timestamp'],
                decrypted_ip,
                decrypted_username,
                decrypted_status,
                row['pwd_length']
            ])
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    cursor.close()

# Main function
def main():
    try:
        # Get database password securely if not hardcoded
        if DB_CONFIG['password'] == 'your_password':
            DB_CONFIG['password'] = getpass.getpass("Enter database password: ")
        
        # Connect to the database
        connection = mysql.connector.connect(**DB_CONFIG)
        print("Connected to database successfully")
        
        # Check if table exists, create if not
        cursor = connection.cursor()
        if not check_table_exists(cursor):
            create_auth_table(cursor)
            populate_sample_data(connection)
        cursor.close()
        
        # Get encryption key
        encryption_key = get_encryption_key()
        
        # Display table before encryption
        print("\n==== BEFORE ENCRYPTION ====")
        display_table(connection)
        
        # Encrypt the data
        encrypt_table_data(connection, encryption_key)
        
        # Display table after encryption
        print("\n==== AFTER ENCRYPTION ====")
        display_table(connection)
        
        # Display decrypted data
        print("\n==== DECRYPTION TEST ====")
        display_table(connection, encryption_key)
        
        # Close connection
        connection.close()
        print("\nEncryption process completed successfully")
        
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()