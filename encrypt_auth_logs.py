import mysql.connector
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import base64

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'your_password',
    'database': 'ssh_logs'
}

def get_encryption_key():
    try:
        with open('encryption.key', 'rb') as f:
            return f.read()
    except FileNotFoundError:
        key = get_random_bytes(32)  # AES-256
        with open('encryption.key', 'wb') as f:
            f.write(key)
        print("Generated new encryption key")
        return key

def encrypt_cbc(plaintext, key):
    if plaintext is None:
        return None
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def main():
    key = get_encryption_key()
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)
    update_cursor = conn.cursor()

    cursor.execute("SELECT id, source_ip, username, status FROM auth_logs")
    rows = cursor.fetchall()
    for row in rows:
        source_ip_enc = encrypt_cbc(row['source_ip'], key)
        username_enc = encrypt_cbc(row['username'], key)
        status_enc = encrypt_cbc(row['status'], key)
        update_cursor.execute(
            "UPDATE auth_logs SET source_ip_encrypted=%s, username_encrypted=%s, status_encrypted=%s WHERE id=%s",
            (source_ip_enc, username_enc, status_enc, row['id'])
        )
    conn.commit()
    print(f"Encrypted {len(rows)} rows in auth_logs.")
    cursor.close()
    update_cursor.close()
    conn.close()

if __name__ == "__main__":
    main() 