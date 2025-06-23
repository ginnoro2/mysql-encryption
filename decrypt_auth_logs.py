import mysql.connector
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'your_password',
    'database': 'ssh_logs'
}

def get_encryption_key():
    with open('encryption.key', 'rb') as f:
        return f.read()

def decrypt_cbc(ciphertext, key):
    if not ciphertext:
        return None
    raw_data = base64.b64decode(ciphertext)
    iv = raw_data[:AES.block_size]
    actual_ciphertext = raw_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(actual_ciphertext)
    return unpad(decrypted_padded, AES.block_size).decode('utf-8')

def main():
    key = get_encryption_key()
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT id, source_ip_encrypted, username_encrypted, status_encrypted FROM auth_logs LIMIT 10")
    rows = cursor.fetchall()
    print(f"{'ID':<4} {'Decrypted IP':<20} {'Decrypted Username':<15} {'Decrypted Status':<10}")
    print("-" * 60)
    for row in rows:
        ip = decrypt_cbc(row['source_ip_encrypted'], key)
        username = decrypt_cbc(row['username_encrypted'], key)
        status = decrypt_cbc(row['status_encrypted'], key)
        print(f"{row['id']:<4} {ip:<20} {username:<15} {status:<10}")

    cursor.close()
    conn.close()

if __name__ == "__main__":
    main() 