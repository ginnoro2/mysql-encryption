# Database Encryption & Decryption Guide for auth_logs

This guide explains how to encrypt sensitive columns in your `auth_logs` table, verify the encrypted data, and decrypt it for viewing. It includes all necessary scripts and step-by-step instructions.

---

## 1. Prerequisites

- Python 3.8+
- MySQL server running (e.g., via Docker Compose)
- Python packages:
  - `pycryptodome`
  - `mysql-connector-python`

Install dependencies if needed:
~~~bash
pip install pycryptodome mysql-connector-python
~~~

Start Container
```bash
docker-compose up -d mysql
docker ps
```
---
---

## 3. Encrypt Data: `encrypt_auth_logs.py`

This script encrypts the `source_ip`, `username`, and `status` columns in `auth_logs` and stores the encrypted values in new columns.

### Script: `encrypt_auth_logs.py`
```python
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
```

### How to Run
~~~bash
python3 encrypt_auth_logs.py
~~~

### Check the Encrypted Data
Show the encrypted columns:
~~~bash
docker-compose exec mysql mysql -u root -pyour_password -e "USE ssh_logs; SELECT id, source_ip_encrypted, username_encrypted, status_encrypted FROM auth_logs LIMIT 10;"
~~~
### Expected Output 
```bash
+----+----------------------------------------------+----------------------------------------------+----------------------------------------------+
| id | source_ip_encrypted                          | username_encrypted                           | status_encrypted                             |
+----+----------------------------------------------+----------------------------------------------+----------------------------------------------+
|  1 | TulsCXGYD4sAi2CYPMPsV+LqVhk+2CIbvXRbmGMSaqY= | qfhcGz3yBh5WE2E9jOuhGikiO0YH+Fmv18MRa/VCKrQ= | 20l75uxNr3e8kh01qNNjcTMQv8rozmkOVE/mLz5C4CY= |
|  2 | NHEZakvhoFWDgd5GgMIcP2ysOc5908jj+HwO1h9g4yE= | cg8q3ig1Ebed2IZGgEx2yOelXGEsALZsgxX/wfPiH0c= | 2ygyMmMYHq6rl521U1buFANnglgq/XQtrYokDFgnGwA= |
|  3 | k9yIY0QcddltCjLKqzPcDlkNrv/ViDTUq7Cfz5+E/ZE= | V75KWPVTpeeJQTC5T0y87KGPmDhh1NayVB6m2nRUlB8= | K3BxlsllrJdKZOhc0uR3DEAoJbPHBYEYk41cuo8O8SM= |
|  4 | 1Rw3t2X7PUvbEOaqboP5/Tj2Ivx/xWtXxYwNncXtn28= | 390paMZxRNeIQwg5IrMjTsWZC2U/7UL5lhWcEnSWAes= | p543hT2MJ5M8pEuJmw9YU34m9ruLCjzwT5zbnghAYiQ= |
|  5 | hHmTpO2uO1pCAs1WHwR38nzFuEtxI+cc46SL+Nnjyrw= | qEStWl1GvmStgPZiEKTfI7yQs6qEgkMtQ42rhJSAE38= | nxMEHb+xljjuxLLffXItngUO3eoe7FNb3sVwaTXI0wY= |
|  6 | EFCMIR0/FkhNBhUZixBYKstJqjbkgI7f3rn94HNQY/A= | iQS+f5YfxHWrYftqaF2GRKMtVny3Hv/gOjsuI4h4/fA= | 8JLshlohPrs4Bmy3BAvllVDMDR3FmGexOOujgIBf6uU= |
|  7 | xfJhrqFsc4y2YrjfLBlDzMElsNDxNmjpmV+GDKav+xw= | 2jw762FzbaUZ9A7/RBO8GSjRmnd/5CvhgsnQOyI7bSM= | 0xLh1bUjyXPLWP5Zu/JueVoG+hWG/WV0Dwe4DF76LT4= |
|  8 | bDDCCf97RWcks6EMWV23XZYcr7ma1Fjba5M0UBY+ots= | 95tWOEhN4o7lCqBOPxJKRvqo9x3ndI1chsUylWRRLkA= | 3IE7dDZffkp4p1hqkBnNzxNxL5wvKF545OgMMyF5AZ4= |
|  9 | VQaMuk7eIeFGLuxuWhHwReYbyD4hY5WlKhzryDoX6Fg= | M/oCLUl9Qsycg5SoWgRIYXNicTHH0sUBU0sNKUbzk2g= | mrP6WNtzbr36BOX7P4t7x1oRiSUH0n+T4pJcntqa0hU= |
| 10 | FIWTtDKrr4kkixUQbDbWj+NEDPZcW5/+pFFevYz2XPY= | MYNqiXgmY31lL/ROw8dYTaguR9vQwV5SxXCfhwXu1+8= | 2EPbGXn/41Qc07MOiVAF9ubh6zGXogMQntgmMgeTyfQ= |
+----+----------------------------------------------+----------------------------------------------+----------------------------------------------+
```
Show both original and encrypted columns:
~~~bash
docker-compose exec mysql mysql -u root -pyour_password -e "USE ssh_logs; SELECT id, source_ip, source_ip_encrypted, username, username_encrypted, status, status_encrypted FROM auth_logs LIMIT 5;"
~~~

---

## 4. Decrypt Data: `decrypt_auth_logs.py`

This script decrypts the encrypted columns and prints the original values.

### Script: `decrypt_auth_logs.py`
```python
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
```

### How to Run
~~~bash
python3 decrypt_auth_logs.py
~~~

### Example Output
```
ID   Decrypted IP         Decrypted Username Decrypted Status
------------------------------------------------------------
1    202.111.72.249       admin           success   
2    57.219.212.112       user            failed    
3    10.248.76.176        user            failed    
4    15.132.186.50        jenkins         success   
5    211.28.82.133        admin           success   
6    237.129.154.71       system          failed    
7    250.187.18.111       user            success   
8    218.253.30.210       jenkins         success   
9    97.241.24.118        admin           success   
10   45.194.31.33         ubuntu          success   
```

---

## 5. Troubleshooting

- Make sure the `encryption.key` file is present in your project directory (it is created automatically by the encryption script).
- Ensure your MySQL credentials in the scripts match your running database.
- If you get `ModuleNotFoundError`, install the required packages with `pip install pycryptodome mysql-connector-python`.

---

**You now have a workflow for encrypting and decrypting sensitive columns in your MySQL database!** 
