# Authentication Table Encryption with CBC Mode

This project demonstrates how to encrypt sensitive fields in a MySQL authentication table using AES in CBC mode. It encrypts IP addresses, usernames, and login status while preserving the ability to decrypt the data when needed.

## Features

- Connects to MySQL database
- Creates and populates sample authentication data if needed
- Encrypts sensitive fields using AES-256 in CBC mode
- Displays data before encryption, after encryption, and after decryption
- Uses random initialization vectors (IVs) for each encryption operation
- Securely stores the encryption key

## Prerequisites

- Python 3.6+
- MySQL database
- Required Python packages

## Installation

1. Clone this repository or download the script

2. Install required dependencies:

```bash
pip install pycryptodome mysql-connector-python tabulate
```

3. Update the database configuration in `encrypt_auth_table.py`:

```python
DB_CONFIG = {
    'host': 'localhost',
    'user': 'your_username',
    'password': 'your_password',
    'database': 'your_database'
}
```

## Usage

Run the script:

```bash
python encrypt_auth_table.py
```

The script will:
- Connect to your database
- Create the auth_table with sample data if it doesn't exist
- Display the original data
- Encrypt sensitive fields using CBC encryption
- Display the encrypted data
- Decrypt and display the data to verify it works correctly

## How It Works

### Encryption Process

1. **Key Generation**: A 256-bit (32-byte) key is generated for AES encryption and saved to `encryption.key`

2. **CBC Encryption**:
   - For each field to encrypt, a random 16-byte initialization vector (IV) is generated
   - The data is padded to a multiple of the AES block size (16 bytes)
   - The data is encrypted using AES in CBC mode
   - The IV is prepended to the ciphertext and the result is base64 encoded

3. **Database Storage**:
   - Encrypted values are stored in dedicated columns (`source_ip_encrypted`, `username_encrypted`, `status_encrypted`)
   - Original data is preserved for comparison

4. **Decryption Process**:
   - The base64-encoded data is decoded
   - The IV is extracted from the first 16 bytes
   - The remainder is decrypted using the same key and the extracted IV
   - Padding is removed and the result is converted back to a string

### CBC Mode Security

CBC (Cipher Block Chaining) provides better security than ECB mode by:
- Using an IV to randomize the encryption, even for identical plaintexts
- Chaining blocks together so each encrypted block depends on previous blocks
- Preventing pattern recognition in the encrypted data

## Example Output

```
Connected to database successfully
Generated new encryption key

==== BEFORE ENCRYPTION ====

--- Original Data ---
+----+---------------------+-----------------+----------+---------+------------+
| ID | Timestamp           | Source IP       | Username | Status  | PWD Length |
+====+=====================+=================+==========+=========+============+
| 1  | 2025-06-12 17:38:16 | 106.251.104.146 | admin    | success | 344        |
+----+---------------------+-----------------+----------+---------+------------+
| 2  | 2025-06-12 17:38:16 | 63.16.140.27    | admin    | success | 344        |
+----+---------------------+-----------------+----------+---------+------------+
| 3  | 2025-06-12 17:38:17 | 87.242.236.35   | root     | success | 344        |
+----+---------------------+-----------------+----------+---------+------------+
| 4  | 2025-06-12 17:38:17 | 6.45.76.6       | root     | success | 344        |
+----+---------------------+-----------------+----------+---------+------------+
| 5  | 2025-06-12 17:38:18 | 240.74.128.5    | admin    | success | 344        |
+----+---------------------+-----------------+----------+---------+------------+

--- Encrypted Data ---
+----+---------------------+----------------------+----------------------+----------------------+------------+
| ID | Timestamp           | Encrypted IP         | Encrypted Username   | Encrypted Status     | PWD Length |
+====+=====================+======================+======================+======================+============+
| 1  | 2025-06-12 17:38:16 | Hj8kLm9pRuT7aBcD... | PqR5tUvWxYz2AbCd... | XyZ1aBcDeFgHiJkL... | 344        |
+----+---------------------+----------------------+----------------------+----------------------+------------+
| 2  | 2025-06-12 17:38:16 | 7aBcDeFgHiJkLm9p... | ZxYwVuTsRqPoNmLk... | JiHgFeDcBaZ9yXwV... | 344        |
+----+---------------------+----------------------+----------------------+----------------------+------------+
| 3  | 2025-06-12 17:38:17 | 3eDcBaZ9yXwVuTsR... | KjHgFeDcBaZ9yXwV... | PoNmLkJiHgFeDcBa... | 344        |
+----+---------------------+----------------------+----------------------+----------------------+------------+
| 4  | 2025-06-12 17:38:17 | QpOnMlKjIhGfEdCb... | TsRqPoNmLkJiHgFe... | LkJiHgFeDcBaZ9yX... | 344        |
+----+---------------------+----------------------+----------------------+----------------------+------------+
| 5  | 2025-06-12 17:38:18 | BaZ9yXwVuTsRqPoN... | EdCbAz9yXwVuTsRq... | CbAz9yXwVuTsRqPo... | 344        |
+----+---------------------+----------------------+----------------------+----------------------+------------+

==== AFTER ENCRYPTION ====
Encrypted 5 records in auth_table

==== DECRYPTION TEST ====

--- Decrypted Data ---
+----+---------------------+-----------------+----------+---------+------------+
| ID | Timestamp           | Decrypted IP    | Decrypted Username | Decrypted Status | PWD Length |
+====+=====================+=================+==========+=========+============+
| 1  | 2025-06-12 17:38:16 | 106.251.104.146 | admin    | success | 344        |
+----+---------------------+-----------------+----------+---------+------------+
| 2  | 2025-06-12 17:38:16 | 63.16.140.27    | admin    | success | 344        |
+----+---------------------+-----------------+----------+---------+------------+
| 3  | 2025-06-12 17:38:17 | 87.242.236.35   | root     | success | 344        |
+----+---------------------+-----------------+----------+---------+------------+
| 4  | 2025-06-12 17:38:17 | 6.45.76.6       | root     | success | 344        |
+----+---------------------+-----------------+----------+---------+------------+
| 5  | 2025-06-12 17:38:18 | 240.74.128.5    | admin    | success | 344        |
+----+---------------------+-----------------+----------+---------+------------+

Encryption process completed successfully
```

## Security Considerations

- **Key Management**: In production, use a proper key management system instead of storing the key in a file
- **Sensitive Data**: Consider removing the original plaintext columns after encryption is verified
- **Access Control**: Implement proper access controls for the database and encryption key
- **Authentication**: For production use, consider adding data authentication (HMAC) to detect tampering

## Quick Start Copy-Paste Commands

```bash
# Install required packages
pip install pycryptodome mysql-connector-python tabulate

# Edit database configuration in encrypt_auth_table.py
# Then run:
python encrypt_auth_table.py
```

## Database Schema

The script creates a table with this structure:

```sql
CREATE TABLE auth_table (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME,
    source_ip VARCHAR(50),
    username VARCHAR(50),
    status VARCHAR(20),
    pwd_length INT,
    source_ip_encrypted TEXT,
    username_encrypted TEXT,
    status_encrypted TEXT
);
```

Sample data from your auth log is automatically populated if the table is empty.