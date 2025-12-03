# 🔐  Encrypted Password Manager (Python)

## This project is a command-line encrypted password manager built in Python. It securely stores login credentials using modern cryptography techniques. All passwords are kept inside an encrypted vault, and the master password is never stored in plain text. 

## 🚀 MAIN FEATURES:

### 🔑 Master Account Security:

####   - Master passwords are hashed using SHA-256.
####   - Each account includes a unique random salt.
####   - A secure key is derived using PBKDF2-HMAC-SHA256 with 100k iterations.
### 🔒 Encrypted Password Vault:
####   - All stored login credentials are encrypted using Fernet (AES-based encryption).
####   - Vault data inside accounts.json appears only as unreadable encrypted text.
####   - The vault is decrypted only after a successful login.
### 📁 Password Management:
####   - Ability to add new website/app credentials.
####   - View saved passwords (after decryption).
####   - Delete entries securely.
### 💾 Local Storage:
####    - The file accounts.json holds encrypted user data.
####    - No plaintext passwords ever appear in storage.
## 🧪 TECHNOLOGIES USED:
####   - Python 3.14.0
####   - hashlib (SHA-256 hashing)
####   - cryptography (Fernet + PBKDF2HMAC)
####   - getpass (hidden password input)
####   - json (local storage)
####   - os / base64 (salt generation + encoding)
## ⚙️ INSTALLATION️:
####   - Install required packages:
####   - In your terminal ---> pip install cryptography
####   - Ensure Python 3.x is installed correctly.
####   - Run the script using:
  ####     "python3 NAME_OF_FILE.py"
## ✅ HOW TO USE:
###   - Start the program:
####     Run script, "python3 NAME_OF_FILE.py"
####  You will see:
#####   - 1) Create account
#####   - 2) Login
#####   - 0) Exit
####  After creating an account and logging in, you gain access to your encrypted vault:
#####  - 1) Add new password
#####   - 2) View saved passwords
#####   - 3) Delete password
#####   - 0) Logout
###   Preview Example Below to visually understand how the manager works in a terminal.
## 📸 Picture Example:
##### <img width="3024" height="1802" alt="Image" src="https://github.com/user-attachments/assets/a96d32ee-9936-40de-9ba9-cb259813c2e6" />

## 🚨 HOW SECURITY WORKS:
###    Master Password Hashing:
####   - SHA-256 is used to hash the master password.
####   - The hash is stored, never the real password.
###   Key Derivation:
####   -  A random 16-byte salt is created per user.
####   - PBKDF2-HMAC-SHA256 derives a 32-byte encryption key.
####   - 100,000 iterations slow down brute-force attacks.
###   Vault Encryption:
####   - Your password entries are converted to JSON.
####   - The JSON is encrypted using Fernet (AES + HMAC).
####   - The encrypted result is saved to accounts.json.
####   - Only your correct master password can generate the proper decryption key.
## 📂 FILE STRUCTURE:
####   - password_manager.py – main application
####   - accounts.json – encrypted data storage

## 🔒 File Encryption and Hashing:
##### <img width="3024" height="680" alt="Image" src="https://github.com/user-attachments/assets/a39b2604-852a-42de-b86c-7aeb6cf69fa1" />

## 🎥 Video Example:

## 📄 Licensing:
This project may be freely modified and used for learning or personal use. You may access the code from this repository.
