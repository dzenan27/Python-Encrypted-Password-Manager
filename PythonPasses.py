import hashlib
import getpass
import json
import os
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

DATA_FILE = "accounts.json"

# ---------- FILE HANDLING ----------

def load_accounts():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_accounts(accounts):
    with open(DATA_FILE, "w") as f:
        json.dump(accounts, f, indent=4)

accounts = load_accounts()

# ---------- SECURITY HELPERS ----------

def hash_password(password: str) -> str:
    """Hash the master password (for login verification only)."""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_salt() -> bytes:
    return os.urandom(16)

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a key from password+salt and make it Fernet-compatible."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)

def encrypt_vault(vault, key: bytes) -> str:
    """Encrypt the vault (a Python list) to a string token."""
    f = Fernet(key)
    data = json.dumps(vault).encode()
    token = f.encrypt(data)
    return token.decode()

def decrypt_vault(token: str, key: bytes):
    """Decrypt the vault string token back into a Python list."""
    if not token:
        return []
    f = Fernet(key)
    data = f.decrypt(token.encode())
    return json.loads(data.decode())

# ---------- ACCOUNT (MASTER LOGIN) ----------

def create_account():
    username = input("Choose a username: ").strip()
    if username in accounts:
        print("That username already exists.")
        return

    password = getpass.getpass("Choose a master password: ")
    confirm = getpass.getpass("Confirm master password: ")

    if password != confirm:
        print("Passwords do not match.")
        return

    salt = generate_salt()
    key = derive_key(password, salt)

    # start with empty encrypted vault
    empty_vault = []
    encrypted_vault = encrypt_vault(empty_vault, key)

    accounts[username] = {
        "password_hash": hash_password(password),              # hashed master password
        "salt": base64.b64encode(salt).decode(),               # base64 salt
        "vault": encrypted_vault                               # ENCRYPTED vault
    }

    save_accounts(accounts)
    print("Account created successfully!")

def login():
    username = input("Username: ").strip()
    if username not in accounts:
        print("No such user.")
        return None, None

    password = getpass.getpass("Master password: ")
    hashed = hash_password(password)

    if hashed != accounts[username]["password_hash"]:
        print("Invalid password.")
        return None, None

    salt_b64 = accounts[username]["salt"]
    salt = base64.b64decode(salt_b64)
    key = derive_key(password, salt)

    print(f"Login successful. Welcome, {username}!")
    return username, key

# ---------- VAULT (INSIDE MASTER ACCOUNT) ----------

def load_vault(username, key):
    token = accounts[username].get("vault", "")
    if not token:
        return []
    return decrypt_vault(token, key)

def save_vault(username, key, vault):
    token = encrypt_vault(vault, key)
    accounts[username]["vault"] = token
    save_accounts(accounts)

def add_entry(username, key):
    vault = load_vault(username, key)

    label = input("Site/App name (e.g., Gmail, Amazon): ").strip()
    acc_username = input("Username/email for that site: ").strip()
    acc_password = input("Password for that site: ").strip()

    entry = {
        "label": label,
        "username": acc_username,
        "password": acc_password  # stays in plaintext INSIDE ENCRYPTED VAULT
    }

    vault.append(entry)
    save_vault(username, key, vault)
    print("Entry saved!")

def view_entries(username, key):
    vault = load_vault(username, key)
    if not vault:
        print("No saved passwords yet.")
        return

    print("\nYour saved passwords:")
    for i, entry in enumerate(vault, start=1):
        print(f"{i}. {entry['label']}")
        print(f"   Username: {entry['username']}")
        print(f"   Password: {entry['password']}")
    print()

def delete_entry(username, key):
    vault = load_vault(username, key)
    if not vault:
        print("No entries to delete.")
        return

    print("\nWhich entry do you want to delete?")
    for i, entry in enumerate(vault, start=1):
        print(f"{i}. {entry['label']} ({entry['username']})")

    choice = input("Enter number (or 0 to cancel): ").strip()
    if not choice.isdigit():
        print("Invalid choice.")
        return

    idx = int(choice)
    if idx == 0:
        print("Cancelled.")
        return

    if 1 <= idx <= len(vault):
        removed = vault.pop(idx - 1)
        save_vault(username, key, vault)
        print(f"Deleted entry: {removed['label']}")
    else:
        print("Invalid number.")

def user_menu(username, key):
    while True:
        print(f"\n=== {username}'s Password Vault ===")
        print("1) Add new password")
        print("2) View saved passwords")
        print("3) Delete a password")
        print("0) Logout")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            add_entry(username, key)
        elif choice == "2":
            view_entries(username, key)
        elif choice == "3":
            delete_entry(username, key)
        elif choice == "0":
            print("Logging out...")
            break
        else:
            print("Invalid choice.")

# ---------- MAIN MENU ----------

def main():
    while True:
        print("\n=== Encrypted Password Manager ===")
        print("1) Create account")
        print("2) Login")
        print("0) Exit")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            create_account()
        elif choice == "2":
            username, key = login()
            if username and key:
                user_menu(username, key)
        elif choice == "0":
            print("Goodbye!")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()

