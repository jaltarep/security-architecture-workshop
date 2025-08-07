import nacl.pwhash
import nacl.utils
import nacl.secret
import base64
import getpass
import time
import resource
import os

# Constants
KEY_SIZE = 32
SALT_SIZE = nacl.pwhash.argon2id.SALTBYTES
NONCE_SIZE = nacl.secret.SecretBox.NONCE_SIZE


def derive_key(password: str, salt: bytes) -> bytes:
    return nacl.pwhash.argon2id.kdf(
        KEY_SIZE,
        password.encode(),
        salt,
        opslimit=nacl.pwhash.argon2id.OPSLIMIT_MODERATE,
        memlimit=nacl.pwhash.argon2id.MEMLIMIT_MODERATE
    )

def encrypt_file(input_path: str, password: str):
    if not os.path.exists(input_path):
        print(f"❌ File not found: {input_path}")
        return

    with open(input_path, "rb") as f:
        data = f.read()

    print(f"\n📦 Loaded file: {input_path} ({len(data)} bytes)")

    salt = nacl.utils.random(SALT_SIZE)
    nonce = nacl.utils.random(NONCE_SIZE)

    print("\n🔐 Deriving key...")
    
    key = derive_key(password, salt)
    

    box = nacl.secret.SecretBox(key)
    encrypted = box.encrypt(data, nonce)

    output_path = input_path + ".bin"
    with open(output_path, "wb") as f:
        f.write(salt + encrypted.nonce + encrypted.ciphertext)

    print(f"{salt = } {encrypted.nonce =} ")
    print(f"\n✅ Encrypted file saved to: {output_path}")
    print(f"📄 Encrypted size: {len(salt + encrypted.nonce + encrypted.ciphertext)} bytes")

def decrypt_file(encrypted_path: str, password: str):
    if not os.path.exists(encrypted_path):
        print(f"❌ File not found: {encrypted_path}")
        return

    with open(encrypted_path, "rb") as f:
        blob = f.read()

    if len(blob) < SALT_SIZE + NONCE_SIZE:
        print("❌ Encrypted file too short or corrupted.")
        return

    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = blob[SALT_SIZE + NONCE_SIZE:]

    print("\n🔓 Deriving key for decryption...")
    key = derive_key(password, salt)

    try:
        box = nacl.secret.SecretBox(key)
        decrypted = box.decrypt(ciphertext, nonce)

        # Remove .bin extension to get original file name
        if encrypted_path.endswith(".bin"):
            output_path = encrypted_path[:-4]
        else:
            output_path = encrypted_path + ".decrypted"

        with open(output_path, "wb") as f:
            f.write(decrypted)

        print(f"\n✅ Decrypted file saved to: {output_path}")
    except Exception as e:
        print(f"❌ Decryption failed: {e}")

def main():
    print("Select mode:\n1. Encrypt\n2. Decrypt")
    mode = input("Choice (1/2): ").strip()
    if mode == "1":
        path = input("Enter path to file: ").strip()
        password = getpass.getpass("Enter password: ")
        encrypt_file(path, password)
    elif mode == "2":
        path = input("Enter path to .bin file: ").strip()
        password = getpass.getpass("Enter password for decryption: ")
        decrypt_file(path, password)
    else:
        print("❌ Invalid choice.")

if __name__ == "__main__":
    main()
