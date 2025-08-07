import os
import struct
import getpass
from nacl import pwhash, secret, utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

'''
Blob
[ 16 bytes salt ]
[ 4 bytes encrypted_key_len ]
[ encrypted_key bytes ]
[ 4 bytes ciphertext_len ]
[ ciphertext bytes ]
'''

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key using libsodium's Argon2id."""
    return pwhash.argon2id.kdf(
        secret.SecretBox.KEY_SIZE,
        password.encode(),
        salt,
        opslimit=pwhash.argon2id.OPSLIMIT_MODERATE,
        memlimit=pwhash.argon2id.MEMLIMIT_MODERATE
    )


def encrypt_file(file_path: str, key: bytes) -> bytes:
    """Encrypt file with XChaCha20-Poly1305 using libsodium."""
    box = secret.SecretBox(key)
    with open(file_path, "rb") as f:
        plaintext = f.read()
    nonce = utils.random(secret.SecretBox.NONCE_SIZE)
    ciphertext = box.encrypt(plaintext, nonce)  # includes nonce
    return ciphertext


def encrypt_key_with_rsa(sym_key: bytes, public_key_pem: bytes) -> bytes:
    """Encrypt symmetric key with RSA public key."""
    public_key = serialization.load_pem_public_key(public_key_pem)
    return public_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


if __name__ == "__main__":
    # Step 1: Password → symmetric key
    password = getpass.getpass("Enter password for encryption: ")
    salt = utils.random(pwhash.argon2id.SALTBYTES)
    sym_key = derive_key(password, salt)

    # Step 2: Encrypt the file
    file_path = input("Enter file path to encrypt: ")
    ciphertext = encrypt_file(file_path, sym_key)

    # Step 3: Encrypt the symmetric key with RSA
    pub_key_path = input("Enter RSA public key (.pem) path: ")
    with open(pub_key_path, "rb") as f:
        pub_key_pem = f.read()
    encrypted_sym_key = encrypt_key_with_rsa(sym_key, pub_key_pem)

    # Step 4: Write binary package
    output_file = file_path + ".package.bin"
    with open(output_file, "wb") as f:
        f.write(salt)
        f.write(struct.pack(">I", len(encrypted_sym_key)))
        f.write(encrypted_sym_key)
        f.write(struct.pack(">I", len(ciphertext)))
        f.write(ciphertext)

    print(f"Encrypted binary package saved to: {output_file}")
