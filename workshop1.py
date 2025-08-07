import getpass
import nacl.pwhash
import nacl.secret
import nacl.utils
import base64
import json

# Constants
KEY_SIZE = nacl.secret.SecretBox.KEY_SIZE #32 
SALT_SIZE = nacl.pwhash.argon2id.SALTBYTES #16
NONCE_SIZE = nacl.secret.SecretBox.NONCE_SIZE #24

def derive_key(password: str, salt: bytes) -> bytes:
    return nacl.pwhash.argon2id.kdf(
        KEY_SIZE,
        password.encode('utf-8'),
        salt,
        opslimit=nacl.pwhash.argon2id.OPSLIMIT_MODERATE,
        memlimit=nacl.pwhash.argon2id.MEMLIMIT_MODERATE
    )

def main():
    salt = nacl.utils.random(SALT_SIZE)
    password = getpass.getpass("Enter password: ")
    key = derive_key(password,salt)
    print (f"Derived {key = } and {salt = }")

    
if __name__ == "__main__":
    main()

'''
Important 
NACL Documentation : https://pynacl.readthedocs.io/en/latest/secret/#nonce


Key
The 32 bytes key given to SecretBox or Aead must be kept secret. 
It is the combination to your “safe” and anyone with this key will be able to decrypt the data, or encrypt new data.



NONCE
The 24-byte nonce (Number used once) given to encrypt(), decrypt(), encrypt() and decrypt() must NEVER be reused for a particular key.
Reusing a nonce may give an attacker enough information to decrypt or forge other messages. 
A nonce is not considered secret and may be freely transmitted or stored in plaintext alongside the ciphertext.



'''