import nacl.pwhash
import nacl.utils
import getpass
import time
import base64
import resource  # For measuring memory usage (Unix only)

# Constants
KEY_SIZE = 32  # 256-bit key
SALT_SIZE = nacl.pwhash.argon2id.SALTBYTES

def derive_key(password: str, salt: bytes, opslimit, memlimit) -> bytes:
    return nacl.pwhash.argon2id.kdf(
        KEY_SIZE,
        password.encode('utf-8'),
        salt,
        opslimit=opslimit,
        memlimit=memlimit
    )

def print_memory_usage(note=""):
    usage_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # On Linux ru_maxrss is in KB; on macOS it's in bytes
    usage_mb = usage_kb / (1024 if not is_macos() else (1024 * 1024))
    print(f"🧠 Memory used{note}: {usage_mb:.2f} MB")

def is_macos():
    import platform
    return platform.system() == "Darwin"

def test_min_settings(password: str, salt: bytes):
    print("\n🔽 Deriving key with MINIMUM settings...")
    start = time.perf_counter()
    key = derive_key(password, salt, nacl.pwhash.argon2id.OPSLIMIT_MIN, nacl.pwhash.argon2id.MEMLIMIT_MIN)
    elapsed = time.perf_counter() - start
    print("🔐 Key (base64):", base64.b64encode(key).decode())
    print(f"⏱️ Time taken (min): {elapsed:.6f} seconds")
    print_memory_usage(" (MIN)")

def test_moderate_settings(password: str, salt: bytes):
    print("\n⚖️ Deriving key with MODERATE settings...")
    start = time.perf_counter()
    key = derive_key(password, salt, nacl.pwhash.argon2id.OPSLIMIT_MODERATE, nacl.pwhash.argon2id.MEMLIMIT_MODERATE)
    elapsed = time.perf_counter() - start
    print("🔐 Key (base64):", base64.b64encode(key).decode())
    print(f"⏱️ Time taken (moderate): {elapsed:.6f} seconds")
    print_memory_usage(" (MODERATE)")

def test_max_settings(password: str, salt: bytes):
    print("\n🔼 Deriving key with MAXIMUM settings (this may take a while)...")
    start = time.perf_counter()
    key = derive_key(password, salt, nacl.pwhash.argon2id.OPSLIMIT_SENSITIVE, nacl.pwhash.argon2id.MEMLIMIT_SENSITIVE)
    elapsed = time.perf_counter() - start
    print("🔐 Key (base64):", base64.b64encode(key).decode())
    print(f"⏱️ Time taken (max): {elapsed:.6f} seconds")
    print_memory_usage(" (MAX)")

def main():
    password = getpass.getpass("Enter password: ")
    print (f"The entered {password = }")
    salt = nacl.utils.random(SALT_SIZE)
    print("\n🧂 Salt (base64):", base64.b64encode(salt).decode())

    test_min_settings(password, salt)
    test_moderate_settings(password, salt)
    test_max_settings(password, salt)

if __name__ == "__main__":
    main()
