import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
from cryptography.hazmat.primitives import hashes

# Step 1: Key Exchange using ECDH (X25519)
def generate_private_key():
    return x25519.X25519PrivateKey.generate()

def generate_shared_key(private_key, peer_public_key):
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
    shared_key = private_key.exchange(peer_public_key)
    return shared_key

# Step 2: Key Derivation using HKDF
def derive_keys(shared_key):
    # Derive multiple keys from shared secret using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,  # This will give us two 32-byte keys
        salt=None,
        info=b"fantomcrypt",
    )
    return hkdf.derive(shared_key)

# Step 3: AES Encryption (GCM Mode)
def aes_encrypt(key, plaintext):
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(nonce + encryptor.tag + ciphertext).decode()

def aes_decrypt(key, encrypted_text):
    encrypted_data = base64.b64decode(encrypted_text.encode())
    nonce, tag, ciphertext = encrypted_data[:12], encrypted_data[12:28], encrypted_data[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Step 4: Double Ratchet (Key Update and Ratchet)
def update_ratchet_key(shared_key, ratchet_key):
    # Update key using a simple hash function (e.g., SHA256 or something more complex)
    return hashlib.sha256(shared_key + ratchet_key).digest()

# Example usage of the above steps
def phantomcrypt():
    # Key exchange: Alice and Bob generate private keys and exchange public keys securely
    alice_private_key = generate_private_key()
    bob_private_key = generate_private_key()

    # Bob and Alice exchange public keys (over a secure channel)
    alice_shared_key = generate_shared_key(alice_private_key, bob_private_key.public_key().public_bytes())
    bob_shared_key = generate_shared_key(bob_private_key, alice_private_key.public_key().public_bytes())

    # Derive session keys
    alice_session_keys = derive_keys(alice_shared_key)
    bob_session_keys = derive_keys(bob_shared_key)

    # Update ratchet keys
    alice_ratchet_key = update_ratchet_key(alice_shared_key, alice_session_keys[0])
    bob_ratchet_key = update_ratchet_key(bob_shared_key, bob_session_keys[0])

    # Encrypt and Decrypt messages using AES
    message = input("Enter message to encrypt: ")
    encrypted_message = aes_encrypt(alice_session_keys[0], message)
    print(f"Encrypted message: {encrypted_message}")
    decrypted_message = aes_decrypt(bob_session_keys[0], encrypted_message)
    print(f"Decrypted message: {decrypted_message}")

if __name__ == "__main__":
    phantomcrypt()
