import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib

# Function to generate Diffie-Hellman parameters for key exchange
def generate_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    return parameters

# Function to generate a key pair for DH
def generate_dh_keypair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

# Function to perform DH key exchange and derive a shared key
def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(dh.ECDH(), peer_public_key)
    return shared_key

# Function to generate AES key from the shared key
def generate_aes_key(shared_key):
    # Use PBKDF2 or scrypt to derive an AES key
    return scrypt(shared_key, salt=b'salt', key_len=32, N=2**14, r=8, p=1)

# Function to encrypt the message using AES (CBC mode)
def encrypt_message(aes_key, message):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext

# Function to decrypt the message using AES (CBC mode)
def decrypt_message(aes_key, ciphertext):
    iv = ciphertext[:16]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
    return decrypted_message.decode()

# Main function to simulate the FantomCRYPT protocol
def fantomcrypt_protocol():
    # Step 1: Generate DH parameters and key pairs for both parties
    parameters = generate_dh_parameters()
    
    # Alice's key pair
    alice_private_key, alice_public_key = generate_dh_keypair(parameters)
    
    # Bob's key pair
    bob_private_key, bob_public_key = generate_dh_keypair(parameters)
    
    # Step 2: Perform the Diffie-Hellman exchange to derive the shared keys
    alice_shared_key = derive_shared_key(alice_private_key, bob_public_key)
    bob_shared_key = derive_shared_key(bob_private_key, alice_public_key)
    
    # Step 3: Derive AES keys from the shared keys (both should be the same)
    alice_aes_key = generate_aes_key(alice_shared_key)
    bob_aes_key = generate_aes_key(bob_shared_key)
    
    # Step 4: Alice sends an encrypted message to Bob
    message_to_encrypt = input("Enter message to encrypt: ")
    encrypted_message = encrypt_message(alice_aes_key, message_to_encrypt)
    
    print(f"Encrypted message: {encrypted_message.hex()}")
    
    # Step 5: Bob decrypts the message
    decrypted_message = decrypt_message(bob_aes_key, encrypted_message)
    
    print(f"Decrypted message: {decrypted_message}")

# Run the FantomCRYPT protocol
fantomcrypt_protocol()
