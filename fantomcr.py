import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad
import base64

# Key Generator Function
def generate_keys(shared_secret: bytes):
    """
    Generate keys for AES192 encryption and HMAC-SHA256.
    The shared secret key is used to derive two keys.
    """
    # Derive AES-192 and HMAC keys from the shared secret using Scrypt KDF
    derived_key = scrypt(shared_secret, salt=b"unique_salt", key_len=48, N=16384, r=8, p=1)
    aes_key = derived_key[:24]  # First 24 bytes for AES-192
    hmac_key = derived_key[24:]  # Remaining 24 bytes for HMAC
    return aes_key, hmac_key

# AES192 Encryption Function
def encrypt_message(aes_key: bytes, message: str):
    """
    Encrypt the message using AES-192 encryption (CBC mode).
    """
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ciphertext = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ciphertext

# AES192 Decryption Function
def decrypt_message(aes_key: bytes, iv: str, ciphertext: str):
    """
    Decrypt the message using AES-192 encryption (CBC mode).
    """
    iv_bytes = base64.b64decode(iv)
    ct_bytes = base64.b64decode(ciphertext)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv_bytes)
    decrypted = unpad(cipher.decrypt(ct_bytes), AES.block_size)
    return decrypted.decode('utf-8')

# HMAC-SHA256 Authentication Function
def generate_hmac(hmac_key: bytes, message: str):
    """
    Generate an HMAC-SHA256 for message integrity and authentication.
    """
    hmac_obj = HMAC.new(hmac_key, msg=message.encode(), digestmod=SHA256)
    return hmac_obj.hexdigest()

# HMAC-SHA256 Verification Function
def verify_hmac(hmac_key: bytes, message: str, hmac_to_verify: str):
    """
    Verify the HMAC-SHA256 for message integrity.
    """
    calculated_hmac = generate_hmac(hmac_key, message)
    return hmac_to_verify == calculated_hmac

# Example Usage
def main():
    # Shared secret between client and server (for example, derived from passwords or other secure means)
    shared_secret = os.urandom(32)  # In a real application, use a secure method to generate this shared secret
    
    # Generate the AES-192 key and HMAC-SHA256 key
    aes_key, hmac_key = generate_keys(shared_secret)

    # Encryption
    print("Enter message to encrypt:")
    message_to_encrypt = input()
    iv, ciphertext = encrypt_message(aes_key, message_to_encrypt)
    print(f"Encrypted Message: {ciphertext}")
    
    # HMAC of the message
    message_hmac = generate_hmac(hmac_key, message_to_encrypt)
    print(f"HMAC of the Message: {message_hmac}")

    # Decryption
    print("Enter message to decrypt:")
    message_to_decrypt = input()
    decrypted_message = decrypt_message(aes_key, iv, message_to_decrypt)
    print(f"Decrypted Message: {decrypted_message}")
    
    # HMAC Verification
    print("Enter HMAC to verify:")
    hmac_to_verify = input()
    if verify_hmac(hmac_key, message_to_decrypt, hmac_to_verify):
        print("HMAC verification successful.")
    else:
        print("HMAC verification failed!")

if __name__ == '__main__':
    main()
