from Crypto.Cipher import DES, AES, DES3
from Crypto import Random
import hashlib
import binascii
import sys

# Function to adjust the key to the required size
def adjust_key(key, required_size):
    """
    Adjusts the key to the required size for the encryption algorithm.
    If the key is too short, it adds random bytes to make it the correct length.
    If the key is too long, it truncates the key to the required size.
    """
    if len(key) < required_size:
        key += Random.get_random_bytes(required_size - len(key))  # Add random bytes if key is too short
    elif len(key) > required_size:
        key = key[:required_size]  # Truncate key if it is too long
    return key

# Function to adjust the IV to the required size
def adjust_iv(iv, required_size):
    """
    Adjusts the IV to the required size for the encryption algorithm.
    If the IV is too short, it adds random bytes to make it the correct length.
    If the IV is too long, it truncates the IV to the required size.
    """
    if len(iv) < required_size:
        iv += Random.get_random_bytes(required_size - len(iv))  # Add random bytes if IV is too short
    elif len(iv) > required_size:
        iv = iv[:required_size]  # Truncate IV if it is too long
    return iv

# DES Encryption and Decryption
def encrypt_decrypt_des(key, iv, text):
    """
    Encrypts and decrypts the given text using DES in CBC mode.
    The text is padded to ensure it is a multiple of the block size (8 bytes).
    """
    cipher = DES.new(key, DES.MODE_CBC, iv)  # Create DES cipher object
    padding_length = 8 - (len(text) % 8)  # Calculate padding length
    text_padded = text + ' ' * padding_length  # Pad text with spaces
    encrypted_text = cipher.encrypt(text_padded.encode('utf-8'))  # Encrypt the padded text
    decipher = DES.new(key, DES.MODE_CBC, iv)  # Create DES decipher object
    decrypted_text = decipher.decrypt(encrypted_text).decode('utf-8').rstrip()  # Decrypt and remove padding
    return encrypted_text, decrypted_text

# AES-256 Encryption and Decryption
def encrypt_decrypt_aes(key, iv, text):
    """
    Encrypts and decrypts the given text using AES-256 in CBC mode.
    The text is padded to ensure it is a multiple of the block size (16 bytes).
    """
    if len(iv) != 16:
        raise ValueError("Incorrect IV length for AES (it must be 16 bytes long)")
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Create AES cipher object
    padding_length = 16 - (len(text) % 16)  # Calculate padding length
    text_padded = text + ' ' * padding_length  # Pad text with spaces
    encrypted_text = cipher.encrypt(text_padded.encode('utf-8'))  # Encrypt the padded text
    decipher = AES.new(key, AES.MODE_CBC, iv)  # Create AES decipher object
    decrypted_text = decipher.decrypt(encrypted_text).decode('utf-8').rstrip()  # Decrypt and remove padding
    return encrypted_text, decrypted_text

# 3DES Encryption and Decryption
def encrypt_decrypt_3des(key, iv, text):
    """
    Encrypts and decrypts the given text using 3DES in CBC mode.
    The text is padded to ensure it is a multiple of the block size (8 bytes).
    """
    if len(iv) != 8:
        raise ValueError("Incorrect IV length for 3DES (it must be 8 bytes long)")
    cipher = DES3.new(key, DES3.MODE_CBC, iv)  # Create 3DES cipher object
    padding_length = 8 - (len(text) % 8)  # Calculate padding length
    text_padded = text + ' ' * padding_length  # Pad text with spaces
    encrypted_text = cipher.encrypt(text_padded.encode('utf-8'))  # Encrypt the padded text
    decipher = DES3.new(key, DES3.MODE_CBC, iv)  # Create 3DES decipher object
    decrypted_text = decipher.decrypt(encrypted_text).decode('utf-8').rstrip()  # Decrypt and remove padding
    return encrypted_text, decrypted_text

# Main entry point
if __name__ == "__main__":
    # Get user input from command line arguments
    if len(sys.argv) != 6:
        print("Usage: python3 main.py <key> <iv_des> <iv_3des> <iv_aes> <text>")
        sys.exit(1)

    key = sys.argv[1].encode('utf-8')  # Convert key to bytes
    iv_des = binascii.unhexlify(sys.argv[2])  # Convert IV for DES from hex string to bytes
    iv_3des = binascii.unhexlify(sys.argv[3])  # Convert IV for 3DES from hex string to bytes
    iv_aes = binascii.unhexlify(sys.argv[4])  # Convert IV for AES from hex string to bytes
    text = sys.argv[5]  # Get the text to be encrypted

    try:
        # DES Encryption and Decryption
        key_des = adjust_key(key, 8)  # Adjust the key for DES (8 bytes)
        iv_des = adjust_iv(iv_des, 8)  # Adjust the IV for DES (8 bytes)
        print("\nKey used for DES:", key_des)
        print("IV used for DES:", iv_des)
        ciphertext, plaintext = encrypt_decrypt_des(key_des, iv_des, text)
        print("Encrypted text with DES:", binascii.hexlify(ciphertext).decode('utf-8'))
        print("Decrypted text with DES:", plaintext)

        # AES-256 Encryption and Decryption
        key_aes = adjust_key(key, 32)  # Adjust the key for AES-256 (32 bytes)
        iv_aes = adjust_iv(iv_aes, 16)  # Adjust the IV for AES (16 bytes)
        print("\nKey used for AES-256:", key_aes)
        print("IV used for AES-256:", iv_aes)
        ciphertext, plaintext = encrypt_decrypt_aes(key_aes, iv_aes, text)
        print("Encrypted text with AES-256:", binascii.hexlify(ciphertext).decode('utf-8'))
        print("Decrypted text with AES-256:", plaintext)

        # 3DES Encryption and Decryption
        key_3des = adjust_key(key, 24)  # Adjust the key for 3DES (24 bytes)
        iv_3des = adjust_iv(iv_3des, 8)  # Adjust the IV for 3DES (8 bytes)
        print("\nKey used for 3DES:", key_3des)
        print("IV used for 3DES:", iv_3des)
        ciphertext, plaintext = encrypt_decrypt_3des(key_3des, iv_3des, text)
        print("Encrypted text with 3DES:", binascii.hexlify(ciphertext).decode('utf-8'))
        print("Decrypted text with 3DES:", plaintext)
    
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
