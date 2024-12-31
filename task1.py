# Different kind of encryption 

from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64

# --- AES Implementation ---
def pad(text, block_size):
    while len(text) % block_size != 0:
        text += ' '
    return text

def aes_encrypt(key, text):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)  # ECB Mode
    encrypted = cipher.encrypt(pad(text, 16).encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def aes_decrypt(key, encrypted_text):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_text))
    return decrypted.decode('utf-8').strip()

# --- DES Implementation ---
def des_encrypt(key, text):
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)  # ECB Mode
    encrypted = cipher.encrypt(pad(text, 8).encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def des_decrypt(key, encrypted_text):
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_text))
    return decrypted.decode('utf-8').strip()

# --- RSA Implementation ---
def rsa_generate_keys():
    key_pair = RSA.generate(2048)
    return key_pair.publickey().export_key(), key_pair.export_key()

def rsa_encrypt(public_key, text):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted = cipher.encrypt(text.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def rsa_decrypt(private_key, encrypted_text):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_text))
    return decrypted.decode('utf-8')

# --- Main Program ---
def main():
    print("Choose Encryption Algorithm:")
    print("1. AES")
    print("2. DES")
    print("3. RSA")
    choice = int(input("Enter your choice: "))

    if choice == 1:
        print("\n--- AES Encryption/Decryption ---")
        key = input("Enter a 16-character key for AES: ")
        if len(key) != 16:
            print("Error: AES key must be exactly 16 characters.")
            return
        text = input("Enter text to encrypt: ")
        encrypted = aes_encrypt(key, text)
        print(f"Encrypted: {encrypted}")
        decrypted = aes_decrypt(key, encrypted)
        print(f"Decrypted: {decrypted}")

    elif choice == 2:
        print("\n--- DES Encryption/Decryption ---")
        key = input("Enter an 8-character key for DES: ")
        if len(key) != 8:
            print("Error: DES key must be exactly 8 characters.")
            return
        text = input("Enter text to encrypt: ")
        encrypted = des_encrypt(key, text)
        print(f"Encrypted: {encrypted}")
        decrypted = des_decrypt(key, encrypted)
        print(f"Decrypted: {decrypted}")

    elif choice == 3:
        print("\n--- RSA Encryption/Decryption ---")
        print("Generating RSA Keys...")
        public_key, private_key = rsa_generate_keys()
        print(f"Public Key:\n{public_key.decode('utf-8')}")
        print(f"Private Key:\n{private_key.decode('utf-8')}")
        text = input("Enter text to encrypt: ")
        encrypted = rsa_encrypt(public_key, text)
        print(f"Encrypted: {encrypted}")
        decrypted = rsa_decrypt(private_key, encrypted)
        print(f"Decrypted: {decrypted}")

    else:
        print("Invalid choice. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()
