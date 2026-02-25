from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Generate a random 256-bit key
key = get_random_bytes(32)
cipher = AES.new(key, AES.MODE_GCM)

# Encrypt a message
plaintext = b"This is a secret message"
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

print(f"Plaintext:  {plaintext.decode()}")
print(f"Key:        {base64.b64encode(key).decode()}")
print(f"Nonce:      {base64.b64encode(cipher.nonce).decode()}")
print(f"Ciphertext: {base64.b64encode(ciphertext).decode()}")
print(f"Tag:        {base64.b64encode(tag).decode()}")

# Decrypt
decrypt_cipher = AES.new(key, AES.MODE_GCM, nonce=cipher.nonce)
decrypted = decrypt_cipher.decrypt_and_verify(ciphertext, tag)
print(f"Decrypted:  {decrypted.decode()}")