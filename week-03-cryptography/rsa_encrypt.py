from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# Generate RSA key pair
key = RSA.generate(2048)
public_key = key.publickey()

print(f"Private key size: {key.size_in_bits()} bits")
print(f"Public key:\n{public_key.export_key().decode()[:80]}...")

# Encrypt with public key
cipher = PKCS1_OAEP.new(public_key)
plaintext = b"RSA encrypted secret"
ciphertext = cipher.encrypt(plaintext)

print(f"\nPlaintext:  {plaintext.decode()}")
print(f"Ciphertext: {base64.b64encode(ciphertext).decode()[:80]}...")

# Decrypt with private key
decrypt_cipher = PKCS1_OAEP.new(key)
decrypted = decrypt_cipher.decrypt(ciphertext)
print(f"Decrypted:  {decrypted.decode()}")