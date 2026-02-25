\# Week 3: Cryptography Hands-On



\*\*MSCS Course Mapping:\*\* SE6003 — Cryptography



\## Objective



Implement symmetric and asymmetric encryption in Python, observe the TLS handshake in Wireshark, and perform hash cracking with Hashcat. This week builds a practical understanding of how encryption protects data in transit and at rest, and how weak password practices can be exploited.



\## Tools Used



\- Python 3 with PyCryptodome

\- Wireshark

\- Hashcat

\- Kali Linux



\## Exercises



\### 1. AES — Symmetric Encryption



Implemented AES-256-GCM encryption in Python. AES is symmetric, meaning the same key is used to both encrypt and decrypt data. It is the standard for bulk data encryption used in HTTPS, disk encryption, and WiFi security.



The script generates a random 256-bit key, encrypts a plaintext message into unreadable ciphertext, and then decrypts it back using the same key.



Key components:

\- \*\*Key (256-bit)\*\* — the shared secret both sides need

\- \*\*Nonce\*\* — a unique value per encryption to prevent identical plaintexts from producing identical ciphertexts

\- \*\*Ciphertext\*\* — the encrypted, unreadable output

\- \*\*Tag\*\* — an integrity check that proves the ciphertext hasn't been tampered with (this is what GCM mode provides)



\*\*Why AES-256-GCM:\*\* The 256-bit key length makes brute force infeasible, and GCM mode provides both confidentiality (encryption) and integrity (tamper detection) in a single operation.



!\[AES Output](https://github.com/rubentot/cybersec-portfolio/blob/main/week-03-cryptography/screenshots/aes.png?raw=true



\### 2. RSA — Asymmetric Encryption



Implemented RSA-2048 encryption in Python. RSA is asymmetric, using a key pair: a public key to encrypt and a private key to decrypt. This solves the key distribution problem — you can share your public key with anyone, but only you can decrypt messages with your private key.



The script generates a 2048-bit key pair, encrypts a message with the public key, and decrypts it with the private key.



\*\*Why this matters:\*\* RSA is used in the TLS handshake to securely exchange keys between a client and server who have never communicated before. The SSH key authentication set up in Week 1 uses the same principle — the public key lives on the server, the private key stays on the client.



\*\*AES vs RSA in practice:\*\* RSA is much slower than AES, so real-world systems use both together. RSA securely exchanges a shared secret, then AES handles the bulk encryption. This hybrid approach is exactly what TLS does.



!\[RSA Output](screenshots/rsa.png)



\### 3. TLS Handshake Analysis



Captured a TLS 1.3 handshake in Wireshark by connecting to `https://www.google.com`. TLS 1.3 combines the concepts from AES and RSA into a real-world protocol that secures virtually all web traffic.



The captured handshake shows:

\- \*\*Client Hello\*\* — the client sends supported ciphers and key exchange material

\- \*\*Server Hello, Change Cipher Spec\*\* — the server responds and switches to encrypted mode

\- \*\*Application Data (during handshake)\*\* — in TLS 1.3, much of the handshake itself is encrypted for additional privacy, including the certificate exchange

\- \*\*Change Cipher Spec (client)\*\* — the client confirms encrypted mode

\- \*\*Application Data\*\* — the actual website content, fully encrypted with the agreed AES key



\*\*TLS 1.3 improvement over 1.2:\*\* The handshake is faster (fewer round trips) and more private (most handshake messages are encrypted). An attacker sniffing the network cannot read the application data or even see the full handshake details.



\*\*How it connects:\*\* The Client Hello and Server Hello establish the asymmetric key exchange (like RSA). Once both sides agree on a shared secret, they switch to symmetric encryption (like AES) for the actual data. The Change Cipher Spec is the moment the connection switches from negotiation to encrypted communication.



!\[TLS Handshake](screenshots/tls.png)



\### 4. Hash Cracking with Hashcat



Generated SHA-256 hashes of three common passwords and cracked them using Hashcat with the rockyou.txt wordlist (a real password list from the 2009 RockYou data breach containing 14 million leaked passwords).



Hashes cracked:

| Hash (SHA-256) | Password | Position in Wordlist |

|---------------|----------|---------------------|

| `ef92b778...` | password123 | Top 2% |

| `1c8bfe8f...` | letmein | Top 2% |

| `a9c43be9...` | dragon | Top 2% |



Results:

\- \*\*All 3 cracked in under 1 second\*\*

\- Hashcat only needed to try \*\*2,048 out of 100,000\*\* entries (2% of the wordlist)

\- Speed: \*\*~43,000 hashes/second\*\* on a single CPU core — a modern GPU can achieve billions per second



\*\*Why this matters:\*\* Attackers who steal a password database crack hashes offline with no rate limiting or detection. Common passwords offer essentially zero protection.



\*\*Defensive lessons:\*\*

\- Use slow hashing algorithms (bcrypt, argon2) instead of fast ones (SHA-256, MD5) — slow algorithms make each guess take longer

\- Salt every hash — add random data before hashing so identical passwords produce different hashes, preventing bulk cracking

\- Enforce long, unique passwords — they won't appear in any wordlist

\- Monitor access to password files — this is why we set up auditd on `/etc/shadow` in Week 1



!\[Hashcat Output](screenshots/hashcat.png)



\## Key Takeaways



\- Symmetric encryption (AES) is fast and used for bulk data encryption, but requires both sides to have the same key

\- Asymmetric encryption (RSA) solves the key distribution problem but is too slow for bulk encryption

\- TLS combines both: asymmetric encryption for the handshake, symmetric encryption for the data

\- Hash functions are one-way, but weak passwords can be cracked in seconds using dictionary attacks

\- The security of encrypted systems depends not just on the algorithm, but on implementation choices like key length, salting, and algorithm speed



\## Next Steps



Week 4 will apply these concepts offensively by exploiting web application vulnerabilities including SQL injection, XSS, and CSRF using DVWA and OWASP Juice Shop.

