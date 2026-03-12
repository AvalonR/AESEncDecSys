# AES Encryption & Decryption Tool

A web application for AES encryption and decryption built with Go.

## Running

```
go run main.go
```

Then open http://localhost:8080 in your browser. No external dependencies required.

## How to use

**Encrypting**
1. Select the Encrypt tab
2. Enter a secret key
3. Choose a mode (ECB, CBC, or CFB)
4. Choose a key length (128, 192, or 256 bits)
5. Type your plaintext message
6. Click Process
7. Copy the result or download it as ciphertext.txt

**Decrypting**
1. Select the Decrypt tab
2. Enter the same secret key used for encryption
3. Choose a source:
   - Paste JSON — paste the contents of a ciphertext.txt produced by this tool
   - Manual — select mode and key length yourself, paste raw base64 ciphertext and IV
   - Upload .txt — upload a ciphertext.txt file directly
4. Click Process

## What is AES

AES (Advanced Encryption Standard) is a symmetric block cipher. It encrypts data in fixed 128-bit blocks using the same key for both encryption and decryption. The number of rounds depends on key size:

- AES-128: 10 rounds
- AES-192: 12 rounds
- AES-256: 14 rounds

More rounds means more resistance to brute-force attacks. AES-256 is considered the most secure of the three.

## Modes of operation

**ECB (Electronic Codebook)**
Each 16-byte block is encrypted independently. Simple but weak — identical plaintext blocks always produce identical ciphertext blocks, which can leak patterns in the data. Avoid for real use.

**CBC (Cipher Block Chaining)**
Each block is XOR-ed with the previous ciphertext block before encryption. Requires a random IV for the first block. Identical plaintexts produce different ciphertexts on every encryption run, hiding patterns.

**CFB (Cipher Feedback)**
Turns the block cipher into a stream cipher. Uses an IV. No block padding required. Suitable for variable-length data.

## Key handling

AES requires keys of exactly 16, 24, or 32 bytes. Since users type arbitrary strings, the key is derived like this:

1. Hash the input with SHA-256 (always produces 32 bytes)
2. Truncate to the required length: 16 bytes for AES-128, 24 for AES-192, 32 for AES-256

The same password and key length will always produce the same AES key, so decryption is reproducible.

## Ciphertext file format

Encrypted output is saved as JSON inside a .txt file:

```
{
  "mode": "CBC",
  "key_size": 256,
  "iv": "<base64>",
  "ciphertext": "<base64>"
}
```

ECB omits the iv field. The file is self-describing, so decryption only needs the secret key.
