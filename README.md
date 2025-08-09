# MiniCrypt

MiniCrypt is a multifunctional CLI tool for encryption, decryption, encoding, hash generation, and random string creation. It includes many popular cryptographic algorithms and ciphers that can be used both interactively and via command-line arguments.

---

## Features

- **Base64** — text encoding and decoding.
- **AES (CBC)** — symmetric encryption and decryption in CBC mode (AES-128).
- **RSA** — encryption, decryption, and RSA key pair generation (2048-bit).
- **Hash** — generating MD5, SHA-1, SHA-256, and SHA-512 hashes.
- **Caesar Cipher** — encryption and decryption using Caesar cipher with a specified shift.
- **Vigenere Cipher** — encryption and decryption using Vigenere cipher with a user-provided key.
- **String Generator** — generates random strings with selectable characters: symbols, digits, lowercase and uppercase letters.

---

## Installation

The tool requires Python 3 and the following libraries:

```bash
pip install pycryptodome cryptography
```

---

## Usage

MiniCrypt can be run in two modes:

- **Interactive menu** (run without arguments):

```bash
python minicypt.py
```

- **With CLI arguments** for quickly performing specific operations.

---

## CLI Usage Examples

### 1. Base64 — encode text

```bash
python minicypt.py base64 encode "Hello World"
```

**Output:**

```
SGVsbG8gV29ybGQ=
```

### 2. AES — encrypt text

Generates a random key and initialization vector (IV):

```bash
python minicypt.py aes encrypt "My secret message"
```

**Output:**

```
Encrypted Text: <base64 encoded ciphertext>
Key (base64): <base64 encoded key>
IV  (base64): <base64 encoded IV>
```

To decrypt, use:

```bash
python minicypt.py aes decrypt <encoded_text> --key <base64_key> --iv <base64_iv>
```

---

## License

This project is licensed under the MIT License.

---

## Donation
- **LTC**: ```ltc1qcylc450gq9nr2gspn3x905kvj6jesmnm0fj8p6```
- **BTC**: ```bc1qp52tyf9hykehc4mjexj5ep36asjr0qskywzxtj```
- **ETH**: ```0x73100e9DcA1C591d07AaDE2B61F30c00Dd6da379```

Thank you for using MiniCrypt! 🔐
