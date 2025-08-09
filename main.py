import sys
import random
import base64
import string
import hashlib
import argparse

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

class Functions:
    class Base64:
        @staticmethod
        def encode(input):
            output = base64.b64encode(input.encode()).decode()
            return output
        
        @staticmethod
        def decode(input):
            output = base64.b64decode(input.encode()).decode()
            return output

        @staticmethod
        def run():
            mode = input("Choose mode (1 for encode, 2 for decode): ")
            new_mode = int(mode)
            if new_mode == 1:
                input_data = input("Enter text to encode: ")
                print("Encoded:", Functions.Base64.encode(input_data))
            elif new_mode == 2:
                input_data = input("Enter text to decode: ")
                print("Decoded:", Functions.Base64.decode(input_data))
            else:
                print("Invalid mode selected.")

    class ARS:
        @staticmethod
        def encrypt(input_text, key, iv):
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(input_text.encode(), AES.block_size))
            return base64.b64encode(ciphertext).decode(), base64.b64encode(iv).decode()

        @staticmethod
        def decrypt(input_b64, key, iv):
            ciphertext = base64.b64decode(input_b64)
            cipher_dec = AES.new(key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher_dec.decrypt(ciphertext), AES.block_size)
            return plaintext.decode()

        @staticmethod
        def run():
            mode = input("Choose mode (1 for encrypt, 2 for decrypt): ").strip()
            if mode == "1":
                input_data = input("Enter text to encrypt: ")
                have_key = input("Do you have a key? (y/n): ").lower()
                key = input("Enter your key (16 chars): ").encode() if have_key == "y" else get_random_bytes(16)

                have_iv = input("Do you have an IV? (y/n): ").lower()
                iv = input("Enter your IV (16 chars): ").encode() if have_iv == "y" else get_random_bytes(16)

                ciphertext, iv_encoded = Functions.ARS.encrypt(input_data, key, iv)
                print("\nEncrypted Text:", ciphertext)
                print("Key (base64):", base64.b64encode(key).decode())
                print("IV  (base64):", iv_encoded)

            elif mode == "2":
                input_data = input("Enter base64 encrypted text: ")
                key = base64.b64decode(input("Enter key (base64): "))
                iv = base64.b64decode(input("Enter IV (base64): "))

                try:
                    decrypted = Functions.ARS.decrypt(input_data, key, iv)
                    print("\nDecrypted Text:", decrypted)
                except Exception as e:
                    print("Decryption failed:", e)
            else:
                print("Invalid mode selected.")

    class RSA:
        @staticmethod
        def encrypt(plaintext):
            public_key = None
            use_from_file = input("Do you want to use a public key from a file? (y/n): ").strip().lower()
            if use_from_file == "y":
                with open("pub.pem", "rb") as pub_file:
                    public_key = serialization.load_pem_public_key(
                        pub_file.read(),
                        backend=default_backend()
                    )
            else:
                public_key = input("Enter your public key (PEM format): ")
            ciphertext = public_key.encrypt(
                plaintext.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(ciphertext).decode()

        @staticmethod
        def decrypt(ciphertext_b64):
            private_key = None
            use_from_file = input("Do you want to use a private key from a file? (y/n): ").strip().lower()
            if use_from_file == "y":
                with open("priv.pem", "rb") as priv_file:
                    private_key = serialization.load_pem_private_key(
                        priv_file.read(),
                        password=None,
                        backend=default_backend()
                    )
            else:
                private_key = input("Enter your private key (PEM format): ")
            ciphertext = base64.b64decode(ciphertext_b64)
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext.decode()

        def generate_keys():

            key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
            )
            private_key = key
            public_key = key.public_key()

            priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
            )
            pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            save = input("Do you want to save the keys to files? (y/n): ").strip().lower()
            if save == "y":
                with open("priv.pem", "wb") as priv_file:
                    priv_file.write(priv_pem)
                with open("pub.pem", "wb") as pub_file:
                    pub_file.write(pub_pem)
            print("Private key saved to priv.pem")
            print("Public key saved to pub.pem")

            print("\nPrivate Key:\n", priv_pem.decode())
            print("\nPublic Key:\n", pub_pem.decode())

        def run():
            mode = input("Choose mode (1 for encrypt, 2 for decrypt, 3 for key generation): ").strip()
            if mode == "1":
                input_data = input("Enter text to encrypt: ")
                encrypted_data = Functions.RSA.encrypt(input_data)
                print("Encrypted Data:", encrypted_data)

            elif mode == "2":
                input_data = input("Enter text to decrypt: ")
                decrypted_data = Functions.RSA.decrypt(input_data)
                print("Decrypted Data:", decrypted_data)

            elif mode == "3":
                Functions.RSA.generate_keys()

    class Hashes:
        class MD5:
            def hash():
                text = input("Enter text to hash: ")
                md5_hash = hashlib.md5(text.encode()).hexdigest()
                print("MD5 Hash: ", md5_hash)

            def run():
                mode = input("Choose mode (1 for hash): ").strip()
                if mode == "1":
                    Functions.MD5.hash()
                else:
                    print("Invalid choice.")
        
        class SHA1:
            def hash():
                text = input("Enter text to hash: ")
                sha1_hash = hashlib.sha1(text.encode()).hexdigest()
                print("SHA-1 Hash: ", sha1_hash)
            
            def run():
                mode = input("Choose mode (1 for hash): ").strip()
                if mode == "1":
                    Functions.SHA1.hash()
                else:
                    print("Invalid choice.")

        class SHA256:
            def hash():
                text = input("Enter text to hash: ")
                sha256_hash = hashlib.sha256(text.encode()).hexdigest()
                print("SHA-256 Hash: ", sha256_hash)

            def run():
                mode = input("Choose mode (1 for hash): ").strip()
                if mode == "1":
                    Functions.SHA256.hash()
                else:
                    print("Invalid choice.")

        class SHA512:
            def hash():
                text = input("Enter text to hash: ")
                sha512_hash = hashlib.sha512(text.encode()).hexdigest()
                print("SHA-512 Hash: ", sha512_hash)

            def run():
                mode = input("Choose mode (1 for hash): ").strip()
                if mode == "1":
                    Functions.SHA512.hash()
                else:
                    print("Invalid choice.")

        @staticmethod
        def run():
            mode = input("Choose one (1 MD5 2 SHA-1 3 SHA-256 4 SHA-512): ").strip()
            if mode == "1":
                Functions.Hashes.MD5.hash()
            elif mode == "2":
                Functions.Hashes.SHA1.hash()
            elif mode == "3":
                Functions.Hashes.SHA256.hash()
            elif mode == "4":
                Functions.Hashes.SHA512.hash()
            else:
                print("Invalid choice.")

    class CaesarCipher:
        @staticmethod
        def encrypt(text, shift):
            result = ""

            for i in range(len(text)):
                char = text[i]

                if (char.isupper()):
                    result += chr((ord(char) + shift - 65) % 26 + 65)

                else:
                    result += chr((ord(char) + shift - 97) % 26 + 97)

            return result
        
        @staticmethod
        def decrypt(text, shift):
            result = ""

            for i in range(len(text)):
                char = text[i]

                if (char.isupper()):
                    result += chr((ord(char) - shift - 65) % 26 + 65)

                else:
                    result += chr((ord(char) - shift - 97) % 26 + 97)

            return result

        @staticmethod
        def run():
            mode = input("Choose mode (1 for encrypt, 2 for decrypt): ").strip()
            if mode == "1":
                text = input("Enter text to encrypt: ")
                shift = int(input("Enter shift value: "))
                encrypted_text = Functions.CaesarCipher.encrypt(text, shift)
                print("Encrypted Text:", encrypted_text)
            elif mode == "2":
                text = input("Enter text to decrypt: ")
                shift = int(input("Enter shift value: "))
                decrypted_text = Functions.CaesarCipher.decrypt(text, shift)
                print("Decrypted Text:", decrypted_text)

    class VigenereCipher:
        @staticmethod
        def generate_key(msg, key):
            key = list(key)
            if len(msg) == len(key):
                return key
            else:
                for i in range(len(msg) - len(key)):
                    key.append(key[i % len(key)])
            return "".join(key)

        @staticmethod
        def encrypt_vigenere(msg, key):
            encrypted_text = []

            for i in range(len(msg)):
                char = msg[i]
                if char.isupper():
                    encrypted_char = chr((ord(char) + ord(key[i]) - 2 * ord('A')) % 26 + ord('A'))
                elif char.islower():
                    encrypted_char = chr((ord(char) + ord(key[i]) - 2 * ord('a')) % 26 + ord('a'))
                else:
                    encrypted_char = char
                encrypted_text.append(encrypted_char)
            return "".join(encrypted_text)

        @staticmethod
        def decrypt_vigenere(msg, key):
            decrypted_text = []

            for i in range(len(msg)):
                char = msg[i]
                if char.isupper():
                    decrypted_char = chr((ord(char) - ord(key[i]) + 26) % 26 + ord('A'))
                elif char.islower():
                    decrypted_char = chr((ord(char) - ord(key[i]) + 26) % 26 + ord('a'))
                else:
                    decrypted_char = char
                decrypted_text.append(decrypted_char)
            return "".join(decrypted_text)

        @staticmethod
        def run():
            key = ""

            key_bool = input("Have you got key? (y/n): ").strip().lower()
            if key_bool == "y":
                key = input("Enter key: ")
            else:
                key = "password"


            mod = input("Choose mode (1 for encrypt, 2 for decrypt): ").strip()
            if mod == "1":
                text = input("Enter text to encrypt: ")
                encrypted_text = Functions.VigenereCipher.encrypt_vigenere(text, key)
                print("Encrypted Text:", encrypted_text)
            elif mod == "2":
                text = input("Enter text to decrypt: ")
                decrypted_text = Functions.VigenereCipher.decrypt_vigenere(text, key)
                print("Decrypted Text:", decrypted_text)

    class StringGenerator:
        @staticmethod
        def generate_string(length, use_symbols, use_numbers, use_small_letters, use_big_letters):
            abc = ""
            if use_small_letters:
                abc += string.ascii_lowercase
            if use_big_letters:
                abc += string.ascii_uppercase
            if use_numbers:
                abc += string.digits
            if use_symbols:
                abc += string.punctuation

            return ''.join(random.choice(abc) for _ in range(length))

        @staticmethod
        def run():
            length = int(input("Enter the length of the string to generate: "))
            symbols = input("Use symbols? (y/n): ").strip().lower()
            numbers = input("Use numbers? (y/n): ").strip().lower()
            small_letters = input("Use small letters? (y/n): ").strip().lower()
            big_letters = input("Use big letters? (y/n): ").strip().lower()

            generated_string = Functions.StringGenerator.generate_string(length, symbols == 'y', numbers == 'y', small_letters == 'y', big_letters == 'y')
            print("Generated String:", generated_string)

def main():
    parser = argparse.ArgumentParser(description="MiniCrypt CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Base64
    parser_b64 = subparsers.add_parser("base64", help="Base64 encode/decode")
    parser_b64.add_argument("mode", choices=["encode", "decode"], help="Operation mode")
    parser_b64.add_argument("text", help="Text to encode or decode")

    # AES
    parser_aes = subparsers.add_parser("aes", help="AES encrypt/decrypt (CBC mode)")
    parser_aes.add_argument("mode", choices=["encrypt", "decrypt"], help="Operation mode")
    parser_aes.add_argument("text", help="Plaintext (for encrypt) or base64 ciphertext (for decrypt)")
    parser_aes.add_argument("--key", help="Base64 encoded 16-byte key (if omitted during encrypt, random key is used)")
    parser_aes.add_argument("--iv", help="Base64 encoded 16-byte IV (if omitted during encrypt, random IV is used)")

    # RSA
    parser_rsa = subparsers.add_parser("rsa", help="RSA encrypt/decrypt/generate keys")
    parser_rsa.add_argument("mode", choices=["encrypt", "decrypt", "genkeys"], help="Operation mode")
    parser_rsa.add_argument("--text", help="Text to encrypt/decrypt (required for encrypt/decrypt)")

    # Hashes
    parser_hash = subparsers.add_parser("hash", help="Hash functions")
    parser_hash.add_argument("type", choices=["md5", "sha1", "sha256", "sha512"], help="Hash type")
    parser_hash.add_argument("text", help="Text to hash")

    # Caesar cipher
    parser_caesar = subparsers.add_parser("caesar", help="Caesar cipher encrypt/decrypt")
    parser_caesar.add_argument("mode", choices=["encrypt", "decrypt"], help="Operation mode")
    parser_caesar.add_argument("text", help="Text to process")
    parser_caesar.add_argument("shift", type=int, help="Shift value (integer)")

    # Vigenere cipher
    parser_vigenere = subparsers.add_parser("vigenere", help="Vigenere cipher encrypt/decrypt")
    parser_vigenere.add_argument("mode", choices=["encrypt", "decrypt"], help="Operation mode")
    parser_vigenere.add_argument("text", help="Text to process")
    parser_vigenere.add_argument("--key", help="Key for Vigenere cipher (default: password)", default="password")

    # String Generator
    parser_strgen = subparsers.add_parser("strgen", help="Generate random string")
    parser_strgen.add_argument("length", type=int, help="Length of string to generate")
    parser_strgen.add_argument("--symbols", action="store_true", help="Include symbols")
    parser_strgen.add_argument("--numbers", action="store_true", help="Include numbers")
    parser_strgen.add_argument("--small", action="store_true", help="Include small letters")
    parser_strgen.add_argument("--big", action="store_true", help="Include big letters")

    args = parser.parse_args()

    if args.command == "base64":
        if args.mode == "encode":
            print(Functions.Base64.encode(args.text))
        else:
            print(Functions.Base64.decode(args.text))

    elif args.command == "aes":
        if args.mode == "encrypt":
            key = base64.b64decode(args.key) if args.key else get_random_bytes(16)
            iv = base64.b64decode(args.iv) if args.iv else get_random_bytes(16)
            ciphertext, iv_encoded = Functions.ARS.encrypt(args.text, key, iv)
            print("Encrypted Text:", ciphertext)
            print("Key (base64):", base64.b64encode(key).decode())
            print("IV  (base64):", iv_encoded)
        else:
            if not args.key or not args.iv:
                print("Key and IV are required for decryption.")
                return
            key = base64.b64decode(args.key)
            iv = base64.b64decode(args.iv)
            try:
                plaintext = Functions.ARS.decrypt(args.text, key, iv)
                print("Decrypted Text:", plaintext)
            except Exception as e:
                print("Decryption failed:", e)

    elif args.command == "rsa":
        if args.mode == "encrypt":
            if not args.text:
                print("Text is required for encryption.")
                return
            encrypted = Functions.RSA.encrypt(args.text)
            print("Encrypted Data:", encrypted)
        elif args.mode == "decrypt":
            if not args.text:
                print("Text is required for decryption.")
                return
            decrypted = Functions.RSA.decrypt(args.text)
            print("Decrypted Data:", decrypted)
        elif args.mode == "genkeys":
            Functions.RSA.generate_keys()

    elif args.command == "hash":
        if args.type == "md5":
            print(hashlib.md5(args.text.encode()).hexdigest())
        elif args.type == "sha1":
            print(hashlib.sha1(args.text.encode()).hexdigest())
        elif args.type == "sha256":
            print(hashlib.sha256(args.text.encode()).hexdigest())
        elif args.type == "sha512":
            print(hashlib.sha512(args.text.encode()).hexdigest())

    elif args.command == "caesar":
        if args.mode == "encrypt":
            print(Functions.CaesarCipher.encrypt(args.text, args.shift))
        else:
            print(Functions.CaesarCipher.decrypt(args.text, args.shift))

    elif args.command == "vigenere":
        if args.mode == "encrypt":
            print(Functions.VigenereCipher.encrypt_vigenere(args.text, args.key))
        else:
            print(Functions.VigenereCipher.decrypt_vigenere(args.text, args.key))

    elif args.command == "strgen":
        generated = Functions.StringGenerator.generate_string(
            args.length,
            args.symbols,
            args.numbers,
            args.small,
            args.big
        )
        print(generated)

def menu():
    while True:
        print("Welcome in MiniCrypt!")
        print("1. Base64\n2. AES (CBC)\n3. RSA\n4. Hash\n5. Caesar cipher\n6. Vigenere cipher\n7. String generator\n0. Exit")

        choice = input("Choose an option > ")
        new_choice = int(choice)
        if new_choice == 0:
            break
        elif new_choice == 1:
            Functions.Base64.run() 
        elif new_choice == 2:
            Functions.ARS.run()
        elif new_choice == 3:
            Functions.RSA.run()
        elif new_choice == 4:
            Functions.Hashes.run()
        elif new_choice == 5:
            Functions.CaesarCipher.run()
        elif new_choice == 6:
            Functions.VigenereCipher.run()
        elif new_choice == 7:
            Functions.StringGenerator.run()
        else:
            print("Invalid choice, please try again.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        main()
    else:
        menu()
