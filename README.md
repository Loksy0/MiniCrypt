# MiniCrypt

MiniCrypt to wielofunkcyjne narzędzie CLI do szyfrowania, deszyfrowania, kodowania i generowania hashy oraz losowych ciągów znaków. Zawiera wiele popularnych algorytmów kryptograficznych i szyfrowania, które można używać zarówno interaktywnie, jak i z poziomu argumentów wiersza poleceń.

---

## Funkcje

- **Base64** — kodowanie i dekodowanie tekstu.
- **AES (CBC)** — symetryczne szyfrowanie i odszyfrowywanie w trybie CBC (AES-128).
- **RSA** — szyfrowanie, deszyfrowanie oraz generowanie par kluczy RSA (2048-bit).
- **Hash** — generowanie hashy MD5, SHA-1, SHA-256, SHA-512.
- **Caesar Cipher** — szyfrowanie i odszyfrowywanie szyfrem Cezara z podanym przesunięciem.
- **Vigenere Cipher** — szyfrowanie i odszyfrowywanie szyfrem Vigenere z możliwością podania klucza.
- **String Generator** — generowanie losowych ciągów znaków z możliwością wyboru znaków: symbole, cyfry, małe i wielkie litery.

---

## Instalacja

Narzędzie wymaga Pythona 3 oraz bibliotek:

```bash
pip install pycryptodome cryptography
```

---

## Użycie

MiniCrypt można uruchomić w dwóch trybach:

- **Interaktywnym menu** (uruchomienie bez argumentów):

```bash
python minicypt.py
```

- **Z argumentami CLI** dla szybkiego wykonania konkretnej operacji.

---

## Przykłady użycia z CLI

### 1. Base64 - kodowanie tekstu

```bash
python minicypt.py base64 encode "Hello World"
```

**Output:**

```
SGVsbG8gV29ybGQ=
```

### 2. AES - szyfrowanie tekstu

Generowanie losowego klucza i wektora inicjalizującego (IV):

```bash
python minicypt.py aes encrypt "My secret message"
```

**Output:**

```
Encrypted Text: <zakodowany tekst base64>
Key (base64): <klucz base64>
IV  (base64): <IV base64>
```

Aby odszyfrować tekst, użyj:

```bash
python minicypt.py aes decrypt <zakodowany_tekst> --key <klucz_base64> --iv <IV_base64>
```

---

## Licencja

Projekt jest dostępny na licencji MIT.

---


---

Dziękuję za skorzystanie z MiniCrypt! 🔐

## Donation
- **LTC**: ```ltc1qcylc450gq9nr2gspn3x905kvj6jesmnm0fj8p6```
- **BTC**: ```bc1qp52tyf9hykehc4mjexj5ep36asjr0qskywzxtj```
- **ETH**: ```0x73100e9DcA1C591d07AaDE2B61F30c00Dd6da379```
