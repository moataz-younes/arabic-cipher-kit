<div align="center">

# Arabic Cipher Kit

**Lightweight Arabic cryptography toolkit for learning, demos, and lab work**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Deps](https://img.shields.io/badge/dependencies-none-success)](#)

Classical Arabic ciphers + password-based modern encryption — **stdlib only**, no install pain.

[Features](#features) · [Install](#install) · [Usage](#usage) · [Ethics](#ethics)

</div>

---

## Why this exists

Arabic text is often ignored by toy cipher demos. This kit is built for Arabic letters first — useful for cybersecurity education, CTF warmups, and investigator lab notes.

## Features

| Mode | What it does |
| --- | --- |
| **Caesar** | Shift Arabic letters by N |
| **Atbash** | Mirror the Arabic alphabet |
| **Vigenère** | Keyword polyalphabetic cipher for Arabic |
| **encrypt / decrypt** | Password-based authenticated blob (PBKDF2 + HMAC) |

- Zero third-party dependencies
- File / stdin / stdout friendly
- Normalization for common Arabic variants (`أ إ آ ة ى` …)

## Install

```bash
git clone https://github.com/moataz-younes/arabic-cipher-kit.git
cd arabic-cipher-kit
python arabic_cipher_kit.py --help
```

> Requires **Python 3.10+**

## Usage

### Classical ciphers

```bash
# Caesar encrypt / decrypt
python arabic_cipher_kit.py caesar -t "مرحبا بالعالم" -s 4
python arabic_cipher_kit.py caesar -t "....." -s 4 --decrypt

# Atbash
python arabic_cipher_kit.py atbash -t "أمن المعلومات"

# Vigenère
python arabic_cipher_kit.py vigenere -t "تحقيق مفتوح المصدر" -k "دليل"
python arabic_cipher_kit.py vigenere -t "....." -k "دليل" --decrypt
```

### Modern password encryption

```bash
python arabic_cipher_kit.py encrypt -t "ملاحظة تحقيق سرية" -p "Strong-Pass-Here"
python arabic_cipher_kit.py decrypt -t "<token>" -p "Strong-Pass-Here"

# From / to files
python arabic_cipher_kit.py encrypt -f notes.txt -p "pass" -o notes.sealed
python arabic_cipher_kit.py decrypt -f notes.sealed -p "pass" -o notes.out.txt
```

## Quick demo

```bash
python arabic_cipher_kit.py caesar -t "سايبر سيكيورتي" -s 3
```

## Ethics

For **education, authorized labs, and personal note protection** only.  
Do not use classical ciphers to protect real sensitive data — they are intentionally weak and transparent for learning. Prefer proven libraries (AES-GCM) for production systems.

## Author

**Moataz Younes** — Cybercrime Investigator · OSINT · Cybersecurity  
GitHub: [moataz-younes](https://github.com/moataz-younes)

## License

MIT — see [LICENSE](LICENSE)
