#!/usr/bin/env python3
"""
Arabic Cipher Kit — lightweight Arabic classical ciphers + optional modern encryption.

Educational / authorized use only.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
from dataclasses import dataclass

# Standard Arabic letters (28) — abjad order used for shifting
ARABIC_LETTERS = list("ابتثجحخدذرزسشصضطظعغفقكلمنهوي")
LETTER_INDEX = {ch: i for i, ch in enumerate(ARABIC_LETTERS)}
N = len(ARABIC_LETTERS)

# Common presentation forms / variants mapped to base letters
NORMALIZE_MAP = str.maketrans(
    {
        "أ": "ا",
        "إ": "ا",
        "آ": "ا",
        "ٱ": "ا",
        "ى": "ي",
        "ة": "ه",
        "ؤ": "و",
        "ئ": "ي",
        "ء": "",
    }
)


def normalize_arabic(text: str, strip_tashkeel: bool = True) -> str:
    text = text.translate(NORMALIZE_MAP)
    if strip_tashkeel:
        # Remove Arabic combining marks (harakat)
        text = "".join(ch for ch in text if not (0x064B <= ord(ch) <= 0x065F or ord(ch) == 0x0670))
    return text


def caesar(text: str, shift: int, decrypt: bool = False) -> str:
    text = normalize_arabic(text)
    if decrypt:
        shift = -shift
    out: list[str] = []
    for ch in text:
        if ch in LETTER_INDEX:
            out.append(ARABIC_LETTERS[(LETTER_INDEX[ch] + shift) % N])
        else:
            out.append(ch)
    return "".join(out)


def atbash(text: str) -> str:
    text = normalize_arabic(text)
    out: list[str] = []
    for ch in text:
        if ch in LETTER_INDEX:
            out.append(ARABIC_LETTERS[N - 1 - LETTER_INDEX[ch]])
        else:
            out.append(ch)
    return "".join(out)


def vigenere(text: str, key: str, decrypt: bool = False) -> str:
    text = normalize_arabic(text)
    key = normalize_arabic(key)
    key_shifts = [LETTER_INDEX[ch] for ch in key if ch in LETTER_INDEX]
    if not key_shifts:
        raise ValueError("Vigenère key must contain at least one Arabic letter.")

    out: list[str] = []
    ki = 0
    for ch in text:
        if ch in LETTER_INDEX:
            shift = key_shifts[ki % len(key_shifts)]
            if decrypt:
                shift = -shift
            out.append(ARABIC_LETTERS[(LETTER_INDEX[ch] + shift) % N])
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def _derive_key(password: str, salt: bytes, rounds: int = 200_000) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds, dklen=32)


def modern_encrypt(plaintext: str, password: str) -> str:
    """
    Lightweight authenticated encryption (stdlib only):
    PBKDF2-HMAC-SHA256 + XOR keystream + HMAC-SHA256 tag.
    Suitable for demos / personal notes — not a replacement for AES-GCM libraries.
    """
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    key = _derive_key(password, salt)
    enc_key, mac_key = key[:16], key[16:]

    data = plaintext.encode("utf-8")
    # Expand keystream via HMAC counter mode
    stream = bytearray()
    counter = 0
    while len(stream) < len(data):
        block = hmac.new(enc_key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        stream.extend(block)
        counter += 1
    ciphertext = bytes(a ^ b for a, b in zip(data, stream))
    tag = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()
    payload = {
        "v": 1,
        "alg": "pbkdf2-hmac-sha256+xor+hmac",
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode(),
    }
    return base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()


def modern_decrypt(token: str, password: str) -> str:
    try:
        payload = json.loads(base64.b64decode(token.encode()).decode())
        salt = base64.b64decode(payload["salt"])
        nonce = base64.b64decode(payload["nonce"])
        ciphertext = base64.b64decode(payload["ct"])
        tag = base64.b64decode(payload["tag"])
    except Exception as exc:  # noqa: BLE001
        raise ValueError("Invalid ciphertext format.") from exc

    key = _derive_key(password, salt)
    enc_key, mac_key = key[:16], key[16:]
    expected = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError("Authentication failed — wrong password or corrupted data.")

    stream = bytearray()
    counter = 0
    while len(stream) < len(ciphertext):
        block = hmac.new(enc_key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        stream.extend(block)
        counter += 1
    plain = bytes(a ^ b for a, b in zip(ciphertext, stream))
    return plain.decode("utf-8")


@dataclass
class CmdResult:
    mode: str
    output: str


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="arabic-cipher-kit",
        description="Lightweight Arabic classical ciphers + password-based modern encryption.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    def add_io(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("-t", "--text", help="Input text")
        sp.add_argument("-f", "--file", help="Read input from file (UTF-8)")
        sp.add_argument("-o", "--output", help="Write result to file")

    ca = sub.add_parser("caesar", help="Arabic Caesar cipher")
    add_io(ca)
    ca.add_argument("-s", "--shift", type=int, default=3, help="Shift amount (default: 3)")
    ca.add_argument("-d", "--decrypt", action="store_true")

    at = sub.add_parser("atbash", help="Arabic Atbash cipher")
    add_io(at)

    vg = sub.add_parser("vigenere", help="Arabic Vigenère cipher")
    add_io(vg)
    vg.add_argument("-k", "--key", required=True, help="Arabic keyword")
    vg.add_argument("-d", "--decrypt", action="store_true")

    enc = sub.add_parser("encrypt", help="Modern password-based encrypt")
    add_io(enc)
    enc.add_argument("-p", "--password", required=True)

    dec = sub.add_parser("decrypt", help="Modern password-based decrypt")
    add_io(dec)
    dec.add_argument("-p", "--password", required=True)

    return p


def read_input(args: argparse.Namespace) -> str:
    if args.text and args.file:
        raise SystemExit("Use either --text or --file, not both.")
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            return fh.read()
    if args.text is not None:
        return args.text
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise SystemExit("Provide --text, --file, or pipe stdin.")


def _configure_stdio() -> None:
    # Avoid Windows cp1252 crashes when printing Arabic
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            pass


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    raw = read_input(args)

    try:
        if args.command == "caesar":
            result = caesar(raw, args.shift, decrypt=args.decrypt)
        elif args.command == "atbash":
            result = atbash(raw)
        elif args.command == "vigenere":
            result = vigenere(raw, args.key, decrypt=args.decrypt)
        elif args.command == "encrypt":
            result = modern_encrypt(raw, args.password)
        elif args.command == "decrypt":
            result = modern_decrypt(raw.strip(), args.password)
        else:
            parser.error("Unknown command")
            return 2
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(result)
            if not result.endswith("\n"):
                fh.write("\n")
        print(f"Wrote: {args.output}")
    else:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
