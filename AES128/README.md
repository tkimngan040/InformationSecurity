# AES-128 Pure Python

This folder contains an educational AES-128 implementation written from the
algorithm specification. It uses no cryptography packages and does not import
Python's `hashlib`.

## Files

- `aes128.py`: AES-128 key expansion, block encryption/decryption, PKCS#7
  padding, ECB message processing, and key derivation.
- `sha256.py`: pure-Python SHA-256 used by `derive_key_from_name`.
- `main.py`: NIST checks, a student-key demo, interactive text encryption, and
  optional performance measurements.

## Run

Open a terminal in this folder and run:

```text
python main.py
```

The program first checks the required SHA-256 and NIST test vectors, then shows
a demo and prompts for a UTF-8 string to encrypt. Press Enter at the prompt to
skip interactive encryption.

Run only the correctness checks:

```text
python main.py --test
```

Run correctness checks followed by the 100-iteration benchmark:

```text
python main.py --benchmark
```

`encrypt_message` and `decrypt_message` accept bytes. For text, encode the
string as UTF-8 before encryption and decode the recovered bytes afterward.

> ECB is included because it is specified for this educational exercise. It
> does not provide semantic security and should not be used to protect real
> sensitive data.
