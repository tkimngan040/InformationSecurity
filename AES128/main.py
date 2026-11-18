"""Command-line demonstrations and tests for the pure-Python AES-128."""

import sys
import time

from aes128 import (
    decrypt_block,
    decrypt_message,
    derive_key_from_name,
    encrypt_block,
    encrypt_message,
    key_expansion,
    state_to_bytes,
)
from sha256 import sha256_bytes


STUDENT_NAME = "Trần Thị Kim Ngân"
ITERATIONS = 100


def run_tests():
    name_digest = sha256_bytes(STUDENT_NAME.encode("utf-8"))
    assert name_digest.hex() == (
        "03faf819ed237a4e4dee14c6af7b0232"
        "05a438255367d1c9231e3b9dd1afd7f1"
    )
    student_key = derive_key_from_name(STUDENT_NAME)
    assert student_key.hex() == "03faf819ed237a4e4dee14c6af7b0232"

    key_a1 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    round_keys_a1 = key_expansion(key_a1)
    assert state_to_bytes(round_keys_a1[1]).hex() == (
        "a0fafe1788542cb123a339392a6c7605"
    )
    assert state_to_bytes(round_keys_a1[10]).hex() == (
        "d014f9a8c9ee2589e13f0cc8b6630ca6"
    )
    plaintext_b = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    assert encrypt_block(plaintext_b, round_keys_a1).hex() == (
        "3925841d02dc09fbdc118597196a0b32"
    )

    key_c1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext_c = bytes.fromhex("00112233445566778899aabbccddeeff")
    round_keys_c1 = key_expansion(key_c1)
    ciphertext_c = encrypt_block(plaintext_c, round_keys_c1)
    assert ciphertext_c.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
    assert decrypt_block(ciphertext_c, round_keys_c1) == plaintext_c

    print("Cac NIST test vector va kiem tra SHA-256: PASS")
    return name_digest, student_key


def show_student_demo(name_digest, student_key):
    plaintext = "Thong diep minh hoa AES-128".encode("utf-8")
    ciphertext = encrypt_message(plaintext, student_key)
    recovered = decrypt_message(ciphertext, student_key)
    print("\n--- Demo khoa sinh tu ten ---")
    print("Ten dau vao: {}".format(STUDENT_NAME))
    print("SHA-256:     {}".format(name_digest.hex()))
    print("Khoa AES-128: {}".format(student_key.hex()))
    print("Ban ro:       {}".format(plaintext.decode("utf-8")))
    print("Ban ma hex:   {}".format(ciphertext.hex()))
    print("Giai ma:      {}".format(recovered.decode("utf-8")))


def interactive_encrypt(student_key):
    print("\n--- Ma hoa chuoi nhap tay ---")
    try:
        plaintext = input("Nhap chuoi can ma hoa (Enter de bo qua): ")
    except EOFError:
        print("Khong co du lieu nhap; bo qua ma hoa tuong tac.")
        return
    if plaintext == "":
        print("Da bo qua ma hoa tuong tac.")
        return

    ciphertext = encrypt_message(plaintext.encode("utf-8"), student_key)
    recovered = decrypt_message(ciphertext, student_key)
    print("Ban ma hex: {}".format(ciphertext.hex()))
    print("Giai ma:    {}".format(recovered.decode("utf-8")))


def _average_seconds(operation):
    start = time.perf_counter()
    for _ in range(ITERATIONS):
        operation()
    return (time.perf_counter() - start) / ITERATIONS


def run_benchmarks(student_key):
    print("\n--- Do hieu nang ({} lan lap) ---".format(ITERATIONS))
    print(
        "{:>10} {:>15} {:>15} {:>15} {:>15} {:>20}".format(
            "Du lieu", "Dan khoa (ms)", "KeyExpansion (ms)",
            "Ma hoa (ms)", "Giai ma (ms)", "Thong luong (KB/s)"
        )
    )
    for size in (16, 1024, 10 * 1024, 100 * 1024):
        plaintext = bytes((index % 256 for index in range(size)))

        derive_seconds = _average_seconds(
            lambda: derive_key_from_name(STUDENT_NAME)
        )
        expansion_seconds = _average_seconds(
            lambda: key_expansion(student_key)
        )
        encrypt_seconds = _average_seconds(
            lambda: encrypt_message(plaintext, student_key)
        )
        ciphertext = encrypt_message(plaintext, student_key)
        decrypt_seconds = _average_seconds(
            lambda: decrypt_message(ciphertext, student_key)
        )
        throughput = size / 1024 / encrypt_seconds if encrypt_seconds else 0

        print(
            "{:>7} B {:>15.4f} {:>15.4f} {:>15.4f} {:>15.4f} {:>20.2f}".format(
                size,
                derive_seconds * 1000,
                expansion_seconds * 1000,
                encrypt_seconds * 1000,
                decrypt_seconds * 1000,
                throughput,
            )
        )


def main():
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")

    if len(sys.argv) > 2 or (
        len(sys.argv) == 2 and sys.argv[1] not in ("--test", "--benchmark")
    ):
        print("Cach dung: python main.py [--test|--benchmark]")
        return 2

    name_digest, student_key = run_tests()
    if len(sys.argv) == 2 and sys.argv[1] == "--test":
        return 0

    show_student_demo(name_digest, student_key)
    if len(sys.argv) == 2 and sys.argv[1] == "--benchmark":
        run_benchmarks(student_key)
    else:
        interactive_encrypt(student_key)
    return 0


if __name__ == "__main__":
    sys.exit(main())
