"""A small, pure-Python implementation of SHA-256."""

_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)

_INITIAL_HASH = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
_MASK_32 = 0xFFFFFFFF


def _rotate_right(value, count):
    return ((value >> count) | (value << (32 - count))) & _MASK_32


def sha256_bytes(data):
    """Return the SHA-256 digest of a bytes-like value as 32 bytes."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")

    message = bytearray(data)
    bit_length = len(message) * 8
    message.append(0x80)
    while len(message) % 64 != 56:
        message.append(0)
    message.extend(bit_length.to_bytes(8, "big"))

    hash_values = list(_INITIAL_HASH)
    for offset in range(0, len(message), 64):
        block = message[offset:offset + 64]
        words = [
            int.from_bytes(block[index:index + 4], "big")
            for index in range(0, 64, 4)
        ]

        for index in range(16, 64):
            x = words[index - 15]
            sigma0 = _rotate_right(x, 7) ^ _rotate_right(x, 18) ^ (x >> 3)
            y = words[index - 2]
            sigma1 = _rotate_right(y, 17) ^ _rotate_right(y, 19) ^ (y >> 10)
            words.append(
                (words[index - 16] + sigma0 + words[index - 7] + sigma1)
                & _MASK_32
            )

        a, b, c, d, e, f, g, h = hash_values
        for index in range(64):
            sum1 = _rotate_right(e, 6) ^ _rotate_right(e, 11) ^ _rotate_right(e, 25)
            choice = (e & f) ^ ((~e) & g)
            temp1 = (h + sum1 + choice + _K[index] + words[index]) & _MASK_32
            sum0 = _rotate_right(a, 2) ^ _rotate_right(a, 13) ^ _rotate_right(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (sum0 + majority) & _MASK_32

            h, g, f, e = g, f, e, (d + temp1) & _MASK_32
            d, c, b, a = c, b, a, (temp1 + temp2) & _MASK_32

        hash_values = [
            (current + updated) & _MASK_32
            for current, updated in zip(
                hash_values, (a, b, c, d, e, f, g, h)
            )
        ]

    return b"".join(value.to_bytes(4, "big") for value in hash_values)
