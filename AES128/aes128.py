"""Pure-Python AES-128 implementation for educational use."""

from sha256 import sha256_bytes

S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

INV_S_BOX = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _validate_byte(value, name):
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFF:
        raise ValueError("{} must be an integer from 0 to 255".format(name))


def _validate_key(master_key):
    if not isinstance(master_key, (bytes, bytearray)) or len(master_key) != 16:
        raise ValueError("AES-128 key must contain exactly 16 bytes")


def _validate_round_keys(round_keys):
    if not isinstance(round_keys, (list, tuple)) or len(round_keys) != 11:
        raise ValueError("round_keys must contain exactly 11 round keys")
    for round_key in round_keys:
        if not isinstance(round_key, (list, tuple)) or len(round_key) != 4:
            raise ValueError("each round key must be a 4-by-4 matrix")
        for row in round_key:
            if not isinstance(row, (list, tuple)) or len(row) != 4:
                raise ValueError("each round key must be a 4-by-4 matrix")
            for value in row:
                _validate_byte(value, "round key byte")


def xtime(b):
    _validate_byte(b, "b")
    if b & 0x80:
        return ((b << 1) ^ 0x1B) & 0xFF
    return (b << 1) & 0xFF


def gmul(a, b):
    _validate_byte(a, "a")
    _validate_byte(b, "b")
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result


def bytes_to_state(block):
    if not isinstance(block, (bytes, bytearray)) or len(block) != 16:
        raise ValueError("AES block must contain exactly 16 bytes")
    return [[block[row + 4 * col] for col in range(4)] for row in range(4)]


def state_to_bytes(state):
    if not isinstance(state, (list, tuple)) or len(state) != 4:
        raise ValueError("state must be a 4-by-4 matrix")
    for row in state:
        if not isinstance(row, (list, tuple)) or len(row) != 4:
            raise ValueError("state must be a 4-by-4 matrix")
        for value in row:
            _validate_byte(value, "state byte")
    return bytes(state[row][col] for col in range(4) for row in range(4))


def derive_key_from_name(full_name):
    if not isinstance(full_name, str):
        raise TypeError("full_name must be a string")
    digest = sha256_bytes(full_name.encode("utf-8"))
    return digest[:16]


def rot_word(word):
    if len(word) != 4:
        raise ValueError("word must contain exactly 4 bytes")
    return list(word[1:]) + list(word[:1])


def sub_word(word):
    if len(word) != 4:
        raise ValueError("word must contain exactly 4 bytes")
    for value in word:
        _validate_byte(value, "word byte")
    return [S_BOX[value] for value in word]


def key_expansion(master_key):
    _validate_key(master_key)
    words = [
        list(master_key[offset:offset + 4])
        for offset in range(0, 16, 4)
    ]

    for index in range(4, 44):
        temp = list(words[index - 1])
        if index % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[index // 4 - 1]
        words.append([
            words[index - 4][byte_index] ^ temp[byte_index]
            for byte_index in range(4)
        ])

    round_keys = []
    for round_index in range(11):
        round_words = words[round_index * 4:round_index * 4 + 4]
        round_keys.append([
            [round_words[col][row] for col in range(4)]
            for row in range(4)
        ])
    return round_keys


def add_round_key(state, round_key):
    for row in range(4):
        for col in range(4):
            state[row][col] ^= round_key[row][col]


def sub_bytes(state):
    for row in range(4):
        for col in range(4):
            state[row][col] = S_BOX[state[row][col]]


def shift_rows(state):
    for row in range(1, 4):
        state[row] = state[row][row:] + state[row][:row]


def mix_columns(state):
    for col in range(4):
        a0, a1, a2, a3 = (state[row][col] for row in range(4))
        state[0][col] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3
        state[1][col] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3
        state[2][col] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3)
        state[3][col] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3)


def inv_sub_bytes(state):
    for row in range(4):
        for col in range(4):
            state[row][col] = INV_S_BOX[state[row][col]]


def inv_shift_rows(state):
    for row in range(1, 4):
        state[row] = state[row][-row:] + state[row][:-row]


def inv_mix_columns(state):
    for col in range(4):
        a0, a1, a2, a3 = (state[row][col] for row in range(4))
        first_pair = xtime(xtime(a0 ^ a2))
        second_pair = xtime(xtime(a1 ^ a3))
        state[0][col] ^= first_pair
        state[1][col] ^= second_pair
        state[2][col] ^= first_pair
        state[3][col] ^= second_pair
    mix_columns(state)


def encrypt_block(block, round_keys):
    if not isinstance(block, (bytes, bytearray)) or len(block) != 16:
        raise ValueError("AES block must contain exactly 16 bytes")
    _validate_round_keys(round_keys)
    state = bytes_to_state(block)
    add_round_key(state, round_keys[0])

    for round_index in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[round_index])

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])
    return state_to_bytes(state)


def decrypt_block(block, round_keys):
    if not isinstance(block, (bytes, bytearray)) or len(block) != 16:
        raise ValueError("AES block must contain exactly 16 bytes")
    _validate_round_keys(round_keys)
    state = bytes_to_state(block)
    add_round_key(state, round_keys[10])

    for round_index in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[round_index])
        inv_mix_columns(state)

    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])
    return state_to_bytes(state)


def pkcs7_pad(data):
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    pad_length = 16 - (len(data) % 16)
    return bytes(data) + bytes([pad_length] * pad_length)


def pkcs7_unpad(data):
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    if not data or len(data) % 16 != 0:
        raise ValueError("padded data must contain complete AES blocks")
    pad_length = data[-1]
    if not 1 <= pad_length <= 16:
        raise ValueError("invalid PKCS#7 padding length")
    if data[-pad_length:] != bytes([pad_length] * pad_length):
        raise ValueError("invalid PKCS#7 padding bytes")
    return bytes(data[:-pad_length])


def encrypt_message(plaintext, key):
    _validate_key(key)
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes or bytearray")
    round_keys = key_expansion(key)
    padded = pkcs7_pad(plaintext)
    return b"".join(
        encrypt_block(padded[offset:offset + 16], round_keys)
        for offset in range(0, len(padded), 16)
    )


def decrypt_message(ciphertext, key):
    _validate_key(key)
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes or bytearray")
    if not ciphertext or len(ciphertext) % 16 != 0:
        raise ValueError("ciphertext must contain one or more complete AES blocks")
    round_keys = key_expansion(key)
    padded = b"".join(
        decrypt_block(ciphertext[offset:offset + 16], round_keys)
        for offset in range(0, len(ciphertext), 16)
    )
    return pkcs7_unpad(padded)
