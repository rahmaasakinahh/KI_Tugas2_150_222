"""Implementasi algoritma AES-128 secara manual tanpa library enkripsi.
Mengacu pada standar FIPS-197 dengan penyimpanan data per kolom.
"""

BLOCK_SIZE = 16


def gf_multiply(a: int, b: int) -> int:
    """Perkalian GF(2^8), reduksi polinomial AES x^8+x^4+x^3+x+1."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= 0x1B
        b >>= 1
    return result


def rotate_left_byte(value: int, count: int) -> int:
    return ((value << count) | (value >> (8 - count))) & 0xFF


def make_sbox():
    """Membangun S-box dengan invers perkalian dan transformasi affine AES."""
    result = []
    for value in range(256):
        inverse = 0
        if value:
            for candidate in range(1, 256):
                if gf_multiply(value, candidate) == 1:
                    inverse = candidate
                    break
        mapped = inverse ^ rotate_left_byte(inverse, 1) ^ rotate_left_byte(inverse, 2)
        mapped ^= rotate_left_byte(inverse, 3) ^ rotate_left_byte(inverse, 4) ^ 0x63
        result.append(mapped)
    return tuple(result)


SBOX = make_sbox()
INVERSE_SBOX = [0] * 256
for _i, _s in enumerate(SBOX):
    INVERSE_SBOX[_s] = _i
INVERSE_SBOX = tuple(INVERSE_SBOX)


def key_expansion(key: bytes) -> bytes:
    """AES-128: 16 byte kunci menjadi 11 round keys (176 byte)."""
    if len(key) != 16:
        raise ValueError("AES-128 mewajibkan key berukuran 16 byte")
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for index in range(4, 44):
        temp = words[index - 1][:]
        if index % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= rcon
            rcon = gf_multiply(rcon, 2)
        words.append([a ^ b for a, b in zip(words[index - 4], temp)])
    return bytes(value for word in words for value in word)


def add_round_key(state: list, expanded_key: bytes, round_number: int) -> None:
    offset = round_number * 16
    for index in range(16):
        state[index] ^= expanded_key[offset + index]


def sub_bytes(state: list, inverse: bool = False) -> None:
    lookup = INVERSE_SBOX if inverse else SBOX
    for index in range(16):
        state[index] = lookup[state[index]]


def shift_rows(state: list, inverse: bool = False) -> None:
    for row in range(1, 4):
        indexes = [row + 4 * col for col in range(4)]
        old = [state[index] for index in indexes]
        shift = (-row if inverse else row) % 4
        shifted = old[shift:] + old[:shift]
        for index, value in zip(indexes, shifted):
            state[index] = value


def mix_columns(state: list, inverse: bool = False) -> None:
    for column in range(4):
        start = column * 4
        a, b, c, d = state[start:start + 4]
        if inverse:
            state[start:start + 4] = [
                gf_multiply(a, 14) ^ gf_multiply(b, 11) ^ gf_multiply(c, 13) ^ gf_multiply(d, 9),
                gf_multiply(a, 9) ^ gf_multiply(b, 14) ^ gf_multiply(c, 11) ^ gf_multiply(d, 13),
                gf_multiply(a, 13) ^ gf_multiply(b, 9) ^ gf_multiply(c, 14) ^ gf_multiply(d, 11),
                gf_multiply(a, 11) ^ gf_multiply(b, 13) ^ gf_multiply(c, 9) ^ gf_multiply(d, 14),
            ]
        else:
            state[start:start + 4] = [
                gf_multiply(a, 2) ^ gf_multiply(b, 3) ^ c ^ d,
                a ^ gf_multiply(b, 2) ^ gf_multiply(c, 3) ^ d,
                a ^ b ^ gf_multiply(c, 2) ^ gf_multiply(d, 3),
                gf_multiply(a, 3) ^ b ^ c ^ gf_multiply(d, 2),
            ]


class AES128:
    """AES-128 block cipher: encrypt_block dan decrypt_block menerima 16 byte."""

    def __init__(self, key: bytes):
        self.round_keys = key_expansion(key)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError("AES hanya menerima blok 16 byte")
        state = list(block)
        add_round_key(state, self.round_keys, 0)
        for round_number in range(1, 10):
            sub_bytes(state)
            shift_rows(state)
            mix_columns(state)
            add_round_key(state, self.round_keys, round_number)
        sub_bytes(state)
        shift_rows(state)
        add_round_key(state, self.round_keys, 10)
        return bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError("AES hanya menerima blok 16 byte")
        state = list(block)
        add_round_key(state, self.round_keys, 10)
        for round_number in range(9, 0, -1):
            shift_rows(state, inverse=True)
            sub_bytes(state, inverse=True)
            add_round_key(state, self.round_keys, round_number)
            mix_columns(state, inverse=True)
        shift_rows(state, inverse=True)
        sub_bytes(state, inverse=True)
        add_round_key(state, self.round_keys, 0)
        return bytes(state)
