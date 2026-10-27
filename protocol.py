"""Mengatur pengiriman pesan JSON dan enkripsi AES-128-CBC secara manual."""
import json
import os
import secrets
import socket
import string
import threading
from aes_manual import AES128, BLOCK_SIZE

KDC_IP = os.environ.get('KDC_IP', '172.28.77.10')
ALICE_IP = os.environ.get('ALICE_IP', '172.28.77.11')
BOB_IP = os.environ.get('BOB_IP', '172.28.77.12')
KDC_PORT = 5000
BOB_PORT = 6000
FRAME_LIMIT = 131072


def ascii_key(text):
    if not isinstance(text, str):
        raise ValueError('Kunci wajib teks ASCII')
    try:
        result = text.encode('ascii')
    except UnicodeEncodeError as exc:
        raise ValueError('Kunci hanya boleh ASCII') from exc
    if len(result) != 16:
        raise ValueError('AES-128 mensyaratkan 16 karakter ASCII tepat')
    return result


def ascii_plaintext(text):
    try:
        return text.encode('ascii')
    except UnicodeEncodeError as exc:
        raise ValueError('Plaintext wajib ASCII; tanpa emoji/aksara non-ASCII') from exc


def new_key():
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(16))


def pad(data):
    n = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([n]) * n


def unpad(data):
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError('Padding salah')
    n = data[-1]
    if not 1 <= n <= BLOCK_SIZE or data[-n:] != bytes([n]) * n:
        raise ValueError('Padding PKCS#7 salah; ciphertext/key dapat tidak cocok')
    return data[:-n]


def encrypt_ascii(key, plain):
    data = pad(ascii_plaintext(plain))
    aes = AES128(ascii_key(key))
    iv = secrets.token_bytes(BLOCK_SIZE)
    chain = iv
    result = bytearray(iv)
    for i in range(0, len(data), BLOCK_SIZE):
        block = bytes(x ^ y for x, y in zip(data[i:i+BLOCK_SIZE], chain))
        chain = aes.encrypt_block(block)
        result.extend(chain)
    return result.hex().upper()


def decrypt_ascii(key, cipher_hex):
    try:
        raw = bytes.fromhex(cipher_hex)
    except (ValueError, TypeError) as exc:
        raise ValueError('Ciphertext bukan Hex valid') from exc
    if len(raw) < 2 * BLOCK_SIZE or len(raw) % BLOCK_SIZE:
        raise ValueError('Ciphertext harus IV(16 byte) + blok AES(16 byte)')
    aes = AES128(ascii_key(key))
    previous = raw[:16]
    output = bytearray()
    for i in range(16, len(raw), 16):
        c = raw[i:i+16]
        p = aes.decrypt_block(c)
        output.extend(a ^ b for a, b in zip(p, previous))
        previous = c
    return unpad(bytes(output)).decode('ascii')


def increment_nonce(nonce_hex):
    if not isinstance(nonce_hex, str) or len(nonce_hex) != 16 or any(x not in string.hexdigits for x in nonce_hex):
        raise ValueError('Nonce harus 16 digit hex (64 bit)')
    return f'{(int(nonce_hex, 16) + 1) % (1 << 64):016X}'


def send_frame(sock, message, lock=None):
    encoded = (json.dumps(message, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')
    if len(encoded) > FRAME_LIMIT:
        raise ValueError('Frame terlalu panjang')
    if lock:
        with lock:
            sock.sendall(encoded)
    else:
        sock.sendall(encoded)


def read_frames(sock):
    with sock.makefile('rb') as reader:
        while True:
            frame = reader.readline(FRAME_LIMIT + 1)
            if not frame:
                break
            if len(frame) > FRAME_LIMIT or not frame.endswith(b'\n'):
                raise ValueError('Frame JSON tidak lengkap / terlalu besar')
            content = json.loads(frame.decode('ascii'))
            if not isinstance(content, dict):
                raise ValueError('Frame JSON wajib object')
            yield content
