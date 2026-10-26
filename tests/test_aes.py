import unittest
from aes_manual import AES128, SBOX, key_expansion
from protocol import (ascii_key, decrypt_ascii, encrypt_ascii, increment_nonce, pad, unpad)


class AESManualTests(unittest.TestCase):
    def test_fips197_c1(self):
        key = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
        plain = bytes.fromhex('00112233445566778899AABBCCDDEEFF')
        expected = bytes.fromhex('69C4E0D86A7B0430D8CDB78070B4C55A')
        aes = AES128(key)
        self.assertEqual(aes.encrypt_block(plain), expected)
        self.assertEqual(aes.decrypt_block(expected), plain)
        self.assertEqual(len(key_expansion(key)), 176)
        self.assertEqual(SBOX[0], 0x63)

    def test_roundtrip_various(self):
        for phrase in ['', 'A', '0123456789ABCDEF', 'Pesan pendek!', 'Pesan ' * 30]:
            with self.subTest(phrase=phrase):
                token = encrypt_ascii('ABCDefgh12345678', phrase)
                self.assertEqual(decrypt_ascii('ABCDefgh12345678', token), phrase)
                self.assertEqual(token, token.upper())
                self.assertNotEqual(token, phrase.encode('ascii').hex().upper())

    def test_iv_acak(self):
        self.assertNotEqual(encrypt_ascii('ABCDefgh12345678', 'Halo'),
                            encrypt_ascii('ABCDefgh12345678', 'Halo'))

    def test_ascii_and_padding_validation(self):
        with self.assertRaises(ValueError):
            ascii_key('terlalu pendek')
        with self.assertRaises(ValueError):
            encrypt_ascii('ABCDefgh12345678', 'emoji 😀')
        for phrase in (b'', b'hello', b'1234567890123456'):
            self.assertEqual(unpad(pad(phrase)), phrase)
        with self.assertRaises(ValueError):
            unpad(b'x' * 15 + b'\x11')

    def test_f_nonce(self):
        self.assertEqual(increment_nonce('0000000000000001'), '0000000000000002')
        self.assertEqual(increment_nonce('FFFFFFFFFFFFFFFF'), '0000000000000000')
