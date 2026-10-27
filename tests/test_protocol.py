import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import alice
import bob
import kdc
from keys_config import read_config, update_key
from protocol import encrypt_ascii, send_frame, read_frames
from capture_packets import pcap_header, pcap_record


class ProtocolTests(unittest.TestCase):
    def test_pcap_format_and_key_update(self):
        self.assertEqual(len(pcap_header()), 24)
        self.assertEqual(len(pcap_record(b'abc', 1234567890000000000)), 19)
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'config.json'
            path.write_text(json.dumps({'Ka': 'ABCDefgh12345678'}))
            update_key('Ka', '87654321hgfedCBA', path)
            self.assertEqual(read_config(path)['Ka'], '87654321hgfedCBA')

    def test_five_steps_chat_and_rekey(self):
        ka = 'ABCDefgh12345678'
        kb = '12345678abcdefgh'
        new_ka = '87654321hgfedCBA'
        new_kb = 'hgfedcba87654321'
        keys = {'Ka': ka, 'Kb': kb}
        errors = []
        chat_received = {'alice': threading.Event(), 'bob': threading.Event()}
        orig_alice_decrypt = alice.decrypt_ascii
        orig_bob_decrypt = bob.decrypt_ascii

        def alice_decrypt(key, data):
            text = orig_alice_decrypt(key, data)
            if text == 'Hello from Bob':
                chat_received['alice'].set()
            return text

        def bob_decrypt(key, data):
            text = orig_bob_decrypt(key, data)
            if text == 'Hello from Alice':
                chat_received['bob'].set()
            return text

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as skdc, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sbob:
            skdc.bind(('127.0.0.1', 0))
            skdc.listen(3)
            sbob.bind(('127.0.0.1', 0))
            sbob.listen(1)
            kdc_port = skdc.getsockname()[1]
            bob_port = sbob.getsockname()[1]
            b = bob.Bob(kb)

            def kdc_worker():
                try:
                    for _ in range(3):
                        con, addr = skdc.accept()
                        kdc.process_peer(con, addr, key_loader=lambda: dict(keys))
                except Exception as exc:
                    errors.append(exc)

            def bob_worker():
                try:
                    con, addr = sbob.accept()
                    b.connected_peer(con, addr)
                except Exception as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=kdc_worker, daemon=True), threading.Thread(target=bob_worker, daemon=True)]
            for thread in threads:
                thread.start()

            with patch.object(alice, 'KDC_IP', '127.0.0.1'), patch.object(alice, 'KDC_PORT', kdc_port), \
                 patch.object(alice, 'BOB_IP', '127.0.0.1'), patch.object(alice, 'BOB_PORT', bob_port), \
                 patch.object(alice, 'decrypt_ascii', alice_decrypt), patch.object(bob, 'decrypt_ascii', bob_decrypt):
                app = alice.Alice(ka)
                with socket.create_connection(('127.0.0.1', bob_port), timeout=5) as peer:
                    peer.settimeout(None)
                    app.peer = peer
                    app.connected = True
                    receiver = threading.Thread(target=app.receive_loop, daemon=True)
                    receiver.start()
                    app.negotiate()
                    initial_key = app.session_key
                    self.assertTrue(app.handshake_ok)
                    self.assertEqual(initial_key, b.session_key)
                    self.assertTrue(b.ready)
                    app.send_chat('Hello from Alice')
                    b.send_chat('Hello from Bob')
                    self.assertTrue(chat_received['alice'].wait(3))
                    self.assertTrue(chat_received['bob'].wait(3))
                    # Session key baru tanpa mengganti master key.
                    app.negotiate()
                    self.assertNotEqual(app.session_key, initial_key)
                    self.assertEqual(app.session_key, b.session_key)
                    # Sinkronisasi perubahan master key manual (KDC, Alice, Bob).
                    keys.update(Ka=new_ka, Kb=new_kb)
                    app.master_key = new_ka
                    b.master_key = new_kb
                    app.negotiate()
                    self.assertEqual(app.session_key, b.session_key)
                    self.assertTrue(b.ready)
                receiver.join(timeout=2)
            self.assertFalse(errors, errors)


    def test_wrong_master_key_keeps_connection(self):
        ka = 'ABCDefgh12345678'
        kb = '12345678abcdefgh'
        keys = {'Ka': ka, 'Kb': kb}
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as skdc, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sbob:
            skdc.bind(('127.0.0.1', 0))
            skdc.listen(2)
            sbob.bind(('127.0.0.1', 0))
            sbob.listen(1)
            kdc_port = skdc.getsockname()[1]
            bob_port = sbob.getsockname()[1]
            b = bob.Bob('salahsalahsalah1')

            def kdc_worker():
                for _ in range(2):
                    con, addr = skdc.accept()
                    kdc.process_peer(con, addr, key_loader=lambda: dict(keys))

            def bob_worker():
                con, addr = sbob.accept()
                b.connected_peer(con, addr)

            for target in (kdc_worker, bob_worker):
                threading.Thread(target=target, daemon=True).start()

            with patch.object(alice, 'KDC_IP', '127.0.0.1'), patch.object(alice, 'KDC_PORT', kdc_port):
                app = alice.Alice(ka)
                with socket.create_connection(('127.0.0.1', bob_port), timeout=5) as peer:
                    peer.settimeout(None)
                    app.peer = peer
                    app.connected = True
                    threading.Thread(target=app.receive_loop, daemon=True).start()
                    with self.assertRaises(RuntimeError) as ctx:
                        app.negotiate()
                    self.assertIn('Bob menolak', str(ctx.exception))
                    self.assertTrue(app.connected)
                    self.assertFalse(b.ready)
                    b.master_key = kb
                    app.negotiate()
                    self.assertTrue(app.handshake_ok)
                    self.assertEqual(app.session_key, b.session_key)
