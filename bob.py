"""Program Bob untuk menerima kunci, melakukan autentikasi, dan komunikasi dua arah."""
import getpass
import secrets
import socket
import threading
from keys_config import read_config, update_key
from protocol import (
    BOB_PORT, ascii_plaintext, decrypt_ascii, encrypt_ascii, increment_nonce,
    read_frames, send_frame,
)


class Bob:
    def __init__(self, kb):
        self.master_key = kb
        self.guard = threading.RLock()
        self.send_guard = threading.Lock()
        self.peer = None
        self.session_key = None
        self.pending_key = None
        self.pending_nonce = None
        self.ready = False

    def connected_peer(self, conn, addr):
        with self.guard:
            self.peer = conn
            self.session_key = None
            self.pending_key = None
            self.pending_nonce = None
            self.ready = False
        print(f'\n[Bob] Koneksi Alice dari IP {addr[0]}', flush=True)
        try:
            with conn:
                for frame in read_frames(conn):
                    typ = frame.get('type')
                    if typ == 'TICKET':
                        with self.guard:
                            kb = self.master_key
                        ticket = decrypt_ascii(kb, frame['data'])
                        values = ticket.split('|')
                        if len(values) != 2 or values[1] != 'Alice' or len(values[0]) != 16 or not values[0].isascii():
                            raise ValueError('Ticket tidak memuat Ks/identitas Alice yang valid')
                        ks = values[0]
                        n2 = secrets.token_hex(8).upper()
                        with self.guard:
                            self.ready = False
                            self.pending_key = ks
                            self.pending_nonce = n2
                        cipher = encrypt_ascii(ks, n2)
                        send_frame(conn, {'type': 'CHALLENGE', 'data': cipher}, self.send_guard)
                        print('[Bob] (3) Ticket dibuka dengan Kb; Ks diterima.', flush=True)
                        print(f'[Bob] (4) E(Ks,N2) challenge terkirim (Hex): {cipher}', flush=True)
                    elif typ == 'RESPONSE':
                        with self.guard:
                            ks = self.pending_key
                            n2 = self.pending_nonce
                        if ks is None or n2 is None:
                            raise ValueError('RESPONSE tanpa CHALLENGE')
                        answer = decrypt_ascii(ks, frame['data'])
                        if not secrets.compare_digest(answer, increment_nonce(n2)):
                            raise ValueError('f(N2) salah: sesi tidak diotorisasi')
                        # Ready dikirim sebelum chat, agar Alice pindah ke key baru lebih dulu.
                        with self.guard:
                            send_frame(conn, {'type': 'READY'}, self.send_guard)
                            self.session_key = ks
                            self.pending_key = None
                            self.pending_nonce = None
                            self.ready = True
                        print('[Bob] (5) f(N2) cocok. AUTENTIKASI BERHASIL; Ks aktif.', flush=True)
                    elif typ == 'CHAT':
                        with self.guard:
                            ks = self.session_key if self.ready else None
                        if ks is None:
                            raise ValueError('CHAT ditolak sebelum autentikasi')
                        plain = decrypt_ascii(ks, frame['data'])
                        print(f'\n[Bob] Ciphertext Alice -> Bob (Hex): {frame["data"]}', flush=True)
                        print(f'[Alice -> Bob] Plaintext ASCII: {plain}', flush=True)
                    else:
                        raise ValueError(f'Tipe pesan tidak dikenal: {typ}')
        except (ValueError, TypeError, KeyError, OSError, UnicodeError) as exc:
            print(f'\n[Bob] Koneksi terputus/ditolak: {exc}', flush=True)
        finally:
            with self.guard:
                if self.peer is conn:
                    self.peer = None
                    self.session_key = None
                    self.ready = False
                    self.pending_key = None
                    self.pending_nonce = None

    def server_loop(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', BOB_PORT))
            server.listen(1)
            print('[Bob] Server TCP aktif pada port 6000.', flush=True)
            while True:
                conn, addr = server.accept()
                self.connected_peer(conn, addr)

    def send_chat(self, plain):
        ascii_plaintext(plain)
        with self.guard:
            sock = self.peer
            ks = self.session_key if self.ready else None
        if sock is None or ks is None:
            print('[Bob] Tunggu Alice menyelesaikan langkah 1-5.')
            return
        cipher = encrypt_ascii(ks, plain)
        send_frame(sock, {'type': 'CHAT', 'data': cipher}, self.send_guard)
        print(f'[Bob] Ciphertext terkirim (Hex): {cipher}')

    def set_master_key(self):
        print('[Bob] /setkey mengubah Kb lokal, bukan Ks. Samakan juga Kb di KDC.')
        key = getpass.getpass('Input Kb baru (ASCII 16 karakter; tidak ditampilkan): ')
        update_key('Kb', key)
        with self.guard:
            self.master_key = key
        print('[Bob] Kb lokal diperbarui. Ubah Kb KDC lalu /rekey di Alice.')

    def cli(self):
        print('Perintah: teks langsung atau /send pesan, /setkey, /status, /quit', flush=True)
        while True:
            try:
                entered = input('Bob> ')
            except (KeyboardInterrupt, EOFError):
                break
            if entered == '/quit':
                break
            if entered == '/status':
                with self.guard:
                    print('Sesi:', 'AKTIF' if self.ready and self.peer else 'BELUM SIAP')
                continue
            if entered == '/setkey':
                try:
                    self.set_master_key()
                except ValueError as exc:
                    print('[Bob] Penggantian key gagal:', exc)
                continue
            text = entered[6:] if entered.startswith('/send ') else entered
            try:
                self.send_chat(text)
            except (ValueError, OSError, UnicodeError) as exc:
                print('[Bob] Gagal mengirim:', exc)


def main():
    try:
        app = Bob(read_config()['Kb'])
        server = threading.Thread(target=app.server_loop, daemon=True)
        server.start()
        app.cli()
    except (ValueError, OSError) as exc:
        print('[Bob] Gagal:', exc, flush=True)


if __name__ == '__main__':
    main()
