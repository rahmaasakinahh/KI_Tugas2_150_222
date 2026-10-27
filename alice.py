"""Program Alice untuk distribusi kunci, komunikasi dua arah, dan penggantian kunci."""
import getpass
import secrets
import socket
import threading
from keys_config import read_config, update_key
from protocol import (
    KDC_IP, KDC_PORT, BOB_IP, BOB_PORT, ascii_plaintext, decrypt_ascii,
    encrypt_ascii, increment_nonce, read_frames, send_frame,
)


class Alice:
    def __init__(self, ka):
        self.master_key = ka
        self.peer = None
        self.guard = threading.RLock()
        self.send_guard = threading.Lock()
        self.ready_event = threading.Event()
        self.session_key = None
        self.pending_key = None
        self.handshake_ok = False
        self.connected = False
        self.last_error = None
        self.closing = False

    def request_key(self):
        n1 = secrets.token_hex(8).upper()
        with socket.create_connection((KDC_IP, KDC_PORT), timeout=10) as conn:
            print(f'\n[Alice] (1) -> KDC REQ_KEY: ID_A=Alice, ID_B=Bob, N1={n1}', flush=True)
            send_frame(conn, {'type': 'REQ_KEY', 'id_a': 'Alice', 'id_b': 'Bob', 'n1': n1})
            reply = next(read_frames(conn), None)
        if not reply or reply.get('type') != 'KDC_REPLY':
            raise ValueError(f'KDC tidak memberi balasan valid: {reply}')
        with self.guard:
            ka = self.master_key
        plain = decrypt_ascii(ka, reply['part_a'])
        fields = plain.split('|')
        if len(fields) != 4 or fields[1:] != ['Alice', 'Bob', n1]:
            raise ValueError('N1/ID_A/ID_B dari KDC tidak cocok; respons ditolak')
        ks = fields[0]
        if len(ks) != 16 or not ks.isascii():
            raise ValueError('Ks dari KDC tidak valid')
        print('[Alice] (2) Part A berhasil dibuka menggunakan Ka; N1 dan identitas cocok.', flush=True)
        print(f'[Alice] Part A ciphertext (Hex): {reply["part_a"]}', flush=True)
        return ks, reply['ticket_b']

    def negotiate(self):
        ks, ticket = self.request_key()
        with self.guard:
            self.pending_key = ks
            self.handshake_ok = False
            self.last_error = None
            self.ready_event.clear()
        print(f'[Alice] (3) Meneruskan tiket terenkripsi untuk Bob (Hex): {ticket}', flush=True)
        send_frame(self.peer, {'type': 'TICKET', 'data': ticket}, self.send_guard)
        if not self.ready_event.wait(timeout=15):
            raise TimeoutError('Bob belum mengirim READY dalam 15 detik')
        with self.guard:
            if not self.handshake_ok or self.pending_key is not None or self.session_key != ks:
                raise RuntimeError(self.last_error or 'Handshake tidak selesai')
        print('[Alice] AUTENTIKASI SUKSES: Ks aktif untuk chat AES.', flush=True)

    def receive_loop(self):
        try:
            for frame in read_frames(self.peer):
                typ = frame.get('type')
                if typ == 'CHALLENGE':
                    with self.guard:
                        ks = self.pending_key
                    if ks is None:
                        raise ValueError('Challenge datang tanpa sesi pending')
                    nonce = decrypt_ascii(ks, frame['data'])
                    answer = encrypt_ascii(ks, increment_nonce(nonce))
                    print(f'\n[Alice] (4) Challenge N2 diterima (Hex): {frame["data"]}', flush=True)
                    send_frame(self.peer, {'type': 'RESPONSE', 'data': answer}, self.send_guard)
                    print(f'[Alice] (5) E(Ks,f(N2)) dikirim (Hex): {answer}', flush=True)
                elif typ == 'READY':
                    with self.guard:
                        if self.pending_key is None:
                            raise ValueError('READY tanpa sesi pending')
                        self.session_key = self.pending_key
                        self.pending_key = None
                        self.handshake_ok = True
                        self.ready_event.set()
                elif typ == 'ERROR':
                    with self.guard:
                        self.pending_key = None
                        self.handshake_ok = False
                        self.last_error = f"Bob menolak: {frame.get('reason')}"
                        self.ready_event.set()
                elif typ == 'CHAT':
                    with self.guard:
                        ks = self.session_key if self.pending_key is None and self.handshake_ok else None
                    if ks is None:
                        print('\n[Alice] CHAT diabaikan: sesi belum aktif.', flush=True)
                        continue
                    plain = decrypt_ascii(ks, frame['data'])
                    print(f'\n[Alice] Ciphertext Bob -> Alice (Hex): {frame["data"]}', flush=True)
                    print(f'[Bob -> Alice] Plaintext ASCII: {plain}', flush=True)
                else:
                    raise ValueError(f'Tipe pesan tidak dikenal: {typ}')
        except (OSError, ValueError, UnicodeError, TypeError, KeyError) as exc:
            print(f'\n[Alice] Peer terputus/error: {exc}', flush=True)
        finally:
            with self.guard:
                self.connected = False
                self.handshake_ok = False
                self.ready_event.set()
            if not self.closing:
                print('\n[Alice] Koneksi dengan Bob terputus. Tekan Enter untuk keluar, '
                      'lalu jalankan ulang Alice setelah Bob aktif kembali.', flush=True)

    def send_chat(self, plain):
        ascii_plaintext(plain)
        with self.guard:
            ks = self.session_key if self.pending_key is None and self.handshake_ok else None
        if ks is None:
            print('[Alice] Pesan tidak terkirim: sesi belum aktif.')
            return
        cipher = encrypt_ascii(ks, plain)
        send_frame(self.peer, {'type': 'CHAT', 'data': cipher}, self.send_guard)
        print(f'[Alice] Ciphertext terkirim (Hex): {cipher}')

    def set_master_key(self):
        print('[Alice] /setkey mengubah Ka lokal, bukan Ks. Samakan juga Ka di KDC.')
        key = getpass.getpass('Input Ka baru (ASCII 16 karakter; tidak ditampilkan): ')
        update_key('Ka', key)
        with self.guard:
            self.master_key = key
        print('[Alice] Ka lokal diperbarui. Ubah Ka KDC, kemudian jalankan /rekey.')

    def run(self):
        with socket.create_connection((BOB_IP, BOB_PORT), timeout=10) as peer:
            peer.settimeout(None)
            self.peer = peer
            self.connected = True
            threading.Thread(target=self.receive_loop, daemon=True).start()
            print(f'[Alice] Terhubung ke Bob {BOB_IP}:{BOB_PORT}', flush=True)
            try:
                self.negotiate()
            except (ValueError, TimeoutError, RuntimeError, OSError) as exc:
                print('[Alice] Autentikasi awal gagal:', exc)
                print('Perbaiki key dengan /setkey, lalu jalankan /rekey.')
            print('\nPerintah: teks langsung atau /send pesan, /rekey, /setkey, /status, /quit')
            while self.connected:
                try:
                    entered = input('Alice> ')
                except (KeyboardInterrupt, EOFError):
                    break
                if not self.connected or entered == '/quit':
                    break
                if entered == '/status':
                    with self.guard:
                        print('Sesi:', 'AKTIF' if self.session_key and self.handshake_ok and not self.pending_key else 'BELUM SIAP')
                    continue
                if entered == '/setkey':
                    try:
                        self.set_master_key()
                    except ValueError as exc:
                        print('[Alice] Penggantian key gagal:', exc)
                    continue
                if entered == '/rekey':
                    try:
                        self.negotiate()
                        print('[Alice] /rekey berhasil tanpa restart aplikasi.')
                    except (ValueError, TimeoutError, RuntimeError, OSError) as exc:
                        print('[Alice] /rekey gagal:', exc)
                        print('Periksa kesamaan Ka Alice-KDC dan Kb Bob-KDC.')
                    continue
                text = entered[6:] if entered.startswith('/send ') else entered
                try:
                    self.send_chat(text)
                except (ValueError, OSError, UnicodeError) as exc:
                    print('[Alice] Gagal mengirim:', exc)
            self.closing = True


def main():
    try:
        Alice(read_config()['Ka']).run()
    except (OSError, RuntimeError, ValueError, TimeoutError) as exc:
        print('[Alice] Gagal:', exc, flush=True)
        print('Periksa: KDC aktif, Bob sudah dijalankan, dan master key sinkron.', flush=True)


if __name__ == '__main__':
    main()
