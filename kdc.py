"""Program KDC untuk membuat dan membagikan kunci pada langkah 1 dan 2."""
import json
import socket
import string
import threading
from keys_config import read_config
from protocol import KDC_PORT, encrypt_ascii, new_key, read_frames, send_frame


def process_peer(conn, addr, key_loader=read_config):
    with conn:
        try:
            for request in read_frames(conn):
                n1 = request.get('n1')
                if (request.get('type') != 'REQ_KEY' or request.get('id_a') != 'Alice'
                        or request.get('id_b') != 'Bob' or not isinstance(n1, str)
                        or len(n1) != 16 or any(x not in string.hexdigits for x in n1)):
                    send_frame(conn, {'type': 'ERROR', 'reason': 'Identitas/nonce invalid'})
                    continue
                config = key_loader()  # Muat ulang: perubahan Ka/Kb dari admin berlaku tanpa restart
                ks = new_key()
                alice_part = encrypt_ascii(config['Ka'], f'{ks}|Alice|Bob|{n1}')
                ticket = encrypt_ascii(config['Kb'], f'{ks}|Alice')
                send_frame(conn, {'type': 'KDC_REPLY', 'part_a': alice_part, 'ticket_b': ticket})
                print(f'[KDC] (1) REQ_KEY dari Alice -> Bob, N1={n1}', flush=True)
                print('[KDC] (2) Ks baru dibuat. Bagian Alice & tiket Bob dienkripsi AES manual.', flush=True)
        except (OSError, ValueError, KeyError, TypeError, UnicodeError, json.JSONDecodeError) as error:
            print(f'[KDC] Koneksi {addr}: {error}', flush=True)


def main():
    read_config()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', KDC_PORT))
        server.listen(10)
        print('[KDC] Aktif di port 5000; siap melayani Alice.', flush=True)
        while True:
            conn, addr = server.accept()
            threading.Thread(target=process_peer, args=(conn, addr), daemon=True).start()


if __name__ == '__main__':
    main()
