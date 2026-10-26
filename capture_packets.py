"""Merekam paket jaringan Alice ke file PCAP untuk diperiksa di Wireshark."""
import os
from pathlib import Path
import socket
import struct
import sys
import time

OUTPUT = Path('/app/captures/demo_kdc_alice_bob.pcap')


def pcap_header():
    return struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)


def pcap_record(packet, timestamp_ns):
    second, nano = divmod(timestamp_ns, 1_000_000_000)
    usec = nano // 1000
    return struct.pack('<IIII', second, usec, len(packet), len(packet)) + packet


def main():
    iface = 'eth0'
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    try:
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sniff:
            sniff.bind((iface, 0))
            print(f'[CAPTURE] Listening {iface} pada namespace Alice. Output: {OUTPUT}', flush=True)
            print('[CAPTURE] Jalankan Bob/Alice, pesan, /rekey; tekan Ctrl+C setelah selesai.', flush=True)
            with open(OUTPUT, 'wb') as output:
                output.write(pcap_header())
                output.flush()
                try:
                    while True:
                        data = sniff.recv(65535)
                        output.write(pcap_record(data, time.time_ns()))
                        output.flush()
                except KeyboardInterrupt:
                    print('\n[CAPTURE] Berhenti. Buka file .pcap dengan Wireshark di Windows.', flush=True)
    except PermissionError:
        print('Akses raw-socket ditolak. Pastikan compose.yaml menyediakan NET_RAW.', file=sys.stderr)
        return 1
    except OSError as exc:
        print('Gagal capture:', exc, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
