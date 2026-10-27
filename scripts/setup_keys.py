"""Membuat master key Ka dan Kb untuk KDC, Alice, dan Bob saat setup awal."""
import getpass
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from protocol import new_key, ascii_key

KEY_ROOT = ROOT / 'runtime' / 'keys'


def ask(label):
    print(f'{label}: Enter kosong = buat kunci ASCII acak; atau ketik 16 karakter ASCII.')
    typed = getpass.getpass(f'Input {label}: ')
    if not typed:
        typed = new_key()
        print(f'{label} dibangkitkan secara acak (nilai tidak ditampilkan).')
    ascii_key(typed)
    return typed


def main():
    paths = {role: KEY_ROOT / role / 'config.json' for role in ('kdc', 'alice', 'bob')}
    if any(path.exists() for path in paths.values()):
        print('Kunci lokal sudah ditemukan. Tidak ditimpa agar sinkron.')
        print('Gunakan /setkey di Alice/Bob dan admin_kdc.py untuk perubahan saat runtime.')
        return 0
    try:
        ka = ask('Ka (Alice-KDC)')
        kb = ask('Kb (Bob-KDC)')
    except ValueError as exc:
        print('GAGAL:', exc)
        return 1
    roles = {'kdc': {'Ka': ka, 'Kb': kb}, 'alice': {'Ka': ka}, 'bob': {'Kb': kb}}
    for role, data in roles.items():
        paths[role].parent.mkdir(parents=True, exist_ok=True)
        with paths[role].open('x', encoding='ascii') as fp:
            json.dump(data, fp)
    print('SUKSES: Ka/Kb tersimpan terpisah untuk KDC, Alice, Bob di runtime/keys (gitignore).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
