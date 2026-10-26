"""Memperbarui kunci Ka dan Kb pada KDC tanpa menghentikan program."""
import getpass
import sys
from keys_config import update_key


def main():
    if len(sys.argv) != 2 or sys.argv[1].lower() not in ('alice', 'bob'):
        print('Pakai: python admin_kdc.py alice  ATAU  python admin_kdc.py bob')
        return 2
    role = sys.argv[1].lower()
    field = 'Ka' if role == 'alice' else 'Kb'
    print(f'KDC: ubah {field}. Harus sama dengan master key di {role.title()}.')
    key = getpass.getpass('Kunci ASCII 16 karakter baru: ')
    try:
        update_key(field, key)
    except ValueError as exc:
        print('GAGAL:', exc)
        return 1
    print(f'BERHASIL: {field} di KDC diperbarui tanpa restart. Jangan tampilkan nilainya.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
