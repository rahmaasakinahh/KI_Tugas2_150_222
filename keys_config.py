"""Menyimpan master key setiap pihak secara lokal tanpa mengirimkannya melalui jaringan."""
import json
import os
from pathlib import Path
from protocol import ascii_key

CONFIG = Path(os.environ.get('KEY_FILE', '/app/private/config.json'))


def read_config(path=CONFIG):
    with open(path, encoding='ascii') as fp:
        obj = json.load(fp)
    for field in ('Ka', 'Kb'):
        if field in obj:
            ascii_key(obj[field])
    return obj


def update_key(field, value, path=CONFIG):
    ascii_key(value)
    obj = read_config(path)
    if field not in obj:
        raise ValueError(f'Kunci {field} tidak tersedia di pihak ini')
    obj[field] = value
    target = Path(path)
    temp = target.with_name(target.name + '.tmp')
    try:
        with open(temp, 'w', encoding='ascii') as out:
            json.dump(obj, out)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, target)
    finally:
        if temp.exists():
            temp.unlink()
