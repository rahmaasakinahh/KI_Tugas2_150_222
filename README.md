# **Tugas 2 Keamanan Informasi AES-128 dan KDC**

---

| Anggota Kelompok | NRP |
|---|---|
|Nabila Shafa Rahayu|5025241150|
|Rahma Sakinah|5025241222|


## **Deskripsi Proyek**

---

Implementasi distribusi kunci menggunakan Key Distribution Center (KDC) dan komunikasi dua arah antara Alice dan Bob menggunakan algoritma AES-128 yang dibuat secara manual dengan Python.

## **Arsitektur Jaringan**

---

| Entitas | IP Address | Port |
|---|---|---|
| KDC | 172.28.77.10 | 5000 |
| Alice | 172.28.77.11 | Client |
| Bob | 172.28.77.12 | 6000 |

Ketiga entitas dijalankan dalam container Docker terpisah pada satu jaringan virtual.

## **Implementasi**

---

- AES-128 manual tanpa library enkripsi siap pakai.
- Mode CBC dengan padding PKCS#7.
- Distribusi session key melalui KDC dalam 5 langkah.
- Komunikasi terenkripsi dua arah antara Alice dan Bob.
- Penggantian session key menggunakan `/rekey`.
- Penggantian master key menggunakan `/setkey`.
- Pengujian transmisi jaringan menggunakan Wireshark.

## **Cara Menjalankan**

---

**1. Membuat master key**

```powershell
python scripts/setup_keys.py
```

**2. Menjalankan Docker**

```powershell
docker compose up -d
```

**3. Menjalankan Bob**

```powershell
docker compose exec bob python -u bob.py
```

**4. Menjalankan Alice**

```powershell
docker compose exec alice python -u alice.py
```

**5. Menjalankan pengujian otomatis**

```powershell
python -m unittest discover -s tests -v
```

## **Menjalankan di Tiga Perangkat**

---

Ketiga perangkat terhubung ke jaringan yang sama. Alamat IP dan lokasi file master key diatur melalui environment variable sehingga kode tidak perlu diubah. File `runtime/keys/<peran>/config.json` hasil `setup_keys.py` disalin ke perangkat masing-masing sebelum program dijalankan (master key dibagikan di luar jaringan).

| Variabel | Fungsi |
|---|---|
| `KDC_IP` | IP perangkat KDC |
| `BOB_IP` | IP perangkat Bob |
| `KEY_FILE` | Lokasi file master key peran tersebut |

**KDC**

```powershell
$env:KEY_FILE="runtime/keys/kdc/config.json"
python kdc.py
```

**Bob**

```powershell
$env:KEY_FILE="runtime/keys/bob/config.json"
python bob.py
```

**Alice**

```powershell
$env:KDC_IP="<IP KDC>"; $env:BOB_IP="<IP Bob>"
$env:KEY_FILE="runtime/keys/alice/config.json"
python alice.py
```

Port 5000 (KDC) dan 6000 (Bob) perlu diizinkan pada firewall. Transmisi diamati langsung di Wireshark pada interface Wi-Fi dengan filter `tcp.port == 5000 || tcp.port == 6000`.

## **Hasil Pengujian**

---

Pengujian yang telah dilakukan meliputi:

1. Distribusi kunci KDC dalam lima langkah.

<img width="1472" height="225" alt="image" src="https://github.com/user-attachments/assets/9c413d8c-f309-42c2-a52f-280b1312d754" />

2. Enkripsi dan dekripsi pesan AES.

<img width="1082" height="278" alt="image" src="https://github.com/user-attachments/assets/3dc458ed-4dc2-435a-893b-5f75ab613f88" />

3. Komunikasi Alice ke Bob dan Bob ke Alice.

<img width="930" height="107" alt="image" src="https://github.com/user-attachments/assets/5022cf53-c456-4fac-8041-b07f3eec7138" />

<img width="948" height="110" alt="image" src="https://github.com/user-attachments/assets/72fb2a22-3219-4c2a-b4b9-a3e62d5c0999" />

4. Penggantian session key tanpa restart.

<img width="1457" height="272" alt="image" src="https://github.com/user-attachments/assets/704e12d7-07dc-489c-9f32-4172dc81c46f" />

5. Penggantian master key.
6. Pengamatan ciphertext menggunakan Wireshark.

Rekaman paket disimpan di `evidence/demo_kdc_alice_bob.pcap`.

*Dokumentasi screenshot pengujian akan ditambahkan pada bagian ini.*
