# NetCut CLI

Tool CLI untuk scan perangkat di jaringan LAN, memutus koneksi internet target, dan memonitor traffic DNS/HTTP/HTTPS (TLS SNI).

> **Peringatan legal:** Hanya gunakan di jaringan milik sendiri atau dengan izin tertulis. ARP/NDP spoofing dan MITM tanpa otorisasi ilegal di banyak yurisdiksi.

## Fitur

| Mode | Fungsi |
|------|--------|
| **Cut** | Putuskan internet target via ARP/NDP blackhole (IPv4 + IPv6) |
| **Sniff** | Monitor domain yang diakses target (DNS, HTTP, HTTPS-SNI) |
| **Keduanya** | Cut + sniff bersamaan |

Fitur tambahan:

- Scan ARP otomatis + resolve hostname & vendor MAC
- Deteksi tipe device (HP, PC, IoT, dll.)
- Verifikasi status cut dari sisi attacker
- Support dual-stack IPv4/IPv6

## Persyaratan

- **macOS** (tool ini memakai `route`, `ifconfig`, `ipconfig`, `ndp`, `sysctl`)
- **Python 3.10+**
- Koneksi ke jaringan LAN/WiFi yang sama dengan target
- **Hak root (sudo)** — wajib untuk ARP poison, sniff, dan scan

## Setup

### 1. Clone / download project

```bash
cd /path/to/netcuting
```

### 2. Jalankan via script (disarankan)

Script `run.sh` otomatis membuat virtualenv dan install dependency:

```bash
chmod +x run.sh
./run.sh
```

### 3. Setup manual (opsional)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python netcut.py
```

## Cara pakai

### Alur interaktif

```bash
./run.sh
```

1. Tool scan perangkat di subnet
2. Pilih mode:
   - `1` Cut — putuskan internet target
   - `2` Sniff — monitor DNS/HTTP/HTTPS target
   - `3` Keduanya — cut + sniff
   - `0` Scan ulang / batal
3. Pilih nomor device target
4. Konfirmasi → session dimulai
5. Tekan **Ctrl+C** untuk stop (koneksi target otomatis di-restore)

### Shortcut CLI

```bash
./run.sh --cut          # langsung ke mode Cut setelah scan
./run.sh --sniff        # langsung ke mode Sniff
./run.sh --cut --sniff  # langsung ke mode Keduanya
./run.sh -v --sniff     # sniff + verbose log
./run.sh -vv            # verbose lebih detail
```

## Mode Sniff — catatan penting

Sniff **tidak** bekerja dengan passive capture biasa di WiFi modern. Tool memakai **ARP/NDP MITM tap** agar traffic target lewat mesin kamu:

- **Sniff saja:** MITM tap + IP forwarding ON → internet target tetap jalan, domain terlihat
- **Cut + Sniff:** MITM tap + forwarding OFF → internet terputus, tapi DNS/SNI attempt tetap bisa terlihat

Yang bisa dideteksi:

| Tipe | Protokol | Contoh output |
|------|----------|---------------|
| DNS | UDP 53 | `DNS google.com` |
| HTTP | TCP 80 | `HTTP example.com` |
| HTTPS | TCP 443 (SNI) | `HTTPS instagram.com` |

Batasan:

- HTTPS hanya menampilkan **domain** (SNI), bukan full URL/path
- DoH/DoT tidak muncul di DNS (tapi SNI HTTPS masih bisa)
- IPv6 privacy address mungkin tidak terdeteksi

## Troubleshooting

### Gateway MAC tidak ditemukan

Scan ulang dari dashboard. Gateway harus muncul di hasil ARP scan sebelum cut/sniff bisa jalan.

### Sniff panel kosong

1. Pastikan target sedang browsing (buka situs/app)
2. Jalankan dengan verbose: `./run.sh -v --sniff`
3. Cek counter **Poison** di panel — harus naik (bukti MITM aktif)
4. Pastikan kamu dan target di **jaringan yang sama**

### Permission denied / butuh root

Tool otomatis delegasi ke `sudo` worker. Masukkan password saat diminta:

```
Delegasi [sniff] ke sudo worker (netcut.sniff_worker)
```

### Scan gagal

- Pastikan WiFi/LAN aktif dan punya IP
- Coba jalankan manual: `sudo .venv/bin/python netcut.py`

## Struktur project

```
netcuting/
├── netcut.py           # Entry point CLI
├── run.sh              # Setup + run helper
├── requirements.txt
└── netcut/
    ├── cli.py          # Dashboard interaktif
    ├── scanner.py      # ARP scan
    ├── cutter.py       # ARP/NDP poison
    ├── sniffer.py      # DNS/HTTP/TLS-SNI sniff
    ├── monitor.py      # Verifikasi cut
    ├── ipv6.py         # IPv6 discovery & NDP
    ├── cut_worker.py   # Root worker (cut)
    └── sniff_worker.py # Root worker (sniff/both)
```

## Dependencies

- [Scapy](https://scapy.net/) — packet crafting & sniffing
- [Rich](https://github.com/Textualize/rich) — terminal UI
