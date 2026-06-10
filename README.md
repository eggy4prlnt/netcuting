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

- **macOS, Linux, atau Windows**
- **Python 3.10+**
- Koneksi ke jaringan LAN/WiFi yang sama dengan target
- **Hak privileged** — wajib untuk ARP poison, sniff, dan scan:
  - macOS / Linux: `sudo` (tool otomatis minta password)
  - Windows: Administrator + [Npcap](https://npcap.com/) (Scapy butuh Npcap untuk raw packet)

### Persyaratan per platform

| Platform | Paket / tool tambahan |
|----------|------------------------|
| **macOS** | Sudah built-in (`route`, `ifconfig`, `ndp`, `sysctl`) |
| **Linux** | `ip` (iproute2), `ping` — umumnya sudah terpasang |
| **Windows** | [Npcap](https://npcap.com/) — **auto-detect & guided install** saat pertama jalan; terminal **as Administrator** |

NetCut di Windows otomatis mengecek Npcap saat startup. Jika belum terpasang, installer resmi diunduh dari npcap.com dan wizard install dibuka (butuh klik **I Agree → Install** — Npcap gratis tidak mendukung silent install).

Lewati cek: `.\run.ps1 --skip-npcap-check`

Hostname resolution (opsional): `dig` (BIND tools) — jika tidak ada, kolom Name tetap kosong.

## Setup

### 1. Clone / download project

```bash
cd /path/to/netcuting
```

### 2. Jalankan via script (disarankan)

**macOS / Linux:**

```bash
chmod +x run.sh
./run.sh
```

**Windows (PowerShell):**

```powershell
.\run.ps1
```

**Windows (CMD):**

```cmd
run.bat
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

### Permission denied / butuh root / admin

- **macOS / Linux:** tool otomatis delegasi ke `sudo` worker. Masukkan password saat diminta.
- **Windows:** setujui prompt UAC saat diminta, atau buka terminal **Run as Administrator** sejak awal.

```
Delegasi [sniff] ke privileged worker (netcut.sniff_worker)
```

### Scan gagal

- Pastikan WiFi/LAN aktif dan punya IP
- **macOS / Linux:** `sudo .venv/bin/python netcut.py`
- **Windows:** buka PowerShell as Administrator, lalu `.\run.ps1`

## Struktur project

```
netcuting/
├── netcut.py           # Entry point CLI
├── run.sh              # Launcher macOS/Linux
├── run.ps1             # Launcher Windows (PowerShell)
├── run.bat             # Launcher Windows (CMD)
├── requirements.txt
└── netcut/
    ├── cli.py          # Dashboard interaktif
    ├── platform_ops.py # Abstraksi OS (network, privilege, forwarding)
    ├── network.py      # Deteksi interface/gateway/subnet
    ├── scanner.py      # ARP scan
    ├── cutter.py       # ARP/NDP poison
    ├── sniffer.py      # DNS/HTTP/TLS-SNI sniff
    ├── monitor.py      # Verifikasi cut
    ├── ipv6.py         # IPv6 discovery & NDP
    ├── cut_worker.py   # Privileged worker (cut)
    ├── sniff_worker.py # Privileged worker (sniff/both)
    └── scan_worker.py  # Privileged worker (ARP scan)
```

## Dependencies

- [Scapy](https://scapy.net/) — packet crafting & sniffing
- [Rich](https://github.com/Textualize/rich) — terminal UI
