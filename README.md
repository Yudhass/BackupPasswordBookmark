# 🗄️ Arsip — Backup Password & Bookmark Semua Browser

> Backup **password dan bookmark milik sendiri** dari Chrome, Edge, Brave, Opera, Vivaldi, Chromium, dan Firefox — lewat Web modern, GUI desktop, atau CLI.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Open_Source-orange)
![UI](https://img.shields.io/badge/UI-Web_%7C_GUI_%7C_CLI-purple)

---

## ⚠️ Disclaimer / Batasan Tanggung Jawab — WAJIB DIBACA

> **Aplikasi ini OPEN SOURCE dan hanya untuk mem-backup data MILIK SENDIRI di komputer sendiri** (misal: pindahan laptop, install ulang, atau arsip pribadi).
>
> ❌ **DILARANG** dipakai untuk mengambil / mencuri / menyalahgunakan data milik orang lain, tanpa izin, atau untuk tindakan melanggar hukum.
>
> ✅ Dengan memakai / meng-clone / mem-fork repo ini, kamu setuju bahwa:
>
> 1. Kamu hanya memakai aplikasi ini untuk data yang kamu miliki / kamu beri kuasa.
> 2. **Penulis / maintainer TIDAK BERTANGGUNG JAWAB** atas segala penyalahgunaan, kerusakan, kehilangan data, atau tuntutan hukum akibat pemakaian di luar semestinya.
> 3. Risiko keamanan file hasil (yang berisi password plain-text) sepenuhnya tanggung jawab pengguna.
>
> Kalau kamu tidak setuju, **jangan gunakan aplikasi ini.**

---

## 📖 Daftar Isi

- [Kenapa Arsip?](#-kenapa-arsip)
- [Tampilan & Cara Pakai Cepat](#-tampilan--cara-pakai-cepat)
- [Hasil Backup](#-hasil-backup)
- [Browser yang Didukung](#-browser-yang-didukung)
- [Syarat & Instalasi](#-syarat--instalasi)
- [Panduan Lengkap Tiap Mode](#-panduan-lengkap-tiap-mode)
- [Import Kembali Hasil Backup](#-import-kembali-hasil-backup)
- [Keamanan](#-keamanan)
- [Troubleshooting](#-troubleshooting)
- [Struktur Proyek](#-struktur-proyek)
- [Bangun File EXE Sendiri](#-bangun-file-exe-sendiri)
- [Kontribusi / Kolaborasi](#-kontribusi--kolaborasi)
- [Aturan Pakai yang Semestinya](#-aturan-pakai-yang-semestinya)
- [Lisensi](#-lisensi)

---

## ✨ Kenapa Arsip?

| Fitur | Keterangan |
|---|---|
| 🌐 **Semua browser populer** | Chromium (Chrome, Edge, Brave, Vivaldi, Opera) + Firefox |
| 👤 **Per profil** | Bisa pilih `Default`, `Profile 1`, `Guest`, profil custom, dll. |
| 📑 **Bookmark super lengkap** | `Bookmarks` + `Bookmarks.bak` digabung, Sync Data (Reading List, Grup Tab, Tab Terbuka), History, Sessions |
| 🔑 **Password v10 + v20 App-Bound** | Mendukung Chrome 127+ (butuh Run as Administrator) |
| 🦊 **Firefox via NSS** | Tanpa admin, pakai `nss3.dll` bawaan Firefox |
| 🖥️ **3 cara pakai** | Web modern (disarankan) / GUI tkinter / CLI |
| 📂 **Struktur folder utuh** | Folder bookmark bersarang tetap rapi saat di-import lagi |
| 🔌 **Tanpa dependensi berat** | Hanya butuh `pycryptodome` |

---

## 🚀 Tampilan & Cara Pakai Cepat

Pilih **salah satu** yang paling nyaman:

### 1️⃣ Web Modern — ⭐ Disarankan (paling mudah)

```bat
run-backup-web.bat
```

1. Browser otomatis membuka halaman **Arsip** di `http://127.0.0.1:12719` (hanya di komputer ini).
2. Centang browser + profil yang mau dibackup.
3. Klik **BACKUP SEKARANG**.
4. Hasil tampil di tabel + tersimpan di folder `hasil-backup/`.

> 💡 Responsif — enak dibuka di layar HP maupun desktop.
> 🔑 Untuk password v20 Chromium: tutup dulu, lalu klik kanan `run-backup-web.bat` → **Run as administrator**.

### 2️⃣ GUI Desktop (tkinter)

```bat
run-backup-gui.bat
```

Tampilan **Arsip**: pita judul + badge administrator, panel **Sumber** (scroll per browser/profil) dan panel **Hasil** yang bisa digeser, plus tombol kuningan **BACKUP SEKARANG** di bawah. Bisa di-resize, backup jalan di background (ada progress).

> 🔑 Klik kanan → **Run as administrator** agar password v20 Chromium terbuka.

### 3️⃣ CLI / Terminal

```bat
python app.py --list-browsers
python app.py                                   REM semua yang terdeteksi
python app.py --browser chrome firefox
python app.py --browser chrome --profile Default
python app.py --show --browser edge             REM tampilkan password di layar
python app.py --diagnosa                        REM cek kenapa v20 terkunci (mode admin)
```

---

## 📦 Hasil Backup

Lokasi default: `hasil-backup/` **di samping aplikasi/EXE** (bukan folder terminal). Dibuat otomatis. Ubah via `--output`.

```text
hasil-backup/
├── passwords/        <- password, CSV (name, url, username, password)
│   ├── chrome-Default-passwords_26_09_2026.csv
│   ├── firefox-xxxx-passwords_26_09_2026.csv
│   └── firefox-xxxx-profilefiles_26_09_2026/   (logins.json + key4.db mentah)
└── bookmarks/        <- bookmark, HTML Netscape per folder root
    ├── chrome-Default-bookmarks-bar_26_09_2026.html    (Bilah bookmark)
    ├── chrome-Default-bookmarks-other_26_09_2026.html  (Bookmark lainnya + Sync/Tab)
    └── chrome-Default-riwayat_26_09_2026.html          (Riwayat, file terpisah)
```

- Struktur folder di dalam tiap file **dipertahankan (nested)** — saat di-import, bookmark kembali masuk ke foldernya.
- Backup di hari yang sama otomatis bernomor: `..._26_09_20262.html`, dst.
- Contoh bentuk file (data dummy) ada di folder `contoh/`.

---

## 🌐 Browser yang Didukung

| Browser | Password | Bookmark | Keterangan |
|---|---|---|---|
| Chrome / Edge / Brave / Vivaldi / Chromium / Opera | v10 + v20 App-Bound | HTML (`Bookmarks` + `.bak` + Sync Data) | v20 butuh Administrator |
| Firefox (+ Dev Edition) | via NSS (`nss3.dll`) | HTML (`places.sqlite` + `bookmarkbackups/*.jsonlz4`) | Tanpa admin; jika ada master password hanya file mentah |

<details>
<summary><b>🔍 Dari mana datanya dibaca? (klik untuk detail)</b></summary>

- **Chromium:** file `Bookmarks` **digabung** `Bookmarks.bak`, semua folder rekursif, + **Sync Data** LevelDB (`reading_list` → Reading List, `saved_tab_group` → Grup Tab Tersimpan, `sessions` → Tab Terbuka, `send_tab_to_self` → Tab Terkirim). Tab lokal (`Sessions/Session_*`) dan **History** (`*-riwayat_*.html` terpisah) ikut dibackup.
- **Firefox:** `places.sqlite` digabung cadangan otomatis `bookmarkbackups/*.jsonlz4`, beserta path folder aslinya.
- Profil terdeteksi dari **salah satu** sinyal (Login Data / Bookmarks / History / Sync / Sessions) — profil tanpa password tetap ikut.

</details>

---

## ⚙️ Syarat & Instalasi

- ✅ Windows + Python 3.10+
- ✅ Install 1 dependensi:

```bat
pip install -r requirements.txt
```

Isi `requirements.txt` hanya `pycryptodome`.

Clone repo:

```bat
git clone https://github.com/Yudhass/BackupPasswordBookmark.git
cd BackupPasswordBookmark
pip install -r requirements.txt
```

---

## 📖 Panduan Lengkap Tiap Mode

| Mode | File | Cocok untuk |
|---|---|---|
| Web | `run-backup-web.bat` / `python app.py --web` | Pemula, tampilan paling jelas |
| GUI | `run-backup-gui.bat` / `python app.py --gui` | Tanpa browser, aplikasi desktop |
| CLI | `run-backup.bat` / `python app.py ...` | Otomatisasi / scripting |
| EXE | `ArsipBackup.exe` | Komputer tanpa Python (lihat bawah) |

Semua mode menyimpan ke folder yang sama (`hasil-backup/`).

---

## 📥 Import Kembali Hasil Backup

- **Password CSV** → `chrome://password-manager/settings` → Import
  (Edge: `edge://wallet/passwords`, Firefox: Settings → Import).
- **Bookmark HTML** → Bookmark Manager (`Ctrl+Shift+O`) → titik tiga → Import.

> 🧹 Setelah selesai import, **hapus CSV** dari folder biasa dan pindahkan ke media terenkripsi / hapus permanen.

---

## 🔐 Keamanan

> Hasil backup berisi **password plain-text**. Perlakukan seperti kunci rumah.

1. Jangan upload `hasil-backup/` ke Git / Drive publik / Discord.
2. Folder ini sudah masuk `.gitignore` — jangan dihapus barisnya.
3. Simpan di flashdisk / HDD terenkripsi (BitLocker / VeraCrypt).
4. Tutup browser saat backup password v20 agar file tidak terkunci.
5. Hanya backup di komputer yang kamu miliki.

---

## 🛠️ Troubleshooting

<details>
<summary><b>🔑 Password v20 terkunci padahal sudah admin?</b></summary>

Jalankan di terminal admin:

```bat
python app.py --diagnosa
```

Hasilnya menunjukkan gagal di tahap mana. Penyebab paling sering:

1. **Elevate sebagai akun berbeda** (mis. akun Administrator lain, bukan pemilik Chrome) → DPAPI gagal. Solusi: jadikan akun harian anggota Administrators, lalu klik kanan → Run as administrator **tanpa memasukkan akun lain**.
2. **LSASS terproteksi (PPL)** → aplikasi otomatis coba `winlogon`/`services`. Kalau semua gagal, output `--diagnosa` akan bilang.

Alternatif: export manual dari `chrome://password-manager/settings`.

</details>

<details>
<summary><b>🦊 Firefox tertulis &lt;firefox terkunci&gt;?</b></summary>

Artinya profil pakai **master password**. Username + URL tetap dibackup, dan file mentah (`logins.json` + `key4.db` + `cert9.db`) disalin agar bisa di-restore. Tanpa master password → langsung terdekripsi via NSS.

</details>

<details>
<summary><b>📑 Bookmark terasa belum semuanya?</b></summary>

Penyebab paling sering: file `Bookmarks` utama sedang kosong/reset (1KB) sementara `Bookmarks.bak` (100–300KB) berisi aslinya. Aplikasi ini **menggabungkan keduanya + Sync + History + Sessions**, jadi biasanya sudah lengkap. Cek file `*-riwayat_*.html` dan folder `Tab Terbuka` / `Reading List` — datamu mungkin ada di sana.

</details>

<details>
<summary><b>🛡️ SmartScreen / antivirus bertanya saat buka EXE?</b></summary>

Wajar karena EXE tidak ditandatangani digital. Pilih **More info → Run anyway**. Kalau ragu, build sendiri dari source (lihat bawah) atau jalankan via Python.

</details>

---

## 📁 Struktur Proyek

```text
app.py               → aplikasi utama (CLI + GUI + web, semua browser)
webui/               → tampilan web (localhost saja: index.html, style.css, app.js)
requirements.txt     → pycryptodome
run-backup-web.bat   → launcher web modern (disarankan)
run-backup-gui.bat   → launcher GUI desktop
run-backup.bat       → launcher CLI
build-exe.bat        → script build ArsipBackup.exe via PyInstaller
hasil-backup/        → output (diabaikan git, jangan di-commit!)
contoh/              → contoh bentuk file CSV & HTML (data dummy)
```

---

## 🔨 Bangun File EXE Sendiri

- `ArsipBackup.exe` = **versi GUI**: klik 2x langsung membuka aplikasi desktop (tanpa console).
- Cara membuat ulang: klik 2x `build-exe.bat` (butuh internet sekali untuk install PyInstaller). Hasil di `dist/` dan disalin ke root.
- Untuk password v20: klik kanan EXE → **Run as administrator**.
- Perintah CLI / `--diagnosa` / `--web` tetap via `python app.py ...` (EXE GUI memang tanpa console).

---

## 🤝 Kontribusi / Kolaborasi

Kontribusi sangat diterima! 🙌 Baik itu lapor bug, tambah browser baru, perbaiki tampilan, atau perbaiki dokumentasi.

### Cara cepat ikut serta

1. **Fork** repo ini → **Clone** fork-mu:
   ```bat
   git clone https://github.com/USERNAME-MU/BackupPasswordBookmark.git
   cd BackupPasswordBookmark
   ```
2. Buat branch baru:
   ```bat
   git checkout -b fitur-nama-fitur
   ```
3. Install & jalankan:
   ```bat
   pip install -r requirements.txt
   python app.py --list-browsers
   ```
4. Commit dengan pesan jelas, lalu **Push + Pull Request** ke repo utama.

### Ide kontribusi yang dibutuhkan

- [ ] Dukungan browser baru (Arc, Floorp, LibreWolf, dll.)
- [ ] Export JSON / encrypted ZIP (password terproteksi)
- [ ] Mode gelap untuk WebUI
- [ ] Terjemahan README (EN / lainnya)
- [ ] Unit test untuk parser LevelDB / Snappy / LZ4
- [ ] Perbaiki dokumentasi / tambah screenshot

### Aturan kontribusi

- Hanya uji dengan **data milik sendiri / dummy**. Jangan sertakan `hasil-backup/` asli, CSV asli, atau file `Login Data` asli di PR/issue.
- Jangan commit file sensitif: `hasil-backup/`, `*.csv`, `Login Data`, `logins.json`, `key4.db`.
- Ikuti gaya kode yang ada (standar library sebisa mungkin, tanpa dependensi berat).
- Satu PR = satu tujuan. Sertakan cara test-nya di deskripsi PR.
- Bersikap sopan — dilarang keras memakai isu/PR untuk meminta / menyebar data curian.

Punya pertanyaan? Buka **Issues** → **New issue** dengan template: kronologi, browser + versi, perintah yang dijalankan, dan output `--diagnosa` (sensor data pribadi!).

---

## 📏 Aturan Pakai yang Semestinya

Dengan memakai repo ini kamu setuju untuk:

1. Mem-backup **hanya data milik sendiri** atau dengan izin tertulis pemiliknya.
2. Tidak memakai untuk phising, malware, warnet tanpa izin, atau forensik ilegal.
3. Tidak mendistribusikan ulang versi yang disalahgunakan untuk mencuri data.
4. Menjaga file hasil dengan enkripsi dan menghapus setelah selesai dipakai.

> Pelanggaran terhadap aturan ini = penyalahgunaan. Segala risiko & tanggung jawab hukum ada pada pelaku, **bukan penulis**.

---

## 📜 Lisensi

Proyek ini dirilis sebagai **Open Source di bawah lisensi MIT** — bebas dipakai, diubah, dan disebar ulang **dengan tetap mencantumkan atribusi**, dan **tanpa jaminan apa pun** (lihat `LICENSE`).

```
MIT License — TANPA JAMINAN. Penulis tidak bertanggung jawab atas
kerusakan / kehilangan / penyalahgunaan akibat pemakaian software ini.
Gunakan hanya untuk data milik sendiri dan sesuai hukum yang berlaku.
```

> 💡 Kalau kamu fork: pertahankan blok Disclaimer di atas agar pengguna berikutnya paham batasannya.

---

<p align="center">
Dibuat untuk kebutuhan arsip pribadi. ⭐ Star repo ini kalau membantu, dan PR dipersilakan!
</p>
