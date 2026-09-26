@echo off
REM Build ArsipBackup.exe versi GUI dari app.py memakai PyInstaller.
REM Hasil: ArsipBackup.exe satu file. Klik 2x untuk langsung membuka
REM aplikasi desktop tanpa jendela hitam console.
REM Cara pakai: klik 2x file ini, tunggu sampai selesai.
REM Untuk password v20 Chromium: klik kanan ArsipBackup.exe,
REM pilih Run as administrator.
REM Catatan: perintah CLI dan --diagnosa tetap dijalankan via python app.py
cd /d "%~dp0"

echo [1/3] Cek Python...
python --version || (echo Python tidak ditemukan, install dari python.org dan centang Add to PATH & pause & exit /b 1)

echo [2/3] Install PyInstaller dan dependensi...
python -m pip install --upgrade pyinstaller pycryptodome || (echo Gagal install, periksa koneksi internet lalu ulangi & pause & exit /b 1)

echo [3/3] Build EXE GUI tanpa console, bisa beberapa menit...
python -m PyInstaller --noconfirm --clean --onefile --windowed --name "ArsipBackup" --add-data "webui;webui" app.py || (echo Build gagal, lihat pesan error di atas & pause & exit /b 1)

copy /y "dist\ArsipBackup.exe" "ArsipBackup.exe"
echo(
echo ============================================================
echo Selesai. File EXE ada di folder ini: ArsipBackup.exe
echo Windows SmartScreen atau antivirus kadang bertanya karena EXE
echo tidak ditandatangani, pilih Run anyway atau More info.
echo Untuk password v20 Chromium: klik kanan, Run as administrator.
echo ============================================================
pause
