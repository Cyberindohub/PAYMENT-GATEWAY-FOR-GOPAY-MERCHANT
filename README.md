Isi paket:
  backend/            -> kode FastAPI + file .env (sudah terisi)
  frontend-build/     -> React SUDAH DI-BUILD
  database/           -> dump database + restore.sh
  nginx.conf.example  -> contoh reverse proxy Nginx
  start-backend.sh    -> menjalankan backend via SSH

Yang HARUS Anda ganti sendiri di backend/.env:
  - GOMERCH_TOKEN  -> token API GoMerch Pro Anda 
  (opsional) ADMIN_PASSWORD kalau ingin ganti password admin.

------------------------------------------------------------------------
LANGKAH CEPAT
------------------------------------------------------------------------
2) DATABASE (MongoDB)
   - Di aaPanel > Databases > MongoDB, pastikan ada database:
       nama: gomerch  |  user: gomerch  |  password: Cpns2019#
     (kalau beda, sesuaikan MONGO_URL di backend/.env — ingat karakter '#'
      ditulis %23 di dalam URL)
   - Restore data bawaan (akun admin + merchant demo + pengaturan):
       bash restore.sh

3) BACKEND (Python Project Manager) — REKOMENDASI
   - App Store > install "Python Project Manager"
   - Version Manager > install Python 3.11
   - Python Project > Add Project:
       Path            : 
       Python version  : 3.11
       Mode/Framework  : uvicorn
       Startup command : uvicorn server:app --host 0.0.0.0 --port 8001
       Port            : 8001
       (aktifkan install requirements.txt)
   - Setelah jalan, buka terminal project lalu:
     lalu Restart project.
   - Uji: curl http://127.0.0.1:8001/api/branding   (harus keluar JSON)

   (Alternatif SSH: jalankan  bash start-backend.sh  dari folder paket)

4) WEBSITE + NGINX
   - aaPanel > Website > Add site: 
   - Settings > Config file: tempel isi nginx.conf.example
     (root frontend sudah menunjuk ke .../frontend-build)
   - Reload Nginx
   - SSL: Website > SSL > Let's Encrypt > aktifkan + Force HTTPS  (WAJIB)

5) SELESAI — buka DOMAINANDA
   Login admin:
     email    : 
     password : GoMerch2026!   (atau sesuai ADMIN_PASSWORD di .env)
   Saat login pertama, admin WAJIB setup 2FA:
     scan QR dengan Google Authenticator lalu masukkan kode 6 digit.

------------------------------------------------------------------------
AKUN DEMO (sudah ada di database)
------------------------------------------------------------------------
  Merchant : merchant.demo@gomerch.pro  / GoMerch2026!
  Staff    : admin.demo@gomerch.pro, finance.demo@gomerch.pro,
             support.demo@gomerch.pro, risk.demo@gomerch.pro  (GoMerch2026!)

------------------------------------------------------------------------
CRON AUTO-SETTLEMENT T+1 (opsional)
------------------------------------------------------------------------
  aaPanel > Cron > Shell Script (harian 01:00):
    curl -X POST https://DOMAINMU/api/cron/auto-settlement \
      -H "Authorization: Bearer cronsec_7173a6a3140456511cbb0b95bee72c58bba16514bbd4c704"

------------------------------------------------------------------------
