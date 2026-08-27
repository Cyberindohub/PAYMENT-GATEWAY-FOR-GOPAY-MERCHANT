#!/bin/bash
# Menjalankan backend FastAPI (dipakai jika TIDAK memakai GUI Python Project Manager).
# Butuh Python 3.11. Jalankan dari folder backend.
set -e
cd "$(dirname "$0")/backend"

if [ ! -d "venv" ]; then
  echo "Membuat virtualenv..."
  python3.11 -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install emergentintegrations --extra-index-url https://d33sy5i8bnduwe.cloudfront.net/simple/

echo "Menjalankan uvicorn di 0.0.0.0:8001 ..."
uvicorn server:app --host 0.0.0.0 --port 8001
