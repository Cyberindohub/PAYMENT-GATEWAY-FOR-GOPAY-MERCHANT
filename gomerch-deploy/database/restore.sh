#!/bin/bash
# Restore database GoMerch ke MongoDB lokal.
# Data akan dimuat ke database bernama "gomerch".
# Jalankan dari folder ini: bash restore.sh
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Restoring database -> gomerch ..."
mongorestore \
  --uri="mongodb://127.0.0.1:27017" \
  --gzip \
  --archive="$DIR/gomerch_db.archive" \
  --nsFrom='test_database.*' \
  --nsTo='gomerch.*' \
  --drop

echo "Selesai. Database 'gomerch' sudah terisi (akun admin, merchant demo, pengaturan, dsb)."
