#!/bin/bash

ROOT_DIR=$(cd $(dirname $0)/..; pwd)
DB_DIR="$ROOT_DIR/db"
BENCH_DIR="$ROOT_DIR/bench"

export MYSQL_PWD=isucon

mysql -h 172.16.195.1 -uisucon -pisucon -e "DROP DATABASE IF EXISTS torb; CREATE DATABASE torb;"
mysql -h 172.16.195.1 -uisucon -pisucon torb < "$DB_DIR/schema.sql"

if [ ! -f "$DB_DIR/isucon8q-initial-dataset.sql.gz" ]; then
  echo "Run the following command beforehand." 1>&2
  echo "$ ( cd \"$BENCH_DIR\" && bin/gen-initial-dataset )" 1>&2
  exit 1
fi

mysql -h 172.16.195.1 -uisucon -pisucon torb -e 'ALTER TABLE reservations DROP KEY event_id_and_sheet_id_idx'
mysql -h 172.16.195.1 -uisucon -pisucon torb -e 'ALTER TABLE reservations DROP KEY reserved_at'
mysql -h 172.16.195.1 -uisucon -pisucon torb -e 'ALTER TABLE reservations DROP KEY event_id_and_canceled_at'
gzip -dc "$DB_DIR/isucon8q-initial-dataset.sql.gz" | mysql -h 172.16.195.1 -uisucon torb -pisucon
mysql -h 172.16.195.1 -uisucon -pisucon torb -e 'ALTER TABLE reservations ADD KEY event_id_and_sheet_id_idx (event_id, sheet_id)'
mysql -h 172.16.195.1 -uisucon -pisucon torb -e 'ALTER TABLE reservations ADD KEY reserved_at (reserved_at)'
mysql -h 172.16.195.1 -uisucon -pisucon torb -e 'ALTER TABLE reservations ADD KEY event_id_and_canceled_at(event_id, canceled_at)'
