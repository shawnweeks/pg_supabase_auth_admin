#!/bin/sh

set -e

# Stop any other instances of supabase
supabase stop --all

supabase stop --no-backup

rm -rf ./supabase/

supabase init

MIGRATION_FILE=./supabase/migrations/20250101000000_init.sql

mkdir -p ./supabase/migrations/

echo "create extension http with schema extensions;" > ${MIGRATION_FILE}
echo "create extension pg_tle;" >> ${MIGRATION_FILE}
cat ./sql/pg_supabase_auth_admin--0.1.0.sql >> ${MIGRATION_FILE}

supabase start --exclude "realtime,storage-api,imgproxy,postgrest,postgres-meta,studio,edge-runtime,logflare,vector,supavisor"

PGPASSWORD=postgres psql \
    -h 127.0.0.1 -p 54322 -U supabase_admin -d postgres \
    -a -v ON_ERROR_STOP=1 -f ./sql/test.sql

supabase stop --no-backup

echo "All Test Cases Ran Succesffuly"