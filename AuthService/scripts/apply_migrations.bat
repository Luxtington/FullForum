@echo off
set PGPASSWORD=postgres
psql -h localhost -U postgres -d forum -f ..\migrations\001_create_users_table.sql 