import sqlite3
import json
conn = sqlite3.connect("db.sqlite3")
conn.row_factory = sqlite3.Row
cur = conn.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cur.fetchall()
supply_tables = [t[0] for t in tables if "supply" in t[0]]
print(supply_tables)
for t in supply_tables:
    cur.execute(f"SELECT * FROM {t} LIMIT 1")
    row = cur.fetchone()
    if row:
        print(f"--- {t} ---")
        print(dict(row))

