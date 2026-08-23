from flask import Flask, request
import sqlite3
import os

app = Flask(__name__)

DB_PATH = "/app/data/crm.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs("/app/data", exist_ok=True)

    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            company TEXT NOT NULL,
            secret TEXT NOT NULL
        )
    """)

    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO users VALUES (?, ?, ?, ?)",
            [
                (1, "admin", "admin123", "admin"),
                (2, "alice", "alice123", "user"),
            ],
        )

    if conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO customers VALUES (?, ?, ?, ?, ?)",
            [
                (1, "Alice Tanaka", "alice@example.com", "ABC Corp", "VIP-001"),
                (2, "Bob Suzuki", "bob@example.com", "XYZ Inc", "VIP-002"),
                (3, "Carol Sato", "carol@example.com", "Demo Ltd", "SECRET-003"),
            ],
        )

    conn.commit()
    conn.close()


@app.route("/")
def index():
    return """
    <html>
      <head>
        <title>K3 Defender Lab</title>
      </head>
      <body>
        <h1>K3 Defender Lab</h1>
        <ul>
          <li><a href="/health">Health</a></li>
          <li><a href="/customer?id=1">Customer #1</a></li>
        </ul>
      </body>
    </html>
    """


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/customer")
def customer():
    customer_id = request.args.get("id", "1")

    # INTENTIONALLY VULNERABLE
    query = f"SELECT id, name, email, company, secret FROM customers WHERE id = {customer_id}"

    conn = get_db()

    try:
        rows = conn.execute(query).fetchall()
    except Exception as e:
        return {
            "error": "database error",
            "detail": str(e)
        }, 500
    finally:
        conn.close()

    return {
        "customers": [dict(row) for row in rows]
    }


init_db()

app.run(host="0.0.0.0", port=8080)
