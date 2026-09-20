from flask import Flask, request, jsonify, send_from_directory, session
import sqlite3, hashlib, secrets, os
from pathlib import Path

app = Flask(__name__, static_folder=".")
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DB = Path(__file__).with_name("messenger.db")

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      avatar TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS messages(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender INTEGER NOT NULL,
      receiver INTEGER NOT NULL,
      text TEXT NOT NULL,
      created REAL DEFAULT (strftime('%s','now'))
    );
    """)
    con.commit()
    con.close()

def pw(x): return hashlib.sha256(x.encode()).hexdigest()

@app.get("/")
def index():
    return send_from_directory(".", "index.html")

@app.post("/api/register")
def register():
    data = request.json or {}
    u = data.get("username", "").strip()
    p = data.get("password", "")
    if len(u) < 3 or len(p) < 4:
        return jsonify(error="Имя: минимум 3 символа, пароль: минимум 4."), 400
    con = db()
    try:
        cur = con.execute("INSERT INTO users(username,password) VALUES(?,?)", (u, pw(p)))
        con.commit()
        uid = cur.lastrowid
    except sqlite3.IntegrityError:
        con.close()
        return jsonify(error="Такой пользователь уже существует."), 409
    con.close()
    session["uid"] = uid
    return jsonify(id=uid, username=u, avatar="")

@app.post("/api/login")
def login():
    d = request.json or {}
    con = db()
    row = con.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (d.get("username", "").strip(), pw(d.get("password", "")))
    ).fetchone()
    con.close()
    if not row:
        return jsonify(error="Неверное имя или пароль."), 401
    session["uid"] = row["id"]
    return jsonify(id=row["id"], username=row["username"], avatar=row["avatar"] or "")

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)

@app.get("/api/me")
def me():
    if not session.get("uid"):
        return jsonify(user=None)
    con = db()
    r = con.execute("SELECT id,username,avatar FROM users WHERE id=?", (session["uid"],)).fetchone()
    con.close()
    return jsonify(user=dict(r) if r else None)

@app.post("/api/avatar")
def set_avatar():
    if not session.get("uid"):
        return jsonify(error="auth"), 401
    d = request.json or {}
    avatar = d.get("avatar", "")
    con = db()
    con.execute("UPDATE users SET avatar=? WHERE id=?", (avatar, session["uid"]))
    con.commit()
    con.close()
    return jsonify(ok=True)

@app.get("/api/users")
def users():
    if not session.get("uid"):
        return jsonify(error="auth"), 401
    q = request.args.get("q", "").strip()
    con = db()
    rows = con.execute(
        "SELECT id,username,avatar FROM users WHERE id<>? AND username LIKE ? ORDER BY username",
        (session["uid"], f"%{q}%")
    ).fetchall()
    con.close()
    return jsonify(users=[dict(x) for x in rows])

@app.get("/api/messages/<int:uid>")
def messages(uid):
    me = session.get("uid")
    if not me:
        return jsonify(error="auth"), 401
    con = db()
    rows = con.execute("""
        SELECT id,sender,receiver,text,created FROM messages
        WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
        ORDER BY id
    """, (me, uid, uid, me)).fetchall()
    con.close()
    return jsonify(messages=[dict(x) for x in rows])

@app.post("/api/messages")
def send():
    me = session.get("uid")
    if not me:
        return jsonify(error="auth"), 401
    d = request.json or {}
    try:
        receiver = int(d.get("receiver", 0))
    except:
        return jsonify(error="Плохой получатель."), 400
    text = (d.get("text", "") or "").strip()
    if not text or not receiver:
        return jsonify(error="Пустое сообщение."), 400
    con = db()
    if not con.execute("SELECT 1 FROM users WHERE id=?", (receiver,)).fetchone():
        con.close()
        return jsonify(error="Пользователь не найден."), 404
    cur = con.execute(
        "INSERT INTO messages(sender,receiver,text) VALUES(?,?,?)",
        (me, receiver, text)
    )
    con.commit()
    row = con.execute(
        "SELECT id,sender,receiver,text,created FROM messages WHERE id=?",
        (cur.lastrowid,)
    ).fetchone()
    con.close()
    return jsonify(message=dict(row))

init()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)