from flask import Flask, request, jsonify, send_from_directory, session
import sqlite3, hashlib, secrets, os, time
from pathlib import Path

app = Flask(__name__, static_folder=".")
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DB = Path(__file__).with_name("messenger.db")

signals = {}
incoming = {}
typing = {}
online = {}

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
      avatar TEXT DEFAULT '',
      last_seen REAL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS messages(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender INTEGER NOT NULL,
      receiver INTEGER NOT NULL,
      text TEXT NOT NULL,
      kind TEXT DEFAULT 'text',
      created REAL DEFAULT (strftime('%s','now')),
      read_at REAL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS reactions(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      message_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      emoji TEXT NOT NULL,
      created REAL DEFAULT (strftime('%s','now')),
      UNIQUE(message_id, user_id)
    );
    """)
    con.commit()
    con.close()

def pw(x): return hashlib.sha256(x.encode()).hexdigest()

def touch_online(uid):
    now = time.time()
    online[uid] = now
    try:
        con = db()
        con.execute("UPDATE users SET last_seen=? WHERE id=?", (now, uid))
        con.commit()
        con.close()
    except: pass

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
        cur = con.execute("INSERT INTO users(username,password,last_seen) VALUES(?,?,?)", (u, pw(p), time.time()))
        con.commit()
        uid = cur.lastrowid
    except sqlite3.IntegrityError:
        con.close()
        return jsonify(error="Такой пользователь уже существует."), 409
    con.close()
    session["uid"] = uid
    online[uid] = time.time()
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
    touch_online(row["id"])
    return jsonify(id=row["id"], username=row["username"], avatar=row["avatar"] or "")

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)

@app.get("/api/me")
def me():
    if not session.get("uid"):
        return jsonify(user=None)
    touch_online(session["uid"])
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
    uid = session.get("uid")
    if not uid:
        return jsonify(error="auth"), 401
    touch_online(uid)
    q = request.args.get("q", "").strip()
    con = db()
    rows = con.execute(
        "SELECT id,username,avatar,last_seen FROM users WHERE id<>? AND username LIKE ? ORDER BY username",
        (uid, f"%{q}%")
    ).fetchall()
    con.close()
    now = time.time()
    out = []
    for r in rows:
        d = dict(r)
        d["online"] = (now - (r["last_seen"] or 0)) < 120
        out.append(d)
    return jsonify(users=out)

@app.get("/api/messages/<int:uid>")
def messages(uid):
    me = session.get("uid")
    if not me:
        return jsonify(error="auth"), 401
    touch_online(me)
    con = db()
    rows = con.execute("""
        SELECT id,sender,receiver,text,kind,created,read_at FROM messages
        WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
        ORDER BY id
    """, (me, uid, uid, me)).fetchall()
    con.execute("UPDATE messages SET read_at=? WHERE sender=? AND receiver=? AND read_at=0",
                (time.time(), uid, me))
    con.commit()
    msg_ids = [r["id"] for r in rows]
    reacts = {}
    if msg_ids:
        qmarks = ",".join("?" for _ in msg_ids)
        rr = con.execute(f"SELECT message_id,user_id,emoji FROM reactions WHERE message_id IN ({qmarks})", msg_ids).fetchall()
        for x in rr:
            reacts.setdefault(x["message_id"], []).append({"user_id": x["user_id"], "emoji": x["emoji"]})
    con.close()
    out = []
    for r in rows:
        d = dict(r)
        d["reactions"] = reacts.get(r["id"], [])
        out.append(d)
    return jsonify(messages=out)

@app.post("/api/messages")
def send():
    me = session.get("uid")
    if not me:
        return jsonify(error="auth"), 401
    touch_online(me)
    d = request.json or {}
    try:
        receiver = int(d.get("receiver", 0))
    except:
        return jsonify(error="Плохой получатель."), 400
    text = (d.get("text", "") or "")
    kind = (d.get("kind", "text") or "text").strip()
    if not text.strip() or not receiver:
        return jsonify(error="Пустое сообщение."), 400
    con = db()
    if not con.execute("SELECT 1 FROM users WHERE id=?", (receiver,)).fetchone():
        con.close()
        return jsonify(error="Пользователь не найден."), 404
    cur = con.execute(
        "INSERT INTO messages(sender,receiver,text,kind) VALUES(?,?,?,?)",
        (me, receiver, text, kind)
    )
    con.commit()
    row = con.execute(
        "SELECT id,sender,receiver,text,kind,created,read_at FROM messages WHERE id=?",
        (cur.lastrowid,)
    ).fetchone()
    con.close()
    m = dict(row); m["reactions"] = []
    return jsonify(message=m)

@app.post("/api/react")
def react():
    me = session.get("uid")
    if not me:
        return jsonify(error="auth"), 401
    d = request.json or {}
    try:
        mid = int(d.get("message_id", 0))
    except:
        return jsonify(error="Нет данных"), 400
    emoji = d.get("emoji", "")
    if not mid or not emoji:
        return jsonify(error="Нет данных"), 400
    con = db()
    existing = con.execute("SELECT id,emoji FROM reactions WHERE message_id=? AND user_id=?", (mid, me)).fetchone()
    if existing:
        if existing["emoji"] == emoji:
            con.execute("DELETE FROM reactions WHERE id=?", (existing["id"],))
        else:
            con.execute("UPDATE reactions SET emoji=? WHERE id=?", (emoji, existing["id"]))
    else:
        con.execute("INSERT INTO reactions(message_id,user_id,emoji) VALUES(?,?,?)", (mid, me, emoji))
    con.commit()
    con.close()
    return jsonify(ok=True)

@app.post("/api/typing")
def set_typing():
    me = session.get("uid")
    if not me:
        return jsonify(error="auth"), 401
    touch_online(me)
    d = request.json or {}
    try:
        to = int(d.get("to", 0))
    except:
        to = 0
    if to:
        typing[to] = {"from": me, "ts": time.time()}
    return jsonify(ok=True)

@app.get("/api/typing")
def get_typing():
    me = session.get("uid")
    if not me:
        return jsonify(error="auth"), 401
    touch_online(me)
    who = request.args.get("who")
    if not who:
        return jsonify(typing=False)
    try:
        who = int(who)
    except:
        return jsonify(typing=False)
    t = typing.get(me)
    now = time.time()
    if t and t["from"] == who and now - t["ts"] < 5:
        return jsonify(typing=True)
    return jsonify(typing=False)

# ========== СИГНАЛИНГ ДЛЯ ЗВОНКОВ ==========

@app.post("/api/signal")
def post_signal():
    if not session.get("uid"):
        return jsonify(error="auth"), 401
    touch_online(session["uid"])
    d = request.json or {}
    room = (d.get("room") or "").strip()
    data = d.get("data")
    if not room or data is None:
        return jsonify(error="Нет room или data"), 400
    signals.setdefault(room, [])
    signals[room].append({"data": data, "ts": time.time()})
    return jsonify(ok=True)

@app.get("/api/signal/<room>")
def get_signal(room):
    if not session.get("uid"):
        return jsonify(error="auth"), 401
    touch_online(session["uid"])
    now = time.time()
    if room in signals:
        signals[room] = [x for x in signals[room] if now - x.get("ts", 0) < 120]
    uid = session["uid"]
    arr = signals.get(room, [])
    out = []
    for x in arr:
        d = x.get("data") or {}
        if d.get("from") == uid:
            continue
        out.append(d)
    return jsonify(items=out)

# ========== ВХОДЯЩИЕ ЗВОНКИ ==========

@app.post("/api/call/invite")
def call_invite():
    me = session.get("uid")
    if not me:
        return jsonify(error="auth"), 401
    d = request.json or {}
    try:
        to = int(d.get("to", 0))
    except:
        return jsonify(error="Плохой получатель."), 400
    room = (d.get("room") or "").strip()
    if not to or not room:
        return jsonify(error="Нет to или room"), 400
    con = db()
    r = con.execute("SELECT username FROM users WHERE id=?", (me,)).fetchone()
    con.close()
    incoming[to] = {
        "room": room, "from": me,
        "fromName": r["username"] if r else "?",
        "ts": time.time()
    }
    return jsonify(ok=True)

@app.get("/api/call/incoming")
def call_incoming():
    me = session.get("uid")
    if not me:
        return jsonify(error="auth"), 401
    touch_online(me)
    now = time.time()
    for k in list(incoming.keys()):
        if now - incoming[k].get("ts", 0) > 60:
            del incoming[k]
    inv = incoming.pop(me, None)
    return jsonify(invite=inv)

init()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False) 
