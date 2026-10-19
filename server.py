from flask import Flask, request, jsonify, send_from_directory, session
import hashlib, secrets, os, time
from functools import wraps
import psycopg2
import psycopg2.extras
from pathlib import Path

app = Flask(__name__, static_folder=".")
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DATABASE_URL = os.environ.get("DATABASE_URL")

MAX_MSG_LEN = 4096
MAX_NAME_LEN = 32

signals = {}
incoming = {}
typing = {}
online = {}

def db():
    return psycopg2.connect(DATABASE_URL)

def init():
    con = db(); cur = con.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      avatar TEXT DEFAULT '',
      email TEXT DEFAULT '',
      is_admin BOOLEAN DEFAULT FALSE,
      last_seen REAL DEFAULT 0
    );""")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT DEFAULT ''")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE")
    cur.execute("INSERT INTO users(username,password,avatar,is_admin) VALUES('admin_bot','!','🤖',FALSE) ON CONFLICT (username) DO NOTHING")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS messages(
      id SERIAL PRIMARY KEY,
      sender INTEGER NOT NULL,
      receiver INTEGER NOT NULL,
      text TEXT NOT NULL,
      kind TEXT DEFAULT 'text',
      created REAL DEFAULT (extract(epoch from now())),
      read_at REAL DEFAULT 0,
      reply_to INTEGER DEFAULT 0,
      deleted INTEGER DEFAULT 0,
      edited INTEGER DEFAULT 0
    );""")
    cur.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_to INTEGER DEFAULT 0")
    cur.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS deleted INTEGER DEFAULT 0")
    cur.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS edited INTEGER DEFAULT 0")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS reactions(
      id SERIAL PRIMARY KEY,
      message_type TEXT DEFAULT 'message',
      message_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      emoji TEXT NOT NULL,
      created REAL DEFAULT (extract(epoch from now())),
      UNIQUE(message_type, message_id, user_id)
    );""")
    cur.execute("ALTER TABLE reactions ADD COLUMN IF NOT EXISTS message_type TEXT DEFAULT 'message'")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS groups(
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      owner INTEGER NOT NULL,
      created REAL DEFAULT (extract(epoch from now()))
    );""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS group_members(
      group_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      PRIMARY KEY(group_id, user_id)
    );""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS group_messages(
      id SERIAL PRIMARY KEY,
      group_id INTEGER NOT NULL,
      sender INTEGER NOT NULL,
      text TEXT NOT NULL,
      kind TEXT DEFAULT 'text',
      created REAL DEFAULT (extract(epoch from now())),
      reply_to INTEGER DEFAULT 0,
      deleted INTEGER DEFAULT 0,
      edited INTEGER DEFAULT 0
    );""")
    cur.execute("ALTER TABLE group_messages ADD COLUMN IF NOT EXISTS reply_to INTEGER DEFAULT 0")
    cur.execute("ALTER TABLE group_messages ADD COLUMN IF NOT EXISTS deleted INTEGER DEFAULT 0")
    cur.execute("ALTER TABLE group_messages ADD COLUMN IF NOT EXISTS edited INTEGER DEFAULT 0")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS group_reactions(
      id SERIAL PRIMARY KEY,
      message_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      emoji TEXT NOT NULL,
      created REAL DEFAULT (extract(epoch from now())),
      UNIQUE(message_id, user_id)
    );""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS blocks(
      id SERIAL PRIMARY KEY,
      blocker INTEGER NOT NULL,
      blocked INTEGER NOT NULL,
      created REAL DEFAULT (extract(epoch from now())),
      UNIQUE(blocker, blocked)
    );""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sticker_packs(
      id SERIAL PRIMARY KEY,
      owner INTEGER NOT NULL,
      name TEXT UNIQUE NOT NULL,
      created REAL DEFAULT (extract(epoch from now()))
    );""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS stickers(
      id SERIAL PRIMARY KEY,
      pack_id INTEGER NOT NULL,
      image TEXT NOT NULL,
      created REAL DEFAULT (extract(epoch from now()))
    );""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS dialogs(
      user_id INTEGER NOT NULL,
      peer_id INTEGER NOT NULL,
      pinned BOOLEAN DEFAULT FALSE,
      muted BOOLEAN DEFAULT FALSE,
      last_read_at REAL DEFAULT 0,
      PRIMARY KEY(user_id, peer_id)
    );""")
    con.commit(); cur.close(); con.close()

def pw(x): return hashlib.sha256(x.encode()).hexdigest()

def touch_online(uid):
    now = time.time()
    online[uid] = now
    try:
        con = db(); cur = con.cursor()
        cur.execute("UPDATE users SET last_seen=%s WHERE id=%s", (now, uid))
        con.commit(); cur.close(); con.close()
    except: pass

def is_admin(uid):
    try:
        con = db(); cur = con.cursor()
        cur.execute("SELECT is_admin FROM users WHERE id=%s", (uid,))
        row = cur.fetchone()
        cur.close(); con.close()
        return bool(row and row[0])
    except:
        return False

def admin_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        uid = session.get("uid")
        if not uid: return jsonify(error="auth"), 401
        if not is_admin(uid): return jsonify(error="Нет доступа"), 403
        return f(*args, **kwargs)
    return wrapper

@app.get("/")
def index():
    return send_from_directory(".", "index.html")

@app.post("/api/register")
def register():
    data = request.json or {}
    u = data.get("username", "").strip()
    p = data.get("password", "")
    if u == 'admin_bot': return jsonify(error="Имя занято."), 409
    if len(u) < 3 or len(u) > MAX_NAME_LEN:
        return jsonify(error="Имя: от 3 до %d символов." % MAX_NAME_LEN), 400
    if len(p) < 4:
        return jsonify(error="Пароль: минимум 4."), 400
    con = db(); cur = con.cursor()
    try:
        cur.execute("INSERT INTO users(username,password,last_seen) VALUES(%s,%s,%s) RETURNING id", (u, pw(p), time.time()))
        uid = cur.fetchone()[0]; con.commit()
    except psycopg2.errors.UniqueViolation:
        con.rollback(); cur.close(); con.close()
        return jsonify(error="Такой пользователь уже существует."), 409
    cur.close(); con.close()
    session["uid"] = uid
    online[uid] = time.time()
    return jsonify(id=uid, username=u, avatar="", email="", is_admin=False, last_seen=time.time())

@app.post("/api/login")
def login():
    d = request.json or {}
    name = d.get("username", "").strip()
    if name == 'admin_bot':
        return jsonify(error="Неверное имя или пароль."), 401
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE username=%s AND password=%s", (name, pw(d.get("password", ""))))
    row = cur.fetchone(); cur.close(); con.close()
    if not row:
        return jsonify(error="Неверное имя или пароль."), 401
    session["uid"] = row["id"]
    touch_online(row["id"])
    return jsonify(id=row["id"], username=row["username"], avatar=row["avatar"] or "", email=row.get("email") or "", is_admin=bool(row.get("is_admin")), last_seen=row.get("last_seen") or 0)

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)

@app.get("/api/me")
def me():
    if not session.get("uid"):
        return jsonify(user=None)
    touch_online(session["uid"])
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id,username,avatar,email,is_admin,last_seen FROM users WHERE id=%s", (session["uid"],))
    r = cur.fetchone(); cur.close(); con.close()
    return jsonify(user=dict(r) if r else None)

@app.get("/api/user/<int:uid>")
def public_profile(uid):
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    touch_online(me)
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id,username,avatar,last_seen FROM users WHERE id=%s", (uid,))
    u = cur.fetchone()
    if not u:
        cur.close(); con.close()
        return jsonify(error="Нет такого"), 404
    now = time.time()
    blocked = False
    cur.execute("SELECT 1 FROM blocks WHERE blocker=%s AND blocked=%s", (me, uid))
    if cur.fetchone(): blocked = True
    cur.close(); con.close()
    return jsonify(user={
        "id": u["id"],
        "username": u["username"],
        "avatar": u["avatar"] or "",
        "last_seen": u["last_seen"] or 0,
        "online": (now - (u["last_seen"] or 0)) < 120,
        "blocked": blocked
    })

@app.post("/api/email")
def set_email():
    if not session.get("uid"): return jsonify(error="auth"), 401
    d = request.json or {}
    email = (d.get("email") or "").strip()
    con = db(); cur = con.cursor()
    cur.execute("UPDATE users SET email=%s WHERE id=%s", (email, session["uid"]))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True, email=email)

@app.post("/api/delete-account")
def delete_account():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    d = request.json or {}
    if d.get("confirm") != "DELETE": return jsonify(error="Нужно подтверждение"), 400
    con = db(); cur = con.cursor()
    cur.execute("SELECT username FROM users WHERE id=%s", (me,))
    row = cur.fetchone()
    if row and row[0] == 'admin_bot':
        cur.close(); con.close()
        return jsonify(error="Бота нельзя удалить"), 400
    cur.execute("DELETE FROM reactions WHERE user_id=%s", (me,))
    cur.execute("DELETE FROM group_reactions WHERE user_id=%s", (me,))
    cur.execute("DELETE FROM messages WHERE sender=%s OR receiver=%s", (me, me))
    cur.execute("DELETE FROM group_messages WHERE sender=%s", (me,))
    cur.execute("DELETE FROM group_members WHERE user_id=%s", (me,))
    cur.execute("DELETE FROM groups WHERE owner=%s", (me,))
    cur.execute("DELETE FROM blocks WHERE blocker=%s OR blocked=%s", (me, me))
    cur.execute("DELETE FROM dialogs WHERE user_id=%s OR peer_id=%s", (me, me))
    cur.execute("DELETE FROM stickers WHERE pack_id IN (SELECT id FROM sticker_packs WHERE owner=%s)", (me,))
    cur.execute("DELETE FROM sticker_packs WHERE owner=%s", (me,))
    cur.execute("DELETE FROM users WHERE id=%s", (me,))
    con.commit(); cur.close(); con.close()
    session.clear()
    return jsonify(ok=True)

@app.post("/api/avatar")
def set_avatar():
    if not session.get("uid"): return jsonify(error="auth"), 401
    d = request.json or {}
    avatar = d.get("avatar", "")
    con = db(); cur = con.cursor()
    cur.execute("UPDATE users SET avatar=%s WHERE id=%s", (avatar, session["uid"]))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.post("/api/username")
def set_username():
    if not session.get("uid"): return jsonify(error="auth"), 401
    d = request.json or {}
    name = (d.get("username") or "").strip()
    if name == 'admin_bot': return jsonify(error="Имя занято."), 409
    if len(name) < 3 or len(name) > MAX_NAME_LEN:
        return jsonify(error="Имя: от 3 до %d символов." % MAX_NAME_LEN), 400
    con = db(); cur = con.cursor()
    try:
        cur.execute("UPDATE users SET username=%s WHERE id=%s", (name, session["uid"]))
        con.commit()
    except psycopg2.errors.UniqueViolation:
        con.rollback(); cur.close(); con.close()
        return jsonify(error="Такое имя уже занято."), 409
    cur.close(); con.close()
    return jsonify(ok=True, username=name)

@app.get("/api/users")
def users():
    uid = session.get("uid")
    if not uid: return jsonify(error="auth"), 401
    touch_online(uid)
    q = request.args.get("q", "").strip()
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""SELECT id,username,avatar,last_seen FROM users
        WHERE id<>%s AND username LIKE %s AND username<>'admin_bot'
        AND id NOT IN (SELECT blocked FROM blocks WHERE blocker=%s)
        AND id NOT IN (SELECT blocker FROM blocks WHERE blocked=%s)
        ORDER BY username""", (uid, f"%{q}%", uid, uid))
    rows = cur.fetchall(); cur.close(); con.close()
    now = time.time()
    out = []
    for r in rows:
        d = dict(r); d["online"] = (now - (r["last_seen"] or 0)) < 120
        out.append(d)
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id,username,avatar,last_seen FROM users WHERE username='admin_bot'")
    bot = cur.fetchone(); cur.close(); con.close()
    if bot and (not q or q.lower() in 'admin_bot'):
        b = dict(bot); b["online"] = True
        out.insert(0, b)
    return jsonify(users=out)

@app.get("/api/dialogs")
def dialogs():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    touch_online(me)
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        WITH pairs AS (
          SELECT
            CASE WHEN sender=%s THEN receiver ELSE sender END AS peer_id,
            MAX(id) AS last_msg_id
          FROM messages
          WHERE sender=%s OR receiver=%s
          GROUP BY peer_id
        )
        SELECT p.peer_id, p.last_msg_id, m.text, m.kind, m.created, m.sender,
               u.username, u.avatar, u.last_seen,
               COALESCE(d.pinned, FALSE) AS pinned,
               COALESCE(d.muted, FALSE) AS muted,
               COALESCE(d.last_read_at, 0) AS last_read_at
        FROM pairs p
        JOIN messages m ON m.id = p.last_msg_id
        JOIN users u ON u.id = p.peer_id
        LEFT JOIN dialogs d ON d.user_id=%s AND d.peer_id=p.peer_id
        ORDER BY pinned DESC, m.created DESC
    """, (me, me, me, me))
    rows = cur.fetchall()

    out = []
    now = time.time()
    for r in rows:
        cur.execute("""
            SELECT COUNT(*) AS c FROM messages
            WHERE sender=%s AND receiver=%s AND created > %s
        """, (r["peer_id"], me, r["last_read_at"] or 0))
        unread = int(cur.fetchone()["c"] or 0)
        preview = ""
        if r["kind"] == "voice": preview = "🎤"
        elif r["kind"] == "image": preview = "🖼"
        elif r["kind"] == "sticker": preview = "🧩"
        else: preview = (r["text"] or "")[:80]
        out.append({
            "id": r["peer_id"],
            "username": r["username"],
            "avatar": r["avatar"] or "",
            "last_msg_id": r["last_msg_id"],
            "preview": preview,
            "created": r["created"] or 0,
            "last_sender": r["sender"],
            "pinned": bool(r["pinned"]),
            "muted": bool(r["muted"]),
            "unread": unread,
            "online": (now - (r["last_seen"] or 0)) < 120
        })
    cur.close(); con.close()
    return jsonify(dialogs=out)

@app.post("/api/messages/<int:uid>/read")
def mark_read(uid):
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    con = db(); cur = con.cursor()
    cur.execute("""
        INSERT INTO dialogs(user_id, peer_id, last_read_at) VALUES(%s, %s, %s)
        ON CONFLICT (user_id, peer_id) DO UPDATE SET last_read_at=EXCLUDED.last_read_at
    """, (me, uid, time.time()))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.post("/api/dialog/pin")
def dialog_pin():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    d = request.json or {}
    try: peer = int(d.get("peer_id", 0))
    except: return jsonify(error="Плохой peer_id"), 400
    val = bool(d.get("pinned", False))
    con = db(); cur = con.cursor()
    cur.execute("""
        INSERT INTO dialogs(user_id, peer_id, pinned) VALUES(%s, %s, %s)
        ON CONFLICT (user_id, peer_id) DO UPDATE SET pinned=EXCLUDED.pinned
    """, (me, peer, val))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.post("/api/dialog/mute")
def dialog_mute():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    d = request.json or {}
    try: peer = int(d.get("peer_id", 0))
    except: return jsonify(error="Плохой peer_id"), 400
    val = bool(d.get("muted", False))
    con = db(); cur = con.cursor()
    cur.execute("""
        INSERT INTO dialogs(user_id, peer_id, muted) VALUES(%s, %s, %s)
        ON CONFLICT (user_id, peer_id) DO UPDATE SET muted=EXCLUDED.muted
    """, (me, peer, val))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.get("/api/unread/total")
def unread_total():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    con = db(); cur = con.cursor()
    cur.execute("""
        SELECT COUNT(*) FROM messages m
        WHERE m.receiver=%s AND m.created > COALESCE(
          (SELECT last_read_at FROM dialogs d WHERE d.user_id=%s AND d.peer_id=m.sender), 0
        )
    """, (me, me))
    c = cur.fetchone()[0]
    cur.close(); con.close()
    return jsonify(total=int(c or 0))

@app.get("/api/search/all")
def search_all():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    q = request.args.get("q", "").strip()
    if not q: return jsonify(results=[])
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT m.id, m.sender, m.receiver, m.text, m.kind, m.created,
               u.username AS peer_name
        FROM messages m
        JOIN users u ON u.id = CASE WHEN m.sender=%s THEN m.receiver ELSE m.sender END
        WHERE (m.sender=%s OR m.receiver=%s) AND m.deleted=0 AND m.text ILIKE %s
        ORDER BY m.id DESC LIMIT 100
    """, (me, me, me, f"%{q}%"))
    rows = cur.fetchall(); cur.close(); con.close()
    return jsonify(results=[dict(r) for r in rows])

@app.get("/api/groups/<int:gid>/search")
def group_search(gid):
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    con = db(); cur = con.cursor()
    cur.execute("SELECT 1 FROM group_members WHERE group_id=%s AND user_id=%s", (gid, me))
    if not cur.fetchone():
        cur.close(); con.close()
        return jsonify(error="Нет доступа"), 403
    q = request.args.get("q", "").strip()
    if not q:
        cur.close(); con.close()
        return jsonify(results=[])
    cur2 = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur2.execute("""
        SELECT id, sender, text, kind, created FROM group_messages
        WHERE group_id=%s AND deleted=0 AND text ILIKE %s
        ORDER BY id DESC LIMIT 100
    """, (gid, f"%{q}%"))
    rows = cur2.fetchall(); cur2.close(); cur.close(); con.close()
    return jsonify(results=[dict(r) for r in rows])

@app.get("/api/messages/<int:uid>")
def messages(uid):
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    touch_online(me)
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT 1 FROM blocks WHERE (blocker=%s AND blocked=%s) OR (blocker=%s AND blocked=%s)", (me, uid, uid, me))
    if cur.fetchone():
        cur.close(); con.close()
        return jsonify(messages=[])
    cur.execute("""
        SELECT m.id,m.sender,m.receiver,m.text,m.kind,m.created,m.read_at,m.reply_to,m.deleted,m.edited,
               r.text AS reply_text, ru.username AS reply_name
        FROM messages m
        LEFT JOIN messages r ON r.id = m.reply_to
        LEFT JOIN users ru ON ru.id = r.sender
        WHERE (m.sender=%s AND m.receiver=%s) OR (m.sender=%s AND m.receiver=%s)
        ORDER BY m.id
    """, (me, uid, uid, me))
    rows = cur.fetchall()
    cur.execute("UPDATE messages SET read_at=%s WHERE sender=%s AND receiver=%s AND read_at=0",
                (time.time(), uid, me))
    con.commit()
    msg_ids = [r["id"] for r in rows]
    reacts = {}
    if msg_ids:
        ph = ",".join(["%s"] * len(msg_ids))
        cur.execute(f"SELECT message_id,user_id,emoji FROM reactions WHERE message_type='message' AND message_id IN ({ph})", msg_ids)
        for x in cur.fetchall():
            reacts.setdefault(x["message_id"], []).append({"user_id": x["user_id"], "emoji": x["emoji"]})
    cur.close(); con.close()
    out = []
    for r in rows:
        d = dict(r); d["reactions"] = reacts.get(r["id"], [])
        out.append(d)
    return jsonify(messages=out)

@app.get("/api/search/<int:uid>")
def search_messages(uid):
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    q = request.args.get("q", "").strip()
    if not q: return jsonify(results=[])
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT id,sender,receiver,text,kind,created FROM messages
        WHERE ((sender=%s AND receiver=%s) OR (sender=%s AND receiver=%s))
        AND deleted=0 AND text ILIKE %s
        ORDER BY id DESC LIMIT 50
    """, (me, uid, uid, me, f"%{q}%"))
    rows = cur.fetchall(); cur.close(); con.close()
    return jsonify(results=[dict(r) for r in rows])

@app.post("/api/messages")
def send():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    touch_online(me)
    d = request.json or {}
    try: receiver = int(d.get("receiver", 0))
    except: return jsonify(error="Плохой получатель."), 400
    text = (d.get("text", "") or "")
    kind = (d.get("kind", "text") or "text").strip()
    try: reply_to = int(d.get("reply_to", 0) or 0)
    except: reply_to = 0
    if not text.strip() or not receiver:
        return jsonify(error="Пустое сообщение."), 400
    if kind in ("text",) and len(text) > MAX_MSG_LEN:
        return jsonify(error="Сообщение слишком длинное (макс %d)." % MAX_MSG_LEN), 400
    if kind in ("image", "sticker") and len(text) > 3 * 1024 * 1024:
        return jsonify(error="Слишком большой файл (макс 2 МБ)."), 413
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT 1 FROM users WHERE id=%s", (receiver,))
    if not cur.fetchone():
        cur.close(); con.close()
        return jsonify(error="Пользователь не найден."), 404
    cur.execute("SELECT 1 FROM blocks WHERE (blocker=%s AND blocked=%s) OR (blocker=%s AND blocked=%s)", (me, receiver, receiver, me))
    if cur.fetchone():
        cur.close(); con.close()
        return jsonify(error="Сообщение не может быть доставлено."), 403
    cur.execute("INSERT INTO messages(sender,receiver,text,kind,reply_to) VALUES(%s,%s,%s,%s,%s) RETURNING id,sender,receiver,text,kind,created,read_at,reply_to,deleted,edited",
                (me, receiver, text, kind, reply_to))
    row = cur.fetchone()
    con.commit(); cur.close(); con.close()
    m = dict(row); m["reactions"] = []
    return jsonify(message=m)

@app.post("/api/messages/<int:mid>/delete")
def delete_message(mid):
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    con = db(); cur = con.cursor()
    cur.execute("UPDATE messages SET deleted=1 WHERE id=%s AND sender=%s", (mid, me))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.post("/api/messages/<int:mid>/edit")
def edit_message(mid):
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    d = request.json or {}
    text = (d.get("text") or "").strip()
    if not text: return jsonify(error="Пусто"), 400
    if len(text) > MAX_MSG_LEN: return jsonify(error="Слишком длинно"), 400
    con = db(); cur = con.cursor()
    cur.execute("UPDATE messages SET text=%s, edited=1 WHERE id=%s AND sender=%s", (text, mid, me))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.post("/api/groups/<int:gid>/messages/<int:mid>/delete")
def group_delete(gid, mid):
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    con = db(); cur = con.cursor()
    cur.execute("UPDATE group_messages SET deleted=1 WHERE id=%s AND sender=%s AND group_id=%s", (mid, me, gid))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.post("/api/groups/<int:gid>/messages/<int:mid>/edit")
def group_edit(gid, mid):
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    d = request.json or {}
    text = (d.get("text") or "").strip()
    if not text: return jsonify(error="Пусто"), 400
    if len(text) > MAX_MSG_LEN: return jsonify(error="Слишком длинно"), 400
    con = db(); cur = con.cursor()
    cur.execute("UPDATE group_messages SET text=%s, edited=1 WHERE id=%s AND sender=%s AND group_id=%s", (text, mid, me, gid))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.post("/api/react")
def react():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    d = request.json or {}
    try: mid = int(d.get("message_id", 0))
    except: return jsonify(error="Нет данных"), 400
    emoji = d.get("emoji", "")
    if not mid or not emoji: return jsonify(error="Нет данных"), 400
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id,emoji FROM reactions WHERE message_type='message' AND message_id=%s AND user_id=%s", (mid, me))
    ex = cur.fetchone()
    if ex:
        if ex["emoji"] == emoji:
            cur.execute("DELETE FROM reactions WHERE id=%s", (ex["id"],))
        else:
            cur.execute("UPDATE reactions SET emoji=%s WHERE id=%s", (emoji, ex["id"]))
    else:
        cur.execute("INSERT INTO reactions(message_type,message_id,user_id,emoji) VALUES('message',%s,%s,%s)", (mid, me, emoji))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.post("/api/groups/<int:gid>/messages/<int:mid>/react")
def group_react(gid, mid):
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    d = request.json or {}
    emoji = d.get("emoji", "")
    if not emoji: return jsonify(error="Нет данных"), 400
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT 1 FROM group_members WHERE group_id=%s AND user_id=%s", (gid, me))
    if not cur.fetchone():
        cur.close(); con.close()
        return jsonify(error="Нет доступа"), 403
    cur.execute("SELECT id,emoji FROM group_reactions WHERE message_id=%s AND user_id=%s", (mid, me))
    ex = cur.fetchone()
    if ex:
        if ex["emoji"] == emoji:
            cur.execute("DELETE FROM group_reactions WHERE id=%s", (ex["id"],))
        else:
            cur.execute("UPDATE group_reactions SET emoji=%s WHERE id=%s", (emoji, ex["id"]))
    else:
        cur.execute("INSERT INTO group_reactions(message_id,user_id,emoji) VALUES(%s,%s,%s)", (mid, me, emoji))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.post("/api/typing")
def set_typing():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    touch_online(me)
    d = request.json or {}
    to = d.get("to")
    group = d.get("group")
    if group:
        try: gid = int(group)
        except: gid = 0
        if gid: typing["g" + str(gid)] = {"from": me, "ts": time.time()}
    else:
        try: to = int(to or 0)
        except: to = 0
        if to: typing[to] = {"from": me, "ts": time.time()}
    return jsonify(ok=True)

@app.get("/api/typing")
def get_typing():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    touch_online(me)
    who = request.args.get("who")
    group = request.args.get("group")
    now = time.time()
    if group:
        try: gid = int(group)
        except: gid = 0
        t = typing.get("g" + str(gid))
        if t and t["from"] != me and now - t["ts"] < 5:
            return jsonify(typing=True)
        return jsonify(typing=False)
    if not who: return jsonify(typing=False)
    try: who = int(who)
    except: return jsonify(typing=False)
    t = typing.get(me); now = time.time()
    if t and t["from"] == who and now - t["ts"] < 5:
        return jsonify(typing=True)
    return jsonify(typing=False)

@app.post("/api/block")
def block_user():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    d = request.json or {}
    try: target = int(d.get("user_id", 0))
    except: return jsonify(error="Плохой user_id"), 400
    if not target or target == me: return jsonify(error="Нельзя"), 400
    con = db(); cur = con.cursor()
    cur.execute("INSERT INTO blocks(blocker,blocked) VALUES(%s,%s) ON CONFLICT DO NOTHING", (me, target))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.post("/api/unblock")
def unblock_user():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    d = request.json or {}
    try: target = int(d.get("user_id", 0))
    except: return jsonify(error="Плохой user_id"), 400
    if not target: return jsonify(error="Нет user_id"), 400
    con = db(); cur = con.cursor()
    cur.execute("DELETE FROM blocks WHERE blocker=%s AND blocked=%s", (me, target))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.get("/api/blocks")
def list_blocks():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT u.id,u.username,u.avatar FROM blocks b JOIN users u ON u.id=b.blocked WHERE b.blocker=%s ORDER BY u.username", (me,))
    rows = cur.fetchall(); cur.close(); con.close()
    return jsonify(blocks=[dict(r) for r in rows])

@app.post("/api/groups")
def create_group():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    d = request.json or {}
    name = (d.get("name") or "").strip()
    members = d.get("members") or []
    if len(name) < 2: return jsonify(error="Имя группы: минимум 2 символа."), 400
    if len(name) > MAX_NAME_LEN: return jsonify(error="Слишком длинно"), 400
    try: members = [int(x) for x in members]
    except: members = []
    if me not in members: members.append(me)
    con = db(); cur = con.cursor()
    cur.execute("INSERT INTO groups(name,owner) VALUES(%s,%s) RETURNING id", (name, me))
    gid = cur.fetchone()[0]
    for u in set(members):
        cur.execute("INSERT INTO group_members(group_id,user_id) VALUES(%s,%s) ON CONFLICT DO NOTHING", (gid, u))
    con.commit(); cur.close(); con.close()
    return jsonify(id=gid, name=name)

@app.get("/api/groups")
def my_groups():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT g.id,g.name,g.owner FROM groups g JOIN group_members m ON m.group_id=g.id WHERE m.user_id=%s ORDER BY g.id", (me,))
    rows = cur.fetchall()
    out = []
    for r in rows:
        d = dict(r)
        cur.execute("SELECT user_id FROM group_members WHERE group_id=%s", (r["id"],))
        d["members"] = [x["user_id"] for x in cur.fetchall()]
        out.append(d)
    cur.close(); con.close()
    return jsonify(groups=out)

@app.get("/api/groups/<int:gid>/messages")
def group_messages(gid):
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT 1 FROM group_members WHERE group_id=%s AND user_id=%s", (gid, me))
    if not cur.fetchone():
        cur.close(); con.close()
        return jsonify(error="Нет доступа"), 403
    cur.execute("""
        SELECT gm.id,gm.sender,gm.text,gm.kind,gm.created,gm.reply_to,gm.deleted,gm.edited,
               u.username AS sender_name, r.text AS reply_text, ru.username AS reply_name
        FROM group_messages gm
        JOIN users u ON u.id=gm.sender
        LEFT JOIN group_messages r ON r.id = gm.reply_to
        LEFT JOIN users ru ON ru.id = r.sender
        WHERE gm.group_id=%s ORDER BY gm.id
    """, (gid,))
    rows = cur.fetchall()
    msg_ids = [r["id"] for r in rows]
    reacts = {}
    if msg_ids:
        ph = ",".join(["%s"] * len(msg_ids))
        cur.execute(f"SELECT message_id,user_id,emoji FROM group_reactions WHERE message_id IN ({ph})", msg_ids)
        for x in cur.fetchall():
            reacts.setdefault(x["message_id"], []).append({"user_id": x["user_id"], "emoji": x["emoji"]})
    cur.close(); con.close()
    out = []
    for r in rows:
        d = dict(r); d["reactions"] = reacts.get(r["id"], [])
        out.append(d)
    return jsonify(messages=out)

@app.post("/api/groups/<int:gid>/messages")
def group_send(gid):
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    d = request.json or {}
    text = (d.get("text") or "")
    kind = (d.get("kind") or "text").strip()
    try: reply_to = int(d.get("reply_to", 0) or 0)
    except: reply_to = 0
    if not text.strip(): return jsonify(error="Пустое сообщение."), 400
    if kind == "text" and len(text) > MAX_MSG_LEN: return jsonify(error="Слишком длинно"), 400
    if kind in ("image", "sticker") and len(text) > 3 * 1024 * 1024: return jsonify(error="Слишком большой файл"), 413
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT 1 FROM group_members WHERE group_id=%s AND user_id=%s", (gid, me))
    if not cur.fetchone():
        cur.close(); con.close()
        return jsonify(error="Нет доступа"), 403
    cur.execute("INSERT INTO group_messages(group_id,sender,text,kind,reply_to) VALUES(%s,%s,%s,%s,%s) RETURNING id,sender,text,kind,created,reply_to,deleted,edited",
                (gid, me, text, kind, reply_to))
    row = cur.fetchone()
    con.commit(); cur.close(); con.close()
    m = dict(row); m["sender_name"] = ""; m["reactions"] = []
    return jsonify(message=m)

@app.post("/api/groups/<int:gid>/members")
def group_add_member(gid):
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    d = request.json or {}
    try: uid = int(d.get("user_id", 0))
    except: return jsonify(error="Плохой user_id"), 400
    con = db(); cur = con.cursor()
    cur.execute("SELECT owner FROM groups WHERE id=%s", (gid,))
    row = cur.fetchone()
    if not row or row[0] != me:
        cur.close(); con.close()
        return jsonify(error="Только владелец может добавлять"), 403
    cur.execute("INSERT INTO group_members(group_id,user_id) VALUES(%s,%s) ON CONFLICT DO NOTHING", (gid, uid))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

# ========== ADMIN ==========

@app.post("/api/admin/secret")
def become_admin():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    d = request.json or {}
    code = (d.get("code") or "").strip()
    secret = os.environ.get("ADMIN_SECRET", "")
    if not secret: return jsonify(error="ADMIN_SECRET не настроен"), 500
    if code != secret: return jsonify(error="Неверный код"), 403
    con = db(); cur = con.cursor()
    cur.execute("UPDATE users SET is_admin=TRUE WHERE id=%s", (me,))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.get("/api/admin/users")
@admin_only
def admin_users():
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id,username,avatar,email,is_admin,last_seen FROM users WHERE username <> 'admin_bot' ORDER BY id")
    rows = cur.fetchall(); cur.close(); con.close()
    now = time.time()
    out = []
    for r in rows:
        d = dict(r); d["online"] = (now - (r["last_seen"] or 0)) < 120
        out.append(d)
    return jsonify(users=out)

@app.post("/api/admin/set-username")
@admin_only
def admin_set_username():
    d = request.json or {}
    try: uid = int(d.get("user_id", 0))
    except: return jsonify(error="Плохой user_id"), 400
    name = (d.get("username") or "").strip()
    if not uid or len(name) < 3 or len(name) > MAX_NAME_LEN: return jsonify(error="Плохие данные"), 400
    con = db(); cur = con.cursor()
    try:
        cur.execute("UPDATE users SET username=%s WHERE id=%s", (name, uid))
        con.commit()
    except psycopg2.errors.UniqueViolation:
        con.rollback(); cur.close(); con.close()
        return jsonify(error="Такое имя уже занято"), 409
    cur.close(); con.close()
    return jsonify(ok=True)

@app.post("/api/admin/set-avatar")
@admin_only
def admin_set_avatar():
    d = request.json or {}
    try: uid = int(d.get("user_id", 0))
    except: return jsonify(error="Плохой user_id"), 400
    avatar = d.get("avatar", "")
    if not uid: return jsonify(error="Плохие данные"), 400
    con = db(); cur = con.cursor()
    cur.execute("UPDATE users SET avatar=%s WHERE id=%s", (avatar, uid))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.post("/api/admin/set-password")
@admin_only
def admin_set_password():
    d = request.json or {}
    try: uid = int(d.get("user_id", 0))
    except: return jsonify(error="Плохой user_id"), 400
    pwd = (d.get("password") or "").strip()
    if not uid or len(pwd) < 4: return jsonify(error="Пароль минимум 4"), 400
    con = db(); cur = con.cursor()
    cur.execute("UPDATE users SET password=%s WHERE id=%s", (pw(pwd), uid))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.post("/api/admin/set-admin")
@admin_only
def admin_set_admin():
    me = session.get("uid")
    d = request.json or {}
    try: uid = int(d.get("user_id", 0))
    except: return jsonify(error="Плохой user_id"), 400
    if not uid or uid == me: return jsonify(error="Нельзя менять свою роль"), 400
    val = bool(d.get("is_admin", False))
    con = db(); cur = con.cursor()
    cur.execute("UPDATE users SET is_admin=%s WHERE id=%s", (val, uid))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.post("/api/admin/delete-user")
@admin_only
def admin_delete_user():
    me = session.get("uid")
    d = request.json or {}
    try: uid = int(d.get("user_id", 0))
    except: return jsonify(error="Плохой user_id"), 400
    if not uid or uid == me: return jsonify(error="Нельзя удалить себя"), 400
    con = db(); cur = con.cursor()
    cur.execute("SELECT username FROM users WHERE id=%s", (uid,))
    row = cur.fetchone()
    if not row: cur.close(); con.close(); return jsonify(error="Нет такого"), 404
    if row[0] == 'admin_bot': cur.close(); con.close(); return jsonify(error="Бота нельзя"), 400
    cur.execute("DELETE FROM reactions WHERE user_id=%s", (uid,))
    cur.execute("DELETE FROM group_reactions WHERE user_id=%s", (uid,))
    cur.execute("DELETE FROM messages WHERE sender=%s OR receiver=%s", (uid, uid))
    cur.execute("DELETE FROM group_messages WHERE sender=%s", (uid,))
    cur.execute("DELETE FROM group_members WHERE user_id=%s", (uid,))
    cur.execute("DELETE FROM groups WHERE owner=%s", (uid,))
    cur.execute("DELETE FROM blocks WHERE blocker=%s OR blocked=%s", (uid, uid))
    cur.execute("DELETE FROM dialogs WHERE user_id=%s OR peer_id=%s", (uid, uid))
    cur.execute("DELETE FROM stickers WHERE pack_id IN (SELECT id FROM sticker_packs WHERE owner=%s)", (uid,))
    cur.execute("DELETE FROM sticker_packs WHERE owner=%s", (uid,))
    cur.execute("DELETE FROM users WHERE id=%s", (uid,))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.post("/api/admin/block-user")
@admin_only
def admin_block_user():
    me = session.get("uid")
    d = request.json or {}
    try: uid = int(d.get("user_id", 0))
    except: return jsonify(error="Плохой user_id"), 400
    if not uid or uid == me: return jsonify(error="Нельзя"), 400
    con = db(); cur = con.cursor()
    cur.execute("INSERT INTO blocks(blocker,blocked) VALUES(%s,%s) ON CONFLICT DO NOTHING", (me, uid))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.post("/api/admin/unblock-user")
@admin_only
def admin_unblock_user():
    me = session.get("uid")
    d = request.json or {}
    try: uid = int(d.get("user_id", 0))
    except: return jsonify(error="Плохой user_id"), 400
    if not uid: return jsonify(error="Нет user_id"), 400
    con = db(); cur = con.cursor()
    cur.execute("DELETE FROM blocks WHERE blocker=%s AND blocked=%s", (me, uid))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.get("/api/admin/user-messages/<int:uid>")
@admin_only
def admin_user_messages_list(uid):
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id, username FROM users WHERE id=%s", (uid,))
    target = cur.fetchone()
    if not target:
        cur.close(); con.close()
        return jsonify(error="Нет такого пользователя"), 404
    cur.execute("""
        SELECT CASE WHEN sender=%s THEN receiver ELSE sender END AS other_id,
               MAX(created) AS last_created
        FROM messages WHERE sender=%s OR receiver=%s
        GROUP BY other_id ORDER BY last_created DESC
    """, (uid, uid, uid))
    rows = cur.fetchall()
    out = []
    for r in rows:
        other_id = r["other_id"]
        cur.execute("SELECT id, username, avatar FROM users WHERE id=%s", (other_id,))
        u = cur.fetchone()
        if not u: continue
        cur.execute("""
            SELECT text, kind, created FROM messages
            WHERE (sender=%s AND receiver=%s) OR (sender=%s AND receiver=%s)
            ORDER BY id DESC LIMIT 1
        """, (uid, other_id, other_id, uid))
        last = cur.fetchone()
        preview = ""
        if last:
            if last["kind"] == "voice": preview = "🎤 голосовое"
            elif last["kind"] == "image": preview = "🖼 картинка"
            elif last["kind"] == "sticker": preview = "🧩 стикер"
            else: preview = (last["text"] or "")[:60]
        out.append({
            "id": u["id"], "username": u["username"], "avatar": u["avatar"] or "",
            "last_created": r["last_created"] or 0, "preview": preview
        })
    cur.close(); con.close()
    return jsonify(target={"id": target["id"], "username": target["username"]}, chats=out)

@app.get("/api/admin/user-messages/<int:uid>/<int:other_id>")
@admin_only
def admin_user_messages_dialog(uid, other_id):
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT m.id, m.sender, m.receiver, m.text, m.kind, m.created, m.deleted, m.edited,
               r.text AS reply_text, ru.username AS reply_name
        FROM messages m
        LEFT JOIN messages r ON r.id = m.reply_to
        LEFT JOIN users ru ON ru.id = r.sender
        WHERE (m.sender=%s AND m.receiver=%s) OR (m.sender=%s AND m.receiver=%s)
        ORDER BY m.id
    """, (uid, other_id, other_id, uid))
    rows = cur.fetchall(); cur.close(); con.close()
    return jsonify(messages=[dict(r) for r in rows])

# ========== СТИКЕР-ПАКИ ==========

@app.get("/api/sticker-packs")
def my_sticker_packs():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id,name FROM sticker_packs WHERE owner=%s ORDER BY id", (me,))
    packs = cur.fetchall()
    out = []
    for p in packs:
        d = dict(p)
        cur.execute("SELECT id,image FROM stickers WHERE pack_id=%s ORDER BY id", (p["id"],))
        d["stickers"] = [dict(x) for x in cur.fetchall()]
        out.append(d)
    cur.close(); con.close()
    return jsonify(packs=out)

@app.post("/api/sticker-packs")
def create_sticker_pack():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    d = request.json or {}
    name = (d.get("name") or "").strip()
    if len(name) < 2: return jsonify(error="Имя пака: минимум 2 символа."), 400
    if len(name) > MAX_NAME_LEN: return jsonify(error="Слишком длинно"), 400
    con = db(); cur = con.cursor()
    try:
        cur.execute("INSERT INTO sticker_packs(owner,name) VALUES(%s,%s) RETURNING id", (me, name))
        pid = cur.fetchone()[0]; con.commit()
    except psycopg2.errors.UniqueViolation:
        con.rollback(); cur.close(); con.close()
        return jsonify(error="Такой пак уже есть."), 409
    cur.close(); con.close()
    return jsonify(id=pid, name=name)

@app.post("/api/sticker-packs/<int:pid>/stickers")
def add_sticker(pid):
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    d = request.json or {}
    image = d.get("image") or ""
    if not image: return jsonify(error="Нет картинки"), 400
    if len(image) > 3 * 1024 * 1024: return jsonify(error="Слишком большой файл (макс 2 МБ)."), 413
    con = db(); cur = con.cursor()
    cur.execute("SELECT owner FROM sticker_packs WHERE id=%s", (pid,))
    row = cur.fetchone()
    if not row or row[0] != me:
        cur.close(); con.close()
        return jsonify(error="Нет доступа"), 403
    cur.execute("INSERT INTO stickers(pack_id,image) VALUES(%s,%s) RETURNING id", (pid, image))
    sid = cur.fetchone()[0]
    con.commit(); cur.close(); con.close()
    return jsonify(id=sid)

# ========== ЗВОНКИ ==========

@app.post("/api/signal")
def post_signal():
    if not session.get("uid"): return jsonify(error="auth"), 401
    touch_online(session["uid"])
    d = request.json or {}
    room = (d.get("room") or "").strip()
    data = d.get("data")
    if not room or data is None: return jsonify(error="Нет room или data"), 400
    signals.setdefault(room, [])
    signals[room].append({"data": data, "ts": time.time()})
    now = time.time()
    for k in list(signals.keys()):
        signals[k] = [x for x in signals[k] if now - x.get("ts", 0) < 120]
        if not signals[k]:
            del signals[k]
    return jsonify(ok=True)

@app.get("/api/signal/<room>")
def get_signal(room):
    if not session.get("uid"): return jsonify(error="auth"), 401
    touch_online(session["uid"])
    now = time.time()
    if room in signals:
        signals[room] = [x for x in signals[room] if now - x.get("ts", 0) < 120]
    uid = session["uid"]
    out = []
    for x in signals.get(room, []):
        d = x.get("data") or {}
        if d.get("from") == uid: continue
        out.append(d)
    return jsonify(items=out)

@app.post("/api/call/invite")
def call_invite():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    d = request.json or {}
    try: to = int(d.get("to", 0))
    except: return jsonify(error="Плохой получатель."), 400
    room = (d.get("room") or "").strip()
    if not to or not room: return jsonify(error="Нет to или room"), 400
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT username FROM users WHERE id=%s", (me,))
    r = cur.fetchone(); cur.close(); con.close()
    incoming[to] = {"room": room, "from": me, "fromName": r["username"] if r else "?", "ts": time.time()}
    return jsonify(ok=True)

@app.get("/api/call/incoming")
def call_incoming():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    touch_online(me)
    now = time.time()
    for k in list(incoming.keys()):
        if now - incoming[k].get("ts", 0) > 60:
            del incoming[k]
    return jsonify(invite=incoming.pop(me, None))

init()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
