from flask import Flask, request, jsonify, send_from_directory, session
import hashlib, secrets, os, time
import psycopg2
import psycopg2.extras
from pathlib import Path

app = Flask(__name__, static_folder=".")
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DATABASE_URL = os.environ.get("DATABASE_URL")

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
      last_seen REAL DEFAULT 0
    );""")
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
      message_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      emoji TEXT NOT NULL,
      created REAL DEFAULT (extract(epoch from now())),
      UNIQUE(message_id, user_id)
    );""")
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
    CREATE TABLE IF NOT EXISTS blocks(
      id SERIAL PRIMARY KEY,
      blocker INTEGER NOT NULL,
      blocked INTEGER NOT NULL,
      created REAL DEFAULT (extract(epoch from now())),
      UNIQUE(blocker, blocked)
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
    con = db(); cur = con.cursor()
    try:
        cur.execute("INSERT INTO users(username,password,last_seen) VALUES(%s,%s,%s) RETURNING id", (u, pw(p), time.time()))
        uid = cur.fetchone()[0]
        con.commit()
    except psycopg2.errors.UniqueViolation:
        con.rollback(); cur.close(); con.close()
        return jsonify(error="Такой пользователь уже существует."), 409
    cur.close(); con.close()
    session["uid"] = uid
    online[uid] = time.time()
    return jsonify(id=uid, username=u, avatar="")

@app.post("/api/login")
def login():
    d = request.json or {}
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE username=%s AND password=%s",
                (d.get("username", "").strip(), pw(d.get("password", ""))))
    row = cur.fetchone()
    cur.close(); con.close()
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
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id,username,avatar FROM users WHERE id=%s", (session["uid"],))
    r = cur.fetchone()
    cur.close(); con.close()
    return jsonify(user=dict(r) if r else None)

@app.post("/api/avatar")
def set_avatar():
    if not session.get("uid"):
        return jsonify(error="auth"), 401
    d = request.json or {}
    avatar = d.get("avatar", "")
    con = db(); cur = con.cursor()
    cur.execute("UPDATE users SET avatar=%s WHERE id=%s", (avatar, session["uid"]))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.post("/api/username")
def set_username():
    if not session.get("uid"):
        return jsonify(error="auth"), 401
    d = request.json or {}
    name = (d.get("username") or "").strip()
    if len(name) < 3:
        return jsonify(error="Имя: минимум 3 символа."), 400
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
    if not uid:
        return jsonify(error="auth"), 401
    touch_online(uid)
    q = request.args.get("q", "").strip()
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""SELECT id,username,avatar,last_seen FROM users
        WHERE id<>%s AND username LIKE %s
        AND id NOT IN (SELECT blocked FROM blocks WHERE blocker=%s)
        AND id NOT IN (SELECT blocker FROM blocks WHERE blocked=%s)
        ORDER BY username""", (uid, f"%{q}%", uid, uid))
    rows = cur.fetchall()
    cur.close(); con.close()
    now = time.time()
    out = []
    for r in rows:
        d = dict(r); d["online"] = (now - (r["last_seen"] or 0)) < 120
        out.append(d)
    return jsonify(users=out)

@app.get("/api/messages/<int:uid>")
def messages(uid):
    me = session.get("uid")
    if not me:
        return jsonify(error="auth"), 401
    touch_online(me)
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""SELECT 1 FROM blocks
        WHERE (blocker=%s AND blocked=%s) OR (blocker=%s AND blocked=%s)""",
        (me, uid, uid, me))
    if cur.fetchone():
        cur.close(); con.close()
        return jsonify(messages=[])
    cur.execute("""SELECT m.id,m.sender,m.receiver,m.text,m.kind,m.created,m.read_at,m.reply_to,m.deleted,m.edited,
            r.text AS reply_text, ru.username AS reply_name
        FROM messages m
        LEFT JOIN messages r ON r.id = m.reply_to
        LEFT JOIN users ru ON ru.id = r.sender
        WHERE (m.sender=%s AND m.receiver=%s) OR (m.sender=%s AND m.receiver=%s)
        ORDER BY m.id""",
        (me, uid, uid, me))
    rows = cur.fetchall()
    cur.execute("UPDATE messages SET read_at=%s WHERE sender=%s AND receiver=%s AND read_at=0",
                (time.time(), uid, me))
    con.commit()
    msg_ids = [r["id"] for r in rows]
    reacts = {}
    if msg_ids:
        ph = ",".join(["%s"] * len(msg_ids))
        cur.execute(f"SELECT message_id,user_id,emoji FROM reactions WHERE message_id IN ({ph})", msg_ids)
        for x in cur.fetchall():
            reacts.setdefault(x["message_id"], []).append({"user_id": x["user_id"], "emoji": x["emoji"]})
    cur.close(); con.close()
    out = []
    for r in rows:
        d = dict(r); d["reactions"] = reacts.get(r["id"], [])
        out.append(d)
    return jsonify(messages=out)

@app.post("/api/messages")
def send():
    me = session.get("uid")
    if not me:
        return jsonify(error="auth"), 401
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
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT 1 FROM users WHERE id=%s", (receiver,))
    if not cur.fetchone():
        cur.close(); con.close()
        return jsonify(error="Пользователь не найден."), 404
    cur.execute("""SELECT 1 FROM blocks
        WHERE (blocker=%s AND blocked=%s) OR (blocker=%s AND blocked=%s)""",
        (me, receiver, receiver, me))
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
    con = db(); cur = con.cursor()
    cur.execute("UPDATE group_messages SET text=%s, edited=1 WHERE id=%s AND sender=%s AND group_id=%s", (text, mid, me, gid))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.post("/api/react")
def react():
    me = session.get("uid")
    if not me:
        return jsonify(error="auth"), 401
    d = request.json or {}
    try: mid = int(d.get("message_id", 0))
    except: return jsonify(error="Нет данных"), 400
    emoji = d.get("emoji", "")
    if not mid or not emoji:
        return jsonify(error="Нет данных"), 400
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id,emoji FROM reactions WHERE message_id=%s AND user_id=%s", (mid, me))
    ex = cur.fetchone()
    if ex:
        if ex["emoji"] == emoji:
            cur.execute("DELETE FROM reactions WHERE id=%s", (ex["id"],))
        else:
            cur.execute("UPDATE reactions SET emoji=%s WHERE id=%s", (emoji, ex["id"]))
    else:
        cur.execute("INSERT INTO reactions(message_id,user_id,emoji) VALUES(%s,%s,%s)", (mid, me, emoji))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.post("/api/typing")
def set_typing():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    touch_online(me)
    d = request.json or {}
    try: to = int(d.get("to", 0))
    except: to = 0
    if to: typing[to] = {"from": me, "ts": time.time()}
    return jsonify(ok=True)

@app.get("/api/typing")
def get_typing():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    touch_online(me)
    who = request.args.get("who")
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
    if not target or target == me:
        return jsonify(error="Нельзя"), 400
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
    if not target:
        return jsonify(error="Нет user_id"), 400
    con = db(); cur = con.cursor()
    cur.execute("DELETE FROM blocks WHERE blocker=%s AND blocked=%s", (me, target))
    con.commit(); cur.close(); con.close()
    return jsonify(ok=True)

@app.get("/api/blocks")
def list_blocks():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""SELECT u.id, u.username, u.avatar FROM blocks b
        JOIN users u ON u.id=b.blocked WHERE b.blocker=%s ORDER BY u.username""", (me,))
    rows = cur.fetchall()
    cur.close(); con.close()
    return jsonify(blocks=[dict(r) for r in rows])

@app.post("/api/groups")
def create_group():
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    d = request.json or {}
    name = (d.get("name") or "").strip()
    members = d.get("members") or []
    if len(name) < 2:
        return jsonify(error="Имя группы: минимум 2 символа."), 400
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
    cur.execute("""SELECT g.id,g.name,g.owner FROM groups g
        JOIN group_members m ON m.group_id=g.id WHERE m.user_id=%s ORDER BY g.id""", (me,))
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
    cur.execute("""SELECT gm.id,gm.sender,gm.text,gm.kind,gm.created,gm.reply_to,gm.deleted,gm.edited,
            u.username AS sender_name, r.text AS reply_text, ru.username AS reply_name
        FROM group_messages gm
        JOIN users u ON u.id=gm.sender
        LEFT JOIN group_messages r ON r.id = gm.reply_to
        LEFT JOIN users ru ON ru.id = r.sender
        WHERE gm.group_id=%s ORDER BY gm.id""", (gid,))
    rows = cur.fetchall()
    cur.close(); con.close()
    return jsonify(messages=[dict(r) for r in rows])

@app.post("/api/groups/<int:gid>/messages")
def group_send(gid):
    me = session.get("uid")
    if not me: return jsonify(error="auth"), 401
    d = request.json or {}
    text = (d.get("text") or "")
    kind = (d.get("kind") or "text").strip()
    try: reply_to = int(d.get("reply_to", 0) or 0)
    except: reply_to = 0
    if not text.strip():
        return jsonify(error="Пустое сообщение."), 400
    con = db(); cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT 1 FROM group_members WHERE group_id=%s AND user_id=%s", (gid, me))
    if not cur.fetchone():
        cur.close(); con.close()
        return jsonify(error="Нет доступа"), 403
    cur.execute("INSERT INTO group_messages(group_id,sender,text,kind,reply_to) VALUES(%s,%s,%s,%s,%s) RETURNING id,sender,text,kind,created,reply_to,deleted,edited",
                (gid, me, text, kind, reply_to))
    row = cur.fetchone()
    con.commit(); cur.close(); con.close()
    m = dict(row); m["sender_name"] = ""
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
    r = cur.fetchone()
    cur.close(); con.close()
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
