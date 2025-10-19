from fastapi import FastAPI, HTTPException, Query, Depends, Header, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import sqlite3
import json
import threading
from typing import Optional, List, Dict, Any
from datetime import datetime
import os
import secrets
import base64
import hashlib
import anyio
from datetime import timedelta

DB_PATH = os.path.join(os.path.dirname(__file__), "messenger.db")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Session lifetime (default: 30 days)
SESSION_TTL = timedelta(days=30)


def dict_factory(cursor, row):
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


class Database:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = dict_factory
        self.lock = threading.Lock()
        self._init()

    def _init(self):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    public_key_jwk TEXT NOT NULL,
                    password_hash TEXT,
                    password_salt TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id INTEGER NOT NULL,
                    recipient_id INTEGER NOT NULL,
                    ciphertext TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(sender_id) REFERENCES users(id),
                    FOREIGN KEY(recipient_id) REFERENCES users(id)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS friendships (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    requester_id INTEGER NOT NULL,
                    addressee_id INTEGER NOT NULL,
                    status TEXT NOT NULL, -- pending|accepted|declined
                    created_at TEXT NOT NULL,
                    UNIQUE(requester_id, addressee_id),
                    FOREIGN KEY(requester_id) REFERENCES users(id),
                    FOREIGN KEY(addressee_id) REFERENCES users(id)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS uploads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id INTEGER NOT NULL,
                    recipient_id INTEGER NOT NULL,
                    filename TEXT NOT NULL,
                    mime TEXT,
                    size INTEGER NOT NULL,
                    total_chunks INTEGER NOT NULL,
                    base_iv TEXT NOT NULL,
                    key_wrapped TEXT NOT NULL,
                    next_index INTEGER NOT NULL DEFAULT 0,
                    finished INTEGER NOT NULL DEFAULT 0,
                    path TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(owner_id) REFERENCES users(id),
                    FOREIGN KEY(recipient_id) REFERENCES users(id)
                )
                """
            )
            # Attempt to add new columns if migrating from older schema
            for coldef in [
                ("users", "password_hash TEXT"),
                ("users", "password_salt TEXT"),
                ("messages", "delivered_at TEXT"),
                ("messages", "read_at TEXT"),
            ]:
                try:
                    cur.execute(f"ALTER TABLE {coldef[0]} ADD COLUMN {coldef[1]}")
                except sqlite3.OperationalError:
                    pass
            self.conn.commit()

    def create_or_get_user(self, username: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM users WHERE username = ?", (username,))
            return cur.fetchone()

    def upsert_user(self, username: str, public_key_jwk: str) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat()
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM users WHERE username = ?", (username,))
            row = cur.fetchone()
            if row is None:
                cur.execute(
                    "INSERT INTO users(username, public_key_jwk, created_at) VALUES (?, ?, ?)",
                    (username, public_key_jwk, now),
                )
                self.conn.commit()
                cur.execute("SELECT * FROM users WHERE username = ?", (username,))
                return cur.fetchone()
            else:
                # If same key, treat as idempotent register
                if row["public_key_jwk"] == public_key_jwk:
                    return row
                # Otherwise, reject to prevent key takeover
                raise ValueError("username_taken")

    def create_user_with_password(self, username: str, public_key_jwk: str, password: str) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat()
        salt = os.urandom(16)
        pwd_hash = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
        salt_b64 = base64.b64encode(salt).decode("ascii")
        hash_b64 = base64.b64encode(pwd_hash).decode("ascii")
        with self.lock:
            cur = self.conn.cursor()
            try:
                cur.execute(
                    "INSERT INTO users(username, public_key_jwk, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?, ?)",
                    (username, public_key_jwk, hash_b64, salt_b64, now),
                )
            except sqlite3.IntegrityError:
                raise ValueError("username_taken")
            self.conn.commit()
            cur.execute("SELECT * FROM users WHERE username = ?", (username,))
            return cur.fetchone()

    def verify_password(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM users WHERE username = ?", (username,))
            u = cur.fetchone()
            if not u or not u.get("password_hash") or not u.get("password_salt"):
                return None
            salt = base64.b64decode(u["password_salt"])  # type: ignore
            expected = base64.b64decode(u["password_hash"])  # type: ignore
            cand = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
            if secrets.compare_digest(cand, expected):
                return u
            return None

    def create_session(self, user_id: int) -> str:
        token = secrets.token_urlsafe(32)
        now = datetime.utcnow().isoformat()
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("INSERT INTO sessions(token, user_id, created_at) VALUES (?, ?, ?)", (token, user_id, now))
            self.conn.commit()
        return token

    def get_user_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT s.created_at, u.id, u.username, u.public_key_jwk FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?",
                (token,),
            )
            row = cur.fetchone()
            if not row:
                return None
            try:
                created = datetime.fromisoformat(row["created_at"])  # type: ignore
            except Exception:
                return None
            if datetime.utcnow() - created > SESSION_TTL:
                try:
                    cur.execute("DELETE FROM sessions WHERE token = ?", (token,))
                    self.conn.commit()
                except Exception:
                    pass
                return None
            return {k: v for k, v in row.items() if k != "created_at"}

    def list_users(self) -> List[Dict[str, Any]]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT id, username, public_key_jwk, created_at FROM users ORDER BY username ASC")
            return cur.fetchall() or []

    def get_user_by_name(self, username: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT id, username, public_key_jwk, created_at FROM users WHERE username = ?", (username,))
            return cur.fetchone()

    def insert_message(self, sender: str, recipient: str, ciphertext: str) -> int:
        now = datetime.utcnow().isoformat()
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT id FROM users WHERE username = ?", (sender,))
            s = cur.fetchone()
            if not s:
                raise KeyError("sender_not_found")
            cur.execute("SELECT id FROM users WHERE username = ?", (recipient,))
            r = cur.fetchone()
            if not r:
                raise KeyError("recipient_not_found")
            # ensure friendship accepted
            cur.execute(
                """
                SELECT 1 FROM friendships
                 WHERE ((requester_id = ? AND addressee_id = ?) OR (requester_id = ? AND addressee_id = ?))
                   AND status = 'accepted'
                """,
                (s["id"], r["id"], r["id"], s["id"]),
            )
            if not cur.fetchone():
                raise PermissionError("not_friends")
            cur.execute(
                "INSERT INTO messages(sender_id, recipient_id, ciphertext, created_at) VALUES (?, ?, ?, ?)",
                (s["id"], r["id"], ciphertext, now),
            )
            self.conn.commit()
            return cur.lastrowid

    def inbox(self, username: str, limit: int = 100, since_id: Optional[int] = None, before_id: Optional[int] = None) -> List[Dict[str, Any]]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT id FROM users WHERE username = ?", (username,))
            u = cur.fetchone()
            if not u:
                raise KeyError("recipient_not_found")
            params: List[Any] = [u["id"]]
            where = "recipient_id = ?"
            order = "ASC"
            if since_id is not None and before_id is not None:
                before_id = None
            if since_id is not None:
                where += " AND m.id > ?"
                params.append(since_id)
                order = "ASC"
            elif before_id is not None:
                where += " AND m.id < ?"
                params.append(before_id)
                order = "DESC"
            else:
                # default: fetch most recent first
                order = "DESC"
            cur.execute(
                f"""
                SELECT m.id, su.username AS sender, ru.username AS recipient, m.ciphertext, m.created_at
                FROM messages m
                JOIN users su ON su.id = m.sender_id
                JOIN users ru ON ru.id = m.recipient_id
                WHERE {where}
                ORDER BY m.id {order}
                LIMIT ?
                """,
                (*params, limit),
            )
            rows = cur.fetchall() or []
            if before_id is not None or (since_id is None and before_id is None):
                rows.reverse()
            return rows

    def thread(self, me: str, other: str, limit: int = 100, since_id: Optional[int] = None, before_id: Optional[int] = None) -> List[Dict[str, Any]]:
        with self.lock:
            cur = self.conn.cursor()
            # Resolve users
            cur.execute("SELECT id FROM users WHERE username = ?", (me,))
            u_me = cur.fetchone()
            cur.execute("SELECT id FROM users WHERE username = ?", (other,))
            u_other = cur.fetchone()
            if not u_me or not u_other:
                raise KeyError("user_not_found")
            # Ensure friendship accepted
            cur.execute(
                """
                SELECT 1 FROM friendships
                 WHERE ((requester_id = ? AND addressee_id = ?) OR (requester_id = ? AND addressee_id = ?))
                   AND status = 'accepted'
                """,
                (u_me["id"], u_other["id"], u_other["id"], u_me["id"]),
            )
            if not cur.fetchone():
                raise PermissionError("not_friends")
            params: List[Any] = [u_me["id"], u_other["id"], u_other["id"], u_me["id"]]
            where = "(m.sender_id = ? AND m.recipient_id = ?) OR (m.sender_id = ? AND m.recipient_id = ?)"
            order = "ASC"
            if since_id is not None and before_id is not None:
                before_id = None
            if since_id is not None:
                where += " AND m.id > ?"
                params.append(since_id)
                order = "ASC"
            elif before_id is not None:
                where += " AND m.id < ?"
                params.append(before_id)
                order = "DESC"
            else:
                order = "DESC"
            cur.execute(
                f"""
                SELECT m.id, su.username AS sender, ru.username AS recipient, m.ciphertext, m.created_at
                FROM messages m
                JOIN users su ON su.id = m.sender_id
                JOIN users ru ON ru.id = m.recipient_id
                WHERE {where}
                ORDER BY m.id {order}
                LIMIT ?
                """,
                (*params, limit),
            )
            rows = cur.fetchall() or []
            if before_id is not None or (since_id is None and before_id is None):
                rows.reverse()
            return rows

    def ack_message(self, message_id: int, username: str, delivered: bool, read: bool) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat()
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT m.id, m.recipient_id, m.sender_id, m.delivered_at, m.read_at, ru.username AS recipient, su.username AS sender FROM messages m JOIN users ru ON ru.id = m.recipient_id JOIN users su ON su.id = m.sender_id WHERE m.id = ?",
                (message_id,),
            )
            row = cur.fetchone()
            if not row:
                raise KeyError("message_not_found")
            if row["recipient"] != username:
                raise PermissionError("not_recipient")
            new_deliv = row.get("delivered_at")
            new_read = row.get("read_at")
            if delivered and not new_deliv:
                new_deliv = now
            if read:
                new_read = now
            cur.execute("UPDATE messages SET delivered_at = ?, read_at = ? WHERE id = ?", (new_deliv, new_read, message_id))
            self.conn.commit()
            return {"sender": row["sender"], "delivered_at": new_deliv, "read_at": new_read}

    # Upload helpers
    def create_upload(self, owner_username: str, recipient_username: str, filename: str, mime: Optional[str], size: int, total_chunks: int, base_iv: str, key_wrapped: str) -> Dict[str, Any]:
        if size < 0 or size > 10 * 1024 * 1024 * 1024:
            raise ValueError("size_limit")
        now = datetime.utcnow().isoformat()
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT id FROM users WHERE username=?", (owner_username,))
            ou = cur.fetchone()
            cur.execute("SELECT id FROM users WHERE username=?", (recipient_username,))
            ru = cur.fetchone()
            if not ou or not ru:
                raise KeyError("user_not_found")
            cur.execute(
                "SELECT 1 FROM friendships WHERE ((requester_id = ? AND addressee_id = ?) OR (requester_id = ? AND addressee_id = ?)) AND status = 'accepted'",
                (ou["id"], ru["id"], ru["id"], ou["id"]),
            )
            if not cur.fetchone():
                raise PermissionError("not_friends")
            path = os.path.join(UPLOAD_DIR, f"upload_{secrets.token_hex(8)}.bin")
            cur.execute(
                """
                INSERT INTO uploads(owner_id, recipient_id, filename, mime, size, total_chunks, base_iv, key_wrapped, next_index, finished, path, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?)
                """,
                (ou["id"], ru["id"], filename, mime, size, total_chunks, base_iv, key_wrapped, path, now),
            )
            self.conn.commit()
            cur.execute("SELECT * FROM uploads WHERE rowid = last_insert_rowid()")
            return cur.fetchone()

    def append_upload_chunk(self, upload_id: int, owner_username: str, index: int, data: bytes) -> Dict[str, Any]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                """SELECT u.id, u.path, u.next_index, u.total_chunks, u.finished, ou.username AS owner
                    FROM uploads u JOIN users ou ON ou.id = u.owner_id WHERE u.id = ?""",
                (upload_id,),
            )
            row = cur.fetchone()
            if not row:
                raise KeyError("upload_not_found")
            if row["owner"] != owner_username:
                raise PermissionError("not_owner")
            if row["finished"]:
                raise ValueError("already_finished")
            if index != row["next_index"]:
                raise ValueError("bad_index")
            with open(row["path"], "ab") as f:
                f.write(data)
            cur.execute("UPDATE uploads SET next_index = ? WHERE id = ?", (index + 1, upload_id))
            self.conn.commit()
            return {"next_index": index + 1, "total_chunks": row["total_chunks"]}

    def finish_upload(self, upload_id: int, owner_username: str):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT u.next_index, u.total_chunks, u.finished, ou.username AS owner FROM uploads u JOIN users ou ON ou.id = u.owner_id WHERE u.id = ?",
                (upload_id,),
            )
            row = cur.fetchone()
            if not row:
                raise KeyError("upload_not_found")
            if row["owner"] != owner_username:
                raise PermissionError("not_owner")
            if row["next_index"] != row["total_chunks"]:
                raise ValueError("incomplete")
            cur.execute("UPDATE uploads SET finished = 1 WHERE id = ?", (upload_id,))
            self.conn.commit()

    def get_upload(self, upload_id: int) -> Optional[Dict[str, Any]]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                """SELECT u.*, ou.username AS owner, ru.username AS recipient
                    FROM uploads u JOIN users ou ON ou.id = u.owner_id JOIN users ru ON ru.id = u.recipient_id
                    WHERE u.id = ?""",
                (upload_id,),
            )
            return cur.fetchone()

    # Friendship helpers
    def send_friend_request(self, from_user: str, to_user: str):
        now = datetime.utcnow().isoformat()
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT id FROM users WHERE username = ?", (from_user,))
            fu = cur.fetchone()
            cur.execute("SELECT id FROM users WHERE username = ?", (to_user,))
            tu = cur.fetchone()
            if not fu or not tu:
                raise KeyError("user_not_found")
            if fu["id"] == tu["id"]:
                raise ValueError("self_request")
            # check if already exists either direction
            cur.execute(
                "SELECT id, requester_id, addressee_id, status FROM friendships WHERE (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)",
                (fu["id"], tu["id"], tu["id"], fu["id"]),
            )
            row = cur.fetchone()
            if row:
                if row.get("status") == "pending":
                    return "pending"
                if row.get("status") == "accepted":
                    return "accepted"
                # status is declined (or any non-pending/accepted) -> revive as new pending from current requester
                cur.execute(
                    "UPDATE friendships SET requester_id=?, addressee_id=?, status='pending', created_at=? WHERE id=?",
                    (fu["id"], tu["id"], now, row["id"]),
                )
            else:
                cur.execute(
                    "INSERT INTO friendships(requester_id, addressee_id, status, created_at) VALUES (?, ?, 'pending', ?)",
                    (fu["id"], tu["id"], now),
                )
            self.conn.commit()
            return "pending"

    def respond_friend_request(self, addressee: str, requester: str, accept: bool):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT id FROM users WHERE username = ?", (addressee,))
            ad = cur.fetchone()
            cur.execute("SELECT id FROM users WHERE username = ?", (requester,))
            rq = cur.fetchone()
            if not ad or not rq:
                raise KeyError("user_not_found")
            status = 'accepted' if accept else 'declined'
            cur.execute(
                "UPDATE friendships SET status=? WHERE requester_id=? AND addressee_id=? AND status='pending'",
                (status, rq["id"], ad["id"]),
            )
            if cur.rowcount == 0:
                raise KeyError("request_not_found")
            self.conn.commit()

    def get_friend_status(self, a: str, b: str) -> str:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT id FROM users WHERE username=?", (a,))
            ua = cur.fetchone()
            cur.execute("SELECT id FROM users WHERE username=?", (b,))
            ub = cur.fetchone()
            if not ua or not ub:
                return "none"
            cur.execute(
                "SELECT status FROM friendships WHERE (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)",
                (ua["id"], ub["id"], ub["id"], ua["id"]),
            )
            row = cur.fetchone()
            return row["status"] if row else "none"

    def list_friends(self, username: str) -> List[str]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT id FROM users WHERE username=?", (username,))
            u = cur.fetchone()
            if not u:
                raise KeyError("user_not_found")
            cur.execute(
                """
                SELECT CASE WHEN requester_id = ? THEN u2.username ELSE u1.username END AS friend
                FROM friendships f
                JOIN users u1 ON u1.id = f.requester_id
                JOIN users u2 ON u2.id = f.addressee_id
                WHERE (requester_id = ? OR addressee_id = ?) AND status = 'accepted'
                ORDER BY friend
                """,
                (u["id"], u["id"], u["id"]),
            )
            rows = cur.fetchall() or []
            return [r["friend"] for r in rows]

    def list_friend_requests(self, username: str) -> Dict[str, List[str]]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT id FROM users WHERE username=?", (username,))
            u = cur.fetchone()
            if not u:
                raise KeyError("user_not_found")
            cur.execute(
                "SELECT u.username AS from_user FROM friendships f JOIN users u ON u.id = f.requester_id WHERE f.addressee_id=? AND f.status='pending'",
                (u["id"],),
            )
            incoming = [r["from_user"] for r in (cur.fetchall() or [])]
            cur.execute(
                "SELECT u.username AS to_user FROM friendships f JOIN users u ON u.id = f.addressee_id WHERE f.requester_id=? AND f.status='pending'",
                (u["id"],),
            )
            outgoing = [r["to_user"] for r in (cur.fetchall() or [])]
            return {"incoming": incoming, "outgoing": outgoing}


db = Database(DB_PATH)

app = FastAPI(title="E2E Messenger", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    # The app serves its own frontend; broad origins are acceptable without credentials.
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class RegisterBody(BaseModel):
    username: str
    password: str
    public_key_jwk: dict


class SendMessageBody(BaseModel):
    sender: str
    recipient: str
    ciphertext: str  # JSON string produced by the client (hybrid RSA-OAEP + AES-GCM)


class LoginBody(BaseModel):
    username: str
    password: str


class FriendRequestBody(BaseModel):
    to: str


class FriendRespondBody(BaseModel):
    requester: str
    accept: bool


def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1]
    u = db.get_user_by_token(token)
    if not u:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {"token": token, **u}


@app.get("/")
def index():
    index_path = os.path.join(os.path.dirname(__file__), "index.html")
    if not os.path.isfile(index_path):
        raise HTTPException(status_code=404, detail="index.html not found")
    return FileResponse(index_path)


@app.get("/app.js")
def app_js():
    js_path = os.path.join(os.path.dirname(__file__), "app.js")
    if not os.path.isfile(js_path):
        raise HTTPException(status_code=404, detail="app.js not found")
    return FileResponse(js_path, media_type="application/javascript")


@app.get("/style.css")
def style_css():
    css_path = os.path.join(os.path.dirname(__file__), "style.css")
    if not os.path.isfile(css_path):
        raise HTTPException(status_code=404, detail="style.css not found")
    return FileResponse(css_path, media_type="text/css")


@app.post("/register")
def register(body: RegisterBody):
    try:
        stored = db.create_user_with_password(
            body.username, json.dumps(body.public_key_jwk, sort_keys=True), body.password
        )
    except ValueError as e:
        if str(e) == "username_taken":
            raise HTTPException(status_code=409, detail="Username already exists")
        raise
    token = db.create_session(stored["id"])  # type: ignore
    return {"username": stored["username"], "token": token}


@app.get("/users")
def users():
    rows = db.list_users()
    # Do not flood with keys; include usernames only by default
    return [{"username": r["username"]} for r in rows]


@app.get("/users/{username}")
def get_user(username: str):
    u = db.get_user_by_name(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return {"username": u["username"], "public_key_jwk": json.loads(u["public_key_jwk"])}


@app.post("/login")
def login(body: LoginBody):
    u = db.verify_password(body.username, body.password)
    if not u:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = db.create_session(u["id"])  # type: ignore
    return {"username": u["username"], "token": token}


@app.get("/me")
def me(user=Depends(get_current_user)):
    return {"username": user["username"]}


@app.post("/friends/request")
def friend_request(body: FriendRequestBody, user=Depends(get_current_user)):
    try:
        status = db.send_friend_request(user["username"], body.to)
    except ValueError as e:
        if str(e) == "self_request":
            raise HTTPException(status_code=400, detail="Cannot friend yourself")
        raise
    except KeyError:
        raise HTTPException(status_code=404, detail="User not found")
    # Notify recipient if online
    notify_user(body.to, {"type": "friend_request", "from": user["username"]})
    return {"status": status}


@app.post("/friends/respond")
def friend_respond(body: FriendRespondBody, user=Depends(get_current_user)):
    try:
        db.respond_friend_request(user["username"], body.requester, body.accept)
    except KeyError as e:
        code = str(e)
        if "user_not_found" in code:
            raise HTTPException(status_code=404, detail="User not found")
        if "request_not_found" in code:
            raise HTTPException(status_code=404, detail="Request not found")
        raise
    notify_user(body.requester, {"type": "friend_response", "to": user["username"], "accepted": body.accept})
    return {"ok": True}


@app.get("/friends")
def friends(user=Depends(get_current_user)):
    try:
        lst = db.list_friends(user["username"])
    except KeyError:
        raise HTTPException(status_code=404, detail="User not found")
    return {"friends": lst}


@app.get("/friends/requests")
def friend_requests(user=Depends(get_current_user)):
    try:
        reqs = db.list_friend_requests(user["username"])
    except KeyError:
        raise HTTPException(status_code=404, detail="User not found")
    return reqs


@app.post("/messages")
def send_message(body: SendMessageBody, user=Depends(get_current_user)):
    if user["username"] != body.sender:
        raise HTTPException(status_code=403, detail="Sender mismatch")
    try:
        msg_id = db.insert_message(body.sender, body.recipient, body.ciphertext)
    except KeyError as e:
        code = str(e)
        if "sender_not_found" in code:
            raise HTTPException(status_code=404, detail="Sender not registered")
        if "recipient_not_found" in code:
            raise HTTPException(status_code=404, detail="Recipient not found")
        raise
    except PermissionError:
        raise HTTPException(status_code=403, detail="Users are not friends")
    # push live event
    notify_user(body.recipient, {"type": "new_message", "id": msg_id, "from": body.sender})
    return {"id": msg_id}


@app.get("/messages/inbox")
def get_inbox(
    username: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    since_id: Optional[int] = Query(None),
    before_id: Optional[int] = Query(None),
    user=Depends(get_current_user),
):
    target = username or user["username"]
    if target != user["username"]:
        raise HTTPException(status_code=403, detail="Cannot read others' inbox")
    try:
        rows = db.inbox(username=target, limit=limit, since_id=since_id, before_id=before_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="User not found")
    return rows


@app.get("/messages/thread")
def get_thread(
    with_user: str = Query(..., alias="with"),
    limit: int = Query(100, ge=1, le=500),
    since_id: Optional[int] = Query(None),
    before_id: Optional[int] = Query(None),
    user=Depends(get_current_user),
):
    try:
        rows = db.thread(user["username"], with_user, limit=limit, since_id=since_id, before_id=before_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="User not found")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Users are not friends")
    return rows

class MessageAckBody(BaseModel):
    id: int
    delivered: Optional[bool] = False
    read: Optional[bool] = False


@app.post("/messages/ack")
def message_ack(body: MessageAckBody, user=Depends(get_current_user)):
    try:
        res = db.ack_message(body.id, user["username"], bool(body.delivered), bool(body.read))
    except KeyError:
        raise HTTPException(status_code=404, detail="Message not found")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Not allowed")
    # notify sender
    notify_user(res["sender"], {"type": "message_status", "id": body.id, "delivered_at": res["delivered_at"], "read_at": res["read_at"]})
    return {"ok": True}


class UploadInitBody(BaseModel):
    recipient: str
    filename: str
    size: int
    mime: Optional[str] = None
    total_chunks: int
    base_iv: str
    key_wrapped: str


@app.post("/uploads/init")
def uploads_init(body: UploadInitBody, user=Depends(get_current_user)):
    try:
        row = db.create_upload(user["username"], body.recipient, body.filename, body.mime, body.size, body.total_chunks, body.base_iv, body.key_wrapped)
    except ValueError as e:
        if str(e) == "size_limit":
            raise HTTPException(status_code=400, detail="File too large (max 10GB)")
        raise
    except PermissionError:
        raise HTTPException(status_code=403, detail="Users are not friends")
    except KeyError:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": row["id"]}


@app.post("/uploads/{upload_id}/chunk")
async def uploads_chunk(upload_id: int, index: int = Query(..., ge=0), request: Request = None, user=Depends(get_current_user)):
    if request is None:
        raise HTTPException(status_code=400, detail="Bad request")
    data = await request.body()
    try:
        res = db.append_upload_chunk(upload_id, user["username"], index, data)
    except KeyError:
        raise HTTPException(status_code=404, detail="Upload not found")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Not allowed")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return res


@app.post("/uploads/{upload_id}/finish")
def uploads_finish(upload_id: int, user=Depends(get_current_user)):
    try:
        db.finish_upload(upload_id, user["username"])
    except KeyError:
        raise HTTPException(status_code=404, detail="Upload not found")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Not allowed")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True}


@app.get("/uploads/{upload_id}")
def uploads_get(upload_id: int, user=Depends(get_current_user)):
    row = db.get_upload(upload_id)
    if not row or not row["finished"]:
        raise HTTPException(status_code=404, detail="Not found")
    if user["username"] not in (row["owner"], row["recipient"]):
        raise HTTPException(status_code=403, detail="Not allowed")
    return FileResponse(row["path"], media_type="application/octet-stream", filename=row["filename"])


# In-memory connection registry for live updates
connections: Dict[str, List[WebSocket]] = {}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # Token via query: /ws?token=...
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4401)
        return
    u = db.get_user_by_token(token)
    if not u:
        await websocket.close(code=4401)
        return
    username = u["username"]
    await websocket.accept()
    lst = connections.setdefault(username, [])
    lst.append(websocket)
    try:
        while True:
            msg = await websocket.receive_text()
            # Echo pings or simple client messages if needed
            if msg == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    finally:
        try:
            lst.remove(websocket)
            if not lst:
                connections.pop(username, None)
        except ValueError:
            pass

async def ws_push(username: str, payload: Dict[str, Any]):
    data = json.dumps(payload)
    for ws in list(connections.get(username, [])):
        try:
            await ws.send_text(data)
        except Exception:
            try:
                connections[username].remove(ws)
            except Exception:
                pass

def notify_user(username: str, payload: Dict[str, Any]):
    # Bridge from sync threadpool to running event loop safely
    try:
        anyio.from_thread.run(ws_push, username, payload)
    except RuntimeError:
        # If called from loop thread, fallback to direct scheduling
        import asyncio
        try:
            asyncio.create_task(ws_push(username, payload))
        except Exception:
            pass


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)


