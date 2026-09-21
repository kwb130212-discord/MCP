import os
import re
import secrets
import uuid
import hashlib
import base64
from datetime import datetime, timezone, timedelta
from pathlib import Path

from PIL import Image, UnidentifiedImageError
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Boolean, JSON, select, func
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, FileResponse, PlainTextResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "web"
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", str(BASE_DIR / "uploads")))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_PUBLISHABLE_KEY = os.environ.get("SUPABASE_PUBLISHABLE_KEY", "")
DATABASE_URL = os.environ.get("SUPABASE_DB_URL") or os.environ.get("DATABASE_URL", "")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "지헌아사랑한다임마")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_TITLE, MAX_BODY, MAX_COMMENT = 120, 10000, 2000
CATEGORIES = ("질문", "공략", "공지", "제재로그", "자유게시판")
NAME_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,24}$")
ALLOWED_IMAGE_TYPES = {"JPEG", "PNG", "WEBP"}
GUEST_COOKIE, CSRF_COOKIE, STAFF_COOKIE = "cat_hero_guest", "cat_hero_csrf", "cat_hero_staff"
SESSION_MAX_AGE = 60 * 60 * 12
RATE_WINDOW = 60
LOGIN_LIMIT = 8
WRITE_LIMIT = 12
_rate = {}

if not DATABASE_URL:
    raise RuntimeError("SUPABASE_DB_URL or DATABASE_URL is required")
if not ADMIN_PASSWORD_HASH and not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD_HASH or ADMIN_PASSWORD is required")

_engine_kwargs = {"pool_pre_ping": True}
if ":6543/" in DATABASE_URL:
    _engine_kwargs["connect_args"] = {"statement_cache_size": 0}
engine = create_async_engine(DATABASE_URL, **_engine_kwargs)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

class Post(Base):
    __tablename__ = "posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    guest_id: Mapped[str] = mapped_column(String(64), index=True)
    nickname: Mapped[str] = mapped_column(String(24))
    title: Mapped[str] = mapped_column(String(MAX_TITLE))
    category: Mapped[str] = mapped_column(String(16), default="자유게시판", index=True)
    body: Mapped[str] = mapped_column(Text)
    image_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    views: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    comments: Mapped[list["Comment"]] = relationship(back_populates="post", cascade="all, delete-orphan")

class Comment(Base):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    post_id: Mapped[int] = mapped_column(ForeignKey("posts.id", ondelete="CASCADE"), index=True)
    guest_id: Mapped[str] = mapped_column(String(64), index=True)
    nickname: Mapped[str] = mapped_column(String(24))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    post: Mapped[Post] = relationship(back_populates="comments")

class Staff(Base):
    __tablename__ = "staff"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(16), default="operator")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))



class Supporter(Base):
    __tablename__ = "supporters"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(64), default="지원자")
    macro_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class GameAccount(Base):
    __tablename__ = "game_accounts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    supporter_id: Mapped[int | None] = mapped_column(ForeignKey("supporters.id", ondelete="SET NULL"), nullable=True, index=True)
    username_enc: Mapped[str] = mapped_column(Text)
    password_enc: Mapped[str] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

SUPPORT_COOKIE = "cat_hero_support"
GAME_ACCOUNT_KEY = os.environ.get("GAME_ACCOUNT_KEY", "")

def support_hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()

def account_fernet():
    if not GAME_ACCOUNT_KEY:
        raise RuntimeError("GAME_ACCOUNT_KEY is not configured")
    from cryptography.fernet import Fernet
    return Fernet(GAME_ACCOUNT_KEY.encode())

def account_encrypt(value: str) -> str:
    return account_fernet().encrypt(value.encode()).decode()

def account_decrypt(value: str) -> str:
    return account_fernet().decrypt(value.encode()).decode()

def new_support_code() -> str:
    return "CAT-" + secrets.token_urlsafe(12).replace("-", "").replace("_", "")[:16].upper()

async def api_support_login(request: Request):
    if rate_limited(client_key(request, "support-login"), LOGIN_LIMIT):
        return json_error("요청이 너무 많습니다. 잠시 후 다시 시도하세요.", 429)
    try:
        code = clean_text(str((await request.json()).get("code") or ""), 32).upper()
    except Exception:
        return json_error("지원 코드를 확인하세요.", 401)
    async with SessionLocal() as db:
        supporter = await db.scalar(select(Supporter).where(Supporter.code_hash == support_hash(code), Supporter.active.is_(True)))
        if not supporter:
            return json_error("유효하지 않거나 비활성화된 지원 코드입니다.", 401)
    response = JSONResponse({"ok": True, "macro_enabled": supporter.macro_enabled})
    response.set_cookie(SUPPORT_COOKIE, code, max_age=60*60*24*30, httponly=True, samesite="lax", secure=request.url.scheme == "https")
    return response

async def current_supporter(request: Request):
    code = request.cookies.get(SUPPORT_COOKIE)
    if not code:
        return None
    async with SessionLocal() as db:
        return await db.scalar(select(Supporter).where(Supporter.code_hash == support_hash(code), Supporter.active.is_(True)))

async def api_support_me(request: Request):
    supporter = await current_supporter(request)
    if not supporter:
        return json_error("supporter unauthorized", 401)
    return JSONResponse({"id": supporter.id, "label": supporter.label, "macro_enabled": supporter.macro_enabled})

async def api_support_account(request: Request):
    supporter = await current_supporter(request)
    if not supporter:
        return json_error("supporter unauthorized", 401)
    if not supporter.macro_enabled:
        return json_error("매크로 권한이 비활성화되어 있습니다.", 403)
    async with SessionLocal() as db:
        account = await db.scalar(select(GameAccount).where(GameAccount.supporter_id == supporter.id, GameAccount.active.is_(True)).order_by(GameAccount.id.desc()))
        if not account:
            return JSONResponse({"account": None})
        try:
            username, password = account_decrypt(account.username_enc), account_decrypt(account.password_enc)
        except Exception:
            return json_error("계정 보안키 설정을 확인하세요.", 500)
        return JSONResponse({"account": {"username": username, "password": password}})

async def api_support_macro(request: Request):
    supporter = await current_supporter(request)
    if not supporter:
        return json_error("supporter unauthorized", 401)
    if not supporter.macro_enabled:
        return json_error("매크로 권한이 비활성화되어 있습니다.", 403)
    async with SessionLocal() as db:
        config = await db.get(MacroConfig, supporter.id)
        if not config:
            return JSONResponse({"macro": {"steps": [], "repeat_count": 10, "interval_ms": 1000}})
        return JSONResponse({"macro": {"steps": config.steps, "repeat_count": config.repeat_count, "interval_ms": config.interval_ms}})

async def api_support_macro_save(request: Request):
    supporter = await current_supporter(request)
    if not supporter:
        return json_error("supporter unauthorized", 401)
    if not supporter.macro_enabled:
        return json_error("매크로 권한이 비활성화되어 있습니다.", 403)
    if not csrf_ok(request) or not same_origin(request):
        return json_error("invalid request", 403)
    try:
        data = await request.json()
        raw_steps = data.get("steps") or []
        if not isinstance(raw_steps, list) or len(raw_steps) > 100:
            raise ValueError
        steps = []
        for raw in raw_steps:
            if not isinstance(raw, dict):
                raise ValueError
            selector = clean_text(str(raw.get("selector") or ""), 500)
            delay = max(100, min(60000, int(raw.get("delay") or 1000)))
            steps.append({"selector": selector, "delay": delay})
        repeat_count = max(1, min(10000, int(data.get("repeat_count") or 10)))
        interval_ms = max(100, min(60000, int(data.get("interval_ms") or 1000)))
    except Exception:
        return json_error("매크로 설정을 확인하세요.")
    async with SessionLocal() as db:
        config = await db.get(MacroConfig, supporter.id)
        if config:
            config.steps, config.repeat_count, config.interval_ms = steps, repeat_count, interval_ms
            config.updated_at = datetime.now(timezone.utc)
        else:
            db.add(MacroConfig(supporter_id=supporter.id, steps=steps, repeat_count=repeat_count, interval_ms=interval_ms))
        await db.commit()
    return JSONResponse({"ok": True})

async def api_support_logout(request: Request):
    if not csrf_ok(request) or not same_origin(request):
        return json_error("invalid request", 403)
    response = JSONResponse({"ok": True})
    response.delete_cookie(SUPPORT_COOKIE)
    return response

async def api_admin_supporters(request: Request):
    if not await require_staff(request, admin_only=True):
        return json_error("forbidden", 403)
    async with SessionLocal() as db:
        rows = (await db.execute(select(Supporter).order_by(Supporter.id.desc()))).scalars().all()
        accounts = (await db.execute(select(GameAccount))).scalars().all()
        assigned = {a.supporter_id for a in accounts if a.active and a.supporter_id is not None}
        return JSONResponse({"supporters": [{"id": s.id, "label": s.label, "macro_enabled": s.macro_enabled, "active": s.active, "has_account": s.id in assigned, "created_at": s.created_at.isoformat()} for s in rows]})

async def api_admin_supporter_create(request: Request):
    if not csrf_ok(request) or not same_origin(request) or not await require_staff(request, admin_only=True):
        return json_error("forbidden", 403)
    try:
        data = await request.json()
        label = clean_text(str(data.get("label") or "지원자"), 64)
    except Exception:
        return json_error("지원자 이름을 확인하세요.")
    code = new_support_code()
    async with SessionLocal() as db:
        db.add(Supporter(code_hash=support_hash(code), label=label))
        await db.commit()
    return JSONResponse({"ok": True, "code": code}, status_code=201)

async def api_admin_game_account_create(request: Request):
    if not csrf_ok(request) or not same_origin(request) or not await require_staff(request, admin_only=True):
        return json_error("forbidden", 403)
    try:
        data = await request.json()
        supporter_id = int(data.get("supporter_id"))
        username = clean_text(str(data.get("username") or ""), 256)
        password = str(data.get("password") or "")
        if not password or len(username) > 256 or len(password) > 512:
            raise ValueError
        account_encrypt(username)
        account_encrypt(password)
    except Exception:
        return json_error("계정 정보 또는 GAME_ACCOUNT_KEY를 확인하세요.")
    async with SessionLocal() as db:
        supporter = await db.get(Supporter, supporter_id)
        if not supporter or not supporter.active:
            return json_error("지원자를 찾을 수 없습니다.", 404)
        old = (await db.execute(select(GameAccount).where(GameAccount.supporter_id == supporter.id, GameAccount.active.is_(True)))).scalars().all()
        for account in old:
            account.active = False
        db.add(GameAccount(supporter_id=supporter.id, username_enc=account_encrypt(username), password_enc=account_encrypt(password)))
        await db.commit()
    return JSONResponse({"ok": True}, status_code=201)

async def api_admin_supporter_toggle(request: Request):
    if not csrf_ok(request) or not same_origin(request) or not await require_staff(request, admin_only=True):
        return json_error("forbidden", 403)
    try:
        supporter_id = int(request.path_params["supporter_id"])
        active = bool((await request.json()).get("active"))
    except Exception:
        return json_error("상태를 확인하세요.")
    async with SessionLocal() as db:
        supporter = await db.get(Supporter, supporter_id)
        if not supporter:
            return json_error("지원자를 찾을 수 없습니다.", 404)
        supporter.active = active
        await db.commit()
    return JSONResponse({"ok": True})

class MacroConfig(Base):
    __tablename__ = "macro_configs"
    supporter_id: Mapped[int] = mapped_column(ForeignKey("supporters.id", ondelete="CASCADE"), primary_key=True)
    steps: Mapped[list] = mapped_column(JSON, default=list)
    repeat_count: Mapped[int] = mapped_column(Integer, default=10)
    interval_ms: Mapped[int] = mapped_column(Integer, default=1000)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class StaffSession(Base):
    __tablename__ = "staff_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    staff_id: Mapped[int] = mapped_column(ForeignKey("staff.id", ondelete="CASCADE"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

async def startup():
    configured_hash = ADMIN_PASSWORD_HASH or hash_password(ADMIN_PASSWORD)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        def migrate(sync_conn):
            from sqlalchemy import inspect, text
            columns = {c["name"] for c in inspect(sync_conn).get_columns("posts")}
            if "category" not in columns:
                sync_conn.execute(text("ALTER TABLE posts ADD COLUMN category VARCHAR(16) DEFAULT '자유게시판'"))
        await conn.run_sync(migrate)
    async with SessionLocal() as db:
        staff = await db.scalar(select(Staff).where(Staff.username == ADMIN_USERNAME))
        if not staff:
            db.add(Staff(username=ADMIN_USERNAME, password_hash=configured_hash, role="admin"))
            await db.commit()
        elif staff.role != "admin" or not staff.active:
            staff.role, staff.active = "admin", True
            await db.commit()

def json_error(message: str, status: int = 400):
    return JSONResponse({"error": message}, status_code=status)

def client_key(request: Request, prefix: str) -> str:
    return prefix + ":" + (request.client.host if request.client else "unknown")

def rate_limited(key: str, limit: int) -> bool:
    now = datetime.now(timezone.utc).timestamp()
    hits = [t for t in _rate.get(key, []) if now - t < RATE_WINDOW]
    if len(hits) >= limit:
        _rate[key] = hits
        return True
    hits.append(now)
    _rate[key] = hits
    if len(_rate) > 5000:
        for k, v in list(_rate.items()):
            if not v or now - v[-1] >= RATE_WINDOW:
                _rate.pop(k, None)
    return False

def clean_text(value: str, limit: int) -> str:
    value = (value or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not value or len(value) > limit or "\x00" in value:
        raise ValueError("invalid text")
    return value

def valid_nickname(value: str) -> str:
    value = clean_text(value, 24)
    if not NAME_RE.fullmatch(value):
        raise ValueError("invalid nickname")
    return value

def get_guest_id(request: Request):
    value = request.cookies.get(GUEST_COOKIE)
    if value and re.fullmatch(r"[a-f0-9]{64}", value):
        return value, False
    return secrets.token_hex(32), True

def csrf_ok(request: Request) -> bool:
    token = request.headers.get("x-csrf-token", "")
    cookie = request.cookies.get(CSRF_COOKIE, "")
    return bool(token and cookie and secrets.compare_digest(token, cookie))

def same_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    return not origin or origin == f"{request.url.scheme}://{request.url.netloc}"

def staff_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return "scrypt$16384$8$1$" + base64.urlsafe_b64encode(salt).decode() + "$" + base64.urlsafe_b64encode(digest).decode()

def verify_password(password: str, stored: str) -> bool:
    try:
        kind, n, r, p, salt_b64, digest_b64 = stored.split("$")
        if kind != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(salt_b64)
        expected = base64.urlsafe_b64decode(digest_b64)
        actual = hashlib.scrypt(password.encode(), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected))
        return secrets.compare_digest(actual, expected)
    except Exception:
        return False

async def current_identity(request: Request):
    guest_id, new_guest = get_guest_id(request)
    nickname = request.cookies.get("cat_hero_nick") or f"손님{guest_id[:4]}"
    return guest_id, nickname, new_guest

async def current_staff(request: Request):
    token = request.cookies.get(STAFF_COOKIE)
    if not token:
        return None
    async with SessionLocal() as db:
        session = await db.scalar(select(StaffSession).where(StaffSession.token_hash == staff_token_hash(token)))
        if not session or session.expires_at <= datetime.now(timezone.utc):
            return None
        staff = await db.get(Staff, session.staff_id)
        return staff if staff and staff.active else None

async def require_staff(request: Request, admin_only=False):
    staff = await current_staff(request)
    return staff if staff and (not admin_only or staff.role == "admin") else None

async def api_session(request: Request):
    guest_id, nickname, new_guest = await current_identity(request)
    csrf = request.cookies.get(CSRF_COOKIE) or secrets.token_hex(32)
    staff = await current_staff(request)
    response = JSONResponse({"nickname": nickname, "guest": True, "staff": bool(staff), "role": staff.role if staff else None})
    if new_guest:
        response.set_cookie(GUEST_COOKIE, guest_id, max_age=60*60*24*180, httponly=True, samesite="lax", secure=request.url.scheme == "https")
    response.set_cookie(CSRF_COOKIE, csrf, max_age=60*60*24*180, httponly=False, samesite="lax", secure=request.url.scheme == "https")
    return response

async def api_set_nickname(request: Request):
    if not csrf_ok(request) or not same_origin(request):
        return json_error("invalid request", 403)
    try:
        nickname = valid_nickname(str((await request.json()).get("nickname", "")))
    except Exception:
        return json_error("닉네임은 1~24자로 입력하세요.")
    response = JSONResponse({"nickname": nickname})
    response.set_cookie("cat_hero_nick", nickname, max_age=60*60*24*180, httponly=True, samesite="lax", secure=request.url.scheme == "https")
    return response

async def save_image(upload):
    if not upload or not getattr(upload, "filename", None):
        return None
    if not (upload.content_type or "").startswith("image/"):
        raise ValueError("image only")
    data = await upload.read(MAX_IMAGE_BYTES + 1)
    if len(data) > MAX_IMAGE_BYTES:
        raise ValueError("image too large")
    try:
        import io
        image = Image.open(io.BytesIO(data))
        image.verify()
        image = Image.open(io.BytesIO(data))
        if image.format not in ALLOWED_IMAGE_TYPES:
            raise ValueError("unsupported image")
        image.load()
    except (UnidentifiedImageError, OSError):
        raise ValueError("invalid image")
    if image.width > 2560 or image.height > 2560:
        image.thumbnail((2560, 2560))
    image = image.convert("RGB")
    name = f"{uuid.uuid4().hex}.jpg"
    image.save(UPLOAD_DIR / name, "JPEG", quality=88, optimize=True)
    return name

def post_dict(post: Post):
    return {"id": post.id, "nickname": post.nickname, "title": post.title, "category": post.category, "body": post.body,
            "image": f"/uploads/{post.image_name}" if post.image_name else None,
            "views": post.views, "created_at": post.created_at.isoformat()}

async def api_posts(request: Request):
    category = request.query_params.get("category", "전체")
    async with SessionLocal() as db:
        query = select(Post).order_by(Post.id.desc()).limit(100)
        count_query = select(func.count(Post.id))
        if category in CATEGORIES:
            query = select(Post).where(Post.category == category).order_by(Post.id.desc()).limit(100)
            count_query = select(func.count(Post.id)).where(Post.category == category)
        total = await db.scalar(count_query)
        rows = (await db.execute(query)).scalars().all()
        return JSONResponse({"posts": [post_dict(p) for p in rows], "total": total or 0})

async def api_post(request: Request):
    async with SessionLocal() as db:
        post = await db.get(Post, int(request.path_params["post_id"]))
        if not post:
            return json_error("게시글을 찾을 수 없습니다.", 404)
        post.views += 1
        await db.commit()
        comments = (await db.execute(select(Comment).where(Comment.post_id == post.id).order_by(Comment.id.asc()))).scalars().all()
        data = post_dict(post)
        data["comments"] = [{"id": c.id, "nickname": c.nickname, "body": c.body, "created_at": c.created_at.isoformat()} for c in comments]
        return JSONResponse(data)

async def api_create_post(request: Request):
    if rate_limited(client_key(request, "post"), WRITE_LIMIT):
        return json_error("요청이 너무 많습니다. 잠시 후 다시 시도하세요.", 429)
    if not csrf_ok(request) or not same_origin(request):
        return json_error("invalid request", 403)
    try:
        form = await request.form()
        category = clean_text(str(form.get("category") or "자유게시판"), 16)
        if category not in CATEGORIES:
            return json_error("올바른 게시판을 선택하세요.")
        title = clean_text(str(form.get("title") or ""), MAX_TITLE)
        body = clean_text(str(form.get("body") or ""), MAX_BODY)
        image = await save_image(form.get("image"))
    except ValueError as e:
        return json_error(str(e))
    except Exception:
        return json_error("게시글을 처리하지 못했습니다.", 400)
    guest_id, nickname, _ = await current_identity(request)
    async with SessionLocal() as db:
        post = Post(guest_id=guest_id, nickname=nickname, title=title, category=category, body=body, image_name=image)
        db.add(post)
        await db.commit()
        await db.refresh(post)
        return JSONResponse(post_dict(post), status_code=201)

async def api_create_comment(request: Request):
    if rate_limited(client_key(request, "comment"), WRITE_LIMIT):
        return json_error("요청이 너무 많습니다. 잠시 후 다시 시도하세요.", 429)
    if not csrf_ok(request) or not same_origin(request):
        return json_error("invalid request", 403)
    try:
        post_id = int(request.path_params["post_id"])
        body = clean_text(str((await request.json()).get("body") or ""), MAX_COMMENT)
    except Exception:
        return json_error("댓글 입력을 확인하세요.")
    guest_id, nickname, _ = await current_identity(request)
    async with SessionLocal() as db:
        if not await db.get(Post, post_id):
            return json_error("게시글을 찾을 수 없습니다.", 404)
        comment = Comment(post_id=post_id, guest_id=guest_id, nickname=nickname, body=body)
        db.add(comment)
        await db.commit()
        await db.refresh(comment)
        return JSONResponse({"id": comment.id, "nickname": comment.nickname, "body": comment.body, "created_at": comment.created_at.isoformat()}, status_code=201)

async def api_admin_login(request: Request):
    if rate_limited(client_key(request, "login"), LOGIN_LIMIT):
        return json_error("로그인 시도가 너무 많습니다. 잠시 후 다시 시도하세요.", 429)
    try:
        data = await request.json()
        username = clean_text(str(data.get("username") or ""), 64)
        password = str(data.get("password") or "")
    except Exception:
        return json_error("로그인 정보를 확인하세요.", 401)
    async with SessionLocal() as db:
        staff = await db.scalar(select(Staff).where(Staff.username == username, Staff.active.is_(True)))
        if not staff or not verify_password(password, staff.password_hash):
            return json_error("아이디 또는 비밀번호가 올바르지 않습니다.", 401)
        token = secrets.token_urlsafe(48)
        db.add(StaffSession(token_hash=staff_token_hash(token), staff_id=staff.id, expires_at=datetime.now(timezone.utc) + timedelta(seconds=SESSION_MAX_AGE)))
        await db.commit()
    response = JSONResponse({"ok": True, "role": staff.role})
    response.set_cookie(STAFF_COOKIE, token, max_age=SESSION_MAX_AGE, httponly=True, samesite="lax", secure=request.url.scheme == "https")
    return response

async def api_admin_logout(request: Request):
    if not csrf_ok(request) or not same_origin(request):
        return json_error("invalid request", 403)
    token = request.cookies.get(STAFF_COOKIE)
    if token:
        async with SessionLocal() as db:
            session = await db.scalar(select(StaffSession).where(StaffSession.token_hash == staff_token_hash(token)))
            if session:
                await db.delete(session)
                await db.commit()
    response = JSONResponse({"ok": True})
    response.delete_cookie(STAFF_COOKIE)
    return response

async def api_admin_me(request: Request):
    staff = await require_staff(request)
    if not staff:
        return json_error("unauthorized", 401)
    return JSONResponse({"username": staff.username, "role": staff.role})

async def api_staff_list(request: Request):
    if not await require_staff(request, admin_only=True):
        return json_error("forbidden", 403)
    async with SessionLocal() as db:
        rows = (await db.execute(select(Staff).order_by(Staff.id.asc()))).scalars().all()
        return JSONResponse({"staff": [{"id": s.id, "username": s.username, "role": s.role, "active": s.active} for s in rows]})

async def api_staff_create(request: Request):
    if not csrf_ok(request) or not same_origin(request) or not await require_staff(request, admin_only=True):
        return json_error("forbidden", 403)
    try:
        data = await request.json()
        username = clean_text(str(data.get("username") or ""), 64)
        password = str(data.get("password") or "")
        role = str(data.get("role") or "operator")
        if not re.fullmatch(r"[A-Za-z0-9가-힣_.-]{2,64}", username) or len(password) < 10 or role not in {"operator", "admin"}:
            raise ValueError
    except Exception:
        return json_error("계정은 올바른 이름과 10자 이상 비밀번호가 필요합니다.")
    async with SessionLocal() as db:
        if await db.scalar(select(Staff).where(Staff.username == username)):
            return json_error("이미 존재하는 운영 계정입니다.", 409)
        db.add(Staff(username=username, password_hash=hash_password(password), role=role))
        await db.commit()
    return JSONResponse({"ok": True}, status_code=201)

async def api_staff_role(request: Request):
    if not csrf_ok(request) or not same_origin(request) or not await require_staff(request, admin_only=True):
        return json_error("forbidden", 403)
    try:
        staff_id = int(request.path_params["staff_id"])
        role = str((await request.json()).get("role") or "")
        if role not in {"operator", "admin"}:
            raise ValueError
    except Exception:
        return json_error("역할을 확인하세요.")
    async with SessionLocal() as db:
        staff = await db.get(Staff, staff_id)
        if not staff:
            return json_error("계정을 찾을 수 없습니다.", 404)
        if staff.username == ADMIN_USERNAME:
            return json_error("기본 관리자 계정의 역할은 변경할 수 없습니다.", 403)
        staff.role = role
        await db.commit()
    return JSONResponse({"ok": True})

async def api_admin_posts(request: Request):
    if not await require_staff(request):
        return json_error("unauthorized", 401)
    async with SessionLocal() as db:
        rows = (await db.execute(select(Post).order_by(Post.id.desc()).limit(100))).scalars().all()
        return JSONResponse({"posts": [post_dict(p) for p in rows]})

async def api_admin_delete_comment(request: Request):
    if not csrf_ok(request) or not same_origin(request) or not await require_staff(request):
        return json_error("forbidden", 403)
    async with SessionLocal() as db:
        comment = await db.get(Comment, int(request.path_params["comment_id"]))
        if not comment:
            return json_error("댓글을 찾을 수 없습니다.", 404)
        await db.delete(comment)
        await db.commit()
    return JSONResponse({"ok": True})

async def api_admin_delete_post(request: Request):
    if not csrf_ok(request) or not same_origin(request) or not await require_staff(request):
        return json_error("forbidden", 403)
    async with SessionLocal() as db:
        post = await db.get(Post, int(request.path_params["post_id"]))
        if not post:
            return json_error("게시글을 찾을 수 없습니다.", 404)
        if post.image_name:
            (UPLOAD_DIR / post.image_name).unlink(missing_ok=True)
        await db.delete(post)
        await db.commit()
    return JSONResponse({"ok": True})

async def health(request: Request):
    return PlainTextResponse("ok")

async def homepage(request: Request):
    return FileResponse(STATIC_DIR / "index.html")

routes = [
    Route("/", homepage),
    Route("/healthz", health),
    Route("/api/session", api_session),
    Route("/api/support/login", api_support_login, methods=["POST"]),
    Route("/api/support/logout", api_support_logout, methods=["POST"]),
    Route("/api/support/me", api_support_me),
    Route("/api/support/account", api_support_account),
    Route("/api/support/macro", api_support_macro),
    Route("/api/support/macro", api_support_macro_save, methods=["POST"]),
    Route("/api/nickname", api_set_nickname, methods=["POST"]),
    Route("/api/posts", api_posts),
    Route("/api/posts", api_create_post, methods=["POST"]),
    Route("/api/posts/{post_id:int}", api_post),
    Route("/api/posts/{post_id:int}/comments", api_create_comment, methods=["POST"]),
    Route("/api/admin/login", api_admin_login, methods=["POST"]),
    Route("/api/admin/logout", api_admin_logout, methods=["POST"]),
    Route("/api/admin/me", api_admin_me),
    Route("/api/admin/staff", api_staff_list),
    Route("/api/admin/supporters", api_admin_supporters),
    Route("/api/admin/supporters", api_admin_supporter_create, methods=["POST"]),
    Route("/api/admin/supporters/{supporter_id:int}", api_admin_supporter_toggle, methods=["POST"]),
    Route("/api/admin/game-accounts", api_admin_game_account_create, methods=["POST"]),
    Route("/api/admin/staff", api_staff_create, methods=["POST"]),
    Route("/api/admin/staff/{staff_id:int}/role", api_staff_role, methods=["POST"]),
    Route("/api/admin/posts", api_admin_posts),
    Route("/api/admin/posts/{post_id:int}", api_admin_delete_post, methods=["DELETE"]),
    Route("/api/admin/comments/{comment_id:int}", api_admin_delete_comment, methods=["DELETE"]),
    Mount("/assets", app=StaticFiles(directory=STATIC_DIR / "assets"), name="assets"),
    Mount("/uploads", app=StaticFiles(directory=UPLOAD_DIR), name="uploads"),
]
web_app = Starlette(routes=routes, on_startup=[startup])
