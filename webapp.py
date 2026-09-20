import os
import re
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image, UnidentifiedImageError
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, select, func
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, FileResponse, PlainTextResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "web"
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", str(BASE_DIR / "uploads")))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///./board.db")
MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_TITLE = 120
MAX_BODY = 10000
MAX_COMMENT = 2000
NAME_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,24}$")
ALLOWED_IMAGE_TYPES = {"JPEG", "PNG", "WEBP"}
GUEST_COOKIE = "cat_hero_guest"
CSRF_COOKIE = "cat_hero_csrf"

engine = create_async_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

class Post(Base):
    __tablename__ = "posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    guest_id: Mapped[str] = mapped_column(String(64), index=True)
    nickname: Mapped[str] = mapped_column(String(24))
    title: Mapped[str] = mapped_column(String(MAX_TITLE))
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

async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

def json_error(message: str, status: int = 400):
    return JSONResponse({"error": message}, status_code=status)

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

async def current_identity(request: Request):
    guest_id, new_guest = get_guest_id(request)
    nickname = request.cookies.get("cat_hero_nick") or f"손님{guest_id[:4]}"
    return guest_id, nickname, new_guest

async def api_session(request: Request):
    guest_id, nickname, new_guest = await current_identity(request)
    csrf = request.cookies.get(CSRF_COOKIE) or secrets.token_hex(32)
    response = JSONResponse({"nickname": nickname, "guest": True})
    if new_guest:
        response.set_cookie(GUEST_COOKIE, guest_id, max_age=60*60*24*180, httponly=True, samesite="lax", secure=request.url.scheme == "https")
    response.set_cookie(CSRF_COOKIE, csrf, max_age=60*60*24*180, httponly=False, samesite="lax", secure=request.url.scheme == "https")
    return response

async def api_set_nickname(request: Request):
    if not csrf_ok(request) or not same_origin(request):
        return json_error("invalid request", 403)
    try:
        data = await request.json()
        nickname = valid_nickname(str(data.get("nickname", "")))
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
    return {"id": post.id, "nickname": post.nickname, "title": post.title, "body": post.body,
            "image": f"/uploads/{post.image_name}" if post.image_name else None,
            "views": post.views, "created_at": post.created_at.isoformat()}

async def api_posts(request: Request):
    async with SessionLocal() as db:
        total = await db.scalar(select(func.count(Post.id)))
        rows = (await db.execute(select(Post).order_by(Post.id.desc()).limit(100))).scalars().all()
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
    if not csrf_ok(request) or not same_origin(request):
        return json_error("invalid request", 403)
    try:
        form = await request.form()
        nickname = valid_nickname(str(form.get("nickname") or ""))
        title = clean_text(str(form.get("title") or ""), MAX_TITLE)
        body = clean_text(str(form.get("body") or ""), MAX_BODY)
        image = await save_image(form.get("image"))
    except ValueError as e:
        return json_error(str(e))
    except Exception:
        return json_error("게시글을 처리하지 못했습니다.", 400)
    guest_id, _, _ = await current_identity(request)
    async with SessionLocal() as db:
        post = Post(guest_id=guest_id, nickname=nickname, title=title, body=body, image_name=image)
        db.add(post)
        await db.commit()
        await db.refresh(post)
        return JSONResponse(post_dict(post), status_code=201)

async def api_create_comment(request: Request):
    if not csrf_ok(request) or not same_origin(request):
        return json_error("invalid request", 403)
    try:
        post_id = int(request.path_params["post_id"])
        data = await request.json()
        nickname = valid_nickname(str(data.get("nickname") or ""))
        body = clean_text(str(data.get("body") or ""), MAX_COMMENT)
    except Exception:
        return json_error("댓글 입력을 확인하세요.")
    guest_id, _, _ = await current_identity(request)
    async with SessionLocal() as db:
        if not await db.get(Post, post_id):
            return json_error("게시글을 찾을 수 없습니다.", 404)
        comment = Comment(post_id=post_id, guest_id=guest_id, nickname=nickname, body=body)
        db.add(comment)
        await db.commit()
        await db.refresh(comment)
        return JSONResponse({"id": comment.id, "nickname": comment.nickname, "body": comment.body, "created_at": comment.created_at.isoformat()}, status_code=201)

async def health(request: Request):
    return PlainTextResponse("ok")

async def homepage(request: Request):
    return FileResponse(STATIC_DIR / "index.html")

routes = [
    Route("/", homepage),
    Route("/healthz", health),
    Route("/api/session", api_session),
    Route("/api/nickname", api_set_nickname, methods=["POST"]),
    Route("/api/posts", api_posts),
    Route("/api/posts", api_create_post, methods=["POST"]),
    Route("/api/posts/{post_id:int}", api_post),
    Route("/api/posts/{post_id:int}/comments", api_create_comment, methods=["POST"]),
    Mount("/assets", app=StaticFiles(directory=STATIC_DIR / "assets"), name="assets"),
    Mount("/uploads", app=StaticFiles(directory=UPLOAD_DIR), name="uploads"),
]
web_app = Starlette(routes=routes, on_startup=[startup])
