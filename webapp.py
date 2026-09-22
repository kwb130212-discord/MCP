import os
import re
import secrets
import uuid
import hashlib
import base64
from datetime import datetime, timezone, timedelta
from pathlib import Path

import httpx
from PIL import Image, UnidentifiedImageError
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Boolean, JSON, select, func
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

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_PUBLISHABLE_KEY = os.environ.get("SUPABASE_PUBLISHABLE_KEY", "")

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

if not SUPABASE_URL or not SUPABASE_PUBLISHABLE_KEY:
    raise RuntimeError("SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY are required")
if not ADMIN_PASSWORD_HASH and not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD_HASH or ADMIN_PASSWORD is required")

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
            username = account_decrypt(account.username_enc)
        except Exception:
            return json_error("계정 보안키 설정을 확인하세요.", 500)
        return JSONResponse({"account": {"username": username, "password_configured": True}})

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
    if not await require_staff(request):
        return json_error("forbidden", 403)
    async with SessionLocal() as db:
        rows = (await db.execute(select(Supporter).order_by(Supporter.id.desc()))).scalars().all()
        accounts = (await db.execute(select(GameAccount))).scalars().all()
        assigned = {a.supporter_id for a in accounts if a.active and a.supporter_id is not None}
        return JSONResponse({"supporters": [{"id": s.id, "label": s.label, "macro_enabled": s.macro_enabled, "active": s.active, "has_account": s.id in assigned, "created_at": s.created_at.isoformat()} for s in rows]})

async def api_admin_supporter_create(request: Request):
    if not csrf_ok(request) or not same_origin(request) or not await require_staff(request):
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
    if not csrf_ok(request) or not same_origin(request) or not await require_staff(request):
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

class _RestResult:
    def __init__(self, rows): self._rows = rows or []
    def scalars(self): return self
    def all(self): return self._rows
    def first(self): return self._rows[0] if self._rows else None

class _RestSession:
    def __init__(self): self.pending=[]; self.deleted=[]; self.loaded={}
    async def __aenter__(self): return self
    async def __aexit__(self, *args): await self.close()
    async def close(self): pass
    def add(self, obj): self.pending.append(obj)
    async def delete(self, obj): self.deleted.append(obj)
    async def get(self, model, ident):
        rows=await _rest_select(model, [(model.__table__.primary_key.columns.values()[0].name, "eq", ident)], limit=1)
        obj=_model_obj(model, rows[0]) if rows else None
        if obj: self.loaded[(model,obj.id)]=obj
        return obj
    async def scalar(self, query):
        result=await self.execute(query)
        return result.first()
    async def execute(self, query): return _RestResult(await _rest_query(query))
    async def refresh(self, obj):
        pk=list(obj.__table__.primary_key.columns)[0].name
        rows=await _rest_select(type(obj), [(pk, "eq", getattr(obj,pk))], limit=1)
        if rows:
            fresh=_model_obj(type(obj), rows[0])
            for col in obj.__table__.columns: setattr(obj,col.name,getattr(fresh,col.name,None))
    async def commit(self):
        for obj in self.pending:
            data=_model_data(obj)
            rows=await _rest_insert(type(obj),data)
            if rows:
                fresh=_model_obj(type(obj),rows[0])
                for col in obj.__table__.columns: setattr(obj,col.name,getattr(fresh,col.name,None))
        self.pending.clear()
        for obj in self.loaded.values():
            original=getattr(obj,"_rest_original",{})
            changes={k:getattr(obj,k) for k in original if getattr(obj,k,None)!=original[k]}
            if changes:
                pk=list(obj.__table__.primary_key.columns)[0].name
                await _rest_update(type(obj),changes,[(pk,"eq",getattr(obj,pk))])
                obj._rest_original=_model_data(obj)
        self.loaded.clear()
        for obj in self.deleted:
            pk=list(obj.__table__.primary_key.columns)[0].name
            await _rest_delete(type(obj),[(pk,"eq",getattr(obj,pk))])
        self.deleted.clear()

class _SessionFactory:
    def __call__(self): return _RestSession()

SessionLocal=_SessionFactory()
_rest_client=None

async def _rest_request(method, table, *, params=None, json=None):
    if _rest_client is None: raise RuntimeError("Supabase REST client is not initialized")
    response=await _rest_client.request(method, f"/{table}", params=params, json=json, headers={"Prefer":"return=representation"})
    response.raise_for_status()
    if not response.content: return []
    data=response.json()
    return data if isinstance(data,list) else [data]

def _field_value(v):
    if hasattr(v,"value"): return v.value
    if hasattr(v,"literal_execute") and hasattr(v,"value"): return v.value
    return v

def _parse_filter(expr):
    if getattr(expr,"operator",None) is None: return []
    op=expr.operator; field=getattr(expr.left,"name",None); right=_field_value(expr.right)
    from sqlalchemy.sql import operators
    mapping={operators.eq:"eq",operators.ne:"neq",operators.gt:"gt",operators.ge:"gte",operators.lt:"lt",operators.le:"lte",operators.is_:"is",operators.is_not:"not.is_",operators.in_op:"in"}
    if field is None or op not in mapping: return []
    return [(field,mapping[op],right)]

def _model_class(query):
    for d in query.column_descriptions:
        if d.get("entity") is not None and hasattr(d["entity"],"__tablename__"): return d["entity"]
    return None

def _model_obj(model,row):
    obj=model()
    for col in model.__table__.columns:
        value=row.get(col.name)
        if value is not None and isinstance(col.type, DateTime) and isinstance(value,str):
            try: value=datetime.fromisoformat(value.replace("Z","+00:00"))
            except ValueError: pass
        setattr(obj,col.name,value)
    obj._rest_original=_model_data(obj)
    return obj

def _model_data(obj):
    return {col.name:getattr(obj,col.name,None) for col in type(obj).__table__.columns if getattr(obj,col.name,None) is not None}

def _postgrest_params(query):
    params=[]
    for expr in query._where_criteria:
        for field,op,value in _parse_filter(expr):
            if op=="in": value="("+",".join(str(x) for x in value)+")"
            params.append((field, f"{op}.{str(value).lower() if isinstance(value,bool) else value}"))
    for clause in query._order_by_clauses:
        element=getattr(clause,"element",clause); name=getattr(element,"name",None)
        if name: params.append(("order",name+".desc" if getattr(clause,"modifier",None).__name__=="desc_op" else name+".asc"))
    if query._limit_clause is not None:
        try: params.append(("limit",str(query._limit_clause.value)))
        except Exception: pass
    return params

async def _rest_select(model, filters=(), limit=None, order=None):
    params=[("select","*")]
    for field,op,value in filters:
        if op=="in": value="("+",".join(str(x) for x in value)+")"
        params.append((field,f"{op}.{str(value).lower() if isinstance(value,bool) else value}"))
    if order: params.append(("order",order[0]+(".desc" if order[1] else ".asc")))
    if limit: params.append(("limit",str(limit)))
    rows=await _rest_request("GET",model.__tablename__,params=params)
    return rows

async def _rest_query(query):
    expr=query.column_descriptions[0].get("expr") if query.column_descriptions else None
    if hasattr(expr, "name") and expr.name == "count":
        model=query.column_descriptions[0]["entity"]
        rows=await _rest_select(model,_postgrest_filters(query))
        return [len(rows)]
    model=_model_class(query)
    if model is None:
        raise RuntimeError("Unsupported Supabase query")
    rows=await _rest_select(model,_postgrest_filters(query),_query_limit(query),_query_order(query))
    return [_model_obj(model,row) for row in rows]

def _postgrest_filters(query):
    out=[]
    for expr in query._where_criteria: out.extend(_parse_filter(expr))
    return out

def _query_limit(query):
    try: return int(query._limit_clause.value) if query._limit_clause is not None else None
    except Exception: return None

def _query_order(query):
    for clause in query._order_by_clauses:
        element=getattr(clause,"element",clause); name=getattr(element,"name",None)
        if name: return (name,getattr(clause,"modifier",None).__name__=="desc_op")
    return None

async def _rest_insert(model,data): return await _rest_request("POST",model.__tablename__,json=data)
async def _rest_update(model,data,filters):
    params=[]
    for field,op,value in filters: params.append((field,f"{op}.{str(value).lower() if isinstance(value,bool) else value}"))
    return await _rest_request("PATCH",model.__tablename__,params=params,json=data)
async def _rest_delete(model,filters):
    params=[]
    for field,op,value in filters: params.append((field,f"{op}.{value}"))
    return await _rest_request("DELETE",model.__tablename__,params=params)

async def startup():
    global _rest_client
    _rest_client=httpx.AsyncClient(base_url=SUPABASE_URL + "/rest/v1", headers={"apikey":SUPABASE_PUBLISHABLE_KEY,"Authorization":"Bearer "+SUPABASE_PUBLISHABLE_KEY}, timeout=20.0)
    configured_hash=ADMIN_PASSWORD_HASH or hash_password(ADMIN_PASSWORD)
    async with SessionLocal() as db:
        staff=await db.scalar(select(Staff).where(Staff.username==ADMIN_USERNAME))
        if not staff:
            db.add(Staff(username=ADMIN_USERNAME,password_hash=configured_hash,role="admin",active=True)); await db.commit(); return
        changed=False
        if staff.role!="admin" or not staff.active: staff.role,staff.active="admin",True; changed=True
        if ADMIN_PASSWORD_HASH and not secrets.compare_digest(staff.password_hash,ADMIN_PASSWORD_HASH): staff.password_hash=ADMIN_PASSWORD_HASH; changed=True
        elif ADMIN_PASSWORD and not ADMIN_PASSWORD_HASH and not verify_password(ADMIN_PASSWORD,staff.password_hash): staff.password_hash=hash_password(ADMIN_PASSWORD); changed=True
        if changed: await db.commit()

