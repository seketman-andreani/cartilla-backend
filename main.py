import os
import datetime
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from authlib.integrations.starlette_client import OAuth, OAuthError
import jwt  # PyJWT
from sqlalchemy import create_engine, Column, String, Integer, DateTime, select
from sqlalchemy.orm import sessionmaker, declarative_base
from starlette.middleware.sessions import SessionMiddleware

from dotenv import load_dotenv

load_dotenv()  # carga .env en local (Render usa env vars del panel)

# ---------- Config ----------
PORT = int(os.getenv("PORT", "10000"))
FRONTEND_BASE = os.getenv("FRONTEND_BASE", "http://localhost:3000")
CARTILLAIA_SECRET = os.getenv("CARTILLAIA_SECRET", "cartillaia-secret-for-dev")
JWT_EXP_MINUTES = int(os.getenv("JWT_EXP_MINUTES", "15"))

# Obras sociales: cada bloque debe estar configurado en variables de entorno
# MEDIFE_* and OSDE_*
OS_KEYS = ["medife", "osde"]

# ---------- DB (SQLite simple para POC) ----------
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./tokens.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

class RefreshTokenEntry(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    sub = Column(String, index=True)           # unique user id from IdP
    os_key = Column(String, index=True)        # medife or osde
    refresh_token = Column(String)
    expires_at = Column(DateTime, nullable=True)  # optional

Base.metadata.create_all(bind=engine)

# ---------- OAuth Client setup ----------
oauth = OAuth()
app = FastAPI(title="CartillaIA Auth POC")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_ORIGIN", FRONTEND_BASE)],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Clave secreta para firmar cookies de sesión
app.add_middleware(
    SessionMiddleware, 
    secret_key=os.getenv("CARTILLAIA_SECRET", "session-secret-for-dev")
)

def register_oidc_clients():
    """
    Registra clientes OIDC en authlib a partir de env vars:
      - {OS}_TENANT_ID
      - {OS}_CLIENT_ID
      - {OS}_CLIENT_SECRET
      - {OS}_REDIRECT_URI  (opcional, se usará la ruta /auth/callback/{os_key})
    """
    for key in OS_KEYS:
        prefix = key.upper()
        tenant = os.getenv(f"{prefix}_TENANT_ID")
        client_id = os.getenv(f"{prefix}_CLIENT_ID")
        client_secret = os.getenv(f"{prefix}_CLIENT_SECRET")
        redirect = os.getenv(f"{prefix}_REDIRECT_URI",
                              f"https://{os.getenv('RENDER_EXTERNAL_URL','localhost')}:/auth/callback/{key}")
        if not (tenant and client_id and client_secret):
            # no raise: permite deploy aunque falten vars (pero login fallará)
            continue
        name = f"azure_{key}"
        server_metadata_url = f"https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"
        oauth.register(
            name=name,
            client_id=client_id,
            client_secret=client_secret,
            server_metadata_url=server_metadata_url,
            client_kwargs={"scope": "openid profile email offline_access"},
        )

@app.on_event("startup")
async def startup_event():
    register_oidc_clients()

# ---------- Helpers ----------
def create_cartillaia_jwt(sub: str, email: Optional[str], name: Optional[str], os_key: str):
    now = datetime.datetime.utcnow()
    payload = {
        "sub": sub,
        "email": email,
        "name": name,
        "os_key": os_key,
        "iss": "CartillaIA",
        "iat": now,
        "exp": now + datetime.timedelta(minutes=JWT_EXP_MINUTES)
    }
    token = jwt.encode(payload, CARTILLAIA_SECRET, algorithm="HS256")
    # PyJWT returns str in modern versions
    if isinstance(token, bytes):
        token = token.decode()
    return token

def decode_cartillaia_jwt(token: str):
    try:
        return jwt.decode(token, CARTILLAIA_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="cartillaia_token_expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid_cartillaia_token")

def db_get_refresh(sub: str, os_key: str):
    db = SessionLocal()
    try:
        q = db.query(RefreshTokenEntry).filter_by(sub=sub, os_key=os_key).first()
        return q
    finally:
        db.close()

def db_upsert_refresh(sub: str, os_key: str, refresh_token: str, expires_at: Optional[datetime.datetime]=None):
    db = SessionLocal()
    try:
        entry = db.query(RefreshTokenEntry).filter_by(sub=sub, os_key=os_key).first()
        if entry:
            entry.refresh_token = refresh_token
            entry.expires_at = expires_at
        else:
            entry = RefreshTokenEntry(sub=sub, os_key=os_key, refresh_token=refresh_token, expires_at=expires_at)
            db.add(entry)
        db.commit()
    finally:
        db.close()

# ---------- Routes ----------
@app.get("/login/{os_key}")
async def login(request: Request, os_key: str):
    if os_key not in OS_KEYS:
        raise HTTPException(status_code=404, detail="unknown_os")
    client_name = f"azure_{os_key}"
    client = oauth.create_client(client_name)
    if client is None:
        raise HTTPException(status_code=500, detail=f"oidc_client_not_configured_for_{os_key}")
    redirect_uri = os.getenv(f"{os_key.upper()}_REDIRECT_URI",
                             f"{request.url.scheme}://{request.url.hostname}/auth/callback/{os_key}")
    return await client.authorize_redirect(request, redirect_uri)

@app.get("/auth/callback/{os_key}")
async def auth_callback(request: Request, os_key: str):
    if os_key not in OS_KEYS:
        raise HTTPException(status_code=404, detail="unknown_os")
    client_name = f"azure_{os_key}"
    client = oauth.create_client(client_name)
    if client is None:
        raise HTTPException(status_code=500, detail=f"oidc_client_not_configured_for_{os_key}")
    try:
        token = await client.authorize_access_token(request)
    except OAuthError as err:
        raise HTTPException(status_code=400, detail=f"oauth_error: {err.error}")
    # token is a dict with access_token, id_token, refresh_token (if offline_access), expires_in...
    # parse id_token to get user info
    try:
        userinfo = token.get("userinfo") or await client.parse_id_token(request, token)
    except Exception:
        userinfo = {}
    sub = userinfo.get("sub") or userinfo.get("oid") or userinfo.get("preferred_username")
    email = userinfo.get("email") or userinfo.get("preferred_username")
    name = userinfo.get("name")

    # Guardar refresh_token en DB (si viene)
    refresh_token = token.get("refresh_token")
    expires_at = None
    if token.get("expires_in"):
        expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=int(token["expires_in"]))
    if refresh_token and sub:
        db_upsert_refresh(sub=sub, os_key=os_key, refresh_token=refresh_token, expires_at=expires_at)

    # Generar JWT CartillaIA y redirigir al frontend con token en query string (POC)
    cart_jwt = create_cartillaia_jwt(sub=sub, email=email, name=name, os_key=os_key)
    redirect_to = f"{os.getenv('FRONTEND_BASE', FRONTEND_BASE)}/dashboard?token={cart_jwt}"
    return RedirectResponse(url=redirect_to)

@app.get("/me")
async def me(request: Request):
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing_token")
    token = auth.split(" ", 1)[1]
    payload = decode_cartillaia_jwt(token)
    return JSONResponse(content=payload)

@app.post("/refresh")
async def refresh(request: Request):
    """
    Refresca el JWT CartillaIA usando el refresh_token guardado.
    El frontend debe enviar Authorization: Bearer <cartillaia_jwt_expired_or_not>
    Este endpoint decodifica el cartillaia JWT para obtener sub + os_key.
    """
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing_token")
    token = auth.split(" ", 1)[1]
    # We should decode WITHOUT validating exp, so we can allow expired CartillaIA token to request refresh.
    try:
        payload = jwt.decode(token, CARTILLAIA_SECRET, algorithms=["HS256"], options={"verify_exp": False})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid_cartillaia_token")

    sub = payload.get("sub")
    os_key = payload.get("os_key")
    if not sub or not os_key:
        raise HTTPException(status_code=400, detail="invalid_token_payload")

    entry = db_get_refresh(sub=sub, os_key=os_key)
    if not entry or not entry.refresh_token:
        raise HTTPException(status_code=401, detail="no_refresh_token_stored")

    # get token endpoint from client's metadata
    client_name = f"azure_{os_key}"
    client = oauth.create_client(client_name)
    if client is None:
        raise HTTPException(status_code=500, detail=f"oidc_client_not_configured_for_{os_key}")

    # token_endpoint is in client's server_metadata
    token_endpoint = client.client_kwargs.get("token_endpoint")
    # but authlib stores metadata in client.server_metadata if available
    if not token_endpoint:
        md = client.server_metadata or {}
        token_endpoint = md.get("token_endpoint")
    if not token_endpoint:
        # fallback for azure pattern
        tenant = os.getenv(f"{os_key.upper()}_TENANT_ID")
        token_endpoint = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"

    try:
        new_token = await client.refresh_token(token_endpoint, refresh_token=entry.refresh_token)
    except Exception as e:
        # refresh failed -> remove stored refresh to force full re-login
        db_upsert_refresh(sub=sub, os_key=os_key, refresh_token="", expires_at=None)
        raise HTTPException(status_code=400, detail=f"refresh_failed: {str(e)}")

    # update stored refresh_token if rotated
    new_refresh = new_token.get("refresh_token")
    if new_refresh:
        db_upsert_refresh(sub=sub, os_key=os_key, refresh_token=new_refresh,
                          expires_at=(datetime.datetime.utcnow() + datetime.timedelta(seconds=int(new_token.get("expires_in", 3600))) if new_token.get("expires_in") else None))

    # parse id_token for userinfo (if present)
    try:
        userinfo = await client.parse_id_token(request, new_token)
    except Exception:
        userinfo = {}

    new_cart_jwt = create_cartillaia_jwt(sub=sub, email=userinfo.get("email"), name=userinfo.get("name"), os_key=os_key)
    return {"token": new_cart_jwt}

@app.get("/")
async def root():
    return {"status": "ok!"}
