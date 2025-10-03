import os
import datetime
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from authlib.integrations.starlette_client import OAuth, OAuthError
import jwt  # PyJWT
import secrets

from sqlalchemy import create_engine, Column, String, Integer, DateTime, select
from sqlalchemy.orm import sessionmaker, declarative_base

from dotenv import load_dotenv
import logging

load_dotenv()  # carga .env en local (Render usa env vars del panel)

# Configurar el logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

def register_oidc_clients():
    """
    Registra clientes OIDC en authlib a partir de env vars:
      - {OS}_TENANT_ID
      - {OS}_CLIENT_ID
      - {OS}_CLIENT_SECRET
      - {OS}_REDIRECT_URI
    """
    for key in OS_KEYS:
        prefix = key.upper()
        tenant = os.getenv(f"{prefix}_TENANT_ID")
        client_id = os.getenv(f"{prefix}_CLIENT_ID")
        client_secret = os.getenv(f"{prefix}_CLIENT_SECRET")
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
    now = datetime.datetime.now(datetime.timezone.utc)
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
# storage temporal de states (en producción usar Redis o DB)
STATE_STORE = {}

@app.get("/login/{os_key}")
async def login(request: Request, os_key: str):
    client = oauth.create_client(f"azure_{os_key}")
    if client is None:
        raise HTTPException(status_code=500, detail=f"OIDC client not configured for {os_key}")

    redirect_uri = os.getenv(f"{os_key.upper()}_REDIRECT_URI")
    if not redirect_uri:
        raise HTTPException(status_code=500, detail=f"{os_key.upper()}_REDIRECT_URI not set")

    # generar state aleatorio
    state = secrets.token_urlsafe(32)
    STATE_STORE[state] = {"os_key": os_key}

    logger.info(f"[{os_key}] Iniciando login con state={state}, redirect_uri={redirect_uri}")

    return await client.authorize_redirect(
        request,
        redirect_uri,
        state=state
    )

@app.get("/auth/callback/{os_key}")
async def auth_callback(request: Request, os_key: str):
    client = oauth.create_client(f"azure_{os_key}")
    if client is None:
        raise HTTPException(status_code=500, detail=f"OIDC client not configured for {os_key}")

    # obtener y validar state
    state = request.query_params.get("state")
    if not state or state not in STATE_STORE:
        raise HTTPException(status_code=400, detail="invalid_or_missing_state")

    try:
        token = await client.authorize_access_token(request, state=state)
    except OAuthError as err:
        logger.error(f"OAuth error for {os_key}: {err.error}")
        raise HTTPException(status_code=400, detail=f"oauth_error: {err.error}")

    # limpiar state
    del STATE_STORE[state]

    # procesar userinfo
    try:
        userinfo = token.get("userinfo") or await client.parse_id_token(request, token)
    except Exception:
        userinfo = {}

    sub = userinfo.get("sub") or userinfo.get("oid")
    email = userinfo.get("email") or userinfo.get("preferred_username")
    name = userinfo.get("name")

    if not sub:
        raise HTTPException(status_code=400, detail="invalid_user_info")

    cart_jwt = create_cartillaia_jwt(sub=sub, email=email, name=name, os_key=os_key)
    redirect_to = f"{os.getenv('FRONTEND_BASE')}/dashboard?token={cart_jwt}"

    logger.info(f"[{os_key}] Usuario autenticado: {email}, redirigiendo al frontend.")
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
    return {"status": "ok"}

@app.get("/healthcheck")
async def healthcheck():
    try:
        # Verificar conexión a la base de datos
        with engine.connect() as connection:
            from sqlalchemy.sql import text
            connection.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    return {
        "status": "ok",
        "db_status": db_status,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }
