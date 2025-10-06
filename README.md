# CartillaIA - Auth POC

## Breve descripción
Proyecto de prueba de concepto (POC) para la autenticación y emisión de tokens JWT ("CartillaIA") que actúa como intermediario entre proveedores OIDC (Azure AD) y un frontend.

## Características principales
- Registro dinámico de clientes OIDC (Azure) usando variables de entorno para varios "os_key" (por ejemplo `medife`, `osde`).
- Endpoints para iniciar login, recibir callback de OIDC, refrescar tokens y obtener información del usuario a partir de un JWT propio.
- Almacenamiento local sencillo de refresh tokens en SQLite (POC) usando SQLAlchemy.

## Requisitos
- Python 3.11+
- pip (se recomienda usar el virtualenv incluido en `cartilla/` o crear uno nuevo)

## Instalación rápida (Windows / PowerShell)
```powershell
# Usando el virtualenv provisto (si existe)
& .\cartilla\Scripts\python.exe -m pip install -r requirements.txt

# O crear un virtualenv y activar
python -m venv .venv
& .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Variables de entorno importantes
El servidor lee varias variables de entorno. Para un entorno de desarrollo local puedes usar un archivo `.env` en la raíz del proyecto.

- `FRONTEND_BASE`: URL base del frontend (por defecto `http://localhost:3000`).
- `FRONTEND_ORIGIN`: Origen permitidos para CORS (si se quiere restringir explícitamente). Si no está presente se usa `FRONTEND_BASE`.
- `CARTILLAIA_SECRET`: Clave usada para firmar los JWTs emitidos por este servicio.
- `JWT_EXP_MINUTES`: Tiempo de expiración (en minutos) para los JWT locales (por defecto `15`).
- `DATABASE_URL`: URL de la base de datos SQLAlchemy (por defecto `sqlite:///./tokens.db`).


Para cada `os_key` (valores por defecto: `medife`, `osde`) se esperan las siguientes variables para registrar clientes OIDC:
- `<OS>_TENANT_ID` (por ejemplo `MEDIFE_TENANT_ID`)
- `<OS>_CLIENT_ID`
- `<OS>_CLIENT_SECRET`
- `<OS>_REDIRECT_URI` (URL de callback que deberás configurar en Azure)
- `<OS>_ADMIN_GROUP_ID`: Identificador del grupo de administración en el proveedor OIDC para cada `os_key`. Si se configura, el campo `groups` del `id_token` será consultado para marcar al usuario como administrador dentro del token CartillaIA.

Ejemplo mínimo en `.env` (desarrollo):
```
FRONTEND_BASE=http://localhost:3000
CARTILLAIA_SECRET=cartillaia-secret-for-dev
JWT_EXP_MINUTES=15
DATABASE_URL=sqlite:///./tokens.db

MEDIFE_TENANT_ID=<your-tenant-id>
MEDIFE_CLIENT_ID=<your-client-id>
MEDIFE_CLIENT_SECRET=<your-client-secret>
MEDIFE_REDIRECT_URI=http://localhost:8000/auth/callback/medife
MEDIFE_ADMIN_GROUP_ID=<your-admin-group-id>

OSDE_TENANT_ID=...
OSDE_CLIENT_ID=...
OSDE_CLIENT_SECRET=...
OSDE_REDIRECT_URI=http://localhost:8000/auth/callback/osde
OSDE_ADMIN_GROUP_ID=<your-admin-group-id>
```

## Cómo ejecutar (desarrollo)
Se recomienda ejecutar con uvicorn desde el virtualenv:
```powershell
# PowerShell
& .\cartilla\Scripts\python.exe -m uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Si usas un virtualenv diferente activa y ejecuta
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## Endpoints principales
- `GET /login/{os_key}`
  - Inicia el flujo OIDC para el `os_key` especificado. Redirige al proveedor OIDC para autenticación.

- `GET /auth/callback/{os_key}`
  - Callback que recibe el código OIDC. Intercambia el código por tokens (id/refresh). Guarda el refresh token (SQLite) y redirige al frontend con un token JWT propio (query param `token`).

- `POST /refresh`
  - Refresca el token de CartillaIA usando el refresh token almacenado. Requiere el token CartillaIA (Bearer) en la cabecera `Authorization`.
  - Devuelve JSON con el nuevo token CartillaIA: `{ "token": "..." }`

- `GET /me`
  - Devuelve el payload del token CartillaIA enviado en `Authorization: Bearer <token>`.

- `GET /healthcheck`
  - Verifica la conectividad a la DB y devuelve estatus y timestamp.

## Notas de seguridad importantes
- En este POC los `id_token` se decodifican sin verificar la firma (opción `verify_signature=False`) — Esto es inseguro para producción. En un entorno real debes validar la firma del id_token y la metadata del proveedor OIDC.
- Usa un `CARTILLAIA_SECRET` fuerte y mantenlo fuera del repositorio (ej. en vault o secretos de despliegue).
- El almacenamiento de refresh tokens en SQLite está pensado sólo para demostración. Para producción usa un almacén seguro (DB gestionada, cifrado, etc.).

## Desarrollo y mantenimiento
- El código principal está en `main.py`.
- Se usa `sqlalchemy` para el modelo `RefreshTokenEntry` en `refresh_tokens`.
- Para linters/formateo se usó `ruff` (pudieras instalarlo en tu entorno de desarrollo).

## Contribuciones
PRs y issues son bienvenidos. Para cambios mayores sugiero abrir un issue con la propuesta.

## Licencia
Revisar el archivo `LICENSE` en el repositorio.

## Contacto
Para dudas técnicas, abrir un issue o contactar al mantenedor del repositorio.
