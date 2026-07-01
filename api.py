"""
api.py — Katrix ERP REST API
FastAPI + JWT. Admin: CRUD completo. Agente: solo lectura.
Arrancar con: uvicorn api:app --host 0.0.0.0 --port 8000
"""
import os, sys
venv_site = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".venv", "lib", "python3.13", "site-packages"))
if venv_site not in sys.path:
    sys.path.append(venv_site)
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, status, Query, Request, Response
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
try:
    from jose import JWTError, jwt
except ImportError:
    import jwt
    from jwt import PyJWTError as JWTError
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ssn_test as db
from api_models import *
import katrix_biometrics

# ─── Pydantic Models para Panel y Biometría ──────────────────────────────────
class PanelLoginRequest(BaseModel):
    username: str
    password: str

class PanelChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str
    new_username: Optional[str] = None

class BiometricRegisterRequest(BaseModel):
    username: str
    credential_id: str
    public_key_der: str
    dispositivo_nombre: str
    challenge_token: str

class BiometricLoginRequest(BaseModel):
    credential_id: str
    signature: str
    authenticator_data: str
    client_data_json: str
    challenge_token: str

class PanelUserCreate(BaseModel):
    username: str
    password: str
    role: str
    permissions: dict

class PanelUserUpdate(BaseModel):
    password: Optional[str] = None
    role: Optional[str] = None
    permissions: Optional[dict] = None

class PanelUserResponse(BaseModel):
    username: str
    role: str
    permissions: dict

# ─── Config ──────────────────────────────────────────────────────────────────
SECRET_KEY  = os.getenv("KATRIX_SECRET_KEY", "cambia-esta-clave-en-produccion-2026")
ALGORITHM   = "HS256"
TOKEN_EXPIRE_HOURS = int(os.getenv("TOKEN_EXPIRE_HOURS", "24"))

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    db.inicializar_db()
    yield

# ─── App ─────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Katrix ERP API",
    description="API REST para productores asesores de seguros. Admin: CRUD completo. Agente: solo lectura.",
    version="1.0.0",
    contact={"name": "Katrix ERP", "email": "admin@katrix.com"},
    license_info={"name": "Privado"},
    lifespan=lifespan,
)

# CORS — ajustá los orígenes a tu dominio real en producción
ALLOWED_ORIGINS = os.getenv(
    "KATRIX_CORS_ORIGINS",
    "http://localhost,http://localhost:3000,http://localhost:8080"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# ─── Panel Sessions tracking in memory ────────────────────────────────────────
PANEL_SESSIONS = {}
REVOKED_SESSIONS = set()

# ─── JWT Helpers ─────────────────────────────────────────────────────────────

def create_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(request: Request, token: str = Depends(oauth2_scheme)) -> TokenData:
    cred_err = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token inválido o expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        username: str = payload.get("username")
        role: str = payload.get("role")
        matricula: str = payload.get("matricula")
        if user_id is None or username is None:
            raise cred_err
            
        # Validar y registrar sesión si es usuario del panel de licencias
        if role in ["panel_admin", "panel_superadmin", "admin"]:
            if username in REVOKED_SESSIONS:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Tu sesión ha sido revocada por un administrador.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Registrar/actualizar la actividad en línea
            client_host = request.client.host if request.client else "Desconocida"
            user_agent = request.headers.get("user-agent", "Desconocido")
            PANEL_SESSIONS[username] = {
                "username": username,
                "role": role,
                "ip": client_host,
                "user_agent": user_agent,
                "last_active": datetime.utcnow().isoformat(),
                "status": "online"
            }
            
        return TokenData(user_id=user_id, username=username, role=role, matricula=matricula)
    except JWTError:
        raise cred_err


def require_admin(current: TokenData = Depends(get_current_user)) -> TokenData:
    if current.role not in ["admin", "panel_superadmin", "panel_admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requiere rol de administrador para realizar esta acción",
        )
    return current


def require_licencias_admin(current: TokenData = Depends(get_current_user)) -> TokenData:
    if current.role not in ["admin", "panel_admin", "panel_superadmin"]:
        raise HTTPException(status_code=403, detail="Se requiere rol de administrador de licencias o administrador general")
    if current.role in ["panel_admin", "panel_superadmin"]:
        user = db.obtener_panel_user(current.username)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuario de panel inexistente o eliminado",
                headers={"WWW-Authenticate": "Bearer"},
            )
    return current


def check_panel_permission(username: str, role: str, permission: str):
    if role == "admin":
        return True  # El admin general del CRM siempre tiene todos los permisos
    
    user = db.obtener_panel_user(username)
    if not user:
        raise HTTPException(status_code=401, detail="Usuario de panel inexistente")
    
    if user["role"] == "superadmin":
        return True  # El superadmin de panel tiene todos los permisos
        
    import json
    try:
        perms = json.loads(user["permissions"])
    except Exception:
        perms = {}
        
    if not perms.get(permission, False):
        raise HTTPException(
            status_code=403,
            detail=f"No tenés permiso para realizar esta acción: {permission}"
        )
    return True


# ─── AUTH ────────────────────────────────────────────────────────────────────

@app.post("/auth/login", response_model=Token, tags=["Auth"])
@limiter.limit("5/minute")
def login(request: Request, body: LoginRequest):
    success, requiere_cambio, error_msg, rol, user_id = db.verificar_login_status(
        body.username, body.password
    )
    if not success:
        raise HTTPException(status_code=401, detail=error_msg or "Usuario o contraseña incorrectos")

    # Obtener datos del usuario para el token
    usuarios = db.obtener_usuarios()
    user = next((u for u in usuarios if u.get("email") == body.username or u.get("usuario") == body.username), None)
    
    token = create_token({
        "user_id":  user_id,
        "username": user.get("usuario") or user.get("email"),
        "role":     rol,
        "matricula": user.get("matricula_asociada"),
    })

    db.registrar_log(body.username, "API_LOGIN", "Login desde API REST")

    return Token(
        access_token=token,
        token_type="bearer",
        role=rol,
        user_id=user_id,
        username=user.get("usuario") or user.get("email"),
    )


@app.get("/auth/me", response_model=PerfilResponse, tags=["Auth"])
def get_me(current: TokenData = Depends(get_current_user)):
    """Retorna el perfil del usuario autenticado."""
    return PerfilResponse(
        user_id=current.user_id,
        username=current.username,
        email="",
        role=current.role,
        matricula=current.matricula,
    )


@app.post("/auth/forgot-password", response_model=MessageResponse, tags=["Auth"])
@limiter.limit("3/minute")
def forgot_password(request: Request, body: ForgotPasswordRequest):
    """Solicita la recuperación de contraseña enviando un link por email."""
    email_clean = body.email.strip().lower()
    usuarios = db.obtener_usuarios()
    user = next((u for u in usuarios if (u.get("email") or "").lower() == email_clean or (u.get("usuario") or "").lower() == email_clean), None)
    
    if not user:
        raise HTTPException(status_code=404, detail="Usuario o correo electrónico no registrado")
    
    user_email = user.get("email")
    if not user_email:
        raise HTTPException(status_code=400, detail="El usuario no tiene una dirección de correo configurada")
        
    # Crear token JWT de recuperación temporal (expira en 1 hora)
    token_exp = datetime.utcnow() + timedelta(hours=1)
    payload = {
        "sub": "reset_password",
        "email": user_email,
        "username": user.get("usuario"),
        "exp": token_exp
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    
    # Generar URL de restablecimiento
    base_url = str(request.base_url).rstrip('/')
    reset_url = f"{base_url}/auth/reset-password?token={token}"
    
    # Enviar correo en segundo plano
    import threading
    def send_recovery():
        db.enviar_mail_recuperacion_link(user_email, reset_url)
    threading.Thread(target=send_recovery, daemon=True).start()
    
    db.registrar_log(user.get("usuario") or user_email, "PASSWORD_RESET_REQUESTED", f"Enlace enviado a {user_email}")
    
    return MessageResponse(ok=True, message="Enlace de recuperación enviado con éxito")


@app.get("/auth/reset-password", tags=["Auth"])
def get_reset_password(token: str):
    """Sirve la vista HTML premium para restablecer la contraseña."""
    from fastapi.responses import HTMLResponse
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") != "reset_password":
            raise HTTPException(status_code=400, detail="Token no válido para restablecer contraseña")
    except JWTError:
        raise HTTPException(status_code=400, detail="El token es inválido o ha expirado")
        
    html_content = f"""
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Restablecer Contraseña — Katrix CRM</title>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-gradient: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      --card-bg: rgba(30, 41, 59, 0.7);
      --card-border: rgba(255, 255, 255, 0.08);
      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --success: #10b981;
      --error: #ef4444;
      --text: #f8fafc;
      --text-muted: #94a3b8;
    }}
    
    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }}
    
    body {{
      font-family: 'Outfit', sans-serif;
      background: var(--bg-gradient);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }}
    
    .container {{
      width: 100%;
      max-width: 440px;
      background: var(--card-bg);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--card-border);
      border-radius: 20px;
      padding: 40px 30px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
      text-align: center;
      position: relative;
      overflow: hidden;
    }}
    
    .container::before {{
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 4px;
      background: linear-gradient(90deg, #3b82f6, #6366f1);
    }}
    
    .logo {{
      font-size: 28px;
      font-weight: 700;
      letter-spacing: 1px;
      background: linear-gradient(to right, #3b82f6, #818cf8);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 8px;
    }}
    
    .subtitle {{
      font-size: 14px;
      color: var(--text-muted);
      margin-bottom: 30px;
      text-transform: uppercase;
      letter-spacing: 1.5px;
    }}
    
    .title {{
      font-size: 20px;
      font-weight: 600;
      margin-bottom: 24px;
    }}
    
    .form-group {{
      text-align: left;
      margin-bottom: 20px;
    }}
    
    label {{
      display: block;
      font-size: 12px;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 8px;
      letter-spacing: 1px;
      text-transform: uppercase;
    }}
    
    input {{
      width: 100%;
      background: rgba(15, 23, 42, 0.6);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 14px 16px;
      color: var(--text);
      font-family: inherit;
      font-size: 15px;
      transition: all 0.3s ease;
    }}
    
    input:focus {{
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15);
    }}
    
    button {{
      width: 100%;
      background: linear-gradient(135deg, var(--primary) 0%, #4f46e5 100%);
      border: none;
      border-radius: 10px;
      padding: 15px;
      color: white;
      font-family: inherit;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s ease;
      box-shadow: 0 4px 12px rgba(79, 70, 229, 0.3);
      margin-top: 10px;
      display: flex;
      justify-content: center;
      align-items: center;
      gap: 10px;
    }}
    
    button:hover {{
      transform: translateY(-2px);
      box-shadow: 0 6px 16px rgba(79, 70, 229, 0.4);
    }}
    
    button:active {{
      transform: translateY(0);
    }}
    
    button:disabled {{
      background: #475569;
      cursor: not-allowed;
      transform: none;
      box-shadow: none;
    }}
    
    .spinner {{
      width: 20px;
      height: 20px;
      border: 2px solid rgba(255, 255, 255, 0.3);
      border-radius: 50%;
      border-top-color: white;
      animation: spin 0.8s linear infinite;
      display: none;
    }}
    
    @keyframes spin {{
      to {{ transform: rotate(360deg); }}
    }}
    
    .alert {{
      padding: 14px;
      border-radius: 10px;
      font-size: 14px;
      margin-bottom: 24px;
      display: none;
      text-align: left;
      line-height: 1.5;
    }}
    
    .alert-error {{
      background: rgba(239, 68, 68, 0.15);
      border: 1px solid rgba(239, 68, 68, 0.3);
      color: #fca5a5;
    }}
    
    .alert-success {{
      background: rgba(16, 185, 129, 0.15);
      border: 1px solid rgba(16, 185, 129, 0.3);
      color: #a7f3d0;
    }}
    
    .success-icon {{
      width: 60px;
      height: 60px;
      background: rgba(16, 185, 129, 0.1);
      border: 2px solid var(--success);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 24px auto;
      color: var(--success);
      font-size: 32px;
      animation: scaleUp 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) forwards;
    }}
    
    @keyframes scaleUp {{
      from {{ transform: scale(0); }}
      to {{ transform: scale(1); }}
    }}
  </style>
</head>
<body>
  <div class="container" id="card">
    <div class="logo">KATRIX</div>
    <div class="subtitle">Sistema de Gestión</div>
    
    <div id="form-view">
      <div class="title">Establecer Nueva Contraseña</div>
      
      <div class="alert alert-error" id="error-box"></div>
      
      <form id="reset-form">
        <input type="hidden" id="token-input" value="{token}">
        
        <div class="form-group">
          <label for="password">Nueva Contraseña</label>
          <input type="password" id="password" required minlength="6" placeholder="Mínimo 6 caracteres">
        </div>
        
        <div class="form-group">
          <label for="confirm-password">Confirmar Contraseña</label>
          <input type="password" id="confirm-password" required minlength="6" placeholder="Repite la contraseña">
        </div>
        
        <button type="submit" id="submit-btn">
          <span class="spinner" id="btn-spinner"></span>
          <span id="btn-text">Cambiar Contraseña</span>
        </button>
      </form>
    </div>
    
    <div id="success-view" style="display: none;">
      <div class="success-icon">✓</div>
      <div class="title" style="margin-bottom: 12px;">¡Contraseña Cambiada!</div>
      <p style="color: var(--text-muted); font-size: 15px; margin-bottom: 24px; line-height: 1.6;">
        Tu contraseña ha sido actualizada con éxito. Ya puedes regresar a la aplicación de Katrix y acceder con tus nuevas credenciales.
      </p>
    </div>
  </div>

  <script>
    const form = document.getElementById('reset-form');
    const password = document.getElementById('password');
    const confirmPassword = document.getElementById('confirm-password');
    const submitBtn = document.getElementById('submit-btn');
    const btnSpinner = document.getElementById('btn-spinner');
    const btnText = document.getElementById('btn-text');
    const errorBox = document.getElementById('error-box');
    const formView = document.getElementById('form-view');
    const successView = document.getElementById('success-view');
    
    form.addEventListener('submit', async (e) => {{
      e.preventDefault();
      
      errorBox.style.display = 'none';
      
      if (password.value !== confirmPassword.value) {{
        errorBox.textContent = 'Las contraseñas no coinciden.';
        errorBox.style.display = 'block';
        return;
      }}
      
      if (password.value.length < 6) {{
        errorBox.textContent = 'La contraseña debe tener al menos 6 caracteres.';
        errorBox.style.display = 'block';
        return;
      }}
      
      // Bloquear botón y mostrar spinner
      submitBtn.disabled = true;
      btnSpinner.style.display = 'inline-block';
      btnText.textContent = 'Procesando...';
      
      try {{
        const token = document.getElementById('token-input').value;
        const response = await fetch('/auth/reset-password', {{
          method: 'POST',
          headers: {{
            'Content-Type': 'application/json',
          }},
          body: JSON.stringify({{
            token: token,
            password: password.value
          }})
        }});
        
        const result = await response.json();
        
        if (response.ok) {{
          formView.style.display = 'none';
          successView.style.display = 'block';
        }} else {{
          errorBox.textContent = result.detail || 'Ocurrió un error al procesar tu solicitud.';
          errorBox.style.display = 'block';
          submitBtn.disabled = false;
          btnSpinner.style.display = 'none';
          btnText.textContent = 'Cambiar Contraseña';
        }}
      }} catch (err) {{
        errorBox.textContent = 'Error de conexión con el servidor.';
        errorBox.style.display = 'block';
        submitBtn.disabled = false;
        btnSpinner.style.display = 'none';
        btnText.textContent = 'Cambiar Contraseña';
      }}
    }});
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html_content, status_code=200)


@app.post("/auth/reset-password", response_model=MessageResponse, tags=["Auth"])
def post_reset_password(body: ResetPasswordRequest):
    """Procesa el formulario web de restablecimiento de contraseña."""
    try:
        payload = jwt.decode(body.token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") != "reset_password":
            raise HTTPException(status_code=400, detail="Token no válido para restablecer contraseña")
        user_email = payload.get("email")
    except JWTError:
        raise HTTPException(status_code=400, detail="El enlace de recuperación es inválido o ha expirado")
        
    if not user_email:
        raise HTTPException(status_code=400, detail="Token inválido: falta información de usuario")
        
    # Buscar el usuario para obtener su identificador principal
    usuarios = db.obtener_usuarios()
    user = next((u for u in usuarios if (u.get("email") or "").lower() == user_email.lower()), None)
    
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
    # Usar el nombre de usuario principal para actualizar la contraseña
    username_key = user.get("usuario") or user_email
    
    success = db.actualizar_password(username_key, body.password)
    if not success:
        raise HTTPException(status_code=500, detail="No se pudo actualizar la contraseña en el sistema")
        
    db.registrar_log(username_key, "PASSWORD_RESET_SUCCESS", "Contraseña restablecida a través de enlace de correo")
    
    return MessageResponse(ok=True, message="Contraseña actualizada exitosamente")


# ─── PAS ─────────────────────────────────────────────────────────────────────

@app.get("/pas/", response_model=PaginatedPAS, tags=["Productores PAS"])
def list_pas(
    q: Optional[str] = Query(None, description="Búsqueda por nombre, matrícula o CUIT"),
    provincia: Optional[str] = None,
    ramo: Optional[str] = None,
    estado_contacto: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current: TokenData = Depends(get_current_user),
):
    """
    Lista PAS filtrable. Admin ve todos; agente solo ve su propio registro.
    """
    records = db.obtener_todos_db(user_id=current.user_id, role=current.role) or []

    # Si es agente, solo ve su propio perfil
    if current.role != "admin" and current.matricula:
        records = [r for r in records if r.get("productor_matricula") == current.matricula]

    # Filtros
    if q:
        ql = q.strip().lower()
        records = [r for r in records if
                   ql in (r.get("productor_apellido_nombre") or "").lower() or
                   ql in (r.get("productor_matricula") or "").lower() or
                   ql in (r.get("productor_id") or "").lower()]
    if provincia:
        records = [r for r in records if
                   (r.get("provincia") or "").upper() == provincia.upper()]
    if ramo:
        records = [r for r in records if
                   (r.get("ramo") or "").lower() == ramo.lower()]
    if estado_contacto:
        records = [r for r in records if
                   (r.get("estado_contacto") or "Sin contactar").lower() == estado_contacto.lower()]

    total = len(records)
    start = (page - 1) * page_size
    page_records = records[start:start + page_size]

    items = [PASListItem(
        matricula=r.get("productor_matricula"),
        nombre=r.get("productor_apellido_nombre"),
        ramo=r.get("ramo"),
        provincia=r.get("provincia"),
        localidad=r.get("localidad"),
        telefono=r.get("telefono"),
        email=r.get("email"),
        estado_contacto=r.get("estado_contacto", "Sin contactar"),
        companias=r.get("companias"),
    ) for r in page_records]

    return PaginatedPAS(total=total, page=page, page_size=page_size, items=items)


@app.get("/pas/{matricula}", response_model=PASResponse, tags=["Productores PAS"])
def get_pas(matricula: str, current: TokenData = Depends(get_current_user)):
    """Detalle completo de un PAS por matrícula."""
    # Agente solo puede ver su propio perfil
    if current.role != "admin" and current.matricula and current.matricula != matricula:
        raise HTTPException(status_code=403, detail="No tenés permiso para ver este productor")

    r = db.obtener_de_db(matricula, user_id=current.user_id, role=current.role)
    if not r:
        raise HTTPException(status_code=404, detail="PAS no encontrado")

    return PASResponse(
        matricula=r.get("matricula"),
        nombre=r.get("nombre"),
        ramo=r.get("ramo"),
        provincia=r.get("provincia"),
        localidad=r.get("localidad"),
        domicilio=r.get("domicilio"),
        cod_postal=r.get("cod_postal"),
        telefono=r.get("telefono"),
        email=r.get("email"),
        estado_contacto=r.get("estado_contacto", "Sin contactar"),
        observaciones=r.get("observaciones"),
        companias=r.get("companias"),
        resolucion=r.get("resolucion"),
        fecha_resolucion=r.get("fecha_resolucion"),
        documento=r.get("documento"),
        cuit=r.get("cuit"),
    )


@app.put("/pas/{matricula}/estado", response_model=MessageResponse, tags=["Productores PAS"])
def update_pas_estado(
    matricula: str,
    body: PASEstadoUpdate,
    current: TokenData = Depends(require_admin),
):
    """Actualizar estado de contacto de un PAS. Solo admin."""
    db.actualizar_estado_contacto(matricula, body.estado_contacto)
    db.registrar_log(current.username, "API_UPDATE_ESTADO", f"Mat {matricula} → {body.estado_contacto}")
    return MessageResponse(ok=True, message="Estado actualizado")


@app.put("/pas/{matricula}/observaciones", response_model=MessageResponse, tags=["Productores PAS"])
def update_pas_obs(
    matricula: str,
    body: PASObservacionesUpdate,
    current: TokenData = Depends(require_admin),
):
    """Actualizar observaciones de un PAS. Solo admin."""
    db.actualizar_observaciones(matricula, body.observaciones)
    db.registrar_log(current.username, "API_UPDATE_OBS", f"Mat {matricula}")
    return MessageResponse(ok=True, message="Observaciones actualizadas")


@app.put("/pas/{matricula}/companias", response_model=MessageResponse, tags=["Productores PAS"])
def update_pas_companias(
    matricula: str,
    body: PASCompaniasUpdate,
    current: TokenData = Depends(require_admin),
):
    """Actualizar las compañías habilitadas de un PAS. Solo admin."""
    db.actualizar_companias(matricula, body.companias)
    db.registrar_log(current.username, "API_UPDATE_COMPANIAS", f"Mat {matricula}")
    return MessageResponse(ok=True, message="Compañías actualizadas")


@app.get("/pas/buscar-ssn/{documento}", response_model=dict, tags=["Productores PAS"])
def buscar_en_ssn(
    documento: str,
    tipo_doc: str = Query("DNI", description="DNI | CUIT"),
    current: TokenData = Depends(require_admin),
):
    """
    Busca un productor directamente en el padrón público de la SSN.
    Solo admin. Usa el scraper interno (puede ser lento la primera vez).
    """
    import threading
    result_container = {}
    def run_search():
        try:
            html = db.buscar_en_ssn(documento, tipo_doc)
            parsed = db.parsear_resultado(html) if html else None
            result_container["data"] = parsed
            result_container["raw_html_len"] = len(html) if html else 0
        except Exception as e:
            result_container["error"] = str(e)

    t = threading.Thread(target=run_search)
    t.start()
    t.join(timeout=30)

    if "error" in result_container:
        raise HTTPException(status_code=502, detail=f"Error al consultar SSN: {result_container['error']}")
    if not result_container.get("data"):
        raise HTTPException(status_code=404, detail="Productor no encontrado en el padrón SSN")
    return result_container["data"]


@app.get("/pas/{matricula}/actividades", response_model=List[ActividadResponse], tags=["Productores PAS"])
def get_pas_actividades(matricula: str, current: TokenData = Depends(get_current_user)):
    """Historial de actividades comerciales de un PAS."""
    if current.role != "admin" and current.matricula and current.matricula != matricula:
        raise HTTPException(status_code=403, detail="Acceso denegado")
    r = db.obtener_de_db(matricula, user_id=current.user_id, role=current.role)
    nombre = r.get("nombre") if r else None
    acts = db.obtener_actividades_por_pas(nombre=nombre, matricula=matricula)
    return [ActividadResponse(**a) for a in acts]


@app.get("/pas/{matricula}/polizas", response_model=List[PolizaResponse], tags=["Productores PAS"])
def get_pas_polizas(matricula: str, current: TokenData = Depends(get_current_user)):
    """Pólizas vinculadas a un PAS."""
    if current.role != "admin" and current.matricula and current.matricula != matricula:
        raise HTTPException(status_code=403, detail="Acceso denegado")
    polizas = db.obtener_polizas(pas_matricula=matricula)
    return [PolizaResponse(**p) for p in polizas]


# ─── VISITAS ─────────────────────────────────────────────────────────────────

@app.get("/visitas/", response_model=List[VisitaResponse], tags=["Plan de Visitas"])
def list_visitas(
    mes: Optional[str] = Query(None, description="Formato YYYY-MM. Default: mes actual"),
    current: TokenData = Depends(get_current_user),
):
    """Lista visitas planificadas del mes."""
    visitas = db.obtener_visitas(mes=mes)
    return [VisitaResponse(**v) for v in visitas]


@app.post("/visitas/", response_model=MessageResponse, tags=["Plan de Visitas"])
def create_visita(body: VisitaCreate, current: TokenData = Depends(require_admin)):
    """Agregar un PAS al plan de visitas. Solo admin."""
    mes = body.mes or db.obtener_mes_actual()
    row_id = db.guardar_visita(
        mes=mes, matricula=body.matricula or "", nombre=body.nombre,
        estado="pendiente", productividad=body.productividad or "",
        estado_org=body.estado_org or "", campaña=body.campaña or "",
    )
    db.registrar_log(current.username, "API_CREATE_VISITA", f"PAS: {body.nombre}")
    return MessageResponse(ok=True, message=f"Visita creada con ID {row_id}")


@app.put("/visitas/{visita_id}", response_model=MessageResponse, tags=["Plan de Visitas"])
def update_visita(visita_id: int, body: VisitaUpdate, current: TokenData = Depends(require_admin)):
    """Actualizar estado de una visita. Solo admin."""
    ok = db.actualizar_visita(visita_id, body.estado,
                              body.productividad or "", body.estado_org or "", body.campaña or "")
    if not ok:
        raise HTTPException(status_code=404, detail="Visita no encontrada")
    return MessageResponse(ok=True, message="Visita actualizada")


@app.delete("/visitas/{visita_id}", response_model=MessageResponse, tags=["Plan de Visitas"])
def delete_visita(visita_id: int, current: TokenData = Depends(require_admin)):
    """Eliminar visita. Solo admin."""
    ok = db.eliminar_visita(visita_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Visita no encontrada")
    return MessageResponse(ok=True, message="Visita eliminada")


# ─── CANDIDATOS ──────────────────────────────────────────────────────────────

@app.get("/candidatos/", response_model=List[CandidatoResponse], tags=["Candidatos"])
def list_candidatos(
    mes: Optional[str] = None,
    current: TokenData = Depends(get_current_user),
):
    cands = db.obtener_candidatos(mes=mes)
    return [CandidatoResponse(**c) for c in cands]


@app.post("/candidatos/", response_model=MessageResponse, tags=["Candidatos"])
def create_candidato(body: CandidatoCreate, current: TokenData = Depends(require_admin)):
    mes = body.mes or db.obtener_mes_actual()
    row_id = db.guardar_candidato(
        mes=mes, nombre=body.nombre, matricula=body.matricula or "",
        tiene_cartera=body.tiene_cartera or 0, estado=body.estado or "candidato",
        notas=body.notas or "",
    )
    return MessageResponse(ok=True, message=f"Candidato creado con ID {row_id}")


@app.put("/candidatos/{cand_id}", response_model=MessageResponse, tags=["Candidatos"])
def update_candidato(cand_id: int, body: CandidatoUpdate, current: TokenData = Depends(require_admin)):
    ok = db.actualizar_candidato(cand_id, body.estado, body.notas or "", body.tiene_cartera or 0)
    if not ok:
        raise HTTPException(status_code=404, detail="Candidato no encontrado")
    return MessageResponse(ok=True, message="Candidato actualizado")


@app.delete("/candidatos/{cand_id}", response_model=MessageResponse, tags=["Candidatos"])
def delete_candidato(cand_id: int, current: TokenData = Depends(require_admin)):
    ok = db.eliminar_candidato(cand_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Candidato no encontrado")
    return MessageResponse(ok=True, message="Candidato eliminado")


# ─── ACTIVIDADES COMERCIALES ─────────────────────────────────────────────────

@app.get("/actividades/", response_model=List[ActividadResponse], tags=["Actividades Comerciales"])
def list_actividades(
    mes: Optional[str] = None,
    tipo: Optional[str] = Query(None, description="Llamado | Reunión"),
    current: TokenData = Depends(get_current_user),
):
    acts = db.obtener_actividades_comerciales(mes=mes)
    if tipo:
        acts = [a for a in acts if a.get("tipo") == tipo]
    # Agente solo ve sus propias actividades
    if current.role != "admin" and current.matricula:
        acts = [a for a in acts if a.get("matricula") == current.matricula]
    return [ActividadResponse(**a) for a in acts]


@app.post("/actividades/", response_model=MessageResponse, tags=["Actividades Comerciales"])
def create_actividad(body: ActividadCreate, current: TokenData = Depends(require_admin)):
    mes = body.fecha_actividad[:7]
    row_id = db.guardar_actividad_comercial(
        mes=mes, fecha_actividad=body.fecha_actividad,
        matricula=body.matricula or "", nombre=body.nombre,
        tipo=body.tipo, compania=body.compania or "",
        observaciones=body.observaciones or "",
    )
    db.registrar_log(current.username, "API_CREATE_ACTIVIDAD", f"{body.tipo}: {body.nombre}")
    return MessageResponse(ok=True, message=f"Actividad registrada con ID {row_id}")


@app.delete("/actividades/{act_id}", response_model=MessageResponse, tags=["Actividades Comerciales"])
def delete_actividad(act_id: int, current: TokenData = Depends(require_admin)):
    ok = db.eliminar_actividad_comercial(act_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Actividad no encontrada")
    return MessageResponse(ok=True, message="Actividad eliminada")


# ─── CLIENTES ────────────────────────────────────────────────────────────────

@app.get("/clientes/", response_model=List[ClienteResponse], tags=["Cartera"])
def list_clientes(current: TokenData = Depends(get_current_user)):
    clientes = db.obtener_clientes()
    return [ClienteResponse(**c) for c in clientes]


@app.post("/clientes/", response_model=MessageResponse, tags=["Cartera"])
def create_cliente(body: ClienteCreate, current: TokenData = Depends(require_admin)):
    import sqlite3
    conn = sqlite3.connect(db.DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO clientes (nombre, dni_cuil, email, telefono, direccion, notas) VALUES (?,?,?,?,?,?)",
        (body.nombre, body.dni_cuil, body.email, body.telefono, body.direccion, body.notas)
    )
    row_id = cursor.lastrowid
    conn.commit(); conn.close()
    db.registrar_log(current.username, "API_CREATE_CLIENTE", body.nombre)
    return MessageResponse(ok=True, message=f"Cliente creado con ID {row_id}")


@app.put("/clientes/{cliente_id}", response_model=MessageResponse, tags=["Cartera"])
def update_cliente(cliente_id: int, body: ClienteUpdate, current: TokenData = Depends(require_admin)):
    import sqlite3
    conn = sqlite3.connect(db.DB_PATH)
    cursor = conn.cursor()
    fields = {k: v for k, v in body.model_dump().items() if v is not None}
    if not fields:
        raise HTTPException(status_code=400, detail="No hay campos para actualizar")
    set_clause = ", ".join(f"{k}=?" for k in fields)
    cursor.execute(f"UPDATE clientes SET {set_clause} WHERE id=?", [*fields.values(), cliente_id])
    ok = cursor.rowcount > 0
    conn.commit(); conn.close()
    if not ok:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")
    return MessageResponse(ok=True, message="Cliente actualizado")


@app.delete("/clientes/{cliente_id}", response_model=MessageResponse, tags=["Cartera"])
def delete_cliente(cliente_id: int, current: TokenData = Depends(require_admin)):
    import sqlite3
    conn = sqlite3.connect(db.DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM clientes WHERE id=?", (cliente_id,))
    ok = cursor.rowcount > 0
    conn.commit(); conn.close()
    if not ok:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")
    return MessageResponse(ok=True, message="Cliente eliminado")


# ─── PÓLIZAS ─────────────────────────────────────────────────────────────────

@app.get("/polizas/", response_model=List[PolizaResponse], tags=["Cartera"])
def list_polizas(
    cliente_id: Optional[int] = None,
    pas_matricula: Optional[str] = None,
    estado: Optional[str] = None,
    current: TokenData = Depends(get_current_user),
):
    # Agente solo ve pólizas de su matrícula
    if current.role != "admin" and current.matricula:
        pas_matricula = current.matricula
    polizas = db.obtener_polizas(cliente_id=cliente_id, pas_matricula=pas_matricula)
    if estado:
        polizas = [p for p in polizas if p.get("estado") == estado]
    return [PolizaResponse(**p) for p in polizas]


@app.post("/polizas/", response_model=MessageResponse, tags=["Cartera"])
def create_poliza(body: PolizaCreate, current: TokenData = Depends(require_admin)):
    ok = db.guardar_poliza(
        cliente_id=body.cliente_id, pas_matricula=body.pas_matricula or "",
        compania=body.compania, ramo=body.ramo, nro_poliza=body.nro_poliza,
        vigencia_desde=body.vigencia_desde, vigencia_hasta=body.vigencia_hasta,
        prima=body.prima or 0.0, premio=body.premio or 0.0,
        comision_porcentaje=body.comision_porcentaje or 0.0,
        estado_pago=body.estado_pago or "Al día",
        estado=body.estado or "Vigente", notas=body.notas or "",
    )
    if not ok:
        raise HTTPException(status_code=500, detail="Error al guardar póliza")
    db.registrar_log(current.username, "API_CREATE_POLIZA", body.nro_poliza)
    return MessageResponse(ok=True, message="Póliza creada")


@app.put("/polizas/{poliza_id}", response_model=MessageResponse, tags=["Cartera"])
def update_poliza(poliza_id: int, body: PolizaUpdate, current: TokenData = Depends(require_admin)):
    ok = db.actualizar_poliza(
        poliza_id=poliza_id, cliente_id=body.cliente_id,
        pas_matricula=body.pas_matricula or "", compania=body.compania,
        ramo=body.ramo, nro_poliza=body.nro_poliza,
        vigencia_desde=body.vigencia_desde, vigencia_hasta=body.vigencia_hasta,
        prima=body.prima or 0.0, premio=body.premio or 0.0,
        comision_porcentaje=body.comision_porcentaje or 0.0,
        estado_pago=body.estado_pago or "Al día",
        estado=body.estado or "Vigente", notas=body.notas or "",
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Póliza no encontrada")
    return MessageResponse(ok=True, message="Póliza actualizada")


@app.delete("/polizas/{poliza_id}", response_model=MessageResponse, tags=["Cartera"])
def delete_poliza(poliza_id: int, current: TokenData = Depends(require_admin)):
    ok = db.eliminar_poliza(poliza_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Póliza no encontrada")
    return MessageResponse(ok=True, message="Póliza eliminada")


# ─── ALERTAS ─────────────────────────────────────────────────────────────────

@app.get("/alertas/vencimiento", response_model=List[AlertaResponse], tags=["Alertas y Métricas"])
def get_alertas(
    dias: int = Query(60, ge=1, le=365, description="Días de anticipación"),
    current: TokenData = Depends(get_current_user),
):
    """
    Pólizas próximas a vencer (dentro de `dias` días) y pólizas impagas.
    Agente solo ve las alertas de su propia matrícula.
    """
    alertas = db.obtener_alertas_vencimiento(dias_umbral=dias)
    if current.role != "admin" and current.matricula:
        alertas = [a for a in alertas if a.get("pas_matricula") == current.matricula]
    return [AlertaResponse(**a) for a in alertas]


# ─── MÉTRICAS ────────────────────────────────────────────────────────────────

@app.get("/metricas/erp", response_model=MetricasERPResponse, tags=["Alertas y Métricas"])
def get_metricas_erp(current: TokenData = Depends(get_current_user)):
    """KPIs generales del ERP: primas, comisiones, clientes, siniestros."""
    metricas = db.obtener_metricas_erp()
    return MetricasERPResponse(**metricas)


@app.get("/metricas/productores", response_model=List[RankingProductorResponse], tags=["Alertas y Métricas"])
def get_ranking(current: TokenData = Depends(get_current_user)):
    """Ranking de productores por volumen de cartera."""
    ranking = db.obtener_ranking_productores()
    # Agente solo se ve a sí mismo
    if current.role != "admin" and current.matricula:
        ranking = [r for r in ranking if r.get("matricula") == current.matricula]
    return [RankingProductorResponse(**r) for r in ranking]


# ─── ACCIONES MENSUALES ──────────────────────────────────────────────────────

@app.get("/acciones/", response_model=List[AccionResponse], tags=["Plan Comercial"])
def list_acciones(
    mes: Optional[str] = Query(None, description="Formato YYYY-MM. Default: mes actual"),
    current: TokenData = Depends(get_current_user),
):
    """Lista acciones del plan mensual."""
    acciones = db.obtener_acciones(mes=mes)
    return [AccionResponse(**a) for a in acciones]


@app.post("/acciones/", response_model=MessageResponse, tags=["Plan Comercial"])
def create_accion(body: AccionCreate, current: TokenData = Depends(require_admin)):
    """Crear una nueva acción en el plan mensual. Solo admin."""
    mes = body.mes or db.obtener_mes_actual()
    row_id = db.guardar_accion(
        mes=mes, tipo=body.tipo,
        descripcion=body.descripcion or "",
        estado=body.estado or "pendiente",
    )
    db.registrar_log(current.username, "API_CREATE_ACCION", f"{body.tipo}: {body.descripcion}")
    return MessageResponse(ok=True, message=f"Acción creada con ID {row_id}")


@app.put("/acciones/{accion_id}", response_model=MessageResponse, tags=["Plan Comercial"])
def update_accion(accion_id: int, body: AccionUpdate, current: TokenData = Depends(require_admin)):
    """Actualizar estado/descripción de una acción. Solo admin."""
    ok = db.actualizar_accion(accion_id, body.estado, body.descripcion or "")
    if not ok:
        raise HTTPException(status_code=404, detail="Acción no encontrada")
    return MessageResponse(ok=True, message="Acción actualizada")


@app.delete("/acciones/{accion_id}", response_model=MessageResponse, tags=["Plan Comercial"])
def delete_accion(accion_id: int, current: TokenData = Depends(require_admin)):
    """Eliminar una acción del plan mensual. Solo admin."""
    ok = db.eliminar_accion(accion_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Acción no encontrada")
    return MessageResponse(ok=True, message="Acción eliminada")


# ─── SINIESTROS ──────────────────────────────────────────────────────────────

@app.get("/siniestros/", response_model=List[SiniestroResponse], tags=["Cartera"])
def list_siniestros(
    poliza_id: Optional[int] = Query(None, description="Filtrar por póliza"),
    current: TokenData = Depends(get_current_user),
):
    """Lista todos los siniestros. Puede filtrarse por póliza."""
    siniestros = db.obtener_siniestros(poliza_id=poliza_id)
    return [SiniestroResponse(**s) for s in siniestros]


@app.get("/siniestros/{siniestro_id}", response_model=SiniestroResponse, tags=["Cartera"])
def get_siniestro(siniestro_id: int, current: TokenData = Depends(get_current_user)):
    """Detalle de un siniestro por ID."""
    siniestros = db.obtener_siniestros()
    for s in siniestros:
        if s.get("id") == siniestro_id:
            return SiniestroResponse(**s)
    raise HTTPException(status_code=404, detail="Siniestro no encontrado")


@app.post("/siniestros/", response_model=MessageResponse, tags=["Cartera"])
def create_siniestro(body: SiniestroCreate, current: TokenData = Depends(require_admin)):
    """Registrar un nuevo siniestro. Solo admin."""
    ok = db.guardar_siniestro(
        poliza_id=body.poliza_id,
        fecha_siniestro=body.fecha_siniestro,
        descripcion=body.descripcion or "",
        estado=body.estado or "En proceso",
        notas=body.notas or "",
    )
    if not ok:
        raise HTTPException(status_code=500, detail="Error al guardar siniestro")
    db.registrar_log(current.username, "API_CREATE_SINIESTRO", f"Póliza ID {body.poliza_id}")
    return MessageResponse(ok=True, message="Siniestro registrado")


@app.put("/siniestros/{siniestro_id}", response_model=MessageResponse, tags=["Cartera"])
def update_siniestro(
    siniestro_id: int,
    body: SiniestroUpdate,
    current: TokenData = Depends(require_admin),
):
    """Actualizar un siniestro. Solo admin."""
    ok = db.actualizar_siniestro(
        siniestro_id=siniestro_id,
        poliza_id=body.poliza_id,
        fecha_siniestro=body.fecha_siniestro,
        descripcion=body.descripcion or "",
        estado=body.estado,
        notas=body.notas or "",
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Siniestro no encontrado")
    db.registrar_log(current.username, "API_UPDATE_SINIESTRO", f"ID {siniestro_id} → {body.estado}")
    return MessageResponse(ok=True, message="Siniestro actualizado")


@app.delete("/siniestros/{siniestro_id}", response_model=MessageResponse, tags=["Cartera"])
def delete_siniestro(siniestro_id: int, current: TokenData = Depends(require_admin)):
    """Eliminar un siniestro. Solo admin."""
    ok = db.eliminar_siniestro(siniestro_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Siniestro no encontrado")
    db.registrar_log(current.username, "API_DELETE_SINIESTRO", f"ID {siniestro_id}")
    return MessageResponse(ok=True, message="Siniestro eliminado")


# ─── USUARIOS (Admin) ────────────────────────────────────────────────────────

@app.get("/usuarios/", response_model=List[UsuarioResponse], tags=["Administración"])
def list_usuarios(current: TokenData = Depends(require_admin)):
    """Lista todos los usuarios del sistema. Solo admin."""
    usuarios = db.obtener_usuarios()
    return [UsuarioResponse(**u) for u in usuarios]


@app.get("/usuarios/{user_id}", response_model=UsuarioResponse, tags=["Administración"])
def get_usuario(user_id: int, current: TokenData = Depends(require_admin)):
    """Obtiene un usuario por ID. Solo admin."""
    usuarios = db.obtener_usuarios()
    for u in usuarios:
        if u.get("id") == user_id:
            return UsuarioResponse(**u)
    raise HTTPException(status_code=404, detail="Usuario no encontrado")


@app.post("/usuarios/", response_model=MessageResponse, tags=["Administración"])
def create_usuario(body: UsuarioCreate, current: TokenData = Depends(require_admin)):
    """Crear un nuevo usuario. Solo admin."""
    ok, msg = db.crear_usuario(
        usuario=body.usuario,
        email=body.email,
        password_txt=body.password,
        rol=body.rol or "agente",
        requiere_cambio=body.requiere_cambio if body.requiere_cambio is not None else 1,
        matricula=body.matricula,
    )
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    db.registrar_log(current.username, "API_CREATE_USUARIO", f"Nuevo usuario: {body.usuario}")
    return MessageResponse(ok=True, message=msg)


@app.put("/usuarios/{user_id}", response_model=MessageResponse, tags=["Administración"])
def update_usuario(
    user_id: int,
    body: UsuarioUpdate,
    current: TokenData = Depends(require_admin),
):
    """Actualizar datos de un usuario. Solo admin."""
    ok, msg = db.actualizar_usuario(
        id_usuario=user_id,
        nuevo_usuario=body.usuario or "",
        nuevo_email=body.email or "",
        password_txt=body.password,
        rol=body.rol,
        requiere_cambio=body.requiere_cambio,
        reset_lock=body.reset_lock or False,
        is_self_update=(current.user_id == user_id),
        matricula=body.matricula,
    )
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    db.registrar_log(current.username, "API_UPDATE_USUARIO", f"ID {user_id}: {msg}")
    return MessageResponse(ok=True, message=msg)


@app.delete("/usuarios/{user_id}", response_model=MessageResponse, tags=["Administración"])
def delete_usuario(user_id: int, current: TokenData = Depends(require_admin)):
    """Eliminar un usuario. Solo admin. No puede eliminarse a sí mismo."""
    if user_id == current.user_id:
        raise HTTPException(status_code=400, detail="No podés eliminar tu propio usuario")
    ok = db.eliminar_usuario(user_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    db.registrar_log(current.username, "API_DELETE_USUARIO", f"ID {user_id} eliminado")
    return MessageResponse(ok=True, message="Usuario eliminado")


# ─── LOGS DE AUDITORÍA ───────────────────────────────────────────────────────

@app.get("/logs/", response_model=List[LogResponse], tags=["Administración"])
def list_logs(
    limite: int = Query(100, ge=1, le=500, description="Máximo de registros a retornar"),
    current: TokenData = Depends(require_admin),
):
    """
    Últimos N registros del log de auditoría. Solo admin.
    Permite auditar acciones realizadas por todos los usuarios del sistema.
    """
    logs = db.obtener_logs(limite=limite)
    return [LogResponse(**l) for l in logs]


# ─── LICENCIAS DE SOFTWARE ───────────────────────────────────────────────────

@app.post("/licencias/validar", response_model=LicenciaValidarResponse, tags=["Licencias de Software"])
@limiter.limit("10/minute")
def api_validar_licencia(request: Request, body: LicenciaValidarRequest):
    """
    Valida la clave de licencia provista con la huella digital del hardware del cliente.
    """
    ip = request.client.host if request.client else "Desconocida"
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
        
    res = db.validar_licencia(
        body.clave, 
        body.dispositivo_id, 
        body.email_cliente, 
        body.dispositivo_nombre,
        ip_address=ip
    )
    return LicenciaValidarResponse(**res)


@app.get("/licencias/", response_model=List[LicenciaResponse], tags=["Licencias de Software"])
def api_list_licencias(current: TokenData = Depends(require_licencias_admin)):
    """Lista todas las licencias del sistema. Solo admin de licencias."""
    check_panel_permission(current.username, current.role, "ver_licencias")
    lics = db.obtener_licencias()
    return [LicenciaResponse(**l) for l in lics]


@app.post("/licencias/", response_model=MessageResponse, tags=["Licencias de Software"])
def api_create_licencia(body: LicenciaCreate, current: TokenData = Depends(require_licencias_admin)):
    check_panel_permission(current.username, current.role, "crear_licencia")
    producto = body.producto.upper()
    if producto not in ["CRM", "ERP", "POS"]:
        raise HTTPException(status_code=400, detail=f"Producto inválido. Opciones: CRM, ERP, POS")
    
    clave = db.generar_clave_licencia(producto)
    row_id = db.guardar_licencia(
        clave=clave,
        cliente=body.cliente,
        email_cliente=body.email_cliente,
        producto=producto,
        fecha_expiracion=body.fecha_expiracion,
        estado=body.estado,
        limite_dispositivos=body.limite_dispositivos
    )
    db.registrar_log(current.username, "API_CREATE_LICENCIA",
                     f"[{producto}] Cliente: {body.cliente} <{body.email_cliente}> -> {clave}")
    return MessageResponse(ok=True, message=f"Licencia creada: {clave}")


@app.put("/licencias/{lic_id}", response_model=MessageResponse, tags=["Licencias de Software"])
def api_update_licencia(lic_id: int, body: LicenciaUpdate, current: TokenData = Depends(require_licencias_admin)):
    """Actualiza los datos de una licencia. Solo admin."""
    lic_previa = db.obtener_licencia_por_id(lic_id)
    if not lic_previa:
        raise HTTPException(status_code=404, detail="Licencia no encontrada")
        
    # Validar permisos detalladamente
    if body.dispositivo_id != lic_previa.get("dispositivo_id") or body.dispositivos_info != lic_previa.get("dispositivos_info"):
        check_panel_permission(current.username, current.role, "desvincular_dispositivo")
    if body.estado != lic_previa.get("estado"):
        check_panel_permission(current.username, current.role, "suspender_licencia")
    if body.cliente != lic_previa.get("cliente") or body.fecha_expiracion != lic_previa.get("fecha_expiracion") or body.limite_dispositivos != lic_previa.get("limite_dispositivos"):
        check_panel_permission(current.username, current.role, "editar_licencia")
        
    ok = db.actualizar_licencia(
        licencia_id=lic_id,
        cliente=body.cliente,
        fecha_expiracion=body.fecha_expiracion,
        estado=body.estado,
        limite_dispositivos=body.limite_dispositivos,
        dispositivo_id=body.dispositivo_id,
        motivo=body.motivo,
        dispositivos_info=body.dispositivos_info,
        integraciones=body.integraciones
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Licencia no encontrada")
        
    db.registrar_log(current.username, "API_UPDATE_LICENCIA", f"ID {lic_id} actualizada")
    
    # Enviar correo si pasa a suspendida
    if body.estado == "suspendida" and lic_previa.get("estado") != "suspendida":
        import threading
        def alert_suspension():
            db.enviar_mail_alerta_licencia(
                destinatario="supit@katrix.com.ar",
                cliente=body.cliente,
                email_cliente=lic_previa.get("email_cliente") or "",
                clave=lic_previa.get("clave") or "",
                accion="SUSPENDIDA",
                motivo=body.motivo,
                dispositivo_id=lic_previa.get("dispositivo_id") or body.dispositivo_id,
                dispositivos_info=lic_previa.get("dispositivos_info") or body.dispositivos_info
            )
        threading.Thread(target=alert_suspension, daemon=True).start()
        
    return MessageResponse(ok=True, message="Licencia actualizada")


@app.delete("/licencias/{lic_id}", response_model=MessageResponse, tags=["Licencias de Software"])
def api_delete_licencia(lic_id: int, current: TokenData = Depends(require_licencias_admin)):
    """Elimina una licencia. Solo admin."""
    check_panel_permission(current.username, current.role, "eliminar_licencia")
    lic_previa = db.obtener_licencia_por_id(lic_id)
    if not lic_previa:
        raise HTTPException(status_code=404, detail="Licencia no encontrada")
        
    ok = db.eliminar_licencia(lic_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Licencia no encontrada")
        
    db.registrar_log(current.username, "API_DELETE_LICENCIA", f"ID {lic_id} eliminada")
    
    # Enviar correo de eliminación
    import threading
    def alert_deletion():
        db.enviar_mail_alerta_licencia(
            destinatario="supit@katrix.com.ar",
            cliente=lic_previa.get("cliente") or "",
            email_cliente=lic_previa.get("email_cliente") or "",
            clave=lic_previa.get("clave") or "",
            accion="ELIMINADA",
            dispositivo_id=lic_previa.get("dispositivo_id"),
            dispositivos_info=lic_previa.get("dispositivos_info")
        )
    threading.Thread(target=alert_deletion, daemon=True).start()
    
    return MessageResponse(ok=True, message="Licencia eliminada")


# ─── Health Check ─────────────────────────────────────────────────────────────

PANEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel.html")

@app.get("/panel", tags=["Panel"])
def servir_panel():
    """Sirve el panel de control de licencias (HTML estático)."""
    if not os.path.exists(PANEL_PATH):
        raise HTTPException(status_code=404, detail="panel.html no encontrado en el servidor")
    return FileResponse(PANEL_PATH, media_type="text/html")


@app.get("/panel/katrix-biometrics.js", tags=["Panel"])
def get_katrix_biometrics_js():
    """Sirve el frontend JavaScript de la librería biométrica."""
    js_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "katrix-biometrics.js")
    if not os.path.exists(js_path):
        raise HTTPException(status_code=404, detail="katrix-biometrics.js no encontrado")
    return FileResponse(js_path, media_type="application/javascript")


# ─── PANEL AUTH & BIOMETRICS ──────────────────────────────────────────────────

@app.post("/panel/auth/login", response_model=Token, tags=["Panel Auth"])
@limiter.limit("5/minute")
def panel_login(request: Request, body: PanelLoginRequest):
    user = db.obtener_panel_user(body.username)
    if not user:
        raise HTTPException(status_code=401, detail="Usuario de panel incorrecto")
        
    if not db.verify_password(user["password_hash"], body.password):
        raise HTTPException(status_code=401, detail="Contraseña de panel incorrecta")
        
    role_token = "panel_superadmin" if user["role"] == "superadmin" else "panel_admin"
    
    import json
    try:
        perms = json.loads(user["permissions"])
    except Exception:
        perms = {}
        
    token = create_token({
        "user_id": 999,
        "username": user["username"],
        "role": role_token,
        "matricula": None
    })
    
    db.registrar_log(user["username"], "PANEL_LOGIN", "Login exitoso en Panel de Licencias")
    
    # Registrar la sesión activa y eliminar de la lista de revocadas
    REVOKED_SESSIONS.discard(user["username"])
    client_host = request.client.host if request.client else "Desconocida"
    user_agent = request.headers.get("user-agent", "Desconocido")
    PANEL_SESSIONS[user["username"]] = {
        "username": user["username"],
        "role": role_token,
        "ip": client_host,
        "user_agent": user_agent,
        "last_active": datetime.utcnow().isoformat(),
        "status": "online"
    }
    
    return Token(
        access_token=token,
        token_type="bearer",
        role=role_token,
        user_id=999,
        username=user["username"],
        permissions=perms
    )

@app.post("/panel/auth/change-password", response_model=MessageResponse, tags=["Panel Auth"])
def panel_change_password(body: PanelChangePasswordRequest, current: TokenData = Depends(require_licencias_admin)):
    user = db.obtener_panel_user(current.username)
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
    if not db.verify_password(user["password_hash"], body.current_password):
        raise HTTPException(status_code=400, detail="La contraseña actual es incorrecta")
        
    db.actualizar_panel_user(user["username"], body.new_password, user["role"], user["permissions"])
    db.registrar_log(user["username"], "PANEL_CHANGE_PASSWORD", "Cambio de contraseña del panel")
    
    return MessageResponse(ok=True, message="Contraseña de panel actualizada correctamente")

@app.get("/panel/auth/biometrics/challenge", tags=["Panel Auth"])
def panel_biometrics_challenge():
    challenge = katrix_biometrics.generar_challenge()
    challenge_token = jwt.encode(
        {
            "challenge": challenge, 
            "exp": datetime.utcnow() + timedelta(minutes=2)
        }, 
        SECRET_KEY, 
        algorithm=ALGORITHM
    )
    return {"challenge": challenge, "challenge_token": challenge_token}

@app.post("/panel/auth/biometrics/register", response_model=MessageResponse, tags=["Panel Auth"])
def panel_biometrics_register(body: BiometricRegisterRequest, current: TokenData = Depends(require_licencias_admin)):
    try:
        payload = jwt.decode(body.challenge_token, SECRET_KEY, algorithms=[ALGORITHM])
        challenge = payload.get("challenge")
        if not challenge:
            raise HTTPException(status_code=400, detail="Token de reto inválido")
    except JWTError:
        raise HTTPException(status_code=400, detail="Token de reto expirado o inválido")
        
    db.guardar_panel_biometric(body.credential_id, body.public_key_der, body.dispositivo_nombre, current.username)
    db.registrar_log(current.username, "PANEL_BIOMETRICS_REG", f"Dispositivo biométrico registrado: {body.dispositivo_nombre}")
    return MessageResponse(ok=True, message="Dispositivo biométrico registrado exitosamente")

@app.post("/panel/auth/biometrics/login", response_model=Token, tags=["Panel Auth"])
@limiter.limit("5/minute")
def panel_biometrics_login(request: Request, body: BiometricLoginRequest):
    try:
        payload = jwt.decode(body.challenge_token, SECRET_KEY, algorithms=[ALGORITHM])
        challenge = payload.get("challenge")
        if not challenge:
            raise HTTPException(status_code=400, detail="Token de reto inválido")
    except JWTError:
        raise HTTPException(status_code=400, detail="Token de reto expirado o inválido")
        
    cred = db.obtener_panel_biometric(body.credential_id)
    if not cred:
        raise HTTPException(status_code=401, detail="Dispositivo biométrico no registrado")
        
    valida, motivo = katrix_biometrics.verificar_firma_biometrica(
        public_key_der_b64=cred["public_key"],
        signature_b64=body.signature,
        authenticator_data_b64=body.authenticator_data,
        client_data_json_b64=body.client_data_json,
        challenge_original=challenge
    )
    
    if not valida:
        raise HTTPException(status_code=401, detail=f"Fallo biométrico: {motivo}")
        
    username = cred["username"]
    user = db.obtener_panel_user(username)
    if not user:
        raise HTTPException(status_code=401, detail="El usuario asociado a este biométrico ya no existe")
        
    role_token = "panel_superadmin" if user["role"] == "superadmin" else "panel_admin"
    
    import json
    try:
        perms = json.loads(user["permissions"])
    except Exception:
        perms = {}
        
    token = create_token({
        "user_id": 999,
        "username": username,
        "role": role_token,
        "matricula": None
    })
    
    db.registrar_log(username, "PANEL_BIOMETRICS_LOGIN", f"Login biométrico exitoso via {cred['dispositivo_nombre']}")
    
    # Registrar la sesión activa y eliminar de la lista de revocadas
    REVOKED_SESSIONS.discard(username)
    client_host = request.client.host if request.client else "Desconocida"
    user_agent = request.headers.get("user-agent", "Desconocido")
    PANEL_SESSIONS[username] = {
        "username": username,
        "role": role_token,
        "ip": client_host,
        "user_agent": user_agent,
        "last_active": datetime.utcnow().isoformat(),
        "status": "online"
    }
    
    return Token(
        access_token=token,
        token_type="bearer",
        role=role_token,
        user_id=999,
        username=username,
        permissions=perms
    )

@app.get("/panel/auth/biometrics/credentials", tags=["Panel Auth"])
def panel_biometrics_credentials():
    creds = db.obtener_todos_panel_biometrics()
    return [c["credential_id"] for c in creds]

# ─── PANEL USER MANAGEMENT (SUPERADMIN ONLY) ───────────────────────────────────

def require_panel_superadmin(current: TokenData = Depends(require_licencias_admin)):
    if current.role == "admin":
        return current  # El admin general del CRM siempre tiene rol de superadmin
    user = db.obtener_panel_user(current.username)
    if user and user["role"] == "superadmin":
        return current
    raise HTTPException(status_code=403, detail="Se requieren permisos de Superadmin del Panel")

@app.get("/panel/users", response_model=List[PanelUserResponse], tags=["Panel Users"])
def panel_list_users(current: TokenData = Depends(require_panel_superadmin)):
    users = db.obtener_todos_panel_users()
    res = []
    import json
    for u in users:
        try:
            perms = json.loads(u["permissions"])
        except Exception:
            perms = {}
        res.append(PanelUserResponse(
            username=u["username"],
            role=u["role"],
            permissions=perms
        ))
    return res

@app.post("/panel/users", response_model=MessageResponse, tags=["Panel Users"])
def panel_create_user(body: PanelUserCreate, current: TokenData = Depends(require_panel_superadmin)):
    if len(body.username.strip()) < 3:
        raise HTTPException(status_code=400, detail="El usuario debe tener al menos 3 caracteres")
    if len(body.password.strip()) < 4:
        raise HTTPException(status_code=400, detail="La contraseña debe tener al menos 4 caracteres")
        
    existing = db.obtener_panel_user(body.username)
    if existing:
        raise HTTPException(status_code=400, detail="El usuario ya existe")
        
    import json
    perms_str = json.dumps(body.permissions)
    ok = db.crear_panel_user(body.username, body.password, body.role, perms_str)
    if not ok:
        raise HTTPException(status_code=500, detail="Error al crear el usuario")
        
    db.registrar_log(current.username, "PANEL_USER_CREATE", f"Creó el usuario de panel: {body.username} (rol: {body.role})")
    return MessageResponse(ok=True, message="Usuario creado exitosamente")

@app.put("/panel/users/{username}", response_model=MessageResponse, tags=["Panel Users"])
def panel_update_user(username: str, body: PanelUserUpdate, current: TokenData = Depends(require_panel_superadmin)):
    existing = db.obtener_panel_user(username)
    if not existing:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
    if existing["role"] == "superadmin" and body.role == "admin":
        superadmins = [u for u in db.obtener_todos_panel_users() if u["role"] == "superadmin"]
        if len(superadmins) <= 1:
            raise HTTPException(status_code=400, detail="Debe haber al menos un superadmin en el sistema")
            
    role = body.role if body.role else existing["role"]
    
    import json
    if body.permissions is not None:
        perms_str = json.dumps(body.permissions)
    else:
        perms_str = existing["permissions"]
        
    ok = db.actualizar_panel_user(username, body.password, role, perms_str)
    if not ok:
        raise HTTPException(status_code=500, detail="Error al actualizar el usuario")
        
    db.registrar_log(current.username, "PANEL_USER_UPDATE", f"Actualizó el usuario de panel: {username}")
    return MessageResponse(ok=True, message="Usuario actualizado exitosamente")

@app.delete("/panel/users/{username}", response_model=MessageResponse, tags=["Panel Users"])
def panel_delete_user(username: str, current: TokenData = Depends(require_panel_superadmin)):
    if username == current.username:
        raise HTTPException(status_code=400, detail="No podés eliminar a tu propio usuario")
        
    existing = db.obtener_panel_user(username)
    if not existing:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
    if existing["role"] == "superadmin":
        superadmins = [u for u in db.obtener_todos_panel_users() if u["role"] == "superadmin"]
        if len(superadmins) <= 1:
            raise HTTPException(status_code=400, detail="Debe haber al menos un superadmin en el sistema")
            
    ok = db.eliminar_panel_user(username)
    if not ok:
        raise HTTPException(status_code=500, detail="Error al eliminar el usuario")
        
    db.registrar_log(current.username, "PANEL_USER_DELETE", f"Eliminó el usuario de panel: {username}")
    return MessageResponse(ok=True, message="Usuario eliminado exitosamente")

# ─── PANEL ACTIVE SESSIONS & AUDIT LOGS ───────────────────────────────────────

@app.get("/panel/sessions", tags=["Panel Sessions"])
def panel_list_sessions(current: TokenData = Depends(require_licencias_admin)):
    # Lazy cleanup of old sessions (inactive for more than 12 hours)
    now = datetime.utcnow()
    for u, s in list(PANEL_SESSIONS.items()):
        try:
            last_act = datetime.fromisoformat(s["last_active"])
            if now - last_act > timedelta(hours=12):
                PANEL_SESSIONS.pop(u, None)
        except Exception:
            PANEL_SESSIONS.pop(u, None)

    if current.role not in ["panel_superadmin", "admin"]:
        check_panel_permission(current.username, current.role, "ver_sesiones")

    return list(PANEL_SESSIONS.values())

@app.post("/panel/sessions/{username}/revoke", response_model=MessageResponse, tags=["Panel Sessions"])
def panel_revoke_session(username: str, current: TokenData = Depends(require_licencias_admin)):
    if username == current.username:
        raise HTTPException(status_code=400, detail="No podés revocar tu propia sesión activa")
        
    if current.role not in ["panel_superadmin", "admin"]:
        check_panel_permission(current.username, current.role, "desvincular_sesion")
        
    # Revocar sesión
    PANEL_SESSIONS.pop(username, None)
    REVOKED_SESSIONS.add(username)
    
    db.registrar_log(current.username, "PANEL_SESSION_REVOKE", f"Forzó cierre de sesión para usuario: {username}")
    return MessageResponse(ok=True, message=f"Sesión del usuario '{username}' revocada exitosamente")

@app.get("/panel/logs", tags=["Panel Logs"])
def panel_list_logs(
    limite: int = Query(100, ge=1, le=500, description="Cantidad máxima de logs a retornar"),
    current: TokenData = Depends(require_licencias_admin)
):
    if current.role not in ["panel_superadmin", "admin"]:
        check_panel_permission(current.username, current.role, "ver_logs")
        
    logs = db.obtener_logs(limite=limite)
    return logs

# ─── PWA STATIC ASSETS ──────────────────────────────────────────────────────────

@app.get("/panel/manifest.json", tags=["Panel"])
def get_manifest():
    manifest_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "manifest.json")
    if not os.path.exists(manifest_path):
        raise HTTPException(status_code=404, detail="manifest.json no encontrado")
    return FileResponse(manifest_path, media_type="application/json")

@app.get("/panel/sw.js", tags=["Panel"])
def get_sw():
    sw_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sw.js")
    if not os.path.exists(sw_path):
        raise HTTPException(status_code=404, detail="sw.js no encontrado")
    return FileResponse(sw_path, media_type="application/javascript", headers={"Cache-Control": "no-store, no-cache, must-revalidate"})

@app.get("/panel/icon-192.png", tags=["Panel"])
def get_icon_192():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "icon-192.png")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="icon-192.png no encontrado")
    return FileResponse(path, media_type="image/png")

@app.get("/panel/icon-512.png", tags=["Panel"])
def get_icon_512():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "icon-512.png")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="icon-512.png no encontrado")
    return FileResponse(path, media_type="image/png")


@app.get("/health", tags=["Sistema"])
def health():
    """Verificar que la API está funcionando."""
    return {
        "status": "ok",
        "version": "1.2.0",
        "timestamp": datetime.utcnow().isoformat(),
        "endpoints": {
            "auth": ["/auth/login", "/auth/me"],
            "pas": ["/pas/", "/pas/{matricula}", "/pas/{matricula}/actividades", "/pas/{matricula}/polizas"],
            "visitas": ["/visitas/"],
            "candidatos": ["/candidatos/"],
            "acciones": ["/acciones/"],
            "actividades": ["/actividades/"],
            "clientes": ["/clientes/"],
            "polizas": ["/polizas/"],
            "siniestros": ["/siniestros/"],
            "alertas": ["/alertas/vencimiento"],
            "metricas": ["/metricas/erp", "/metricas/productores"],
            "usuarios": ["/usuarios/"],
            "logs": ["/logs/"],
            "licencias": ["/licencias/validar", "/licencias/"],
            "panel": ["/panel"],
        }
    }

