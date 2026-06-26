"""
api.py — Katrix ERP REST API
FastAPI + JWT. Admin: CRUD completo. Agente: solo lectura.
Arrancar con: uvicorn api:app --host 0.0.0.0 --port 8000
"""
import os, sys
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, status, Query
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ssn_test as db
from api_models import *

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
    "http://localhost,http://localhost:3000,http://localhost:8080,*"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# ─── JWT Helpers ─────────────────────────────────────────────────────────────

def create_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)) -> TokenData:
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
        return TokenData(user_id=user_id, username=username, role=role, matricula=matricula)
    except JWTError:
        raise cred_err


def require_admin(current: TokenData = Depends(get_current_user)) -> TokenData:
    if current.role != "admin":
        raise HTTPException(status_code=403, detail="Se requiere rol de administrador")
    return current


# ─── AUTH ────────────────────────────────────────────────────────────────────

@app.post("/auth/login", response_model=Token, tags=["Auth"])
def login(body: LoginRequest):
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
def api_validar_licencia(body: LicenciaValidarRequest):
    """
    Valida la clave de licencia provista con la huella digital del hardware del cliente.
    """
    res = db.validar_licencia(body.clave, body.dispositivo_id)
    return LicenciaValidarResponse(**res)


@app.get("/licencias/", response_model=List[LicenciaResponse], tags=["Licencias de Software"])
def api_list_licencias(current: TokenData = Depends(require_admin)):
    """Lista todas las licencias del sistema. Solo admin."""
    lics = db.obtener_licencias()
    return [LicenciaResponse(**l) for l in lics]


@app.post("/licencias/", response_model=MessageResponse, tags=["Licencias de Software"])
def api_create_licencia(body: LicenciaCreate, current: TokenData = Depends(require_admin)):
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
def api_update_licencia(lic_id: int, body: LicenciaUpdate, current: TokenData = Depends(require_admin)):
    """Actualiza los datos de una licencia. Solo admin."""
    ok = db.actualizar_licencia(
        licencia_id=lic_id,
        cliente=body.cliente,
        fecha_expiracion=body.fecha_expiracion,
        estado=body.estado,
        limite_dispositivos=body.limite_dispositivos,
        dispositivo_id=body.dispositivo_id
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Licencia no encontrada")
    db.registrar_log(current.username, "API_UPDATE_LICENCIA", f"ID {lic_id} actualizada")
    return MessageResponse(ok=True, message="Licencia actualizada")


@app.delete("/licencias/{lic_id}", response_model=MessageResponse, tags=["Licencias de Software"])
def api_delete_licencia(lic_id: int, current: TokenData = Depends(require_admin)):
    """Elimina una licencia. Solo admin."""
    ok = db.eliminar_licencia(lic_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Licencia no encontrada")
    db.registrar_log(current.username, "API_DELETE_LICENCIA", f"ID {lic_id} eliminada")
    return MessageResponse(ok=True, message="Licencia eliminada")


# ─── Health Check ─────────────────────────────────────────────────────────────

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
        }
    }

