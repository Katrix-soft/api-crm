"""
api_models.py — Schemas Pydantic para Katrix ERP API
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Any
from datetime import datetime


# ─── Auth ───────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(..., description="Nombre de usuario o email")
    password: str

class ForgotPasswordRequest(BaseModel):
    email: str = Field(..., description="Email o usuario de la cuenta a recuperar")

class ResetPasswordRequest(BaseModel):
    token: str = Field(..., description="Token JWT de recuperación")
    password: str = Field(..., min_length=6, description="Nueva contraseña")

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    user_id: int
    username: str

class TokenData(BaseModel):
    user_id: int
    username: str
    role: str
    matricula: Optional[str] = None


# ─── Usuario / Perfil ────────────────────────────────────────────────────────

class PerfilResponse(BaseModel):
    user_id: int
    username: str
    email: str
    role: str
    matricula: Optional[str] = None


# ─── PAS (Productores Asesores de Seguros) ───────────────────────────────────

class PASResponse(BaseModel):
    matricula: Optional[str]
    nombre: Optional[str]
    ramo: Optional[str]
    provincia: Optional[str]
    localidad: Optional[str]
    domicilio: Optional[str]
    cod_postal: Optional[str]
    telefono: Optional[str]
    email: Optional[str]
    estado_contacto: Optional[str] = "Sin contactar"
    observaciones: Optional[str]
    companias: Optional[str]
    resolucion: Optional[str]
    fecha_resolucion: Optional[str]
    documento: Optional[str]
    cuit: Optional[str]

class PASListItem(BaseModel):
    matricula: Optional[str]
    nombre: Optional[str]
    ramo: Optional[str]
    provincia: Optional[str]
    localidad: Optional[str]
    telefono: Optional[str]
    email: Optional[str]
    estado_contacto: Optional[str] = "Sin contactar"
    companias: Optional[str]
    documento: Optional[str] = None
    cuit: Optional[str] = None

class PASEstadoUpdate(BaseModel):
    estado_contacto: str = Field(..., description="Sin contactar | Contactado | No responde | Interesado")

class PASObservacionesUpdate(BaseModel):
    observaciones: str


# ─── Visitas PAS ─────────────────────────────────────────────────────────────

class VisitaCreate(BaseModel):
    nombre: str = Field(..., min_length=1)
    matricula: Optional[str] = ""
    productividad: Optional[str] = ""
    estado_org: Optional[str] = ""
    campaña: Optional[str] = ""
    mes: Optional[str] = None   # default = mes actual

class VisitaUpdate(BaseModel):
    estado: str = Field(..., description="pendiente | realizada")
    productividad: Optional[str] = ""
    estado_org: Optional[str] = ""
    campaña: Optional[str] = ""

class VisitaResponse(BaseModel):
    id: int
    mes: str
    matricula: Optional[str]
    nombre: str
    estado: str
    productividad: Optional[str]
    estado_org: Optional[str]
    campaña: Optional[str]
    fecha: Optional[str]


# ─── Candidatos ──────────────────────────────────────────────────────────────

class CandidatoCreate(BaseModel):
    nombre: str = Field(..., min_length=1)
    matricula: Optional[str] = ""
    tiene_cartera: Optional[int] = 0
    estado: Optional[str] = "candidato"
    notas: Optional[str] = ""
    mes: Optional[str] = None

class CandidatoUpdate(BaseModel):
    estado: str
    notas: Optional[str] = ""
    tiene_cartera: Optional[int] = 0

class CandidatoResponse(BaseModel):
    id: int
    mes: str
    nombre: str
    matricula: Optional[str]
    tiene_cartera: Optional[int]
    estado: str
    notas: Optional[str]
    fecha: Optional[str]


# ─── Actividades Comerciales ─────────────────────────────────────────────────

class ActividadCreate(BaseModel):
    fecha_actividad: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$",
                                  description="Formato YYYY-MM-DD")
    matricula: Optional[str] = ""
    nombre: str = Field(..., min_length=1)
    tipo: str = Field(..., description="Llamado | Reunión")
    compania: Optional[str] = ""
    observaciones: Optional[str] = ""

class ActividadResponse(BaseModel):
    id: int
    mes: str
    fecha_actividad: Optional[str]
    matricula: Optional[str]
    nombre: str
    tipo: str
    compania: Optional[str]
    observaciones: Optional[str]
    fecha_registro: Optional[str]


# ─── Clientes ────────────────────────────────────────────────────────────────

class ClienteCreate(BaseModel):
    nombre: str = Field(..., min_length=1)
    dni_cuil: Optional[str] = None
    email: Optional[str] = None
    telefono: Optional[str] = None
    direccion: Optional[str] = None
    notas: Optional[str] = None

class ClienteUpdate(BaseModel):
    nombre: Optional[str] = None
    dni_cuil: Optional[str] = None
    email: Optional[str] = None
    telefono: Optional[str] = None
    direccion: Optional[str] = None
    notas: Optional[str] = None

class ClienteResponse(BaseModel):
    id: int
    nombre: str
    dni_cuil: Optional[str]
    email: Optional[str]
    telefono: Optional[str]
    direccion: Optional[str]
    notas: Optional[str]
    fecha_registro: Optional[str]


# ─── Pólizas ─────────────────────────────────────────────────────────────────

class PolizaCreate(BaseModel):
    cliente_id: int
    pas_matricula: Optional[str] = None
    compania: str = Field(..., min_length=1)
    ramo: str = Field(..., min_length=1)
    nro_poliza: str = Field(..., min_length=1)
    vigencia_desde: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    vigencia_hasta: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    prima: Optional[float] = 0.0
    premio: Optional[float] = 0.0
    comision_porcentaje: Optional[float] = 0.0
    estado_pago: Optional[str] = "Al día"
    estado: Optional[str] = "Vigente"
    notas: Optional[str] = None

class PolizaUpdate(PolizaCreate):
    pass

class PolizaResponse(BaseModel):
    id: int
    cliente_id: int
    cliente_nombre: Optional[str]
    pas_matricula: Optional[str]
    compania: str
    ramo: str
    nro_poliza: str
    vigencia_desde: str
    vigencia_hasta: str
    prima: Optional[float]
    premio: Optional[float]
    comision_porcentaje: Optional[float]
    comision_monto: Optional[float]
    estado_pago: Optional[str]
    estado: Optional[str]
    notas: Optional[str]
    fecha_registro: Optional[str]


# ─── Alertas ─────────────────────────────────────────────────────────────────

class AlertaResponse(BaseModel):
    id: int
    nro_poliza: str
    cliente_nombre: Optional[str]
    compania: Optional[str]
    ramo: Optional[str]
    vigencia_hasta: Optional[str]
    estado_pago: Optional[str]
    pas_matricula: Optional[str]
    premio: Optional[float]
    dias_restantes: Optional[int]
    tipo_alerta: str       # "vencimiento" | "impago"
    urgencia: int          # 0=impago, 1=≤15d, 2=≤30d, 3=≤60d


# ─── Métricas ────────────────────────────────────────────────────────────────

class MetricasERPResponse(BaseModel):
    premio_total: float
    prima_total: float
    polizas_vigentes: int
    comisiones_totales: float
    clientes_totales: int
    siniestros_abiertos: int
    ramos_distribucion: List[Any]
    companias_distribucion: List[Any]

class RankingProductorResponse(BaseModel):
    matricula: Optional[str]
    nombre: Optional[str]
    polizas_vigentes: Optional[int]
    premio_total: Optional[float]
    comisiones_estimadas: Optional[float]
    companias: Optional[str]


# ─── Acciones Mensuales ──────────────────────────────────────────────────────

class AccionCreate(BaseModel):
    tipo: str = Field(..., min_length=1, description="Tipo de acción (p.ej. 'Llamado', 'Reunión', 'Email')")
    descripcion: Optional[str] = ""
    estado: Optional[str] = "pendiente"
    mes: Optional[str] = None   # default = mes actual

class AccionUpdate(BaseModel):
    estado: str = Field(..., description="pendiente | completada | cancelada")
    descripcion: Optional[str] = ""

class AccionResponse(BaseModel):
    id: int
    mes: str
    tipo: str
    descripcion: Optional[str]
    estado: str
    fecha: Optional[str]


# ─── Siniestros ───────────────────────────────────────────────────────────────

class SiniestroCreate(BaseModel):
    poliza_id: int
    fecha_siniestro: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$",
                                 description="Formato YYYY-MM-DD")
    descripcion: Optional[str] = ""
    estado: Optional[str] = "En proceso"
    notas: Optional[str] = ""

class SiniestroUpdate(BaseModel):
    poliza_id: int
    fecha_siniestro: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    descripcion: Optional[str] = ""
    estado: str = Field(..., description="En proceso | Liquidado | Rechazado | Cerrado")
    notas: Optional[str] = ""

class SiniestroResponse(BaseModel):
    id: int
    poliza_id: int
    nro_poliza: Optional[str]
    cliente_nombre: Optional[str]
    fecha_siniestro: str
    descripcion: Optional[str]
    estado: str
    notas: Optional[str]
    fecha_registro: Optional[str]


# ─── Usuarios (Admin) ────────────────────────────────────────────────────────

class UsuarioCreate(BaseModel):
    usuario: str = Field(..., min_length=3)
    email: str
    password: str = Field(..., min_length=6)
    rol: Optional[str] = "agente"
    requiere_cambio: Optional[int] = 1
    matricula: Optional[str] = None

class UsuarioUpdate(BaseModel):
    usuario: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None
    rol: Optional[str] = None
    requiere_cambio: Optional[int] = None
    reset_lock: Optional[bool] = False
    matricula: Optional[str] = None

class UsuarioResponse(BaseModel):
    id: int
    usuario: Optional[str]
    email: Optional[str]
    rol: Optional[str]
    requiere_cambio: Optional[int]
    intentos_fallidos: Optional[int]
    bloqueado_hasta: Optional[int]
    matricula_asociada: Optional[str]


# ─── Logs de Auditoría ───────────────────────────────────────────────────────

class LogResponse(BaseModel):
    id: int
    fecha: Optional[str]
    usuario: Optional[str]
    accion: Optional[str]
    detalles: Optional[str]


# ─── PAS Compañías ───────────────────────────────────────────────────────────

class PASCompaniasUpdate(BaseModel):
    companias: str = Field(..., description="Listado de compañías separadas por coma")


# ─── Helpers ─────────────────────────────────────────────────────────────────

class MessageResponse(BaseModel):
    ok: bool
    message: str

class PaginatedPAS(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[PASListItem]


# ─── Licencias de Software ──────────────────────────────────────────────────

class LicenciaCreate(BaseModel):
    cliente: str
    email_cliente: str
    producto: str = "CRM"
    fecha_expiracion: str
    estado: str = "activa"
    limite_dispositivos: int = 1

class LicenciaUpdate(BaseModel):
    cliente: str
    fecha_expiracion: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    estado: str = Field(..., description="activa | expirada | suspendida")
    limite_dispositivos: int
    dispositivo_id: Optional[str] = None
    motivo: Optional[str] = None
    dispositivos_info: Optional[str] = None
    integraciones: Optional[str] = None

class LicenciaResponse(BaseModel):
    id: int
    clave: str
    cliente: str
    dispositivo_id: Optional[str] = None
    fecha_creacion: Optional[str] = None
    fecha_expiracion: str
    estado: str
    limite_dispositivos: int
    email_cliente: Optional[str] = None
    producto: Optional[str] = None
    dispositivos_info: Optional[str] = None
    motivo: Optional[str] = None
    integraciones: Optional[str] = None

class LicenciaValidarRequest(BaseModel):
    clave: str
    dispositivo_id: str
    email_cliente: str = ""
    dispositivo_nombre: str = ""

class LicenciaValidarResponse(BaseModel):
    valid: bool
    message: str
    cliente: str
    fecha_expiracion: str
    limite_dispositivos: Optional[int] = None


# ─── Configuración del Sistema ───────────────────────────────────────────────

class ConfigUpdateRequest(BaseModel):
    clave: str
    valor: str


class SoporteTicketRequest(BaseModel):
    nombre: str
    email: str
    telefono: Optional[str] = ""
    mensaje: str
    fingerprint: Optional[str] = None
    fecha: Optional[str] = None


