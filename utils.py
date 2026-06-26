"""
utils.py - Optimizado con índice pre-normalizado para búsqueda rápida
"""
import unicodedata
import re
from typing import List, Dict, Any, Optional, Tuple

# ---------------------------------------------------------------------------
# Columnas del CSV
# ---------------------------------------------------------------------------
COL_MATRICULA = "productor_matricula"
COL_TIPO_ID   = "productor_tipo_id"
COL_ID        = "productor_id"
COL_NOMBRE    = "productor_apellido_nombre"
COL_RAMO      = "ramo"

TABLE_COLUMNS = [COL_MATRICULA, COL_NOMBRE, COL_ID, COL_TIPO_ID, COL_RAMO]

COLUMN_LABELS: Dict[str, str] = {
    COL_MATRICULA: "Matrícula",
    COL_TIPO_ID:   "Tipo ID",
    COL_ID:        "CUIT / Doc.",
    COL_NOMBRE:    "Nombre / Apellido",
    COL_RAMO:      "Ramo",
}

DETAIL_ORDER = [COL_MATRICULA, COL_NOMBRE, COL_TIPO_ID, COL_ID, COL_RAMO]

RAMOS_FILTER = [None, "Patrimoniales y Vida", "Vida", "Articulo 19"]
RAMOS_LABELS = {
    None:                   "Todos los ramos",
    "Patrimoniales y Vida": "Patrimoniales y Vida",
    "Vida":                 "Solo Vida",
    "Articulo 19":          "Artículo 19",
}

MAX_RESULTS = 200
PAGE_SIZE   = 50   # Registros por página

EXTRA_COLS_NOTE = (
    "Domicilio, Email, Teléfono y Localidad no están en el CSV público. "
    "Consultá la matrícula individual en ssn.gov.ar para esos datos."
)

# ---------------------------------------------------------------------------
# Índice pre-normalizado — se construye UNA sola vez al cargar los datos
# Estructura: lista de (haystack_normalizado, ramo_normalizado, record)
# ---------------------------------------------------------------------------
_INDEX: List[Tuple[str, str, Dict[str, Any]]] = []


def normalize(text: str) -> str:
    if not text:
        return ""
    nfd = unicodedata.normalize("NFD", str(text))
    without_accents = "".join(c for c in nfd if unicodedata.category(c) != "Mn")
    return without_accents.lower().strip()


def build_index(records: List[Dict[str, Any]]) -> None:
    """
    Construye el índice de búsqueda. Llamar UNA vez después de cargar el CSV.
    Normaliza todos los campos de búsqueda por adelantado.
    """
    global _INDEX
    _INDEX = []
    for rec in records:
        haystack = " ".join([
            normalize(rec.get(COL_MATRICULA, "")),
            normalize(rec.get(COL_NOMBRE, "")),
            normalize(rec.get(COL_ID, "")),
            normalize(rec.get("provincia", "")),
            normalize(rec.get("localidad", "")),
        ])
        ramo_norm = normalize(rec.get(COL_RAMO, ""))
        _INDEX.append((haystack, ramo_norm, rec))


def fuzzy_filter(
    records: List[Dict[str, Any]],
    query: str,
    ramo_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    norm_query = normalize(query)
    norm_ramo  = normalize(ramo_filter) if ramo_filter else None

    # Si es numérico corto (<= 6 dígitos), asumimos que busca matrícula de forma específica
    es_matricula_query = norm_query.isdigit() and len(norm_query) <= 6

    results = []
    for haystack, ramo_norm, rec in _INDEX:
        if norm_ramo and ramo_norm != norm_ramo:
            continue
            
        if norm_query:
            if es_matricula_query:
                mat = normalize(rec.get(COL_MATRICULA, ""))
                if not (mat == norm_query or mat.startswith(norm_query)):
                    continue
            else:
                if norm_query not in haystack:
                    continue
                    
        results.append(rec)
    return results


def count_matches(
    records: List[Dict[str, Any]],
    query: str,
    ramo_filter: Optional[str] = None,
) -> int:
    norm_query = normalize(query)
    norm_ramo  = normalize(ramo_filter) if ramo_filter else None
    
    es_matricula_query = norm_query.isdigit() and len(norm_query) <= 6

    count = 0
    for haystack, ramo_norm, rec in _INDEX:
        if norm_ramo and ramo_norm != norm_ramo:
            continue
            
        if norm_query:
            if es_matricula_query:
                mat = normalize(rec.get(COL_MATRICULA, ""))
                if not (mat == norm_query or mat.startswith(norm_query)):
                    continue
            else:
                if norm_query not in haystack:
                    continue
        count += 1
    return count


def record_to_clipboard(record: Dict[str, Any]) -> str:
    lines = ["=== Productor Asesor de Seguros (SSN) ==="]
    for col in DETAIL_ORDER:
        label = COLUMN_LABELS.get(col, col)
        value = record.get(col, "—") or "—"
        if col == COL_ID:
            value = format_cuit(value)
        lines.append(f"{label}: {value}")
    
    extra_cols = [k for k in record.keys() if k not in DETAIL_ORDER and k not in ["productor_matricula", "productor_apellido_nombre", "productor_id", "productor_tipo_id", "ramo"]]
    for col in extra_cols:
        label = col.replace("_", " ").title()
        value = record.get(col, "—") or "—"
        lines.append(f"{label}: {value}")
        
    lines.append("")
    lines.append("Fuente: Superintendencia de Seguros de la Nación")
    lines.append("datosabiertos.ssn.gob.ar")
    return "\n".join(lines)


def format_cuit(cuit: str) -> str:
    digits = re.sub(r"\D", "", str(cuit))
    if len(digits) == 11:
        return f"{digits[:2]}-{digits[2:10]}-{digits[10]}"
    return cuit


def truncate(text: str, max_len: int = 40) -> str:
    if len(text) > max_len:
        return text[:max_len - 1] + "…"
    return text