"""
ssn_test.py — Scraper de Productores SSN con Capsolver y Cache SQLite
Busca productores por DNI/Matrícula:
1. Busca en el caché SQLite local (costo $0).
2. Busca en el CSV local (costo $0).
3. Si no existe en el CSV, busca en vivo en la SSN resolviendo el captcha (sólo para nuevos).
"""

import time
import requests
from bs4 import BeautifulSoup
import re
import sys
import os
import sqlite3
from typing import Optional, List, Dict, Any
# Optimize SQLite for minimal resource usage, WAL mode, memory temp store, cache size limiting.
_wal_initialized = False
_orig_sqlite_connect = sqlite3.connect
def _custom_sqlite_connect(*args, **kwargs):
    global _wal_initialized
    if "timeout" not in kwargs:
        kwargs["timeout"] = 30.0
    conn = _orig_sqlite_connect(*args, **kwargs)
    try:
        if not _wal_initialized:
            conn.execute("PRAGMA journal_mode = WAL;")
            _wal_initialized = True
        # NORMAL synchronous mode is faster and safe in WAL mode
        conn.execute("PRAGMA synchronous = NORMAL;")
        # Store temp tables in memory to avoid disk access
        conn.execute("PRAGMA temp_store = MEMORY;")
        # Limit memory cache to ~2MB to keep RAM footprint low when compiled to .exe
        conn.execute("PRAGMA cache_size = -2000;")
    except Exception:
        pass
    return conn
sqlite3.connect = _custom_sqlite_connect
import csv
import secrets
import string
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random

# ─── CONFIG ───────────────────────────────────────────────
CAPSOLVER_KEY = "CAP-C2E8606E5DE98E5692406D135A712F7F403B8D352CBAFD8F725543CD36EFD815"
SSN_URL       = "https://ssn.gob.ar/storage/registros/productores/productoresactivosfiltro.asp"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
]

def obtener_headers_seguros() -> dict:
    ua = random.choice(USER_AGENTS)
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "es-419,es;q=0.9,en;q=0.8,pt;q=0.7",
        "Referer": SSN_URL,
        "Origin": "https://ssn.gob.ar",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0"
    }
    if "Chrome/12" in ua:
        headers["Sec-Ch-Ua"] = '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"'
        headers["Sec-Ch-Ua-Mobile"] = "?0"
        headers["Sec-Ch-Ua-Platform"] = '"Windows"' if "Windows" in ua else ('"macOS"' if "Macintosh" in ua else '"Linux"')
    return headers

def obtener_proxies_activos() -> dict:
    proxies = {}
    http_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if http_proxy:
        proxies["http"] = http_proxy
    if https_proxy:
        proxies["https"] = https_proxy
    return proxies

DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "productores_scraped.db")
CSV_URL = "https://datosabiertos.ssn.gob.ar/dataset/be4927ba-6b6d-4cee-b33e-5319b33b15b8/resource/07de24f8-4191-497e-a0da-da83cf5eb5d9/download/productores-asesores.csv"
CSV_PATH_LOCAL = os.path.join(DB_DIR, "productores-asesores.csv")
CSV_PATH_ROOT = "productores-asesores.csv"


import hashlib

# Hashing de contraseñas con PBKDF2 y HMAC-SHA256 (100,000 iteraciones)
def hash_password(password: str, salt: bytes = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + ":" + key.hex()

def verify_password(stored_hash: str, password_to_check: str) -> bool:
    try:
        salt_hex, key_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        key = bytes.fromhex(key_hex)
        new_key = hashlib.pbkdf2_hmac('sha256', password_to_check.encode('utf-8'), salt, 100000)
        return secrets.compare_digest(key, new_key)
    except Exception:
        return False

# Registro de logs de auditoría en base de datos
def registrar_log(usuario: str, accion: str, detalles: str):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        # Asegurar que la tabla de logs exista
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs_auditoria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                usuario TEXT,
                accion TEXT,
                detalles TEXT
            )
        """)
        cursor.execute(
            "INSERT INTO logs_auditoria (usuario, accion, detalles) VALUES (?, ?, ?)",
            (usuario, accion, detalles)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error al registrar log de auditoría: {e}")


# ─── BASE DE DATOS SQLITE ─────────────────────────────────
def inicializar_db():
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS productores_detalle (
            matricula TEXT PRIMARY KEY,
            nombre TEXT,
            documento TEXT,
            cuit TEXT,
            ramo TEXT,
            provincia TEXT,
            telefono TEXT,
            email TEXT,
            resolucion TEXT,
            fecha_resolucion TEXT,
            scraped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Agregar columnas si no existen
    for col in [
        ("domicilio", "TEXT"), 
        ("localidad", "TEXT"), 
        ("cod_postal", "TEXT"),
        ("estado_contacto", "TEXT DEFAULT 'Sin contactar'"),
        ("observaciones", "TEXT"),
        ("companias", "TEXT"),
        ("sociedades", "TEXT")
    ]:
        try:
            cursor.execute(f"ALTER TABLE productores_detalle ADD COLUMN {col[0]} {col[1]}")
        except sqlite3.OperationalError:
            pass  # Ya existe la columna

    # Crear tabla de sociedades
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sociedades (
            matricula TEXT PRIMARY KEY,
            tipo_id TEXT,
            documento TEXT,
            denominacion TEXT,
            ramo TEXT
        )
    """)
    
    # Importar del CSV si está vacía
    cursor.execute("SELECT COUNT(*) FROM sociedades")
    if cursor.fetchone()[0] == 0:
        csv_path = "productores-asesores-sociedades.csv"
        if os.path.exists(csv_path):
            try:
                import csv
                with open(csv_path, encoding="utf-8", newline="") as f:
                    reader = csv.DictReader(f)
                    to_insert = []
                    for row in reader:
                        to_insert.append((
                            row.get("productores_sociedad_matricula", "").strip(),
                            row.get("productores_sociedad_tipo_id", "").strip(),
                            row.get("productores_sociedad_id", "").strip(),
                            row.get("productores_sociedad_denominacion", "").strip(),
                            row.get("ramo", "").strip()
                        ))
                    if to_insert:
                        cursor.executemany("""
                            INSERT OR IGNORE INTO sociedades (matricula, tipo_id, documento, denominacion, ramo)
                            VALUES (?, ?, ?, ?, ?)
                        """, to_insert)
            except Exception as e:
                print(f"Error al importar sociedades desde CSV: {e}")

    # Crear índices para mejorar el rendimiento de las consultas y reducir uso de CPU/IO
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_prod_estado ON productores_detalle(estado_contacto)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_prod_provincia ON productores_detalle(provincia)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_prod_localidad ON productores_detalle(localidad)")

    # Crear tabla de relación muchos a muchos productor_sociedad (Eloquent style)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS productor_sociedad (
            productor_matricula TEXT,
            sociedad_matricula TEXT,
            PRIMARY KEY (productor_matricula, sociedad_matricula),
            FOREIGN KEY (productor_matricula) REFERENCES productores_detalle(matricula) ON DELETE CASCADE,
            FOREIGN KEY (sociedad_matricula) REFERENCES sociedades(matricula) ON DELETE CASCADE
        )
    """)

    # Migrar datos existentes de la columna sociedades a la tabla intermedia
    cursor.execute("SELECT 1 FROM productor_sociedad LIMIT 1")
    if not cursor.fetchone():
        try:
            cursor.execute("SELECT matricula, sociedades FROM productores_detalle WHERE sociedades IS NOT NULL AND sociedades != ''")
            rows = cursor.fetchall()
            for p_mat, soc_str in rows:
                if not soc_str:
                    continue
                import re
                parts = soc_str.split(";") if ";" in soc_str else soc_str.split(",")
                for part in parts:
                    match = re.search(r"\(Mat:\s*(\d+)\)", part)
                    if match:
                        s_mat = match.group(1).strip()
                        cursor.execute("""
                            INSERT OR IGNORE INTO productor_sociedad (productor_matricula, sociedad_matricula)
                            VALUES (?, ?)
                        """, (p_mat, s_mat))
        except Exception as e:
            print(f"Error al migrar sociedades a tabla intermedia: {e}")

    # Crear tabla de usuarios para login
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT,
            requiere_cambio INTEGER DEFAULT 0,
            intentos_fallidos INTEGER DEFAULT 0,
            bloqueado_hasta INTEGER DEFAULT 0
        )
    """)
    
    # Asegurar que la columna usuario exista por si la tabla ya existía
    try:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN usuario TEXT")
    except sqlite3.OperationalError:
        pass

    # Asegurar que la columna requiere_cambio exista por si la tabla ya existía
    try:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN requiere_cambio INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass

    # Asegurar que las columnas de lockout existan
    try:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN intentos_fallidos INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN bloqueado_hasta INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass

    # Asegurar columna rol en usuarios
    try:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN rol TEXT DEFAULT 'agente'")
    except sqlite3.OperationalError:
        pass

    # Asegurar columna username_changed en usuarios
    try:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN username_changed INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass

    # Asegurar columna usuario_id en productores_detalle
    try:
        cursor.execute("ALTER TABLE productores_detalle ADD COLUMN usuario_id INTEGER")
    except sqlite3.OperationalError:
        pass

    # Asegurar tabla permisos_visibilidad
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS permisos_visibilidad (
            usuario_lector_id INTEGER,
            usuario_propietario_id INTEGER,
            PRIMARY KEY (usuario_lector_id, usuario_propietario_id),
            FOREIGN KEY (usuario_lector_id) REFERENCES usuarios(id) ON DELETE CASCADE,
            FOREIGN KEY (usuario_propietario_id) REFERENCES usuarios(id) ON DELETE CASCADE
        )
    """)

    # Asegurar que la tabla de logs exista
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs_auditoria (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            usuario TEXT,
            accion TEXT,
            detalles TEXT
        )
    """)

    # ── Módulo Gestión Comercial ──────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS visitas_pas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mes TEXT NOT NULL,
            matricula TEXT,
            nombre TEXT NOT NULL,
            estado TEXT DEFAULT 'pendiente',
            productividad TEXT DEFAULT '',
            estado_org TEXT DEFAULT '',
            campaña TEXT DEFAULT '',
            fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Migrar columnas faltantes por si la tabla ya existe
    for col in [("campaña", "TEXT DEFAULT ''"), ("productividad", "TEXT DEFAULT ''"), ("estado_org", "TEXT DEFAULT ''")]:
        try:
            cursor.execute(f"ALTER TABLE visitas_pas ADD COLUMN {col[0]} {col[1]}")
        except Exception:
            pass

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS candidatos_captacion (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mes TEXT NOT NULL,
            nombre TEXT NOT NULL,
            matricula TEXT DEFAULT '',
            tiene_cartera INTEGER DEFAULT 0,
            estado TEXT DEFAULT 'candidato',
            notas TEXT DEFAULT '',
            fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    for col in [("tiene_cartera", "INTEGER DEFAULT 0"), ("notas", "TEXT DEFAULT ''")]:
        try:
            cursor.execute(f"ALTER TABLE candidatos_captacion ADD COLUMN {col[0]} {col[1]}")
        except Exception:
            pass

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS acciones_mensuales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mes TEXT NOT NULL,
            tipo TEXT NOT NULL,
            descripcion TEXT DEFAULT '',
            estado TEXT DEFAULT 'pendiente',
            fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS actividades_comerciales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mes TEXT NOT NULL,
            fecha_actividad TEXT,
            matricula TEXT DEFAULT '',
            nombre TEXT NOT NULL,
            tipo TEXT NOT NULL,
            compania TEXT DEFAULT '',
            observaciones TEXT DEFAULT '',
            fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ── Módulo ERP de Cartera y Operaciones ─────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS clientes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            dni_cuil TEXT UNIQUE,
            email TEXT,
            telefono TEXT,
            direccion TEXT,
            notas TEXT,
            fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS polizas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cliente_id INTEGER NOT NULL,
            pas_matricula TEXT,
            compania TEXT NOT NULL,
            ramo TEXT NOT NULL,
            nro_poliza TEXT NOT NULL,
            vigencia_desde TEXT NOT NULL,
            vigencia_hasta TEXT NOT NULL,
            prima REAL DEFAULT 0.0,
            premio REAL DEFAULT 0.0,
            comision_porcentaje REAL DEFAULT 0.0,
            comision_monto REAL DEFAULT 0.0,
            estado_pago TEXT DEFAULT 'Al día',
            estado TEXT DEFAULT 'Vigente',
            notas TEXT,
            fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (cliente_id) REFERENCES clientes(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS siniestros (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            poliza_id INTEGER NOT NULL,
            fecha_siniestro TEXT NOT NULL,
            descripcion TEXT,
            estado TEXT DEFAULT 'En proceso',
            notas TEXT,
            fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (poliza_id) REFERENCES polizas(id) ON DELETE CASCADE
        )
    """)

    # Crear tabla de licencias de software
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS licencias (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            clave TEXT UNIQUE NOT NULL,
            cliente TEXT NOT NULL,
            dispositivo_id TEXT,
            fecha_creacion TEXT DEFAULT (datetime('now', 'localtime')),
            fecha_expiracion TEXT NOT NULL,
            estado TEXT DEFAULT 'activa',
            limite_dispositivos INTEGER DEFAULT 1
        )
    """)

    # Insertar licencia de prueba por defecto si no hay licencias
    cursor.execute("SELECT COUNT(*) FROM licencias")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO licencias (clave, cliente, fecha_expiracion, estado, limite_dispositivos)
            VALUES (?, ?, ?, ?, ?)
        """, ("KTX-TEST-VALID-2026", "Cliente Prueba", "2030-12-31", "activa", 2))
    # ─────────────────────────────────────────────────────────────────────

    # Insertar usuarios por defecto si no existen
    for u, e, p, r in [
        ("broker", "broker@katrix.com", "password123", "admin"),
    ]:
        cursor.execute("SELECT COUNT(*) FROM usuarios WHERE email = ?", (e,))
        if cursor.fetchone()[0] == 0:
            hashed_p = hash_password(p)
            cursor.execute("INSERT INTO usuarios (usuario, email, password, requiere_cambio, rol) VALUES (?, ?, ?, 0, ?)", (u, e, hashed_p, r))
        else:
            # Si ya existía por email, asegurar que tenga el usuario asignado
            cursor.execute("UPDATE usuarios SET usuario = ?, rol = ? WHERE email = ? AND (usuario IS NULL OR usuario = '')", (u, r, e))
            # Si la contraseña no está hasheada (no contiene ":"), hashearla para actualizar seguridad
            cursor.execute("SELECT password FROM usuarios WHERE email = ?", (e,))
            curr_p = cursor.fetchone()[0]
            if curr_p and ":" not in curr_p:
                hashed_p = hash_password(curr_p)
                cursor.execute("UPDATE usuarios SET password = ? WHERE email = ?", (hashed_p, e))

    # Carga de Semilla de Datos ERP
    cursor.execute("SELECT COUNT(*) FROM clientes")
    if cursor.fetchone()[0] == 0:
        cursor.execute("SELECT matricula FROM productores_detalle LIMIT 3")
        mats = [r[0] for r in cursor.fetchall()]
        while len(mats) < 3:
            mats.append(f"M-{len(mats)+70000}")
            
        dummy_clients = [
            ("Juan Pérez", "20-34567890-9", "juan.perez@gmail.com", "11-4567-8901", "Av. Cabildo 1540, CABA", "Cliente desde 2024. Prefiere contacto por WhatsApp."),
            ("María Rodríguez", "27-40123456-8", "maria.rod@hotmail.com", "261-987-6543", "San Martín 450, Mendoza", "Interesada en seguros de Vida."),
            ("Carlos González", "20-22334455-6", "carlos.gonzalez@empresa.com", "351-555-0199", "Colón 120, Córdoba", "Director de Pyme local."),
            ("Sofía Martínez", "27-38445566-1", "sofia.m@gmail.com", "11-2345-6789", "Corrientes 890, CABA", "Cliente con múltiples vehículos."),
            ("Estudio Contable ASOC", "30-71556677-9", "contacto@estudioasoc.com", "341-480-1234", "Pellegrini 1400, Rosario", "Cuenta corporativa. Pólizas de Comercio.")
        ]
        for c in dummy_clients:
            cursor.execute("INSERT INTO clientes (nombre, dni_cuil, email, telefono, direccion, notas) VALUES (?, ?, ?, ?, ?, ?)", c)
            
        dummy_policies = [
            (1, mats[0], "San Cristóbal", "Automotor", "POL-98765", "2026-01-15", "2027-01-15", 120000.0, 150000.0, 15.0, 22500.0, "Al día", "Vigente", "Toyota Corolla 2022. Cobertura Todo Riesgo."),
            (1, mats[0], "Allianz", "Hogar", "POL-11223", "2026-03-01", "2027-03-01", 35000.0, 45000.0, 20.0, 9000.0, "Al día", "Vigente", "Casa de familia en Olivos. Robo e Incendio."),
            (2, mats[1], "Sancor", "Vida", "POL-44556", "2026-02-10", "2027-02-10", 60000.0, 70000.0, 25.0, 17500.0, "Al día", "Vigente", "Seguro de vida individual con capital capitalizable."),
            (3, mats[2], "San Cristóbal", "Integral de Comercio", "POL-77889", "2026-05-01", "2027-05-01", 200000.0, 260000.0, 18.0, 46800.0, "Financiada", "Vigente", "Oficinas comerciales. Adicional robo de valores."),
            (4, mats[0], "Federación Patronal", "Automotor", "POL-33445", "2025-06-01", "2026-06-01", 90000.0, 110000.0, 15.0, 16500.0, "Impaga", "Vigente", "Ford Focus 2018. Responsabilidad Civil."),
            (5, mats[1], "Allianz", "ART", "POL-55667", "2026-04-15", "2027-04-15", 300000.0, 380000.0, 10.0, 38000.0, "Al día", "Vigente", "Contrato ART para empleados administrativos.")
        ]
        for p in dummy_policies:
            cursor.execute("""
                INSERT INTO polizas (cliente_id, pas_matricula, compania, ramo, nro_poliza, vigencia_desde, vigencia_hasta, prima, premio, comision_porcentaje, comision_monto, estado_pago, estado, notas)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, p)
            
        dummy_claims = [
            (1, "2026-05-10", "Choque menor en la vía pública (esquina). Daño en paragolpes trasero. Repuestos autorizados.", "En proceso", "Taller oficial Toyota en proceso de reparación."),
            (6, "2026-06-02", "Accidente in-itinere de empleado. Esguince de tobillo. Asistencia médica brindada.", "Liquidado", "Caso cerrado. Alta médica otorgada.")
        ]
        for cl in dummy_claims:
            # Seguro que el policy ID exista. El sexto es de Allianz ART (ID 6)
            cursor.execute("INSERT INTO siniestros (poliza_id, fecha_siniestro, descripcion, estado, notas) VALUES (?, ?, ?, ?, ?)", cl)
        
    conn.commit()
    conn.close()

    # Auto-importar desde la planilla Excel si la tabla está vacía y el archivo existe
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM actividades_comerciales")
        count = cursor.fetchone()[0]
        conn.close()
        if count == 0:
            excel_name = "PLANILLA SEGUIMIENTO REUNION Y LLAMADOS.xlsx"
            if os.path.exists(excel_name):
                print(f"Auto-importando actividades desde {excel_name}...")
                res = importar_actividades_desde_excel(excel_name)
                print(res.get("message", ""))
    except Exception as e:
        print(f"Error al auto-importar actividades: {e}")



# ── CRUD Visitas PAS ─────────────────────────────────────────────────────
def obtener_mes_actual() -> str:
    from datetime import datetime
    return datetime.now().strftime("%Y-%m")

def obtener_visitas(mes: str = None) -> list:
    if mes is None:
        mes = obtener_mes_actual()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM visitas_pas WHERE mes = ? ORDER BY nombre ASC", (mes,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def guardar_visita(mes: str, matricula: str, nombre: str, estado: str = "pendiente",
                   productividad: str = "", estado_org: str = "", campaña: str = "") -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO visitas_pas (mes, matricula, nombre, estado, productividad, estado_org, campaña)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (mes, matricula, nombre, estado, productividad, estado_org, campaña))
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id

def actualizar_visita(visita_id: int, estado: str, productividad: str = "", estado_org: str = "", campaña: str = "") -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE visitas_pas SET estado=?, productividad=?, estado_org=?, campaña=? WHERE id=?
    """, (estado, productividad, estado_org, campaña, visita_id))
    ok = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return ok

def eliminar_visita(visita_id: int) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM visitas_pas WHERE id=?", (visita_id,))
    ok = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return ok


# ── CRUD Candidatos Captación ─────────────────────────────────────────────
def obtener_candidatos(mes: str = None) -> list:
    if mes is None:
        mes = obtener_mes_actual()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM candidatos_captacion WHERE mes = ? ORDER BY nombre ASC", (mes,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def guardar_candidato(mes: str, nombre: str, matricula: str = "", tiene_cartera: int = 0,
                      estado: str = "candidato", notas: str = "") -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO candidatos_captacion (mes, nombre, matricula, tiene_cartera, estado, notas)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (mes, nombre, matricula, tiene_cartera, estado, notas))
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id

def actualizar_candidato(cand_id: int, estado: str, notas: str = "", tiene_cartera: int = 0) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE candidatos_captacion SET estado=?, notas=?, tiene_cartera=? WHERE id=?
    """, (estado, notas, tiene_cartera, cand_id))
    ok = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return ok

def eliminar_candidato(cand_id: int) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM candidatos_captacion WHERE id=?", (cand_id,))
    ok = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return ok


# ── CRUD Acciones Mensuales ───────────────────────────────────────────────
def obtener_acciones(mes: str = None) -> list:
    if mes is None:
        mes = obtener_mes_actual()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM acciones_mensuales WHERE mes = ? ORDER BY tipo ASC", (mes,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def guardar_accion(mes: str, tipo: str, descripcion: str = "", estado: str = "pendiente") -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO acciones_mensuales (mes, tipo, descripcion, estado)
        VALUES (?, ?, ?, ?)
    """, (mes, tipo, descripcion, estado))
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id

def actualizar_accion(accion_id: int, estado: str, descripcion: str = "") -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE acciones_mensuales SET estado=?, descripcion=? WHERE id=?", (estado, descripcion, accion_id))
    ok = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return ok

def eliminar_accion(accion_id: int) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM acciones_mensuales WHERE id=?", (accion_id,))
    ok = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return ok


# ── CRUD Actividades Comerciales (Llamados y Reuniones de Planilla Excel) ──

def guardar_actividad_comercial(mes: str, fecha_actividad: str, matricula: str, nombre: str, tipo: str, compania: str = "", observaciones: str = "") -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Check if duplicate exists
    cursor.execute("""
        SELECT id FROM actividades_comerciales 
        WHERE fecha_actividad = ? AND nombre = ? AND tipo = ?
    """, (fecha_actividad, nombre, tipo))
    exists = cursor.fetchone()
    if exists:
        conn.close()
        return exists[0]
        
    cursor.execute("""
        INSERT INTO actividades_comerciales (mes, fecha_actividad, matricula, nombre, tipo, compania, observaciones)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (mes, fecha_actividad, matricula, nombre, tipo, compania, observaciones))
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id

def obtener_actividades_comerciales(mes: str = None) -> list:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    if mes:
        cursor.execute("SELECT * FROM actividades_comerciales WHERE mes = ? ORDER BY fecha_actividad DESC, id DESC", (mes,))
    else:
        cursor.execute("SELECT * FROM actividades_comerciales ORDER BY fecha_actividad DESC, id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def eliminar_actividad_comercial(actividad_id: int) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM actividades_comerciales WHERE id = ?", (actividad_id,))
    ok = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return ok

def importar_actividades_desde_excel(file_path: str) -> dict:
    import zipfile
    import xml.etree.ElementTree as ET
    
    if not os.path.exists(file_path):
        return {"success": False, "message": f"El archivo '{file_path}' no existe en la carpeta."}
        
    try:
        with zipfile.ZipFile(file_path) as z:
            shared_strings = []
            if 'xl/sharedStrings.xml' in z.namelist():
                with z.open('xl/sharedStrings.xml') as f:
                    tree = ET.parse(f)
                    root = tree.getroot()
                    ns = {'ns': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
                    for t in root.findall('.//ns:t', ns):
                        shared_strings.append(t.text if t.text else '')

            if 'xl/worksheets/sheet3.xml' not in z.namelist():
                return {"success": False, "message": "No se encontró la hoja BASE DATOS PAS en el archivo."}

            with z.open('xl/worksheets/sheet3.xml') as f:
                tree = ET.parse(f)
                root = tree.getroot()
                ns = {'ns': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
                rows = root.findall('.//ns:row', ns)
                
                if len(rows) < 6:
                    return {"success": False, "message": "La hoja no tiene suficientes filas de datos."}
                    
                row5 = rows[4]
                row6 = rows[5]
                
                months_dict = {}
                for c in row5.findall('ns:c', ns):
                    cell_ref = c.attrib.get('r')
                    col_letter = ''.join([char for char in cell_ref if char.isalpha()])
                    val_tag = c.find('ns:v', ns)
                    val = val_tag.text if val_tag is not None else ''
                    if c.attrib.get('t') == 's' and val.isdigit():
                        val = shared_strings[int(val)]
                    if val.strip():
                        months_dict[col_letter] = val.strip()
                        
                def col_idx_to_letter(idx):
                    letter = ''
                    while idx > 0:
                        idx, remainder = divmod(idx - 1, 26)
                        letter = chr(65 + remainder) + letter
                    return letter
                    
                col_letters = [col_idx_to_letter(i) for i in range(8, 200)]
                
                col_to_month = {}
                current_month = 'ABRIL'
                for col in col_letters:
                    if col in months_dict:
                        current_month = months_dict[col]
                    col_to_month[col] = current_month
                    
                col_to_day = {}
                for c in row6.findall('ns:c', ns):
                    cell_ref = c.attrib.get('r')
                    col_letter = ''.join([char for char in cell_ref if char.isalpha()])
                    val_tag = c.find('ns:v', ns)
                    val = val_tag.text if val_tag is not None else ''
                    if c.attrib.get('t') == 's' and val.isdigit():
                        val = shared_strings[int(val)]
                    if val.strip():
                        col_to_day[col_letter] = val.strip()

                month_mapping = {
                    'ABRIL': '04',
                    'MAYO': '05',
                    'JUNIO': '06',
                    'JULIO': '07',
                    'AGOSTO': '08',
                    'SETIEMBRE': '09'
                }

                imported_count = 0
                for r in rows[6:]:
                    r_vals = {}
                    for c in r.findall('ns:c', ns):
                        cell_type = c.attrib.get('t')
                        val_tag = c.find('ns:v', ns)
                        val = val_tag.text if val_tag is not None else ''
                        if cell_type == 's' and val.isdigit():
                            val = shared_strings[int(val)]
                        col_name = ''.join([char for char in c.attrib.get('r') if char.isalpha()])
                        r_vals[col_name] = val
                        
                    name = r_vals.get('B', '').strip()
                    if name and name != 'Nombre Productor' and not name.startswith('Total'):
                        comp = r_vals.get('C', '').strip()
                        for col, val in r_vals.items():
                            if col in col_to_month and val in ['1', '2']:
                                m_name = col_to_month[col]
                                m_num = month_mapping.get(m_name, '01')
                                day_str = col_to_day.get(col, '01')
                                if len(day_str) == 1:
                                    day_str = '0' + day_str
                                date_str = f"2024-{m_num}-{day_str}"
                                mes_str = f"2024-{m_num}"
                                act_type = 'Llamado' if val == '1' else 'Reunión'
                                
                                # Find if there is a matricula in the DB for this name
                                conn_find = sqlite3.connect(DB_PATH)
                                cursor_find = conn_find.cursor()
                                cursor_find.execute("SELECT matricula FROM productores_detalle WHERE nombre LIKE ? LIMIT 1", (f"%{name}%",))
                                mat_row = cursor_find.fetchone()
                                mat = mat_row[0] if mat_row else ""
                                conn_find.close()
                                
                                # Save it
                                guardar_actividad_comercial(
                                    mes=mes_str,
                                    fecha_actividad=date_str,
                                    matricula=mat,
                                    nombre=name,
                                    tipo=act_type,
                                    compania=comp
                                )
                                imported_count += 1
                                
                return {"success": True, "count": imported_count, "message": f"Se importaron {imported_count} actividades con éxito."}
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"success": False, "message": f"Error al leer planilla: {e}"}




def obtener_de_db(identificador: str, user_id: int = None, role: str = None) -> dict | None:
    """Busca en el caché local de nuevos productores por matrícula, documento o cuit con filtrado de roles."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    id_limpio = re.sub(r"\D", "", identificador)
    
    if role == "agente" and user_id is not None:
        cursor.execute("""
            SELECT * FROM productores_detalle 
            WHERE (matricula = ? OR documento = ? OR cuit = ? OR REPLACE(cuit, '-', '') = ? OR REPLACE(documento, '-', '') = ?)
              AND (usuario_id = ? OR usuario_id IN (SELECT usuario_propietario_id FROM permisos_visibilidad WHERE usuario_lector_id = ?) OR usuario_id IS NULL)
        """, (identificador, identificador, identificador, id_limpio, id_limpio, user_id, user_id))
    else:
        cursor.execute("""
            SELECT * FROM productores_detalle 
            WHERE matricula = ? OR documento = ? OR cuit = ? OR REPLACE(cuit, '-', '') = ? OR REPLACE(documento, '-', '') = ?
        """, (identificador, identificador, identificador, id_limpio, id_limpio))
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        res = dict(row)
        # Fetch associated societies from the junction table (Many-to-Many relational "Eloquent" style)
        conn = sqlite3.connect(DB_PATH)
        cursor2 = conn.cursor()
        cursor2.execute("""
            SELECT s.denominacion, s.matricula 
            FROM sociedades s
            JOIN productor_sociedad ps ON s.matricula = ps.sociedad_matricula
            WHERE ps.productor_matricula = ?
            ORDER BY s.denominacion ASC
        """, (res["matricula"],))
        soc_rows = cursor2.fetchall()
        conn.close()
        
        soc_list = [f"{s[0]} (Mat: {s[1]})" for s in soc_rows]
        res["sociedades"] = "; ".join(soc_list)
        return res
    return None


def guardar_en_db(datos: dict, user_id: int = None):
    if not datos or not datos.get("matricula"):
        return
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Preservar o definir estado de contacto, observaciones, usuario_id, domicilio, localidad y cod_postal
    matricula = datos.get("matricula")
    cursor.execute("""
        SELECT estado_contacto, observaciones, usuario_id, domicilio, localidad, cod_postal 
        FROM productores_detalle WHERE matricula = ?
    """, (matricula,))
    res = cursor.fetchone()
    
    existing_estado = res[0] if res else None
    existing_obs = res[1] if res else None
    existing_user_id = res[2] if res else None
    existing_dom = res[3] if res else None
    existing_loc = res[4] if res else None
    existing_cp = res[5] if res else None
    
    estado = datos.get("estado_contacto") or existing_estado or "Sin contactar"
    obs = datos.get("observaciones") or existing_obs
    final_user_id = existing_user_id if existing_user_id is not None else user_id
    
    domicilio = datos.get("domicilio") or existing_dom
    localidad = datos.get("localidad") or existing_loc
    cod_postal = datos.get("cod_postal") or existing_cp
    
    cursor.execute("""
        INSERT OR REPLACE INTO productores_detalle (
            matricula, nombre, documento, cuit, ramo, provincia, telefono, email, 
            resolucion, fecha_resolucion, domicilio, localidad, cod_postal, estado_contacto, observaciones, usuario_id, scraped_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    """, (
        datos.get("matricula"),
        datos.get("nombre"),
        datos.get("documento"),
        datos.get("cuit"),
        datos.get("ramo"),
        datos.get("provincia"),
        datos.get("telefono"),
        datos.get("email"),
        datos.get("resolucion"),
        datos.get("fecha_resolucion"),
        domicilio,
        localidad,
        cod_postal,
        estado,
        obs,
        final_user_id
    ))
    conn.commit()
    conn.close()


def obtener_total_cached() -> int:
    if not os.path.exists(DB_PATH):
        return 0
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM productores_detalle")
        count = cursor.fetchone()[0]
        conn.close()
        return count
    except Exception:
        return 0


def obtener_todos_db(user_id: int = None, role: str = None) -> list[dict]:
    """Retorna todos los productores en el cache SQLite con filtrado de roles."""
    if not os.path.exists(DB_PATH):
        return []
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        # High performance query utilizing LEFT JOIN and GROUP_CONCAT to fetch all associated societies in a single trip (Eloquent style)
        if role == "agente" and user_id is not None:
            cursor.execute("""
                SELECT p.matricula, p.nombre, p.documento, p.cuit, p.ramo, p.provincia, p.telefono, p.email, 
                       p.resolucion, p.fecha_resolucion, p.scraped_at, p.domicilio, p.localidad, p.cod_postal, 
                       p.estado_contacto, p.observaciones, p.companias, p.usuario_id,
                       GROUP_CONCAT(s.denominacion || ' (Mat: ' || s.matricula || ')', '; ') as sociedades
                FROM productores_detalle p
                LEFT JOIN productor_sociedad ps ON p.matricula = ps.productor_matricula
                LEFT JOIN sociedades s ON ps.sociedad_matricula = s.matricula
                WHERE p.usuario_id = ? 
                   OR p.usuario_id IN (SELECT usuario_propietario_id FROM permisos_visibilidad WHERE usuario_lector_id = ?)
                   OR p.usuario_id IS NULL
                GROUP BY p.matricula
            """, (user_id, user_id))
        else:
            cursor.execute("""
                SELECT p.matricula, p.nombre, p.documento, p.cuit, p.ramo, p.provincia, p.telefono, p.email, 
                       p.resolucion, p.fecha_resolucion, p.scraped_at, p.domicilio, p.localidad, p.cod_postal, 
                       p.estado_contacto, p.observaciones, p.companias, p.usuario_id,
                       GROUP_CONCAT(s.denominacion || ' (Mat: ' || s.matricula || ')', '; ') as sociedades
                FROM productores_detalle p
                LEFT JOIN productor_sociedad ps ON p.matricula = ps.productor_matricula
                LEFT JOIN sociedades s ON ps.sociedad_matricula = s.matricula
                GROUP BY p.matricula
            """)
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"Error al obtener todos de la DB: {e}")
        return []


def obtener_cartera_db(user_id: int = None, role: str = None) -> list[dict]:
    """Retorna únicamente los productores calificados para la cartera (con actividad, pólizas o asignados)."""
    if not os.path.exists(DB_PATH):
        return []
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Filtro de cartera: estado de contacto activo, con pólizas, en visitas, en candidatos, o asignado a un usuario
        # Se requiere nombre válido para no tener vacíos al principio y restringir a Mendoza y San Juan.
        cartera_filter = """
            (
                (p.estado_contacto NOT IN ('Sin contactar', 'Sin contacto', '') AND p.estado_contacto IS NOT NULL)
                OR p.usuario_id IS NOT NULL
                OR p.matricula IN (SELECT DISTINCT pas_matricula FROM polizas)
                OR p.matricula IN (SELECT DISTINCT matricula FROM visitas_pas)
                OR p.matricula IN (SELECT DISTINCT matricula FROM candidatos_captacion)
            )
            AND p.nombre IS NOT NULL AND p.nombre != '' AND p.nombre != '—'
            AND UPPER(p.provincia) IN ('MENDOZA', 'SAN JUAN')
        """
        
        if role == "agente" and user_id is not None:
            cursor.execute(f"""
                SELECT p.matricula, p.nombre, p.documento, p.cuit, p.ramo, p.provincia, p.telefono, p.email, 
                       p.resolucion, p.fecha_resolucion, p.scraped_at, p.domicilio, p.localidad, p.cod_postal, 
                       p.estado_contacto, p.observaciones, p.companias, p.usuario_id,
                       GROUP_CONCAT(s.denominacion || ' (Mat: ' || s.matricula || ')', '; ') as sociedades
                FROM productores_detalle p
                LEFT JOIN productor_sociedad ps ON p.matricula = ps.productor_matricula
                LEFT JOIN sociedades s ON ps.sociedad_matricula = s.matricula
                WHERE (
                    p.usuario_id = ? 
                    OR p.usuario_id IN (SELECT usuario_propietario_id FROM permisos_visibilidad WHERE usuario_lector_id = ?)
                    OR p.usuario_id IS NULL
                )
                AND ({cartera_filter})
                GROUP BY p.matricula
            """, (user_id, user_id))
        else:
            cursor.execute(f"""
                SELECT p.matricula, p.nombre, p.documento, p.cuit, p.ramo, p.provincia, p.telefono, p.email, 
                       p.resolucion, p.fecha_resolucion, p.scraped_at, p.domicilio, p.localidad, p.cod_postal, 
                       p.estado_contacto, p.observaciones, p.companias, p.usuario_id,
                       GROUP_CONCAT(s.denominacion || ' (Mat: ' || s.matricula || ')', '; ') as sociedades
                FROM productores_detalle p
                LEFT JOIN productor_sociedad ps ON p.matricula = ps.productor_matricula
                LEFT JOIN sociedades s ON ps.sociedad_matricula = s.matricula
                WHERE {cartera_filter}
                GROUP BY p.matricula
            """)
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"Error al obtener cartera de la DB: {e}")
        return []



def verificar_login_status(usuario: str, password_txt: str) -> tuple[bool, bool, str, str | None, int | None]:
    """Retorna (login_exitoso, requiere_cambio, mensaje_error, rol, user_id)."""
    if not usuario or not password_txt:
        return False, False, "Usuario y contraseña requeridos", None, None
    
    usuario_clean = usuario.strip().lower()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password, requiere_cambio, intentos_fallidos, bloqueado_hasta, email, rol, id FROM usuarios WHERE usuario = ? OR email = ?", 
        (usuario_clean, usuario_clean)
    )
    res = cursor.fetchone()
    
    if not res:
        conn.close()
        registrar_log(usuario_clean, "LOGIN_FAILED", "Usuario no encontrado")
        time.sleep(0.5)  # Anti timing attack delay
        return False, False, "Usuario o contraseña incorrectos", None, None
        
    stored_pass, requiere_cambio, intentos, bloqueado_hasta, email, rol, user_id = res
    now = int(time.time())
    
    # Verificar bloqueo temporal
    if bloqueado_hasta and now < bloqueado_hasta:
        conn.close()
        time_left = bloqueado_hasta - now
        registrar_log(usuario_clean, "LOGIN_BLOCKED", f"Intento en cuenta bloqueada. Expira en {time_left}s")
        return False, False, f"Cuenta bloqueada temporalmente. Intente en {time_left} segundos.", None, None
        
    # Verificar contraseña usando helper de hashing
    if verify_password(stored_pass, password_txt.strip()):
        # Login exitoso: reiniciar contadores
        cursor.execute(
            "UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = 0 WHERE usuario = ? OR email = ?",
            (usuario_clean, usuario_clean)
        )
        conn.commit()
        conn.close()
        registrar_log(usuario_clean, "LOGIN_SUCCESS", "Inicio de sesión exitoso")
        return True, bool(requiere_cambio), "", rol, user_id
    else:
        # Fallo de contraseña
        nuevos_intentos = (intentos or 0) + 1
        nuevo_bloqueo = 0
        mensaje = "Usuario o contraseña incorrectos"
        
        if nuevos_intentos >= 5:
            nuevo_bloqueo = now + 30  # Bloquear por 30 segundos
            mensaje = "Cuenta bloqueada temporalmente por 30 segundos debido a reiterados intentos fallidos."
            registrar_log(usuario_clean, "LOGIN_LOCKED", "Cuenta bloqueada por superar intentos fallidos")
        else:
            registrar_log(usuario_clean, "LOGIN_FAILED", f"Intento fallido #{nuevos_intentos}")
            
        cursor.execute(
            "UPDATE usuarios SET intentos_fallidos = ?, bloqueado_hasta = ? WHERE usuario = ? OR email = ?",
            (nuevos_intentos, nuevo_bloqueo, usuario_clean, usuario_clean)
        )
        conn.commit()
        conn.close()
        time.sleep(0.5)  # Anti brute-force delay
        return False, False, mensaje, None, None


def verificar_login(usuario: str, password_txt: str) -> bool:
    success, _, _, _, _ = verificar_login_status(usuario, password_txt)
    return success


def actualizar_password(usuario: str, nueva_pass: str) -> bool:
    if not usuario or not nueva_pass:
        return False
    hashed = hash_password(nueva_pass.strip())
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE usuarios SET password = ?, requiere_cambio = 0, intentos_fallidos = 0, bloqueado_hasta = 0 WHERE usuario = ? OR email = ?", 
        (hashed, usuario.strip().lower(), usuario.strip().lower())
    )
    changed = cursor.rowcount > 0
    conn.commit()
    conn.close()
    if changed:
        registrar_log(usuario.strip().lower(), "PASSWORD_CHANGED", "Contraseña actualizada exitosamente")
    return changed


def generar_password_provisorio(usuario: str) -> tuple[str, str] | None:
    """Genera contraseña provisoria. Retorna (temp_pass, email) si el usuario existe, sino None."""
    if not usuario:
        return None
    chars = string.ascii_letters + string.digits
    # Contraseña provisoria segura de 10 caracteres
    temp_pass = "TEMP-" + "".join(secrets.choice(chars) for _ in range(8))
    hashed = hash_password(temp_pass)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM usuarios WHERE usuario = ? OR email = ?", (usuario.strip().lower(), usuario.strip().lower()))
    res = cursor.fetchone()
    if not res:
        conn.close()
        return None
        
    email = res[0]
    cursor.execute(
        "UPDATE usuarios SET password = ?, requiere_cambio = 1, intentos_fallidos = 0, bloqueado_hasta = 0 WHERE usuario = ? OR email = ?", 
        (hashed, usuario.strip().lower(), usuario.strip().lower())
    )
    conn.commit()
    conn.close()
    registrar_log(usuario.strip().lower(), "PASSWORD_RESET_REQUESTED", f"Generada contraseña provisoria. Mail enviado a {email}")
    return temp_pass, email


def enviar_mail_recuperacion(destinatario: str, password_provisorio: str) -> bool:
    smtp_address = "mail.arkhon.com.ar"
    smtp_port = 587
    sender_email = "no-reply@katrix.com.ar"
    sender_name = "No responder - Katrix"
    smtp_username = "no-reply@katrix.com.ar"
    smtp_password = "Nachax5$"
    
    msg = MIMEMultipart()
    msg['From'] = f'"{sender_name}" <{sender_email}>'
    msg['To'] = destinatario
    msg['Subject'] = "Contraseña Provisoria - Katrix CRM"
    
    body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333333;">
        <h2 style="color: #1F3C88; border-bottom: 2px solid #1F3C88; padding-bottom: 8px;">Recuperación de Contraseña</h2>
        <p>Hola,</p>
        <p>Se ha generado una contraseña provisoria de un solo uso para tu cuenta en el CRM de Productores.</p>
        <p>Tu contraseña temporal de acceso es:</p>
        <div style="background-color: #F0F4F8; padding: 15px; border-left: 5px solid #1F3C88; font-size: 18px; font-weight: bold; letter-spacing: 1px; margin: 15px 0; display: inline-block;">
          {password_provisorio}
        </div>
        <p><strong>Nota de seguridad:</strong> Por tu seguridad, esta contraseña es de un solo uso. Deberás cambiarla obligatoriamente por una nueva al iniciar sesión.</p>
        <hr style="border: none; border-top: 1px solid #EEEEEE; margin: 20px 0;" />
        <p style="font-size: 11px; color: #777777;">Este es un correo automático generado por el sistema de Katrix. Por favor no lo respondas.</p>
      </body>
    </html>
    """
    msg.attach(MIMEText(body, 'html', 'utf-8'))
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        server = smtplib.SMTP(smtp_address, smtp_port, timeout=3)
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(smtp_username, smtp_password)
        server.sendmail(sender_email, destinatario, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Error al enviar correo por SMTP: {e}")
        return False


def actualizar_estado_contacto(matricula: str, estado: str, usuario: str = "broker") -> bool:
    if not matricula or not estado:
        return False
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Obtener estado anterior para auditoría
    cursor.execute("SELECT nombre, estado_contacto FROM productores_detalle WHERE matricula = ?", (matricula,))
    res = cursor.fetchone()
    old_state = res[1] if res else "Sin contactar"
    nombre = res[0] if res else "Desconocido"
    
    cursor.execute("UPDATE productores_detalle SET estado_contacto = ? WHERE matricula = ?", (estado, matricula))
    changed = cursor.rowcount > 0
    conn.commit()
    conn.close()
    if changed:
        registrar_log(usuario, "CONTACT_STATUS_CHANGED", f"Matrícula {matricula} ({nombre}): '{old_state}' -> '{estado}'")
    return changed


def actualizar_observaciones(matricula: str, observaciones: str, usuario: str = "broker") -> bool:
    if not matricula:
        return False
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("UPDATE productores_detalle SET observaciones = ? WHERE matricula = ?", (observaciones, matricula))
    changed = cursor.rowcount > 0
    conn.commit()
    conn.close()
    if changed:
        registrar_log(usuario, "OBSERVACIONES_CHANGED", f"Matrícula {matricula}: observaciones actualizadas.")
    return changed


def actualizar_companias(matricula: str, companias: str, usuario: str = "broker") -> bool:
    if not matricula:
        return False
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("UPDATE productores_detalle SET companias = ? WHERE matricula = ?", (companias, matricula))
    changed = cursor.rowcount > 0
    conn.commit()
    conn.close()
    if changed:
        registrar_log(usuario, "COMPANIAS_CHANGED", f"Matrícula {matricula}: compañías actualizadas.")
    return changed

def actualizar_sociedades(matricula: str, sociedades: str, usuario: str = "broker") -> bool:
    if not matricula:
        return False
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 1. Update denormalized column for safety/compatibility
    cursor.execute("UPDATE productores_detalle SET sociedades = ? WHERE matricula = ?", (sociedades, matricula))
    changed = cursor.rowcount > 0
    
    # 2. Synchronize Many-to-Many junction table (Eloquent style)
    cursor.execute("DELETE FROM productor_sociedad WHERE productor_matricula = ?", (matricula,))
    
    if sociedades:
        import re
        parts = sociedades.split(";") if ";" in sociedades else sociedades.split(",")
        for part in parts:
            match = re.search(r"\(Mat:\s*(\d+)\)", part)
            if match:
                s_mat = match.group(1).strip()
                cursor.execute("""
                    INSERT OR IGNORE INTO productor_sociedad (productor_matricula, sociedad_matricula)
                    VALUES (?, ?)
                """, (matricula, s_mat))
                changed = True
                
    conn.commit()
    conn.close()
    if changed:
        registrar_log(usuario, "SOCIEDADES_CHANGED", f"Matrícula {matricula}: sociedades actualizadas.")
    return changed

def obtener_todas_sociedades() -> list:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT matricula, tipo_id, documento, denominacion, ramo FROM sociedades ORDER BY denominacion ASC")
    rows = cursor.fetchall()
    conn.close()
    
    sociedades = []
    for r in rows:
        sociedades.append({
            "matricula": r[0],
            "tipo_id": r[1],
            "documento": r[2],
            "denominacion": r[3],
            "ramo": r[4]
        })
    return sociedades
def obtener_csv_path() -> str:
    """Retorna la ruta del archivo CSV. Si no existe, lo descarga desde datosabiertos.ssn.gob.ar."""
    if os.path.exists(CSV_PATH_LOCAL):
        return CSV_PATH_LOCAL
    if os.path.exists(CSV_PATH_ROOT):
        return CSV_PATH_ROOT
    
    print(f"\nArchivo CSV no encontrado localmente. Descargando de {CSV_URL}...")
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR)
        
    try:
        r = requests.get(CSV_URL, headers={"User-Agent": "Mozilla/5.0"}, timeout=45, stream=True)
        r.raise_for_status()
        with open(CSV_PATH_LOCAL, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
        print("  CSV descargado con éxito y guardado en data/productores-asesores.csv")
        return CSV_PATH_LOCAL
    except Exception as e:
        print(f"  Error al descargar el CSV: {e}")
        raise FileNotFoundError("No se encontró el archivo CSV ni se pudo descargar.")


def buscar_en_csv(identificador: str) -> dict | None:
    """Busca un productor en el CSV oficial de forma rápida."""
    try:
        csv_path = obtener_csv_path()
    except Exception as e:
        print(f"  No se pudo verificar el CSV: {e}")
        return None

    id_limpio = re.sub(r"\D", "", identificador)
    
    # Intentamos abrir con utf-8 o latin-1
    encodings = ["utf-8", "latin-1"]
    for encoding in encodings:
        try:
            with open(csv_path, encoding=encoding, newline="", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    matricula = row.get("productor_matricula", "").strip()
                    cuit = row.get("productor_id", "").strip()
                    cuit_limpio = re.sub(r"\D", "", cuit)
                    
                    if identificador == matricula or identificador == cuit or id_limpio == cuit_limpio:
                        return {
                            "matricula": matricula,
                            "nombre": row.get("productor_apellido_nombre", "").strip(),
                            "documento": cuit,
                            "cuit": cuit,
                            "ramo": row.get("ramo", "").strip(),
                            "provincia": "No disponible en CSV público",
                            "telefono": "No disponible en CSV público",
                            "email": "No disponible en CSV público",
                            "resolucion": "Ver en CSV público",
                            "fecha_resolucion": "Ver en CSV público"
                        }
            break  # Si se leyó con éxito, salimos del bucle
        except UnicodeDecodeError:
            continue
        except Exception as e:
            print(f"  Error al procesar el CSV: {e}")
            break
            
    return None


# ─── PASO 0: Extraer el sitekey real del HTML ─────────────
def obtener_sitekey() -> str:
    print("Iniciando Paso 0: Obteniendo sitekey real de la página SSN...")
    proxies = obtener_proxies_activos()
    if proxies:
        print(f"  [Seguridad] Usando proxy activo: {proxies}")
    
    headers = obtener_headers_seguros()
    
    delay = random.uniform(1.0, 2.0)
    print(f"  Aguardando {delay:.2f}s para disipar patrones de tráfico...")
    time.sleep(delay)
    
    print(f"  Haciendo petición GET a {SSN_URL}...")
    r = requests.get(SSN_URL, headers=headers, proxies=proxies, timeout=15)
    r.raise_for_status()
    print(f"  Petición exitosa. Código de respuesta: {r.status_code}")

    # 1. Buscar data-sitekey en el HTML (forma estándar del widget reCAPTCHA)
    match = re.search(r'data-sitekey=["\']([^"\']+)["\']', r.text)
    if match:
        sitekey = match.group(1)
        print(f"  Sitekey encontrado (data-sitekey): {sitekey}")
        return sitekey

    # 2. Fallback: buscar en el src del script de reCAPTCHA
    match2 = re.search(r'render=([A-Za-z0-9_-]{30,})', r.text)
    if match2:
        sitekey = match2.group(1)
        print(f"  Sitekey encontrado (render): {sitekey}")
        return sitekey

    # 3. Fallback: buscar en la configuración javascript de recaptcha (ej. ["conf",null,"6L..."])
    match3 = re.search(r'(?:conf|sitekey).*?(?:\\x22|\\u0022|["\'])(6L[A-Za-z0-9_-]{35,45})(?:\\x22|\\u0022|["\'])', r.text)
    if match3:
        sitekey = match3.group(1)
        print(f"  Sitekey encontrado (patrón conf/escape): {sitekey}")
        return sitekey

    # 4. Fallback final super permisivo: cualquier string de reCAPTCHA de 35-45 chars que empiece con 6L
    match4 = re.search(r'\b(6L[A-Za-z0-9_-]{35,45})\b', r.text)
    if match4:
        sitekey = match4.group(1)
        print(f"  Sitekey encontrado (búsqueda directa 6L): {sitekey}")
        return sitekey

    debug_path = "debug_form.html"
    with open(debug_path, "w", encoding="utf-8") as f:
        f.write(r.text)
    raise ValueError(f"No se encontró el sitekey. HTML guardado en {debug_path} para inspeccionar.")


# ─── PASO 1: Resolver reCAPTCHA con Capsolver ─────────────
def resolver_captcha(site_key: str) -> str:
    print(f"Iniciando Paso 1: Resolviendo reCAPTCHA con Capsolver...")
    print(f"  Sitekey a resolver: {site_key}")
    print("  Enviando tarea a Capsolver...")

    r = requests.post("https://api.capsolver.com/createTask", json={
        "clientKey": CAPSOLVER_KEY,
        "task": {
            "type": "ReCaptchaV2TaskProxyLess",
            "websiteURL": SSN_URL,
            "websiteKey": site_key,
        }
    }, timeout=30)
    r.raise_for_status()
    
    resp_data = r.json()
    if resp_data.get("errorId") != 0:
        raise RuntimeError(f"Error al crear tarea en Capsolver: {resp_data}")

    task_id = resp_data["taskId"]
    print(f"  TaskId: {task_id}")
    print("  Haciendo polling para obtener la solución...")

    for intento in range(40):
        time.sleep(5)
        poll_resp = requests.post("https://api.capsolver.com/getTaskResult", json={
            "clientKey": CAPSOLVER_KEY,
            "taskId": task_id
        }, timeout=15)
        poll_resp.raise_for_status()
        poll = poll_resp.json()

        status = poll.get("status")
        print(f"  [{intento+1}] status: {status}")

        if status == "ready":
            token = poll["solution"]["gRecaptchaResponse"]
            print(f"  Token obtenido (primeros 40 caracteres): {token[:40]}...")
            return token
        elif status == "failed":
            raise RuntimeError(f"Capsolver falló: {poll}")

    raise TimeoutError("Capsolver no respondió en tiempo")


# ─── PASO 2: POST al SSN con el token ─────────────────────
def buscar_en_ssn(documento: str, tipo_doc: str = "DNI", token: str = "") -> str:
    print(f"Iniciando Paso 2: Buscando {tipo_doc} {documento} en SSN...")

    proxies = obtener_proxies_activos()
    headers = obtener_headers_seguros()
    
    delay = random.uniform(1.0, 2.5)
    print(f"  Aguardando {delay:.2f}s para simular acción humana y evadir bloqueo...")
    time.sleep(delay)

    if tipo_doc.upper() == "MATRICULA":
        data = {
            "socpro": "PAS",
            "tipoPas": "matricula",
            "docNro": "",
            "matricula": documento,
            "apellidorazonsocial": "",
            "Submit": "Buscar",
            
            "tipoBusqueda": "P",
            "tipoDoc": "",
            "nroDoc": "",
            "btnBuscar": "BUSCAR",
            
            "g-recaptcha-response": token,
        }
    else:
        data = {
            "socpro": "PAS",
            "tipoPas": "docNro",
            "docNro": documento,
            "matricula": "",
            "apellidorazonsocial": "",
            "Submit": "Buscar",
            
            "tipoBusqueda": "P",
            "tipoDoc": tipo_doc,
            "nroDoc": documento,
            "btnBuscar": "BUSCAR",
            
            "g-recaptcha-response": token,
        }

    r = requests.post(SSN_URL, data=data, headers=headers, proxies=proxies, timeout=30)
    r.raise_for_status()
    return r.text


# ─── PASO 3: Parsear el HTML resultado ────────────────────
def parsear_resultado(html: str) -> dict | None:
    print("Iniciando Paso 3: Parseando el HTML de respuesta con extractor posicional...")
    if not html:
        return None
        
    html_lower = html.lower()
    if "no se encontraron" in html_lower or "sin resultado" in html_lower or "ingrese matrícula o apellido" in html_lower:
        print("  Búsqueda finalizada sin resultados o con error en el formulario.")
        return None

    import html as html_mod
    clean_text = html_mod.unescape(html)
    clean_text = re.sub(r'<[^>]+>', ' ', clean_text)
    clean_text = " ".join(clean_text.split())

    # Definir los marcadores/labels
    markers = [
        "Matrícula:", "Nombre:", "Documento:", "CUIT:", "Ramo:", 
        "Provincia", "Teléfonos:", "Teléfono:", "E-mail:", "Email:", 
        "Nro. de Resolución", "Fº de Resolución", "F° de Resolución", "Datos de alta"
    ]
    
    # Encontrar todas las posiciones reales de los marcadores en el texto
    positions = []
    text_lower = clean_text.lower()
    for m in markers:
        idx = text_lower.find(m.lower())
        if idx != -1:
            positions.append((idx, m))
            
    # Ordenar las posiciones por su ubicación en el texto
    positions.sort(key=lambda x: x[0])

    def extraer_valor_posicional(label: str) -> str:
        target_idx = -1
        for i, (pos, m) in enumerate(positions):
            if m.lower() == label.lower():
                target_idx = i
                break
                
        if target_idx == -1:
            return ""
            
        p_start, m_name = positions[target_idx]
        val_start = p_start + len(m_name)
        
        if target_idx + 1 < len(positions):
            p_end = positions[target_idx + 1][0]
        else:
            p_end = len(clean_text)
            
        val = clean_text[val_start:p_end].strip()
        if val.startswith(":") or val.startswith("-"):
            val = val[1:].strip()
        return val

    resultado = {}
    resultado["matricula"] = extraer_valor_posicional("Matrícula:")
    resultado["nombre"] = extraer_valor_posicional("Nombre:")
    resultado["documento"] = extraer_valor_posicional("Documento:")
    resultado["cuit"] = extraer_valor_posicional("CUIT:")
    resultado["ramo"] = extraer_valor_posicional("Ramo:")
    resultado["provincia"] = extraer_valor_posicional("Provincia")
    
    tel = extraer_valor_posicional("Teléfonos:") or extraer_valor_posicional("Teléfono:")
    resultado["telefono"] = tel
    
    mail = extraer_valor_posicional("E-mail:") or extraer_valor_posicional("Email:")
    resultado["email"] = mail
    
    resultado["resolucion"] = extraer_valor_posicional("Nro. de Resolución")
    
    f_res = extraer_valor_posicional("Fº de Resolución") or extraer_valor_posicional("F° de Resolución")
    resultado["fecha_resolucion"] = f_res

    if not any(resultado.values()):
        return None

    return resultado


# ─── FUNCIONES DE CLI ─────────────────────────────────────
def imprimir_resultado(datos: dict):
    print("="*65)
    for k, v in datos.items():
        if k == "scraped_at":
            label = "Fecha de descarga"
        else:
            label = k.replace("_", " ").capitalize()
        print(f"  {label:20}: {v if v else 'No especificado'}")
    print("="*65)


def buscar_productor_interactivo():
    inicializar_db()
    identificador = input("\nIngrese DNI o Matrícula a buscar: ").strip()
    if not identificador:
        print("Búsqueda vacía.")
        return
        
    print(f"\nBuscando '{identificador}'...")
    
    # 1. Buscar en caché local de nuevos (costo $0)
    datos = obtener_de_db(identificador)
    if datos:
        print("\n[INFO] Encontrado en el cache SQLite de nuevos productores (costo $0):")
        imprimir_resultado(datos)
        return
        
    # 2. Buscar en el CSV local (costo $0)
    datos_csv = buscar_en_csv(identificador)
    if datos_csv:
        print("\n[INFO] Encontrado en el CSV local (costo $0, sin scraping):")
        imprimir_resultado(datos_csv)
        return
        
    # 3. Si no está en el CSV, realizamos la búsqueda en vivo con Capsolver
    print("No se encontró en el CSV local ni en caché (posible productor nuevo).")
    print("Realizando consulta en vivo a la SSN (requiere resolver captcha)...")
    try:
        site_key = obtener_sitekey()
        token = resolver_captcha(site_key)
        
        html = buscar_en_ssn(identificador, "DNI", token)
        
        debug_res_path = "debug_resultado.html"
        with open(debug_res_path, "w", encoding="utf-8") as f:
            f.write(html)
            
        datos = parsear_resultado(html)
        if datos:
            guardar_en_db(datos)
            print("\n[INFO] Encontrado en vivo en la SSN (Guardado en cache para futuras consultas):")
            imprimir_resultado(datos)
        else:
            print("\nNo se encontraron resultados en el sitio de la SSN.")
            
    except Exception as e:
        print(f"\n[ERROR] Ocurrió un problema al buscar en vivo: {e}")


def mostrar_estadisticas():
    inicializar_db()
    total_db = obtener_total_cached()
    
    try:
        csv_path = obtener_csv_path()
        with open(csv_path, encoding="utf-8", errors="ignore") as f:
            total_csv = sum(1 for line in f) - 1
    except Exception:
        total_csv = "Desconocido (CSV no disponible)"
        
    print("\n" + "="*50)
    print("ESTADÍSTICAS DEL CACHE LOCAL")
    print("="*50)
    print(f"  Ubicación de la Base de Datos : {DB_PATH}")
    print(f"  Nuevos productores en SQLite : {total_db}")
    print(f"  Productores en CSV oficial   : {total_csv}")
    print("="*50)


def parsear_e_importar_archivo(file_path: str) -> int:
    ext = os.path.splitext(file_path)[1].lower()
    
    if ext in [".xlsx", ".xlsm"]:
        import zipfile
        import xml.etree.ElementTree as ET
        
        with zipfile.ZipFile(file_path, 'r') as z:
            names = z.namelist()
            shared_strings = []
            if "xl/sharedStrings.xml" in names:
                with z.open("xl/sharedStrings.xml") as f:
                    tree = ET.parse(f)
                    root = tree.getroot()
                    ns = {'ns': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
                    for t in root.findall('.//ns:t', ns):
                        shared_strings.append(t.text)
            
            if "xl/worksheets/sheet1.xml" not in names:
                raise ValueError("No se encontró la hoja de datos principal en el archivo Excel.")
                
            with z.open("xl/worksheets/sheet1.xml") as f:
                tree = ET.parse(f)
                root = tree.getroot()
                ns = {'ns': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
                rows = root.findall('.//ns:row', ns)
                
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                registros_insertados = 0
                
                # Fila 1 suele ser el encabezado, iterar desde la fila 2
                for r in rows[1:]:
                    cells = r.findall('ns:c', ns)
                    row_data = {}
                    for c in cells:
                        cell_ref = c.attrib.get('r')
                        col_letter = ''.join([char for char in cell_ref if char.isalpha()])
                        cell_type = c.attrib.get('t')
                        val_tag = c.find('ns:v', ns)
                        val = val_tag.text if val_tag is not None else ""
                        
                        if cell_type == 's' and val.isdigit():
                            idx = int(val)
                            if idx < len(shared_strings):
                                val = shared_strings[idx]
                                
                        row_data[col_letter] = val.strip() if val else ""
                    
                    matricula = row_data.get('A', '')
                    if matricula:
                        provincia = row_data.get('H', '').strip().upper() or "—"
                        localidad = row_data.get('G', '').strip().upper() or "—"
                        cursor.execute("""
                            INSERT INTO productores_detalle (
                                matricula, nombre, documento, cuit, ramo, provincia, telefono, email, 
                                resolucion, fecha_resolucion, domicilio, localidad, cod_postal, scraped_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                            ON CONFLICT(matricula) DO UPDATE SET
                                nombre = CASE WHEN excluded.nombre != '' THEN excluded.nombre ELSE productores_detalle.nombre END,
                                documento = CASE WHEN excluded.documento != '' THEN excluded.documento ELSE productores_detalle.documento END,
                                cuit = CASE WHEN excluded.cuit != '' THEN excluded.cuit ELSE productores_detalle.cuit END,
                                ramo = CASE WHEN excluded.ramo != '' AND excluded.ramo != 'Patrimoniales y Vida' THEN excluded.ramo ELSE productores_detalle.ramo END,
                                provincia = CASE WHEN excluded.provincia != '—' AND excluded.provincia != '' THEN excluded.provincia ELSE productores_detalle.provincia END,
                                telefono = CASE WHEN excluded.telefono != '—' AND excluded.telefono != '' THEN excluded.telefono ELSE productores_detalle.telefono END,
                                email = CASE WHEN excluded.email != '—' AND excluded.email != '' THEN excluded.email ELSE productores_detalle.email END,
                                domicilio = CASE WHEN excluded.domicilio != '—' AND excluded.domicilio != '' THEN excluded.domicilio ELSE productores_detalle.domicilio END,
                                localidad = CASE WHEN excluded.localidad != '—' AND excluded.localidad != '' THEN excluded.localidad ELSE productores_detalle.localidad END,
                                cod_postal = CASE WHEN excluded.cod_postal != '—' AND excluded.cod_postal != '' THEN excluded.cod_postal ELSE productores_detalle.cod_postal END,
                                scraped_at = CURRENT_TIMESTAMP
                            WHERE (
                                (CASE WHEN productores_detalle.telefono IS NULL OR productores_detalle.telefono IN ('', '—') THEN 1 ELSE 0 END) +
                                (CASE WHEN productores_detalle.email IS NULL OR productores_detalle.email IN ('', '—') THEN 1 ELSE 0 END) +
                                (CASE WHEN productores_detalle.domicilio IS NULL OR productores_detalle.domicilio IN ('', '—') THEN 1 ELSE 0 END) +
                                (CASE WHEN productores_detalle.localidad IS NULL OR productores_detalle.localidad IN ('', '—') THEN 1 ELSE 0 END) +
                                (CASE WHEN productores_detalle.cod_postal IS NULL OR productores_detalle.cod_postal IN ('', '—') THEN 1 ELSE 0 END) +
                                (CASE WHEN productores_detalle.resolucion IS NULL OR productores_detalle.resolucion IN ('', '—') THEN 1 ELSE 0 END) +
                                (CASE WHEN productores_detalle.fecha_resolucion IS NULL OR productores_detalle.fecha_resolucion IN ('', '—') THEN 1 ELSE 0 END)
                            ) >= 2
                        """, (
                            matricula,
                            row_data.get('B', '').strip(),
                            row_data.get('C', '').strip(),
                            row_data.get('D', '').strip(),
                            row_data.get('E', '').strip(),
                            provincia,
                            row_data.get('I', '').strip(),
                            row_data.get('J', '').strip(),
                            "Excel Import",
                            "—",
                            row_data.get('F', '').strip(),
                            localidad,
                            row_data.get('K', '').strip()
                        ))
                        registros_insertados += 1
                
                cursor.execute("SELECT COUNT(*) FROM productores_detalle WHERE telefono IN ('', '—') OR email IN ('', '—')")
                incompletos = cursor.fetchone()[0]
                conn.commit()
                conn.close()
                return registros_insertados, incompletos

    elif ext == ".csv":
        import csv
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                f.read(2048)
        except UnicodeDecodeError:
            encoding = "latin-1"
        else:
            encoding = "utf-8"
            
        with open(file_path, "r", encoding=encoding) as f:
            sample = f.read(4096)
            f.seek(0)
            delimiter = ","
            if ";" in sample and sample.count(";") > sample.count(","):
                delimiter = ";"
                
            reader = csv.DictReader(f, delimiter=delimiter)
            if not reader.fieldnames:
                raise ValueError("El archivo CSV no tiene encabezados válidos.")
                
            col_mat = None
            col_nom = None
            col_doc = None
            col_cuit = None
            col_ramo = None
            col_prov = None
            col_tel = None
            col_mail = None
            col_dom = None
            col_loc = None
            col_cp = None
            
            def find_col(aliases: list[str]) -> str | None:
                for alias in aliases:
                    for real in reader.fieldnames:
                        if alias in real.strip().lower():
                            return real
                return None
                
            col_mat = find_col(["matricula", "matrícula", "mat", "pas"])
            col_nom = find_col(["nombre", "apellido_nombre", "apellido y nombre", "nombre/apellido", "denominacion", "razon social"])
            col_doc = find_col(["documento", "doc", "dni", "nro doc"])
            col_cuit = find_col(["cuit", "cuil", "cuit/cuil"])
            col_ramo = find_col(["ramo", "ramos"])
            col_prov = find_col(["provincia", "prov"])
            col_tel = find_col(["telefono", "teléfono", "teléfonos", "telefonos", "tel"])
            col_mail = find_col(["email", "e-mail", "mail", "correo"])
            col_dom = find_col(["domicilio", "dirección", "direccion", "calle"])
            col_loc = find_col(["localidad", "loc"])
            col_cp = find_col(["cod_postal", "codigo postal", "cp"])
            
            if not col_mat:
                raise ValueError("No se pudo identificar una columna de 'Matrícula' en el archivo CSV.")
                
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            registros_insertados = 0
            
            for row in reader:
                matricula = row.get(col_mat, "").strip()
                if not matricula:
                    continue
                    
                nombre = row.get(col_nom, "").strip() if col_nom else ""
                documento = row.get(col_doc, "").strip() if col_doc else ""
                cuit = row.get(col_cuit, "").strip() if col_cuit else ""
                ramo = row.get(col_ramo, "").strip() if col_ramo else "Patrimoniales y Vida"
                provincia = (row.get(col_prov, "").strip().upper() if col_prov else "").strip() or "—"
                telefono = row.get(col_tel, "").strip() if col_tel else "—"
                email = row.get(col_mail, "").strip() if col_mail else "—"
                domicilio = row.get(col_dom, "").strip() if col_dom else "—"
                localidad = (row.get(col_loc, "").strip().upper() if col_loc else "").strip() or "—"
                cod_postal = row.get(col_cp, "").strip() if col_cp else "—"
                
                cursor.execute("""
                    INSERT INTO productores_detalle (
                        matricula, nombre, documento, cuit, ramo, provincia, telefono, email, 
                        resolucion, fecha_resolucion, domicilio, localidad, cod_postal, scraped_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(matricula) DO UPDATE SET
                        nombre = CASE WHEN excluded.nombre != '' THEN excluded.nombre ELSE productores_detalle.nombre END,
                        documento = CASE WHEN excluded.documento != '' THEN excluded.documento ELSE productores_detalle.documento END,
                        cuit = CASE WHEN excluded.cuit != '' THEN excluded.cuit ELSE productores_detalle.cuit END,
                        ramo = CASE WHEN excluded.ramo != '' AND excluded.ramo != 'Patrimoniales y Vida' THEN excluded.ramo ELSE productores_detalle.ramo END,
                        provincia = CASE WHEN excluded.provincia != '—' AND excluded.provincia != '' THEN excluded.provincia ELSE productores_detalle.provincia END,
                        telefono = CASE WHEN excluded.telefono != '—' AND excluded.telefono != '' THEN excluded.telefono ELSE productores_detalle.telefono END,
                        email = CASE WHEN excluded.email != '—' AND excluded.email != '' THEN excluded.email ELSE productores_detalle.email END,
                        domicilio = CASE WHEN excluded.domicilio != '—' AND excluded.domicilio != '' THEN excluded.domicilio ELSE productores_detalle.domicilio END,
                        localidad = CASE WHEN excluded.localidad != '—' AND excluded.localidad != '' THEN excluded.localidad ELSE productores_detalle.localidad END,
                        cod_postal = CASE WHEN excluded.cod_postal != '—' AND excluded.cod_postal != '' THEN excluded.cod_postal ELSE productores_detalle.cod_postal END,
                        scraped_at = CURRENT_TIMESTAMP
                    WHERE (
                        (CASE WHEN productores_detalle.telefono IS NULL OR productores_detalle.telefono IN ('', '—') THEN 1 ELSE 0 END) +
                        (CASE WHEN productores_detalle.email IS NULL OR productores_detalle.email IN ('', '—') THEN 1 ELSE 0 END) +
                        (CASE WHEN productores_detalle.domicilio IS NULL OR productores_detalle.domicilio IN ('', '—') THEN 1 ELSE 0 END) +
                        (CASE WHEN productores_detalle.localidad IS NULL OR productores_detalle.localidad IN ('', '—') THEN 1 ELSE 0 END) +
                        (CASE WHEN productores_detalle.cod_postal IS NULL OR productores_detalle.cod_postal IN ('', '—') THEN 1 ELSE 0 END) +
                        (CASE WHEN productores_detalle.resolucion IS NULL OR productores_detalle.resolucion IN ('', '—') THEN 1 ELSE 0 END) +
                        (CASE WHEN productores_detalle.fecha_resolucion IS NULL OR productores_detalle.fecha_resolucion IN ('', '—') THEN 1 ELSE 0 END)
                    ) >= 2
                """, (
                    matricula, nombre, documento, cuit, ramo, provincia, telefono, email,
                    "CSV Import", "—", domicilio, localidad, cod_postal
                ))
                registros_insertados += 1
                
            cursor.execute("SELECT COUNT(*) FROM productores_detalle WHERE telefono IN ('', '—') OR email IN ('', '—')")
            incompletos = cursor.fetchone()[0]
            conn.commit()
            conn.close()
            return registros_insertados, incompletos
    else:
        raise ValueError("Formato de archivo no soportado. Debe ser .xlsx, .xlsm o .csv")


def vaciar_base_de_datos() -> int:
    """Elimina todos los registros de la base de datos (función de administrador)."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM productores_detalle")
        count = cursor.fetchone()[0]
        cursor.execute("DELETE FROM productores_detalle")
        conn.commit()
        conn.close()
        return count
    except Exception as e:
        print(f"Error al vaciar base de datos: {e}")
        return 0

def obtener_ultima_actualizacion() -> str:
    """Devuelve la fecha de la última actualización masiva (Excel/CSV)."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(scraped_at) FROM productores_detalle WHERE resolucion IN ('CSV Import', 'Excel Import')")
        row = cursor.fetchone()
        conn.close()
        if row and row[0]:
            # Retorna la fecha truncada a dia/mes/año hora:minuto
            return row[0][:16]
        return "Nunca"
    except Exception:
        return "Nunca"

# ─── FUNCIONES DE ADMINISTRADOR ────────────────────────────
def obtener_usuarios() -> list[dict]:
    """Obtiene todos los usuarios del sistema junto con su matrícula asociada si existiese."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.id, u.usuario, u.email, u.requiere_cambio, u.intentos_fallidos, u.bloqueado_hasta, u.rol, u.username_changed,
               GROUP_CONCAT(p.matricula, ', ') AS matricula_asociada
        FROM usuarios u
        LEFT JOIN productores_detalle p ON p.usuario_id = u.id
        GROUP BY u.id
        ORDER BY u.id
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def crear_usuario(usuario: str, email: str, password_txt: str, rol: str = "agente", requiere_cambio: int = 1, matricula: str = None) -> tuple[bool, str]:
    """Crea un nuevo usuario en el sistema con opciones completas y validación de matrícula."""
    try:
        usuario = usuario.strip().lower()
        email = email.strip().lower()
        
        import re
        email_pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        if not re.match(email_pattern, email):
            return False, "El formato del correo electrónico no es válido."
            
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Verificar duplicados
        cursor.execute("SELECT id FROM usuarios WHERE usuario = ? OR email = ?", (usuario, email))
        if cursor.fetchone():
            conn.close()
            return False, "El nombre de usuario o correo electrónico ya existe."
            
        # Validar matrícula si se provee
        if matricula:
            matricula = matricula.strip()
            cursor.execute("SELECT matricula, usuario_id FROM productores_detalle WHERE matricula = ?", (matricula,))
            prod = cursor.fetchone()
            if not prod:
                conn.close()
                return False, f"La matrícula '{matricula}' no fue encontrada en el sistema."
            prod_matricula, prod_usuario_id = prod
            if prod_usuario_id is not None:
                cursor.execute("SELECT usuario FROM usuarios WHERE id = ?", (prod_usuario_id,))
                owner = cursor.fetchone()
                owner_name = owner[0] if owner else "otro usuario"
                conn.close()
                return False, f"La matrícula '{matricula}' ya está asignada al usuario '{owner_name}'."
                
        # Insertar usuario
        hashed_pw = hash_password(password_txt)
        cursor.execute(
            "INSERT INTO usuarios (usuario, email, password, requiere_cambio, rol, username_changed) VALUES (?, ?, ?, ?, ?, 0)",
            (usuario, email, hashed_pw, requiere_cambio, rol)
        )
        new_user_id = cursor.lastrowid
        
        # Vincular matrícula si corresponde
        if matricula:
            cursor.execute("UPDATE productores_detalle SET usuario_id = ? WHERE matricula = ?", (new_user_id, matricula))
            
        conn.commit()
        conn.close()
        return True, f"Usuario '{usuario}' creado exitosamente."
    except Exception as e:
        print(f"Error al crear usuario: {e}")
        return False, f"Error al crear usuario: {str(e)}"

def actualizar_usuario(id_usuario: int, nuevo_usuario: str, nuevo_email: str, password_txt: str = None, rol: str = None, requiere_cambio: int = None, reset_lock: bool = False, is_self_update: bool = False, matricula: str = None) -> tuple[bool, str]:
    """Actualiza los datos de un usuario con opción de asociar/desasociar matrícula."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # 1. Obtener datos actuales
        cursor.execute("SELECT usuario, email, username_changed, rol FROM usuarios WHERE id = ?", (id_usuario,))
        res = cursor.fetchone()
        if not res:
            conn.close()
            return False, "Usuario no encontrado"
        
        actual_usuario, actual_email, user_changed, actual_rol = res
        
        # Normalizar valores
        nuevo_usuario = nuevo_usuario.strip()
        nuevo_email = nuevo_email.strip().lower()
        
        # Validar cambio de nombre de usuario
        set_changed = 0
        if nuevo_usuario.lower() != actual_usuario.lower():
            if is_self_update and user_changed:
                conn.close()
                return False, "El nombre de usuario solo se puede cambiar una sola vez"
            set_changed = 1
            
        # Verificar si el nuevo nombre de usuario o email ya existen en otro usuario
        cursor.execute("SELECT id FROM usuarios WHERE (usuario = ? OR email = ?) AND id != ?", (nuevo_usuario.lower(), nuevo_email, id_usuario))
        dup = cursor.fetchone()
        if dup:
            conn.close()
            return False, "El nombre de usuario o el correo electrónico ya están en uso por otro usuario"
        
        # Validar y actualizar matrícula si es provista
        if matricula is not None:
            matricula = matricula.strip()
            
            # Obtener matrícula actualmente vinculada al usuario
            cursor.execute("SELECT matricula FROM productores_detalle WHERE usuario_id = ?", (id_usuario,))
            curr_matricula_row = cursor.fetchone()
            curr_matricula = curr_matricula_row[0] if curr_matricula_row else ""
            
            if matricula != curr_matricula:
                # Desvincular al usuario de cualquier matrícula previa
                cursor.execute("UPDATE productores_detalle SET usuario_id = NULL WHERE usuario_id = ?", (id_usuario,))
                
                # Si la nueva matrícula no está en blanco, vincularla
                if matricula != "":
                    # Verificar que la matrícula exista
                    cursor.execute("SELECT matricula, usuario_id FROM productores_detalle WHERE matricula = ?", (matricula,))
                    prod = cursor.fetchone()
                    if not prod:
                        conn.rollback()
                        conn.close()
                        return False, f"La matrícula '{matricula}' no fue encontrada en el sistema."
                    
                    prod_matricula, prod_usuario_id = prod
                    if prod_usuario_id is not None and prod_usuario_id != id_usuario:
                        cursor.execute("SELECT usuario FROM usuarios WHERE id = ?", (prod_usuario_id,))
                        owner = cursor.fetchone()
                        owner_name = owner[0] if owner else "otro usuario"
                        conn.rollback()
                        conn.close()
                        return False, f"La matrícula '{matricula}' ya está asignada al usuario '{owner_name}'."
                        
                    # Vincular
                    cursor.execute("UPDATE productores_detalle SET usuario_id = ? WHERE matricula = ?", (id_usuario, matricula))

        # 2. Construir la consulta de actualización del usuario
        params = [nuevo_usuario, nuevo_email]
        sql = "UPDATE usuarios SET usuario = ?, email = ?"
        
        if is_self_update and set_changed:
            sql += ", username_changed = 1"
        
        if password_txt and password_txt.strip():
            hashed = hash_password(password_txt.strip())
            sql += ", password = ?"
            if is_self_update:
                sql += ", requiere_cambio = 0"
            params.append(hashed)
            
        if rol:
            sql += ", rol = ?"
            params.append(rol)
            
        if requiere_cambio is not None:
            sql += ", requiere_cambio = ?"
            params.append(requiere_cambio)
            
        if reset_lock:
            sql += ", intentos_fallidos = 0, bloqueado_hasta = 0"
            
        sql += " WHERE id = ?"
        params.append(id_usuario)
        
        cursor.execute(sql, params)
        conn.commit()
        conn.close()
        return True, "Usuario actualizado correctamente"
    except Exception as e:
        return False, f"Error al actualizar el usuario: {str(e)}"

def eliminar_usuario(id_usuario: int) -> bool:
    """Elimina un usuario por su ID y desvincula cualquier matrícula asociada."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        # Desvincular matrícula primero
        cursor.execute("UPDATE productores_detalle SET usuario_id = NULL WHERE usuario_id = ?", (id_usuario,))
        # Eliminar usuario
        cursor.execute("DELETE FROM usuarios WHERE id = ?", (id_usuario,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error al eliminar usuario ID {id_usuario}: {e}")
        return False

def cambiar_password_admin(id_usuario: int, new_password_txt: str) -> bool:
    """Cambia la contraseña de un usuario por parte del admin."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        hashed_pw = hash_password(new_password_txt)
        # El admin cambia la contraseña y puede forzar que el usuario la cambie luego
        cursor.execute("UPDATE usuarios SET password = ?, requiere_cambio = 1, intentos_fallidos = 0, bloqueado_hasta = 0 WHERE id = ?", (hashed_pw, id_usuario))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False

def actualizar_rol_usuario(id_usuario: int, nuevo_rol: str) -> bool:
    """Actualiza el rol de un usuario."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE usuarios SET rol = ? WHERE id = ?", (nuevo_rol, id_usuario))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False

def obtener_permisos_visibilidad(usuario_lector_id: int) -> list[int]:
    """Obtiene la lista de IDs de usuarios propietarios a los que tiene acceso el lector."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT usuario_propietario_id FROM permisos_visibilidad WHERE usuario_lector_id = ?", (usuario_lector_id,))
        rows = cursor.fetchall()
        conn.close()
        return [r[0] for r in rows]
    except Exception:
        return []

def actualizar_permisos_visibilidad(usuario_lector_id: int, propietarios_ids: list[int]) -> bool:
    """Actualiza los permisos de visibilidad para un usuario lector."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM permisos_visibilidad WHERE usuario_lector_id = ?", (usuario_lector_id,))
        for prop_id in propietarios_ids:
            cursor.execute("INSERT INTO permisos_visibilidad (usuario_lector_id, usuario_propietario_id) VALUES (?, ?)", (usuario_lector_id, prop_id))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error al actualizar permisos de visibilidad: {e}")
        return False

def obtener_logs(limite: int = 100) -> list[dict]:
    """Obtiene los últimos logs del sistema."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM logs_auditoria ORDER BY id DESC LIMIT ?", (limite,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []

# ── ERP Portfolio & Claims CRUD ──────────────────────────────────────────
def obtener_clientes() -> list:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM clientes ORDER BY nombre ASC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []

def guardar_cliente(nombre: str, dni_cuil: str, email: str, telefono: str, direccion: str, notas: str) -> bool:
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO clientes (nombre, dni_cuil, email, telefono, direccion, notas)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (nombre, dni_cuil, email, telefono, direccion, notas))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error guardar_cliente: {e}")
        return False

def actualizar_cliente(cliente_id: int, nombre: str, dni_cuil: str, email: str, telefono: str, direccion: str, notas: str) -> bool:
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE clientes SET nombre=?, dni_cuil=?, email=?, telefono=?, direccion=?, notas=?
            WHERE id=?
        """, (nombre, dni_cuil, email, telefono, direccion, notas, cliente_id))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error actualizar_cliente: {e}")
        return False

def eliminar_cliente(cliente_id: int) -> bool:
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM clientes WHERE id=?", (cliente_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error eliminar_cliente: {e}")
        return False

def obtener_polizas(cliente_id: int = None, pas_matricula: str = None) -> list:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if cliente_id is not None:
            cursor.execute("""
                SELECT p.*, c.nombre as cliente_nombre 
                FROM polizas p
                JOIN clientes c ON p.cliente_id = c.id
                WHERE p.cliente_id = ?
                ORDER BY p.id DESC
            """, (cliente_id,))
        elif pas_matricula is not None:
            cursor.execute("""
                SELECT p.*, c.nombre as cliente_nombre 
                FROM polizas p
                JOIN clientes c ON p.cliente_id = c.id
                WHERE p.pas_matricula = ?
                ORDER BY p.id DESC
            """, (pas_matricula,))
        else:
            cursor.execute("""
                SELECT p.*, c.nombre as cliente_nombre 
                FROM polizas p
                JOIN clientes c ON p.cliente_id = c.id
                ORDER BY p.id DESC
            """)
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"Error obtener_polizas: {e}")
        return []

def guardar_poliza(cliente_id: int, pas_matricula: str, compania: str, ramo: str, nro_poliza: str,
                   vigencia_desde: str, vigencia_hasta: str, prima: float, premio: float,
                   comision_porcentaje: float, estado_pago: str, estado: str, notas: str) -> bool:
    try:
        comision_monto = (float(premio) * float(comision_porcentaje)) / 100.0
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO polizas (cliente_id, pas_matricula, compania, ramo, nro_poliza, vigencia_desde, vigencia_hasta, prima, premio, comision_porcentaje, comision_monto, estado_pago, estado, notas)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (cliente_id, pas_matricula, compania, ramo, nro_poliza, vigencia_desde, vigencia_hasta, prima, premio, comision_porcentaje, comision_monto, estado_pago, estado, notas))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error guardar_poliza: {e}")
        return False

def actualizar_poliza(poliza_id: int, cliente_id: int, pas_matricula: str, compania: str, ramo: str, nro_poliza: str,
                      vigencia_desde: str, vigencia_hasta: str, prima: float, premio: float,
                      comision_porcentaje: float, estado_pago: str, estado: str, notas: str) -> bool:
    try:
        comision_monto = (float(premio) * float(comision_porcentaje)) / 100.0
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE polizas SET cliente_id=?, pas_matricula=?, compania=?, ramo=?, nro_poliza=?, vigencia_desde=?, vigencia_hasta=?, prima=?, premio=?, comision_porcentaje=?, comision_monto=?, estado_pago=?, estado=?, notas=?
            WHERE id=?
        """, (cliente_id, pas_matricula, compania, ramo, nro_poliza, vigencia_desde, vigencia_hasta, prima, premio, comision_porcentaje, comision_monto, estado_pago, estado, notas, poliza_id))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error actualizar_poliza: {e}")
        return False

def eliminar_poliza(poliza_id: int) -> bool:
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM polizas WHERE id=?", (poliza_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error eliminar_poliza: {e}")
        return False

def obtener_siniestros(poliza_id: int = None) -> list:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if poliza_id is not None:
            cursor.execute("""
                SELECT s.*, p.nro_poliza, c.nombre as cliente_nombre
                FROM siniestros s
                JOIN polizas p ON s.poliza_id = p.id
                JOIN clientes c ON p.cliente_id = c.id
                WHERE s.poliza_id = ?
                ORDER BY s.id DESC
            """, (poliza_id,))
        else:
            cursor.execute("""
                SELECT s.*, p.nro_poliza, c.nombre as cliente_nombre
                FROM siniestros s
                JOIN polizas p ON s.poliza_id = p.id
                JOIN clientes c ON p.cliente_id = c.id
                ORDER BY s.id DESC
            """)
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"Error obtener_siniestros: {e}")
        return []

def guardar_siniestro(poliza_id: int, fecha_siniestro: str, descripcion: str, estado: str, notas: str) -> bool:
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO siniestros (poliza_id, fecha_siniestro, descripcion, estado, notas)
            VALUES (?, ?, ?, ?, ?)
        """, (poliza_id, fecha_siniestro, descripcion, estado, notas))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error guardar_siniestro: {e}")
        return False

def actualizar_siniestro(siniestro_id: int, poliza_id: int, fecha_siniestro: str, descripcion: str, estado: str, notas: str) -> bool:
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE siniestros SET poliza_id=?, fecha_siniestro=?, descripcion=?, estado=?, notas=?
            WHERE id=?
        """, (poliza_id, fecha_siniestro, descripcion, estado, notas, siniestro_id))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error actualizar_siniestro: {e}")
        return False

def eliminar_siniestro(siniestro_id: int) -> bool:
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM siniestros WHERE id=?", (siniestro_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error eliminar_siniestro: {e}")
        return False

def obtener_metricas_erp() -> dict:
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Premio total y prima total administrada (pólizas vigentes)
        cursor.execute("SELECT SUM(premio), SUM(prima), COUNT(*) FROM polizas WHERE estado = 'Vigente'")
        row_pol = cursor.fetchone()
        premio_total = row_pol[0] or 0.0
        prima_total = row_pol[1] or 0.0
        polizas_vigentes = row_pol[2] or 0
        
        # Comisiones proyectadas
        cursor.execute("SELECT SUM(comision_monto) FROM polizas WHERE estado = 'Vigente'")
        comisiones_totales = cursor.fetchone()[0] or 0.0
        
        # Clientes totales
        cursor.execute("SELECT COUNT(*) FROM clientes")
        clientes_totales = cursor.fetchone()[0] or 0
        
        # Siniestros en proceso o abiertos
        cursor.execute("SELECT COUNT(*) FROM siniestros WHERE estado != 'Liquidado' AND estado != 'Rechazado'")
        siniestros_abiertos = cursor.fetchone()[0] or 0
        
        # Distribución por ramo
        cursor.execute("SELECT ramo, COUNT(*), SUM(premio) FROM polizas WHERE estado = 'Vigente' GROUP BY ramo")
        ramos_dist = [{"ramo": r[0], "cantidad": r[1], "premio": r[2] or 0.0} for r in cursor.fetchall()]
        
        # Distribución por compañía
        cursor.execute("SELECT compania, COUNT(*), SUM(premio) FROM polizas WHERE estado = 'Vigente' GROUP BY compania")
        companias_dist = [{"compania": r[0], "cantidad": r[1], "premio": r[2] or 0.0} for r in cursor.fetchall()]
        
        conn.close()
        return {
            "premio_total": premio_total,
            "prima_total": prima_total,
            "polizas_vigentes": polizas_vigentes,
            "comisiones_totales": comisiones_totales,
            "clientes_totales": clientes_totales,
            "siniestros_abiertos": siniestros_abiertos,
            "ramos_distribucion": ramos_dist,
            "companias_distribucion": companias_dist
        }
    except Exception as e:
        print(f"Error obtener_metricas_erp: {e}")
        return {
            "premio_total": 0.0,
            "prima_total": 0.0,
            "polizas_vigentes": 0,
            "comisiones_totales": 0.0,
            "clientes_totales": 0,
            "siniestros_abiertos": 0,
            "ramos_distribucion": [],
            "companias_distribucion": []
        }

def obtener_ranking_productores() -> list:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                p.pas_matricula as matricula, 
                COALESCE(pd.nombre, 'Productor Desconocido') as nombre, 
                COUNT(p.id) as polizas_vigentes, 
                SUM(p.premio) as premio_total, 
                SUM(p.comision_monto) as comisiones_estimadas,
                GROUP_CONCAT(DISTINCT p.compania) as companias
            FROM polizas p
            LEFT JOIN productores_detalle pd ON p.pas_matricula = pd.matricula
            WHERE p.estado = 'Vigente'
            GROUP BY p.pas_matricula
            ORDER BY premio_total DESC
        """)
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"Error obtener_ranking_productores: {e}")
        return []



# ── Alertas de Vencimiento de Pólizas ────────────────────────────────────────
def obtener_alertas_vencimiento(dias_umbral: int = 60) -> list:
    """
    Retorna las pólizas próximas a vencer (dentro de `dias_umbral` días)
    y las pólizas con estado_pago = 'Impaga', ordenadas por urgencia.
    Cada item incluye: poliza_id, nro_poliza, cliente_nombre, compania, ramo,
    vigencia_hasta, dias_restantes, tipo_alerta ('vencimiento'|'impago').
    """
    try:
        from datetime import datetime, timedelta
        hoy = datetime.now().date()
        limite = hoy + timedelta(days=dias_umbral)
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT p.id, p.nro_poliza, p.vigencia_hasta, p.compania, p.ramo,
                   p.estado_pago, p.pas_matricula, p.premio,
                   c.nombre as cliente_nombre
            FROM polizas p
            JOIN clientes c ON p.cliente_id = c.id
            WHERE p.estado = 'Vigente'
            ORDER BY p.vigencia_hasta ASC
        """)
        rows = cursor.fetchall()
        conn.close()

        alertas = []
        for r in rows:
            r = dict(r)
            try:
                venc = datetime.strptime(r["vigencia_hasta"], "%Y-%m-%d").date()
                dias = (venc - hoy).days
            except Exception:
                dias = None

            if r.get("estado_pago") == "Impaga":
                alertas.append({**r, "dias_restantes": dias, "tipo_alerta": "impago",
                                 "urgencia": 0})
            elif dias is not None and 0 <= dias <= dias_umbral:
                urgencia = 1 if dias <= 15 else (2 if dias <= 30 else 3)
                alertas.append({**r, "dias_restantes": dias, "tipo_alerta": "vencimiento",
                                 "urgencia": urgencia})

        alertas.sort(key=lambda x: (x["urgencia"], x.get("dias_restantes") or 999))
        return alertas
    except Exception as e:
        print(f"Error obtener_alertas_vencimiento: {e}")
        return []


# ── Actividades Comerciales filtradas por PAS ─────────────────────────────────
def obtener_actividades_por_pas(nombre: str = None, matricula: str = None) -> list:
    """
    Retorna las actividades comerciales (llamados/reuniones) asociadas
    a un PAS específico, filtrando por nombre y/o matrícula.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        conditions = []
        params = []
        if nombre:
            conditions.append("LOWER(nombre) LIKE ?")
            params.append(f"%{nombre.strip().lower()}%")
        if matricula:
            conditions.append("matricula = ?")
            params.append(matricula.strip())
        if not conditions:
            cursor.execute(
                "SELECT * FROM actividades_comerciales ORDER BY fecha_actividad DESC LIMIT 50"
            )
        else:
            where = " OR ".join(conditions)
            cursor.execute(
                f"SELECT * FROM actividades_comerciales WHERE {where} ORDER BY fecha_actividad DESC LIMIT 100",
                params
            )
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"Error obtener_actividades_por_pas: {e}")
        return []


# ── Exportar Ficha PDF del Productor ─────────────────────────────────────────
def exportar_ficha_pdf(pas_data: dict, polizas: list = None, output_path: str = None) -> str | None:
    """
    Genera un PDF con la ficha del productor: datos de contacto, KPIs y
    listado de pólizas vigentes.  Retorna la ruta del archivo generado, o None
    si reportlab no está instalado.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors as rl_colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        )
        from datetime import datetime
        import os

        if output_path is None:
            export_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exportaciones")
            os.makedirs(export_dir, exist_ok=True)
            safe_name = (pas_data.get("nombre") or "productor").replace(" ", "_").replace("/", "_")[:30]
            output_path = os.path.join(export_dir, f"ficha_{safe_name}_{int(datetime.now().timestamp())}.pdf")

        doc = SimpleDocTemplate(
            output_path, pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm
        )
        styles = getSampleStyleSheet()

        # Colores corporativos Katrix
        PRIMARY   = rl_colors.HexColor("#38BDF8")
        DARK_BG   = rl_colors.HexColor("#1E293B")
        DARK_TEXT = rl_colors.HexColor("#F8FAFC")
        MUTED     = rl_colors.HexColor("#94A3B8")
        SUCCESS   = rl_colors.HexColor("#34D399")
        WARNING   = rl_colors.HexColor("#FBBF24")
        DANGER    = rl_colors.HexColor("#F87171")

        title_style = ParagraphStyle(
            "KatrixTitle", parent=styles["Heading1"],
            textColor=DARK_BG, fontSize=20, spaceAfter=4
        )
        subtitle_style = ParagraphStyle(
            "KatrixSub", parent=styles["Normal"],
            textColor=MUTED, fontSize=10, spaceAfter=12
        )
        section_style = ParagraphStyle(
            "KatrixSection", parent=styles["Heading2"],
            textColor=DARK_BG, fontSize=13, spaceBefore=14, spaceAfter=6
        )
        body_style = ParagraphStyle(
            "KatrixBody", parent=styles["Normal"],
            textColor=DARK_BG, fontSize=10, leading=16
        )
        label_style = ParagraphStyle(
            "KatrixLabel", parent=styles["Normal"],
            textColor=MUTED, fontSize=9
        )

        nombre       = pas_data.get("nombre") or "Productor Desconocido"
        matricula    = pas_data.get("matricula") or "—"
        ramo         = pas_data.get("ramo") or "—"
        provincia    = pas_data.get("provincia") or "—"
        localidad    = pas_data.get("localidad") or "—"
        telefono     = pas_data.get("telefono") or "—"
        email_val    = pas_data.get("email") or "—"
        estado_c     = pas_data.get("estado_contacto") or "Sin contactar"
        observs      = pas_data.get("observaciones") or ""
        fecha_gen    = datetime.now().strftime("%d/%m/%Y %H:%M")

        if polizas is None:
            polizas = []
        vigentes     = [p for p in polizas if p.get("estado") == "Vigente"]
        total_premio = sum(float(p.get("premio", 0) or 0) for p in vigentes)
        total_com    = sum(float(p.get("comision_monto", 0) or 0) for p in vigentes)
        clientes_u   = len(set(p.get("cliente_nombre", "") for p in vigentes if p.get("cliente_nombre")))

        def fmt_money(v):
            try: return f"$ {float(v):,.0f}".replace(",", ".")
            except: return "$ 0"

        story = []

        # ── Encabezado ──
        story.append(Paragraph(f"<b>{nombre}</b>", title_style))
        story.append(Paragraph(
            f"Ficha de Productor Asesor de Seguros &bull; Matrícula: <b>{matricula}</b> &bull; "
            f"Katrix ERP &bull; Generado: {fecha_gen}",
            subtitle_style
        ))
        story.append(HRFlowable(width="100%", thickness=2, color=PRIMARY, spaceAfter=12))

        # ── Datos de contacto ──
        story.append(Paragraph("Datos de Contacto", section_style))
        contact_data = [
            ["Ramo", ramo,       "Provincia", provincia],
            ["Localidad", localidad, "Teléfono", telefono],
            ["Email", email_val, "Estado", estado_c],
        ]
        contact_table = Table(contact_data, colWidths=[3*cm, 6*cm, 3*cm, 5.5*cm])
        contact_table.setStyle(TableStyle([
            ("FONTSIZE",    (0,0), (-1,-1), 9),
            ("FONTNAME",    (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTNAME",    (2,0), (2,-1), "Helvetica-Bold"),
            ("TEXTCOLOR",   (0,0), (0,-1), DARK_BG),
            ("TEXTCOLOR",   (2,0), (2,-1), DARK_BG),
            ("TEXTCOLOR",   (1,0), (1,-1), DARK_BG),
            ("TEXTCOLOR",   (3,0), (3,-1), DARK_BG),
            ("ROWBACKGROUNDS", (0,0), (-1,-1), [rl_colors.HexColor("#F8FAFC"), rl_colors.white]),
            ("GRID",        (0,0), (-1,-1), 0.3, MUTED),
            ("TOPPADDING",  (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0), (-1,-1), 5),
            ("LEFTPADDING", (0,0), (-1,-1), 8),
        ]))
        story.append(contact_table)
        if observs:
            story.append(Spacer(1, 6))
            story.append(Paragraph(f"<b>Observaciones:</b> {observs}", body_style))

        # ── KPIs ──
        story.append(Paragraph("Resumen de Cartera", section_style))
        kpi_data = [
            ["Pólizas Vigentes", "Clientes Únicos", "Premio Total", "Comisiones Est."],
            [str(len(vigentes)), str(clientes_u), fmt_money(total_premio), fmt_money(total_com)],
        ]
        kpi_table = Table(kpi_data, colWidths=[4.2*cm, 4.2*cm, 4.2*cm, 4.2*cm])
        kpi_table.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,0), DARK_BG),
            ("TEXTCOLOR",    (0,0), (-1,0), DARK_TEXT),
            ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",     (0,0), (-1,0), 9),
            ("ALIGN",        (0,0), (-1,-1), "CENTER"),
            ("FONTSIZE",     (0,1), (-1,1), 14),
            ("FONTNAME",     (0,1), (-1,1), "Helvetica-Bold"),
            ("TEXTCOLOR",    (0,1), (0,1), PRIMARY),
            ("TEXTCOLOR",    (1,1), (1,1), rl_colors.HexColor("#8B5CF6")),
            ("TEXTCOLOR",    (2,1), (2,1), SUCCESS),
            ("TEXTCOLOR",    (3,1), (3,1), WARNING),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [rl_colors.HexColor("#F0F9FF")]),
            ("GRID",         (0,0), (-1,-1), 0.5, MUTED),
            ("TOPPADDING",   (0,0), (-1,-1), 8),
            ("BOTTOMPADDING",(0,0), (-1,-1), 8),
        ]))
        story.append(kpi_table)

        # ── Pólizas ──
        if vigentes:
            story.append(Paragraph("Pólizas Vigentes", section_style))
            pol_header = ["N° Póliza", "Cliente", "Compañía", "Ramo", "Vto.", "Premio", "Est. Pago"]
            pol_rows = [pol_header]
            for p in vigentes[:20]:
                est_pago = p.get("estado_pago", "—")
                pol_rows.append([
                    p.get("nro_poliza", "—"),
                    (p.get("cliente_nombre") or "—")[:22],
                    (p.get("compania") or "—")[:14],
                    (p.get("ramo") or "—")[:14],
                    p.get("vigencia_hasta", "—"),
                    fmt_money(p.get("premio", 0)),
                    est_pago,
                ])
            col_w = [2.5*cm, 4*cm, 3*cm, 3*cm, 2.2*cm, 2.5*cm, 1.8*cm]
            pol_table = Table(pol_rows, colWidths=col_w, repeatRows=1)
            pol_style = [
                ("BACKGROUND",   (0,0), (-1,0), DARK_BG),
                ("TEXTCOLOR",    (0,0), (-1,0), DARK_TEXT),
                ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",     (0,0), (-1,-1), 8),
                ("ALIGN",        (5,1), (5,-1), "RIGHT"),
                ("ROWBACKGROUNDS",(0,1), (-1,-1), [rl_colors.white, rl_colors.HexColor("#F8FAFC")]),
                ("GRID",         (0,0), (-1,-1), 0.3, MUTED),
                ("TOPPADDING",   (0,0), (-1,-1), 4),
                ("BOTTOMPADDING",(0,0), (-1,-1), 4),
                ("LEFTPADDING",  (0,0), (-1,-1), 5),
            ]
            # Colorear estado de pago
            for row_idx, p in enumerate(vigentes[:20], start=1):
                ep = p.get("estado_pago", "")
                c = SUCCESS if ep == "Al día" else (WARNING if ep == "Financiada" else DANGER)
                pol_style.append(("TEXTCOLOR", (6, row_idx), (6, row_idx), c))
                pol_style.append(("FONTNAME",  (6, row_idx), (6, row_idx), "Helvetica-Bold"))
            pol_table.setStyle(TableStyle(pol_style))
            story.append(pol_table)
            if len(vigentes) > 20:
                story.append(Spacer(1, 4))
                story.append(Paragraph(
                    f"... y {len(vigentes) - 20} pólizas más no mostradas en este informe.",
                    label_style
                ))

        # ── Pie de página ──
        story.append(Spacer(1, 20))
        story.append(HRFlowable(width="100%", thickness=1, color=MUTED, spaceAfter=6))
        story.append(Paragraph(
            f"Generado por <b>Katrix ERP</b> &bull; {fecha_gen} &bull; Documento de uso interno.",
            label_style
        ))

        doc.build(story)
        return output_path

    except ImportError:
        print("reportlab no está instalado. Ejecutá: pip install reportlab")
        return None
    except Exception as e:
        print(f"Error exportar_ficha_pdf: {e}")
        return None


# ─── CRUD Licencias de Software ───────────────────────────────────────────
def generar_clave_licencia() -> str:
    """Genera una clave de licencia con formato KTX-XXXX-XXXX-XXXX"""
    import secrets
    import string
    chars = string.ascii_uppercase + string.digits
    part1 = "".join(secrets.choice(chars) for _ in range(4))
    part2 = "".join(secrets.choice(chars) for _ in range(4))
    part3 = "".join(secrets.choice(chars) for _ in range(4))
    return f"KTX-{part1}-{part2}-{part3}"

def obtener_licencias() -> list:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM licencias ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def obtener_licencia_por_clave(clave: str) -> Optional[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM licencias WHERE clave = ?", (clave.strip().upper(),))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def guardar_licencia(clave: str, cliente: str, fecha_expiracion: str, estado: str = "activa", limite_dispositivos: int = 1) -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO licencias (clave, cliente, fecha_expiracion, estado, limite_dispositivos)
        VALUES (?, ?, ?, ?, ?)
    """, (clave.strip().upper(), cliente.strip(), fecha_expiracion, estado, limite_dispositivos))
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id

def actualizar_licencia(licencia_id: int, cliente: str, fecha_expiracion: str, estado: str, limite_dispositivos: int, dispositivo_id: Optional[str] = None) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if dispositivo_id is not None:
        cursor.execute("""
            UPDATE licencias 
            SET cliente=?, fecha_expiracion=?, estado=?, limite_dispositivos=?, dispositivo_id=?
            WHERE id=?
        """, (cliente.strip(), fecha_expiracion, estado, limite_dispositivos, dispositivo_id, licencia_id))
    else:
        cursor.execute("""
            UPDATE licencias 
            SET cliente=?, fecha_expiracion=?, estado=?, limite_dispositivos=?
            WHERE id=?
        """, (cliente.strip(), fecha_expiracion, estado, limite_dispositivos, licencia_id))
    ok = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return ok

def eliminar_licencia(licencia_id: int) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM licencias WHERE id = ?", (licencia_id,))
    ok = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return ok

def validar_licencia(clave: str, dispositivo_id: str) -> dict:
    """
    Valida una clave de licencia.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM licencias WHERE clave = ?", (clave.strip().upper(),))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return {"valid": False, "message": "Clave de licencia inexistente", "cliente": "", "fecha_expiracion": ""}
        
    lic = dict(row)
    
    if lic["estado"] != "activa":
        return {"valid": False, "message": f"La licencia está {lic['estado']}", "cliente": lic["cliente"], "fecha_expiracion": lic["fecha_expiracion"]}
        
    from datetime import datetime
    try:
        exp_date = datetime.strptime(lic["fecha_expiracion"], "%Y-%m-%d")
        if exp_date < datetime.now():
            return {"valid": False, "message": "La licencia ha expirado", "cliente": lic["cliente"], "fecha_expiracion": lic["fecha_expiracion"]}
    except ValueError:
        pass
        
    registered_devices = []
    if lic["dispositivo_id"]:
        registered_devices = [d.strip() for d in lic["dispositivo_id"].split(",") if d.strip()]
        
    if dispositivo_id not in registered_devices:
        if len(registered_devices) >= lic["limite_dispositivos"]:
            return {
                "valid": False, 
                "message": f"Límite de dispositivos alcanzado ({lic['limite_dispositivos']})", 
                "cliente": lic["cliente"], 
                "fecha_expiracion": lic["fecha_expiracion"]
            }
        registered_devices.append(dispositivo_id)
        new_disp_str = ",".join(registered_devices)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE licencias SET dispositivo_id = ? WHERE id = ?", (new_disp_str, lic["id"]))
        conn.commit()
        conn.close()
        
    return {
        "valid": True, 
        "message": "Licencia válida y activa", 
        "cliente": lic["cliente"], 
        "fecha_expiracion": lic["fecha_expiracion"]
    }


# ─── MAIN ────────────────────────────────────────────────
if __name__ == "__main__":
    inicializar_db()
    
    if len(sys.argv) > 1:
        # Se pasó un documento/matrícula como argumento de línea de comandos
        identificador = sys.argv[1].strip()
        
        # 1. Buscar en cache SQLite
        datos = obtener_de_db(identificador)
        if datos:
            print("\n[INFO] Encontrado en el cache SQLite (costo $0):")
            imprimir_resultado(datos)
            sys.exit(0)
            
        # 2. Buscar en CSV
        datos_csv = buscar_en_csv(identificador)
        if datos_csv:
            print("\n[INFO] Encontrado en el CSV local (costo $0, sin scraping):")
            imprimir_resultado(datos_csv)
            sys.exit(0)
            
        # 3. Buscar en vivo
        print(f"No encontrado en CSV ni caché. Buscando '{identificador}' en vivo en la SSN...")
        try:
            site_key = obtener_sitekey()
            token = resolver_captcha(site_key)
            html = buscar_en_ssn(identificador, "DNI", token)
            datos = parsear_resultado(html)
            if datos:
                guardar_en_db(datos)
                print("\n[INFO] Encontrado en vivo en la SSN:")
                imprimir_resultado(datos)
                sys.exit(0)
            else:
                print("\nNo se encontraron resultados en el sitio de la SSN.")
                sys.exit(1)
        except Exception as e:
            print(f"\n[ERROR]: {e}")
            sys.exit(1)

    # Menú Interactivo
    while True:
        print("\n" + "="*65)
        print("  SSN SCRAPER & CACHE MANAGER")
        print("="*65)
        print("  1) Buscar productor por DNI/Matrícula (On-demand con Cache)")
        print("  2) Ver estadísticas del Cache local")
        print("  3) Salir")
        print("="*65)
        
        opcion = input("Seleccione una opción: ").strip()
        
        if opcion == "1":
            buscar_productor_interactivo()
        elif opcion == "2":
            mostrar_estadisticas()
        elif opcion == "3":
            print("\n¡Hasta luego!")
            break
        else:
            print("Opción inválida. Intente de nuevo.")