# Guía de Uso y Despliegue: Katrix ERP REST API

Esta guía documenta la arquitectura, el flujo de autenticación, el sistema de licenciamiento por hardware y el despliegue en producción usando **Easypanel (Docker)** de la API REST de Katrix ERP.

---


## 1. Arquitectura y Roles (RBAC)

La API REST está construida con **FastAPI** y protegida mediante **JWT** (JSON Web Tokens). Centraliza la lógica relacional en una base de datos SQLite (`productores_scraped.db`) utilizando transacciones en modo WAL.

### Control de Acceso Basado en Roles (RBAC)
- **Rol `admin`**: Posee acceso total de lectura y escritura (CRUD) a usuarios, productores, pólizas, siniestros, visitas, candidatos y logs de auditoría. Puede generar y revocar licencias.
- **Rol `agente`**: Acceso restringido. Solo lectura de la base general y lectura/escritura en los datos que le corresponden a su propia matrícula y usuario.

---

## 2. Despliegue en Servidor (Easypanel / Docker)

**Easypanel** compilará el backend automáticamente leyendo el `Dockerfile` que se encuentra en la raíz del proyecto.

### Paso 1: Configurar el Repositorio de Git
Subí a un repositorio privado de GitHub únicamente los archivos del backend:
```text
├── api.py
├── api_models.py
├── ssn_test.py
├── utils.py
├── requirements.txt
├── Dockerfile
└── productores-asesores-sociedades.csv
```

### Paso 2: Crear el Servicio en Easypanel
1. Hacé clic en **Create Service** → **App**.
2. Vinculá tu repositorio de GitHub e indicá la rama principal (`main`).
3. En **Build Method**, seleccioná **Dockerfile**.

### Paso 3: Configurar el Volumen Persistente (SQLite) ⚠️
Para evitar perder los datos y usuarios registrados cada vez que el contenedor se compile de nuevo:
1. En la configuración de la App en Easypanel, andá a la pestaña **Volumes** (Volúmenes).
2. Agregá un volumen con la configuración:
   - **Mount Path**: `/app/data` (La base de datos se creará dentro de esta ruta persistente).
   - **Name**: `katrix-db-vol`

### Paso 4: Redes y Puertos
- Configura el **App Port** en `8000`. Easypanel creará el certificado SSL (HTTPS) de forma automática.

### Paso 5: Variables de Entorno y Base de Datos (PostgreSQL / SQLite)
La API soporta de forma dinámica tanto **SQLite** (por defecto) como **PostgreSQL** para la persistencia.

Si querés usar **PostgreSQL** (altamente recomendado en producción), simplemente agregá la variable `DATABASE_URL` en la configuración de la App. La API detectará el motor, creará las tablas y sembrará los usuarios por defecto (`kadmin` y `nicodev`) de manera automática.

Agregá las siguientes variables en la pestaña **Environment**:
```env
KATRIX_SECRET_KEY=clave-super-secreta-de-64-caracteres-para-jwt
TOKEN_EXPIRE_HOURS=24
KATRIX_CORS_ORIGINS=*
# Para usar PostgreSQL (producción):
DATABASE_URL=postgresql://postgres:Nachax5$@vps-katrix_postgres:5432/vps-katrix
```

---

## 3. Certificados de Licencia por Hardware

La API gestiona licencias vinculando cada clave a una huella digital única del hardware de la PC cliente (Machine ID).

### Flujo de Activación
1. Al arrancar la aplicación de escritorio Flet, esta genera un hash SHA-256 estable a partir del hardware del equipo (Machine ID).
2. Si no hay una licencia válida guardada en `data/licencia_config.json`, la app solicita la clave (formato `KTX-XXXX-XXXX-XXXX`).
3. Hace una llamada POST a `/licencias/validar` enviando la clave y la huella digital.
4. El servidor registra el dispositivo (si está dentro del límite) y devuelve el estado.
5. La app guarda localmente la clave activada. Admite **Modo Offline** (si el servidor no responde pero la licencia ya fue activada con anterioridad en esa misma máquina, se permite el acceso).

---

## 4. Ejemplos Prácticos de Integración

### Autenticación y Obtención de Token JWT

```bash
# Iniciar sesión para obtener el token JWT
curl -X POST "https://tu-api.com/auth/login" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=broker&password=password123"
```
**Respuesta exitosa:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

---

### Validación de Licencia (Flet Desktop App)

```bash
# Validar licencia con huella digital del hardware
curl -X POST "https://tu-api.com/licencias/validar" \
     -H "Content-Type: application/json" \
     -d '{
       "clave": "KTX-TEST-VALID-2026",
       "dispositivo_id": "84B6F7B8C4A9D2E1"
     }'
```
**Respuesta:**
```json
{
  "valid": true,
  "message": "Licencia válida y activa",
  "cliente": "Cliente Prueba",
  "fecha_expiracion": "2030-12-31"
}
```

---

### Integración en Python (Ejemplo de Consumo Remoto)

```python
import requests
import json

BASE_URL = "https://tu-api.com"

# 1. Validar la licencia
lic_payload = {
    "clave": "KTX-TEST-VALID-2026",
    "dispositivo_id": "MI-PC-HARDWARE-ID"
}
res_lic = requests.post(f"{BASE_URL}/licencias/validar", json=lic_payload)
if not res_lic.json().get("valid"):
    print("Error: Licencia inválida o expirada.")
    exit(1)

# 2. Login de Usuario
login_data = {
    "username": "broker",
    "password": "password123"
}
res_login = requests.post(f"{BASE_URL}/auth/login", data=login_data)
token = res_login.json()["access_token"]

# 3. Realizar peticiones authenticated usando el Token JWT
headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

# Obtener los productores PAS
res_pas = requests.get(f"{BASE_URL}/pas/", headers=headers)
print(f"Productores: {res_pas.json()}")
```

---

## 5. Entorno de Pruebas Local

Para testear la API localmente sin afectar a la base de datos de producción:
1. Asegurate de tener activado el entorno virtual.
2. Ejecutá el script de pruebas automatizadas:
   ```bash
   ./run_api_tests.sh
   ```
3. Para correr la consola interactiva CLI contra tu servidor local:
   ```bash
   python test_api.py --live --url http://localhost:8000
   ```
