"""
test_api.py
Suite de pruebas automatizadas y cliente interactivo de demostración para la API REST de Katrix ERP.
"""
import os
import sys
import time
import json
import shutil
import unittest
import argparse
import requests
from datetime import datetime

# Agregar la ruta de .venv al final de sys.path para que use slowapi de allí sin sobreescribir typing_extensions u otros paquetes más nuevos del sistema.
venv_site = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".venv", "lib", "python3.13", "site-packages"))
if venv_site not in sys.path:
    sys.path.append(venv_site)

# ─────────────────────────────────────────────────────────────────────────────
# 1. Configuración de Aislamiento para Tests Unitarios
# ─────────────────────────────────────────────────────────────────────────────
TEST_DB_DIR = "data"
TEST_DB_NAME = "test_api_temp.db"
TEST_DB_PATH = os.path.join(TEST_DB_DIR, TEST_DB_NAME)

# Parcheamos la ruta de la base de datos en ssn_test antes de importarla o importar api.py
import ssn_test
ssn_test.DB_PATH = TEST_DB_PATH

from fastapi.testclient import TestClient
import api
from api import app

# ─────────────────────────────────────────────────────────────────────────────
# 2. Clase de Tests Unitarios Automatizados
# ─────────────────────────────────────────────────────────────────────────────
class KatrixAPITestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Asegurar directorio de test
        os.makedirs(TEST_DB_DIR, exist_ok=True)
        # Limpiar base de datos previa de test
        if os.path.exists(TEST_DB_PATH):
            try:
                os.remove(TEST_DB_PATH)
            except Exception:
                pass
        # Inicializar la base de datos limpia de test
        ssn_test.inicializar_db()
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        # Eliminar base de datos de test temporal
        if os.path.exists(TEST_DB_PATH):
            try:
                # Pequeña espera para liberar locks de SQLite
                time.sleep(0.5)
                os.remove(TEST_DB_PATH)
                # Remover archivos temporales de WAL si existen
                for ext in ["-wal", "-journal", "-shm"]:
                    if os.path.exists(TEST_DB_PATH + ext):
                        os.remove(TEST_DB_PATH + ext)
            except Exception as e:
                print(f"\n[Warning] No se pudo limpiar la base de datos de test temporal: {e}")

    def test_01_health_check(self):
        """Verificar endpoint de salud y disponibilidad."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("licencias", data["endpoints"])

    def test_02_validation_licencia_defecto(self):
        """Verificar la validación de la licencia semilla por defecto."""
        payload = {
            "clave": "KTX-TEST-VALID-2026",
            "dispositivo_id": "TEST-FINGERPRINT-1"
        }
        response = self.client.post("/licencias/validar", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["valid"])
        self.assertEqual(data["cliente"], "Cliente Prueba")

    def test_03_validation_licencia_limite_dispositivos(self):
        """Verificar el bloqueo por límite de dispositivos en licencias."""
        # La licencia semilla KTX-TEST-VALID-2026 tiene un límite de 2 dispositivos.
        # Dispositivo 1 (ya registrado en test_02)
        # Dispositivo 2 (debería registrarse con éxito)
        response = self.client.post("/licencias/validar", json={
            "clave": "KTX-TEST-VALID-2026",
            "dispositivo_id": "TEST-FINGERPRINT-2"
        })
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["valid"])

        # Dispositivo 3 (debería ser rechazado por límite excedido)
        response = self.client.post("/licencias/validar", json={
            "clave": "KTX-TEST-VALID-2026",
            "dispositivo_id": "TEST-FINGERPRINT-3"
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertFalse(data["valid"])
        self.assertIn("dispositivos alcanzado", data["message"])

    def test_04_login_incorrecto(self):
        """Verificar que las credenciales incorrectas retornen error."""
        response = self.client.post("/auth/login", json={
            "username": "broker",
            "password": "wrongpassword"
        })
        self.assertEqual(response.status_code, 401)

    def test_05_login_exitoso_y_perfil(self):
        """Verificar login del admin por defecto y obtención de perfil."""
        response = self.client.post("/auth/login", json={
            "username": "broker",
            "password": "password123"
        })
        self.assertEqual(response.status_code, 200)
        token_data = response.json()
        self.assertIn("access_token", token_data)
        token = token_data["access_token"]

        # Consultar perfil /auth/me
        headers = {"Authorization": f"Bearer {token}"}
        response_me = self.client.get("/auth/me", headers=headers)
        self.assertEqual(response_me.status_code, 200)
        user_data = response_me.json()
        self.assertEqual(user_data["username"], "broker")
        self.assertEqual(user_data["role"], "admin")

    def test_06_crud_licencias_admin(self):
        """Verificar la creación, listado, edición y eliminación de licencias (Admin)."""
        # 1. Login Admin
        login_res = self.client.post("/auth/login", json={"username": "broker", "password": "password123"})
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Crear nueva licencia
        payload = {
            "cliente": "Nuevo Cliente Comercial",
            "email_cliente": "nuevo@cliente.com",
            "fecha_expiracion": "2027-12-31",
            "estado": "activa",
            "limite_dispositivos": 5
        }
        res_create = self.client.post("/licencias/", json=payload, headers=headers)
        self.assertEqual(res_create.status_code, 200)
        self.assertTrue(res_create.json()["ok"])
        
        # 3. Listar licencias
        res_list = self.client.get("/licencias/", headers=headers)
        self.assertEqual(res_list.status_code, 200)
        lics = res_list.json()
        self.assertTrue(len(lics) >= 2) # Semilla + la nueva
        
        nueva_lic = next(l for l in lics if l["cliente"] == "Nuevo Cliente Comercial")
        self.assertIsNotNone(nueva_lic)
        self.assertEqual(nueva_lic["limite_dispositivos"], 5)
        lic_id = nueva_lic["id"]
        lic_clave = nueva_lic["clave"]

        # 4. Validar la licencia recién creada
        res_val = self.client.post("/licencias/validar", json={
            "clave": lic_clave,
            "dispositivo_id": "CLIENT-HW-99"
        })
        self.assertTrue(res_val.json()["valid"])

        # 5. Editar licencia (Suspender)
        payload_upd = {
            "cliente": "Nuevo Cliente Comercial",
            "fecha_expiracion": "2027-12-31",
            "estado": "suspendida",
            "limite_dispositivos": 5,
            "dispositivo_id": "CLIENT-HW-99"
        }
        res_upd = self.client.put(f"/licencias/{lic_id}", json=payload_upd, headers=headers)
        self.assertEqual(res_upd.status_code, 200)

        # 6. Validar de nuevo (debería ser inválida ahora)
        res_val_susp = self.client.post("/licencias/validar", json={
            "clave": lic_clave,
            "dispositivo_id": "CLIENT-HW-99"
        })
        self.assertFalse(res_val_susp.json()["valid"])

        # 7. Eliminar licencia
        res_del = self.client.delete(f"/licencias/{lic_id}", headers=headers)
        self.assertEqual(res_del.status_code, 200)

        # 8. Validar eliminada (debería ser inexistente)
        res_val_del = self.client.post("/licencias/validar", json={
            "clave": lic_clave,
            "dispositivo_id": "CLIENT-HW-99"
        })
        self.assertFalse(res_val_del.json()["valid"])
        self.assertEqual(res_val_del.json()["message"], "Clave de licencia inexistente")

    def test_07_panel_sessions_and_logs(self):
        """Verificar endpoints de sesiones del panel y logs de auditoría."""
        # 1. Login kadmin (Superadmin)
        login_res = self.client.post("/panel/auth/login", json={"username": "kadmin", "password": "Katrix2026$"})
        self.assertEqual(login_res.status_code, 200)
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Consultar sesiones
        res_sess = self.client.get("/panel/sessions", headers=headers)
        self.assertEqual(res_sess.status_code, 200)
        sessions = res_sess.json()
        self.assertTrue(any(s["username"] == "kadmin" for s in sessions))

        # 3. Consultar logs
        res_logs = self.client.get("/panel/logs", headers=headers)
        self.assertEqual(res_logs.status_code, 200)
        logs = res_logs.json()
        self.assertTrue(len(logs) > 0)

        # 4. Login nicodev (Admin) y verificar que tiene sesión registrada
        login_nico = self.client.post("/panel/auth/login", json={"username": "nicodev", "password": "nicodev"})
        self.assertEqual(login_nico.status_code, 200)
        nico_token = login_nico.json()["access_token"]
        nico_headers = {"Authorization": f"Bearer {nico_token}"}

        # Verificar nico puede consultar su perfil
        res_me = self.client.get("/auth/me", headers=nico_headers)
        self.assertEqual(res_me.status_code, 200)

        # 5. Revocar nicodev por kadmin
        res_revoke = self.client.post("/panel/sessions/nicodev/revoke", json={}, headers=headers)
        self.assertEqual(res_revoke.status_code, 200)
        self.assertTrue(res_revoke.json()["ok"])

        # 6. Consultar perfil con nicodev token de nuevo (debería ser rechazado por sesión revocada)
        res_me_revoked = self.client.get("/auth/me", headers=nico_headers)
        self.assertEqual(res_me_revoked.status_code, 401)
        self.assertIn("revocada", res_me_revoked.json()["detail"])

    def test_08_pas_sorting_and_filtering(self):
        """Verificar el filtrado, ordenamiento y exportación de PAS a CSV en API-CRM."""
        # 1. Login Admin
        login_res = self.client.post("/auth/login", json={"username": "broker", "password": "password123"})
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Consultar listado de PAS
        response = self.client.get("/pas/", headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("items", data)
        self.assertIn("total", data)
        
        # 3. Filtrar y ordenar
        response_filtered = self.client.get("/pas/?q=test&ramo=Vida&mostly_complete=true&sort_by=nombre&sort_desc=true", headers=headers)
        self.assertEqual(response_filtered.status_code, 200)
        
        # 4. Exportar a CSV
        response_csv = self.client.get("/pas/exportar-csv?q=test&ramo=Vida&mostly_complete=true", headers=headers)
        self.assertEqual(response_csv.status_code, 200)
        self.assertEqual(response_csv.headers.get("content-type"), "text/csv; charset=utf-8")
        self.assertIn("attachment; filename=productores_exportados.csv", response_csv.headers.get("content-disposition", ""))


# ─────────────────────────────────────────────────────────────────────────────
# 3. Cliente Interactivo (CLI Live Demo)
# ─────────────────────────────────────────────────────────────────────────────
def run_live_cli(base_url):
    print("="*65)
    print("  KATRIX ERP REST API — CLIENTE INTERACTIVO (DEMO)")
    print("="*65)
    print(f"Conectando a: {base_url}")
    
    # Verificar salud del servidor
    try:
        r = requests.get(f"{base_url}/health", timeout=5)
        if r.status_code == 200:
            print(f"✅ Conexión establecida. Versión API: {r.json().get('version', 'unknown')}")
        else:
            print(f"❌ Conexión fallida (HTTP {r.status_code})")
            return
    except Exception as e:
        print(f"❌ Error de conexión al servidor en {base_url}: {e}")
        return

    session = requests.Session()
    token = None
    role = None

    while True:
        print("\n" + "-"*40)
        print(" Menú de Acciones:")
        print(" 1) Validar Licencia de Software")
        print(" 2) Iniciar Sesión (Obtener JWT)")
        print(" 3) Ver mi perfil (/auth/me)")
        print(" 4) Listar Productores PAS")
        print(" 5) Ver Licencias Registradas (Solo Admin)")
        print(" 6) Generar Nueva Licencia (Solo Admin)")
        print(" 0) Salir")
        print("-"*40)
        
        op = input("Seleccione una opción: ").strip()
        if op == "0":
            print("¡Adiós!")
            break
            
        elif op == "1":
            clave = input("Ingrese Clave de Licencia (ej: KTX-TEST-VALID-2026): ").strip()
            hw_id = input("Ingrese Machine ID (deje vacío para auto-generar): ").strip()
            if not hw_id:
                hw_id = "DEMO-FINGERPRINT-CLI"
            payload = {"clave": clave, "dispositivo_id": hw_id}
            try:
                r = session.post(f"{base_url}/licencias/validar", json=payload)
                print(json.dumps(r.json(), indent=4, ensure_ascii=False))
            except Exception as e:
                print("Error:", e)
                
        elif op == "2":
            user = input("Usuario: ").strip() or "broker"
            password = input("Contraseña: ").strip() or "password123"
            try:
                r = session.post(f"{base_url}/auth/login", json={"username": user, "password": password})
                if r.status_code == 200:
                    token = r.json()["access_token"]
                    session.headers.update({"Authorization": f"Bearer {token}"})
                    print("✅ Sesión iniciada con éxito. Token JWT almacenado.")
                else:
                    print("❌ Error:", r.json())
            except Exception as e:
                print("Error:", e)
                
        elif op == "3":
            try:
                r = session.get(f"{base_url}/auth/me")
                print(json.dumps(r.json(), indent=4, ensure_ascii=False))
            except Exception as e:
                print("Error:", e)
                
        elif op == "4":
            try:
                r = session.get(f"{base_url}/pas/")
                if r.status_code == 200:
                    pas_list = r.json()
                    print(f"Se encontraron {len(pas_list)} productores.")
                    for p in pas_list[:5]:
                        print(f" - Matrícula: {p.get('matricula')} | Nombre: {p.get('nombre')} | Estado: {p.get('estado')}")
                    if len(pas_list) > 5:
                        print(" ... (lista truncada a los primeros 5)")
                else:
                    print("❌ Error:", r.json())
            except Exception as e:
                print("Error:", e)
                
        elif op == "5":
            try:
                r = session.get(f"{base_url}/licencias/")
                if r.status_code == 200:
                    print(json.dumps(r.json(), indent=4, ensure_ascii=False))
                else:
                    print("❌ Error:", r.json())
            except Exception as e:
                print("Error:", e)
                
        elif op == "6":
            cliente = input("Nombre del Cliente: ").strip()
            exp = input("Fecha Expiración (YYYY-MM-DD): ").strip() or "2027-12-31"
            limite = input("Límite de Dispositivos (default 1): ").strip()
            limite = int(limite) if limite.isdigit() else 1
            payload = {
                "cliente": cliente,
                "fecha_expiracion": exp,
                "estado": "activa",
                "limite_dispositivos": limite
            }
            try:
                r = session.post(f"{base_url}/licencias/", json=payload)
                print(json.dumps(r.json(), indent=4, ensure_ascii=False))
            except Exception as e:
                print("Error:", e)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Entrypoint del Script
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Katrix ERP API Test and Client Utility")
    parser.add_argument("--test", action="store_true", help="Ejecutar suite de tests automatizados (aislados)")
    parser.add_argument("--live", action="store_true", help="Ejecutar CLI interactivo contra servidor en vivo")
    parser.add_argument("--url", default="http://localhost:8000", help="URL del servidor API remoto (usado con --live)")
    
    args = parser.parse_args()
    
    if args.test:
        # Ejecutar suite de pruebas unitarias
        print("Iniciando pruebas unitarias automatizadas con base de datos aislada...")
        sys.argv = [sys.argv[0]] # Limpiar argumentos para unittest
        unittest.main()
    elif args.live:
        run_live_cli(args.url)
    else:
        parser.print_help()
        print("\nEjemplo para correr tests: python test_api.py --test")
        print("Ejemplo para cliente interactivo: python test_api.py --live --url http://localhost:8000")
