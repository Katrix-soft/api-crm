"""
katrix_biometrics.py
Librería para gestionar la criptografía de biometría WebAuthn (Touch ID / Face ID / Windows Hello)
utilizando la biblioteca 'cryptography' nativa.
"""
import os
import secrets
import hashlib
import json
import base64
from typing import Tuple, Optional
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.exceptions import InvalidSignature

# Generar un reto seguro y aleatorio de 32 bytes en formato hexadecimal
def generar_challenge() -> str:
    return secrets.token_hex(32)

def clean_base64(b64_str: str) -> bytes:
    # Limpia el padding y decodifica Base64/Base64URL de forma segura
    b64_str = b64_str.replace("-", "+").replace("_", "/")
    # Añadir padding si es necesario
    missing_padding = len(b64_str) % 4
    if missing_padding:
        b64_str += "=" * (4 - missing_padding)
    return base64.b64decode(b64_str)

def verificar_firma_biometrica(
    public_key_der_b64: str,
    signature_b64: str,
    authenticator_data_b64: str,
    client_data_json_b64: str,
    challenge_original: str
) -> Tuple[bool, str]:
    """
    Verifica criptográficamente la firma digital generada por el sensor biométrico del cliente.
    Retorna (True, "") si es válida, o (False, "motivo") si no lo es.
    """
    try:
        # 1. Decodificar datos de entrada
        public_key_bytes = clean_base64(public_key_der_b64)
        signature = clean_base64(signature_b64)
        authenticator_data = clean_base64(authenticator_data_b64)
        client_data_json_bytes = clean_base64(client_data_json_b64)
        
        # 2. Cargar clave pública (soporta EC y RSA)
        try:
            public_key = serialization.load_der_public_key(public_key_bytes)
        except Exception as e:
            return False, f"Error al cargar la clave pública DER: {str(e)}"
            
        # 3. Validar que el challenge original coincida con el que está dentro de clientDataJSON
        client_data = json.loads(client_data_json_bytes.decode("utf-8"))
        challenge_recibido = client_data.get("challenge", "")
        
        # El cliente puede enviarlo en base64url, normalizarlo para comparar
        try:
            # Si el challenge original es hex, verifiquemos si coincide decodificándolo o comparando bytes
            challenge_recibido_bytes = clean_base64(challenge_recibido)
            challenge_original_bytes = bytes.fromhex(challenge_original)
            if challenge_recibido_bytes != challenge_original_bytes:
                return False, "El challenge en clientDataJSON no coincide con el original"
        except Exception:
            # Comparación directa de string como contingencia
            if challenge_recibido != challenge_original:
                return False, "El challenge recibido no coincide con el original"

        # 4. Reconstruir los datos firmados (WebAuthn firma: authenticatorData + sha256(clientDataJSON))
        client_data_hash = hashlib.sha256(client_data_json_bytes).digest()
        datos_firmados = authenticator_data + client_data_hash
        
        # 5. Verificar firma según tipo de clave pública
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature,
                datos_firmados,
                ec.ECDSA(hashes.SHA256())
            )
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                datos_firmados,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        else:
            return False, "Algoritmo de clave pública no soportado (solo EC o RSA)"
            
        return True, ""
        
    except InvalidSignature:
        return False, "Firma digital biométrica inválida"
    except Exception as e:
        return False, f"Error en la verificación biométrica: {str(e)}"
