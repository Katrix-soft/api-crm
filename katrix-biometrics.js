/**
 * katrix-biometrics.js
 * Wrapper frontend para autenticación biométrica segura (WebAuthn).
 */

const KatrixBiometrics = {
  // Verificar si el navegador y dispositivo soportan biometría local (Touch ID / Face ID / Windows Hello)
  async isSupported() {
    if (!window.PublicKeyCredential) return false;
    try {
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch (e) {
      return false;
    }
  },

  // Conversiones criptográficas internas
  bufferToBase64URL(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  },

  base64URLToBuffer(base64url) {
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  },

  hexToBuffer(hex) {
    const view = new Uint8Array(hex.length / 2);
    for (let i = 0; i < view.length; i++) {
      view[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return view.buffer;
  },

  /**
   * Registra una nueva credencial biométrica en el dispositivo del cliente.
   * @param {string} username - Nombre de usuario (ej. panel_admin)
   * @param {string} challengeHex - Challenge criptográfico generado por el servidor (en hex)
   */
  async registerCredential(username, challengeHex) {
    if (!(await this.isSupported())) {
      throw new Error("Este dispositivo o navegador no soporta autenticación biométrica.");
    }

    const challengeBuffer = this.hexToBuffer(challengeHex);
    const userIdBuffer = new TextEncoder().encode(username + "_" + Date.now());

    const publicKeyOptions = {
      challenge: challengeBuffer,
      rp: {
        name: "Katrix CRM Panel",
        id: window.location.hostname
      },
      user: {
        id: userIdBuffer,
        name: username,
        displayName: "Administrador Katrix"
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },   // ES256 (Curva elíptica) - El más común en móviles/computadoras
        { type: "public-key", alg: -257 }  // RS256 (RSA) - Usado por Windows Hello viejo
      ],
      authenticatorSelection: {
        authenticatorAttachment: "platform", // Huella, Rostro, PIN nativo
        userVerification: "required",
        residentKey: "preferred"
      },
      timeout: 60000,
      attestation: "none"
    };

    const credential = await navigator.credentials.create({ publicKey: publicKeyOptions });
    
    // Obtener la clave pública del dispositivo en formato SubjectPublicKeyInfo (DER)
    let rawPublicKey = null;
    if (typeof credential.response.getPublicKey === 'function') {
      rawPublicKey = credential.response.getPublicKey();
    } else {
      throw new Error("No se pudo extraer la clave pública biométrica de este dispositivo.");
    }

    return {
      credentialId: this.bufferToBase64URL(credential.rawId),
      publicKeyDer: this.bufferToBase64URL(rawPublicKey),
      clientDataJSON: this.bufferToBase64URL(credential.response.clientDataJSON),
      attestationObject: this.bufferToBase64URL(credential.response.attestationObject)
    };
  },

  /**
   * Autentica al usuario usando el sensor biométrico.
   * @param {string} challengeHex - Challenge criptográfico del servidor (en hex)
   * @param {Array<string>} allowedCredentialIds - IDs de credenciales registradas permitidas
   */
  async loginCredential(challengeHex, allowedCredentialIds) {
    if (!(await this.isSupported())) {
      throw new Error("Este dispositivo o navegador no soporta autenticación biométrica.");
    }

    if (!allowedCredentialIds || allowedCredentialIds.length === 0) {
      throw new Error("No hay huellas o biométricos registrados para este panel todavía.");
    }

    const challengeBuffer = this.hexToBuffer(challengeHex);
    const allowCredentials = allowedCredentialIds.map(id => ({
      type: "public-key",
      id: this.base64URLToBuffer(id)
    }));

    const publicKeyOptions = {
      challenge: challengeBuffer,
      allowCredentials: allowCredentials,
      userVerification: "required",
      timeout: 60000
    };

    const assertion = await navigator.credentials.get({ publicKey: publicKeyOptions });

    return {
      credentialId: this.bufferToBase64URL(assertion.rawId),
      signature: this.bufferToBase64URL(assertion.response.signature),
      authenticatorData: this.bufferToBase64URL(assertion.response.authenticatorData),
      clientDataJSON: this.bufferToBase64URL(assertion.response.clientDataJSON)
    };
  }
};

window.KatrixBiometrics = KatrixBiometrics;
