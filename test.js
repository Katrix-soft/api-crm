let API_BASE = "";
let TOKEN = "";
let USER = null;
let licencias = [];

const $ = (id) => document.getElementById(id);

function hasPerm(permission) {
  if (!USER) return false;
  if (USER.role === "panel_superadmin") return true;
  if (USER.role === "admin") return true; // general CRM admin
  if (!USER.permissions) return true;
  return USER.permissions[permission] !== false;
}

function showToast(msg, isError){
  const t = $("toast");
  t.textContent = msg;
  t.style.borderColor = isError ? "var(--red)" : "var(--border)";
  t.style.color = isError ? "var(--red)" : "var(--text)";
  t.style.display = "block";
  clearTimeout(t._timer);
  t._timer = setTimeout(()=> t.style.display = "none", 3500);
}

async function apiFetch(path, options = {}){
  const headers = Object.assign(
    { "Content-Type": "application/json" },
    options.headers || {}
  );
  if (TOKEN) headers["Authorization"] = "Bearer " + TOKEN;

  const res = await fetch(API_BASE + path, Object.assign({}, options, { headers }));
  if (res.status === 401){
    showToast("Tu sesión expiró. Iniciá sesión de nuevo.", true);
    cerrarSesion();
    throw new Error("401");
  }
  if (!res.ok){
    let detail = "Error " + res.status;
    try { const j = await res.json(); detail = j.detail || detail; } catch(e){}
    throw new Error(detail);
  }
  if (res.status === 204) return null;
  return res.json();
}

  // -----------------------------------------------------------
  // LÓGICA TEMA CLARO / OSCURO
  // -----------------------------------------------------------
  let currentTheme = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', currentTheme);
  
  document.getElementById('btnThemeToggle').addEventListener('click', () => {
      currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', currentTheme);
      localStorage.setItem('theme', currentTheme);
  });

  // -----------------------------------------------------------
  // LÓGICA DE INSTALACIÓN PWA (Android e iOS)
  // -----------------------------------------------------------
  let deferredPrompt;
  const btnInstallApp = document.getElementById('btnInstallApp');

  // Detectar iOS
  const isIos = () => {
    const userAgent = window.navigator.userAgent.toLowerCase();
    return /iphone|ipad|ipod/.test(userAgent);
  };
  // Detectar si ya está en modo standalone (instalada)
  const isInStandaloneMode = () => ('standalone' in window.navigator) && (window.navigator.standalone);

  // En Android/Chrome salta este evento si es instalable
  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e;
    btnInstallApp.style.display = 'inline-flex';
    btnInstallApp.innerHTML = '📱 Instalar en Android';
  });

  // Mostrar botón en iOS si no está instalada
  if (isIos() && !isInStandaloneMode()) {
    btnInstallApp.style.display = 'inline-flex';
    btnInstallApp.innerHTML = '📱 Instalar en iOS';
  }

  btnInstallApp.addEventListener('click', async () => {
    if (isIos()) {
      alert("Para instalar en iPhone/iPad:\n1. Tocá el ícono de 'Compartir' (el cuadradito con flecha hacia arriba) en la barra de Safari.\n2. Seleccioná 'Agregar a Inicio' o 'Add to Home Screen'.");
    } else if (deferredPrompt) {
      deferredPrompt.prompt();
      const { outcome } = await deferredPrompt.userChoice;
      if (outcome === 'accepted') {
        btnInstallApp.style.display = 'none';
      }
      deferredPrompt = null;
    } else {
      alert("Para instalar en Android:\nTocá los 3 puntitos del navegador Chrome y elegí 'Instalar aplicación' o 'Agregar a la pantalla principal'.");
    }
  });

  // Escuchar si se instaló exitosamente
  window.addEventListener('appinstalled', () => {
    btnInstallApp.style.display = 'none';
    deferredPrompt = null;
    console.log('PWA instalada correctamente');
  });

  // -----------------------------------------------------------

$("btnLogin").addEventListener("click", login);
$("loginPass").addEventListener("keydown", (e)=>{ if(e.key === "Enter") login(); });

async function login(){
  const base = $("apiBase").value.trim().replace(/\/$/, "");
  const username = $("loginUser").value.trim();
  const password = $("loginPass").value;
  const errBox = $("loginError");
  errBox.style.display = "none";

  if (!base || !username || !password){
    errBox.textContent = "Completá la URL de la API, usuario y contraseña.";
    errBox.style.display = "block";
    return;
  }
  API_BASE = base;

  try{
    const res = await fetch(API_BASE + "/panel/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok){
      const j = await res.json().catch(()=>({}));
      throw new Error(j.detail || "Usuario o contraseña incorrectos");
    }
    const data = await res.json();
    if (data.role !== "panel_admin" && data.role !== "panel_superadmin"){
      throw new Error("Acceso denegado: rol de administrador del panel requerido.");
    }
    TOKEN = data.access_token;
    USER = data;
    sessionStorage.setItem("katrix_token", TOKEN);
    sessionStorage.setItem("katrix_api_base", API_BASE);
    sessionStorage.setItem("katrix_user", JSON.stringify(USER));
    mostrarDashboard();
  }catch(err){
    errBox.textContent = err.message;
    errBox.style.display = "block";
  }
}

function cerrarSesion(){
  TOKEN = ""; USER = null;
  sessionStorage.removeItem("katrix_token");
  sessionStorage.removeItem("katrix_user");
  $("dashboard").style.display = "none";
  $("loginScreen").style.display = "flex";
}
$("btnLogout").addEventListener("click", cerrarSesion);

$("chkShowLoginPass").addEventListener("change", function() {
  $("loginPass").type = this.checked ? "text" : "password";
});

$("chkShowModalPass").addEventListener("change", function() {
  const type = this.checked ? "text" : "password";
  $("fCurrentPass").type = type;
  $("fNewPass").type = type;
  $("fConfirmPass").type = type;
});

function mostrarDashboard(){
  $("loginScreen").style.display = "none";
  $("dashboard").style.display = "block";
  $("userInfo").textContent = `Conectado como ${USER.username} (${USER.role}) · ${API_BASE}`;
  
  if (USER.role === "panel_admin" || USER.role === "panel_superadmin" || USER.role === "superadmin") {
    $("btnChangePass").style.display = "inline-flex";
    $("btnRegBio").style.display = "inline-flex";
  } else {
    $("btnChangePass").style.display = "none";
    $("btnRegBio").style.display = "none";
  }
  
  if (USER.role === "panel_superadmin" || USER.role === "superadmin") {
    $("btnManageUsers").style.display = "inline-flex";
  } else {
    $("btnManageUsers").style.display = "none";
  }
  
  if (hasPerm("crear_licencia")) {
    $("btnNueva").style.display = "inline-flex";
  } else {
    $("btnNueva").style.display = "none";
  }

  // Control Visibility of Tabs
  if (USER.role === "panel_superadmin" || USER.role === "superadmin") {
    $("navTabUsers").style.display = "inline-flex";
    $("navTabSesiones").style.display = "inline-flex";
    $("navTabLogs").style.display = "inline-flex";
  } else {
    $("navTabUsers").style.display = "none";
    
    if (hasPerm("ver_sesiones")) {
      $("navTabSesiones").style.display = "inline-flex";
    } else {
      $("navTabSesiones").style.display = "none";
    }
    
    if (hasPerm("ver_logs")) {
      $("navTabLogs").style.display = "inline-flex";
    } else {
      $("navTabLogs").style.display = "none";
    }
  }

  switchTab("tab-licencias");
}

async function checkBiometricsSupport() {
  try {
    const supported = await KatrixBiometrics.isSupported();
    if (!supported) return;

    // Obtener las credenciales registradas del servidor
    const res = await fetch(API_BASE + "/panel/auth/biometrics/credentials");
    if (res.ok) {
      const creds = await res.json();
      if (creds && creds.length > 0) {
        $("btnBioLogin").style.display = "flex";
        window.allowedCredentials = creds;
      } else {
        $("btnBioLogin").style.display = "none";
      }
    }
  } catch(e) {
    console.warn("Biometrics check failed: ", e);
  }
}

/* Restaurar sesión si ya había una en esta pestaña */
(function restaurar(){
  $("apiBase").value = window.location.origin;
  API_BASE = window.location.origin;

  const t = sessionStorage.getItem("katrix_token");
  const u = sessionStorage.getItem("katrix_user");
  const b = sessionStorage.getItem("katrix_api_base");
  if (t && u && b){
    const parsedUser = JSON.parse(u);
    if (parsedUser.role === "panel_admin" || parsedUser.role === "panel_superadmin") {
      TOKEN = t; USER = parsedUser; API_BASE = b;
      $("apiBase").value = API_BASE;
      mostrarDashboard();
    } else {
      cerrarSesion();
    }
  }
  
  // Verificar soporte biométrico al cargar
  checkBiometricsSupport();
})();


// Eventos de Autenticación Biométrica y Cambio de Clave
$("btnBioLogin").addEventListener("click", async () => {
  const base = $("apiBase").value.trim().replace(/\/$/, "");
  const errBox = $("loginError");
  errBox.style.display = "none";
  API_BASE = base;

  if (!window.allowedCredentials || window.allowedCredentials.length === 0) {
    errBox.textContent = "No hay biométricos registrados para este servidor.";
    errBox.style.display = "block";
    return;
  }

  try {
    // 1. Obtener challenge
    const challengeRes = await fetch(API_BASE + "/panel/auth/biometrics/challenge");
    if (!challengeRes.ok) throw new Error("No se pudo obtener el reto biométrico.");
    const challengeData = await challengeRes.json();

    // 2. Solicitar autenticación biométrica local
    showToast("Colocá tu huella o usá el reconocimiento facial...");
    const assertion = await KatrixBiometrics.loginCredential(
      challengeData.challenge,
      window.allowedCredentials
    );

    // 3. Enviar firma biométrica al backend
    const loginRes = await fetch(API_BASE + "/panel/auth/biometrics/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        credential_id: assertion.credentialId,
        signature: assertion.signature,
        authenticator_data: assertion.authenticatorData,
        client_data_json: assertion.clientDataJSON,
        challenge_token: challengeData.challenge_token
      })
    });

    if (!loginRes.ok) {
      const j = await loginRes.json().catch(() => ({}));
      throw new Error(j.detail || "Fallo en la autenticación biométrica");
    }

    const data = await loginRes.json();
    TOKEN = data.access_token;
    USER = data;
    sessionStorage.setItem("katrix_token", TOKEN);
    sessionStorage.setItem("katrix_api_base", API_BASE);
    sessionStorage.setItem("katrix_user", JSON.stringify(USER));
    mostrarDashboard();
    showToast("¡Inicio de sesión biométrico exitoso!");
  } catch (err) {
    errBox.textContent = err.message;
    errBox.style.display = "block";
    showToast(err.message, true);
  }
});

// MODAL: Cambiar contraseña
$("btnChangePass").addEventListener("click", () => {
  $("fNewUsername").value = "";
  $("fCurrentPass").value = "";
  $("fNewPass").value = "";
  $("fConfirmPass").value = "";
  $("chkShowModalPass").checked = false;
  $("fCurrentPass").type = "password";
  $("fNewPass").type = "password";
  $("fConfirmPass").type = "password";
  $("changePassError").style.display = "none";
  $("modalChangePassOverlay").style.display = "flex";
});

$("btnCancelChangePass").addEventListener("click", () => {
  $("modalChangePassOverlay").style.display = "none";
});

$("btnConfirmChangePass").addEventListener("click", async () => {
  const new_username = $("fNewUsername").value.trim();
  const current_password = $("fCurrentPass").value;
  const new_password = $("fNewPass").value;
  const confirm_password = $("fConfirmPass").value;
  const errBox = $("changePassError");
  errBox.style.display = "none";

  if (!current_password || !new_password || !confirm_password) {
    errBox.textContent = "Completá todos los campos.";
    errBox.style.display = "block";
    return;
  }

  if (new_password !== confirm_password) {
    errBox.textContent = "Las contraseñas nuevas no coinciden.";
    errBox.style.display = "block";
    return;
  }

  try {
    const payload = { current_password, new_password };
    if (new_username) {
      payload.new_username = new_username;
    }
    await apiFetch("/panel/auth/change-password", {
      method: "POST",
      body: JSON.stringify(payload)
    });
    
    showToast("Credenciales actualizadas. Iniciá sesión con tus nuevos datos.");
    cerrarSesion();
    $("modalChangePassOverlay").style.display = "none";
  } catch(e) {
    errBox.textContent = e.message;
    errBox.style.display = "block";
  }
});

// MODAL: Registrar huella
$("btnRegBio").addEventListener("click", () => {
  $("fBioDeviceName").value = "";
  $("bioError").style.display = "none";
  $("modalBiometricsOverlay").style.display = "flex";
});

$("btnCancelBio").addEventListener("click", () => {
  $("modalBiometricsOverlay").style.display = "none";
});

$("btnConfirmBio").addEventListener("click", async () => {
  const dispositivo_nombre = $("fBioDeviceName").value.trim();
  const errBox = $("bioError");
  errBox.style.display = "none";

  if (!dispositivo_nombre) {
    errBox.textContent = "Completá el nombre del dispositivo.";
    errBox.style.display = "block";
    return;
  }

  try {
    // 1. Obtener challenge
    const challengeRes = await apiFetch("/panel/auth/biometrics/challenge");
    
    // 2. Registrar en hardware del cliente
    showToast("Colocá tu huella en el lector...");
    const cred = await KatrixBiometrics.registerCredential(USER.username, challengeRes.challenge);

    // 3. Enviar registro al servidor
    await apiFetch("/panel/auth/biometrics/register", {
      method: "POST",
      body: JSON.stringify({
        username: USER.username,
        credential_id: cred.credentialId,
        public_key_der: cred.publicKeyDer,
        dispositivo_nombre: dispositivo_nombre,
        challenge_token: challengeRes.challenge_token
      })
    });

    showToast("¡Dispositivo biométrico registrado exitosamente!");
    $("modalBiometricsOverlay").style.display = "none";
    
    // Recargar credenciales para el botón de login
    await checkBiometricsSupport();
  } catch(e) {
    errBox.textContent = e.message;
    errBox.style.display = "block";
    showToast(e.message, true);
  }
});

function customConfirm({ title, message, promptLabel, promptValue, onAccept }) {
  $("confirmModalTitle").textContent = title || "Confirmar Acción";
  $("confirmModalMessage").textContent = message || "";
  
  const promptField = $("confirmPromptField");
  const promptInput = $("confirmPromptInput");
  
  if (promptLabel) {
    $("confirmPromptLabel").textContent = promptLabel;
    promptInput.value = promptValue || "";
    promptField.style.display = "block";
  } else {
    promptField.style.display = "none";
  }
  
  $("confirmModalOverlay").style.display = "flex";
  
  $("btnAcceptConfirm").onclick = () => {
    const val = promptLabel ? promptInput.value.trim() : null;
    $("confirmModalOverlay").style.display = "none";
    if (onAccept) onAccept(val);
  };
  
  $("btnCancelConfirm").onclick = () => {
    $("confirmModalOverlay").style.display = "none";
  };
}

/* ---------------- DATOS ---------------- */

function diasRestantes(fechaISO){
  const hoy = new Date(); hoy.setHours(0,0,0,0);
  const venc = new Date(fechaISO + "T00:00:00");
  return Math.round((venc - hoy) / 86400000);
}

async function cargarLicencias(){
  try{
    licencias = await apiFetch("/licencias/");
    localStorage.setItem("katrix_cached_licencias", JSON.stringify(licencias));
    render();
  }catch(err){
    if (err.message !== "401") {
      const cached = localStorage.getItem("katrix_cached_licencias");
      if (cached) {
        licencias = JSON.parse(cached);
        render();
        showToast("Visualizando datos guardados localmente (sin conexión).");
      } else {
        showToast("No se pudieron obtener los datos. Por favor, contacte al administrador del sistema.", true);
      }
    }
  }
}
$("btnRefrescar").addEventListener("click", cargarLicencias);
$("btnExportCSV").addEventListener("click", () => {
    let csv = "Cliente,Clave,Dominio,Email,Dispositivo ID,Estado,Hardware\n";
    licencias.forEach(l => {
        let hw = "N/A";
        if (l.dispositivo_nombre) {
            try { hw = JSON.parse(l.dispositivo_nombre).sistema_operativo; } catch(e) { hw = "Desconocido"; }
        }
        csv += `"${l.cliente}","${l.clave}","${l.dominio}","${l.email_cliente || ''}","${l.dispositivo_id || ''}","${l.estado}","${hw}"\n`;
    });
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `licencias_${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    showToast("CSV descargado exitosamente", "success");
});

function render(){
  const q = $("buscar").value.toLowerCase();
  const fEstado = $("filtroEstado").value;
  const fProducto = $("filtroProducto").value;

  const filtradas = licencias.filter(l=>{
    const matchQ = !q ||
      (l.cliente||"").toLowerCase().includes(q) ||
      (l.email_cliente||"").toLowerCase().includes(q) ||
      (l.clave||"").toLowerCase().includes(q);
    const matchE = fEstado === "todos" || l.estado === fEstado;
    const matchP = fProducto === "todos" || l.producto === fProducto;
    return matchQ && matchE && matchP;
  });

  $("statActivas").textContent = licencias.filter(l=>l.estado==="activa").length;
  $("statPorVencer").textContent = licencias.filter(l=>l.estado==="activa" && diasRestantes(l.fecha_expiracion) <= 15 && diasRestantes(l.fecha_expiracion) >= 0).length;
  $("statSuspendidas").textContent = licencias.filter(l=>l.estado==="suspendida").length;
  $("statTotal").textContent = licencias.length;

  const body = $("tablaBody");
  body.innerHTML = "";
  $("emptyMsg").style.display = filtradas.length ? "none" : "block";

  filtradas.forEach(l=>{
    const tr = document.createElement("tr");
    const dias = diasRestantes(l.fecha_expiracion);
    const venceTxt = new Date(l.fecha_expiracion + "T00:00:00").toLocaleDateString("es-AR");
    const claseBadge = l.estado === "activa" ? "badge-activa" : (l.estado === "suspendida" ? "badge-suspendida" : "badge-expirada");
    const labelEstado = l.estado === "activa" ? (dias < 0 ? "Vencida" : "Activa") : (l.estado === "suspendida" ? "Suspendida" : "Expirada");

    let dispositivos = [];
    try {
      const info = JSON.parse(l.dispositivos_info || '{}');
      dispositivos = Object.keys(info).map(k => ({
        id: k,
        ...info[k]
      }));
    } catch(e) {}
    const cantDisp = dispositivos.length;

    tr.innerHTML = `
      <td>
        <div style="font-weight:600;">${l.cliente}</div>
        <div style="font-size:12px; color:var(--muted);">${l.email_cliente || ""}</div>
      </td>
      <td class="clave">${l.clave}</td>
      <td>${l.producto || "-"}</td>
      <td>${venceTxt}${dias>=0 && dias<=15 ? ` <span style="color:var(--amber); font-size:11px;">(${dias}d)</span>` : ""}</td>
      <td>
        <span class="badge" style="background: rgba(255,255,255,0.05); color: var(--text); border: 1px solid var(--border); padding: 4px 8px; cursor: pointer; border-radius: 4px; display: inline-flex; align-items: center; gap: 4px;" onclick="mostrarDispositivos(${l.id})">
          ${cantDisp}/${l.limite_dispositivos} <span style="font-size:10px;">🔍</span>
        </span>
      </td>
      <td><span class="badge ${claseBadge}">${labelEstado}</span></td>
      <td>
        <div class="row-actions">
          ${hasPerm("suspender_licencia")
            ? (l.estado !== "suspendida"
              ? `<button class="btn-warn" data-action="suspender" data-id="${l.id}">Suspender</button>`
              : `<button class="btn-ok" data-action="reactivar" data-id="${l.id}">Reactivar</button>`)
            : ""}
          ${l.dispositivo_nombre ? `<button class="btn-ghost" data-action="hw" data-id="${l.id}">💻 Equipo</button>` : ''}
          ${hasPerm("editar_licencia")
            ? `<button class="btn-ghost" data-action="editar" data-id="${l.id}">Editar</button>`
            : ""}
          ${hasPerm("eliminar_licencia")
            ? `<button class="btn-danger" data-action="eliminar" data-id="${l.id}">Eliminar</button>`
            : ""}
        </div>
      </td>
    `;
    body.appendChild(tr);
  });
}

$("buscar").addEventListener("input", render);
$("filtroEstado").addEventListener("change", render);
$("filtroProducto").addEventListener("change", render);

/* ---------------- ACCIONES DE FILA ---------------- */

$("tablaBody").addEventListener("click", async (e)=>{
  const btn = e.target.closest("button");
  if (!btn) return;
  const id = Number(btn.dataset.id);
  const accion = btn.dataset.action;
  const lic = licencias.find(l=>l.id === id);
  if (!lic) return;

  if (accion === "editar"){
    abrirModal(lic);
    return;
  }
  
  if (accion === "hw") {
    let msg = "Detalle del hardware:\n" + lic.dispositivo_nombre;
    try {
        const parsed = JSON.parse(lic.dispositivo_nombre);
        msg = `Hardware Registrado:\n\nSistema: ${parsed.sistema_operativo}\nUsuario: ${parsed.usuario}\nHost: ${parsed.hostname}\nProcesador: ${parsed.procesador}\nArquitectura: ${parsed.arquitectura}`;
    } catch(e) {}
    alert(msg);
    return;
  }

  if (accion === "eliminar"){
    customConfirm({
      title: "Eliminar Licencia",
      message: `¿Eliminar definitivamente la licencia de "${lic.cliente}"? Esta acción no se puede deshacer.`,
      onAccept: async () => {
        try{
          await apiFetch(`/licencias/${id}`, { method: "DELETE" });
          showToast("Licencia eliminada.");
          cargarLicencias();
        }catch(err){ showToast(err.message, true); }
      }
    });
    return;
  }

  const nuevoEstado = accion === "suspender" ? "suspendida" : "activa";
  if (accion === "suspender") {
    customConfirm({
      title: "Suspender Licencia",
      message: `¿Estás seguro de que deseas suspender la licencia de "${lic.cliente}"?`,
      promptLabel: "Motivo de la suspensión (ej: falta de pago):",
      promptValue: "falta_de_pago",
      onAccept: async (motivo) => {
        try{
          await apiFetch(`/licencias/${id}`, {
            method: "PUT",
            body: JSON.stringify({
              cliente: lic.cliente,
              fecha_expiracion: lic.fecha_expiracion,
              estado: nuevoEstado,
              limite_dispositivos: lic.limite_dispositivos,
              dispositivo_id: lic.dispositivo_id || null,
              motivo: motivo || "falta_de_pago"
            }),
          });
          showToast("Licencia suspendida.");
          cargarLicencias();
        }catch(err){ showToast(err.message, true); }
      }
    });
  } else {
    customConfirm({
      title: "Reactivar Licencia",
      message: `¿Deseas reactivar la licencia de "${lic.cliente}"?`,
      onAccept: async () => {
        try{
          await apiFetch(`/licencias/${id}`, {
            method: "PUT",
            body: JSON.stringify({
              cliente: lic.cliente,
              fecha_expiracion: lic.fecha_expiracion,
              estado: nuevoEstado,
              limite_dispositivos: lic.limite_dispositivos,
              dispositivo_id: lic.dispositivo_id || null,
              motivo: null
            }),
          });
          showToast("Licencia reactivada.");
          cargarLicencias();
        }catch(err){ showToast(err.message, true); }
      }
    });
  }
});

/* ---------------- MODAL NUEVA / EDITAR ---------------- */

$("btnNueva").addEventListener("click", ()=> abrirModal(null));
$("btnCancelarModal").addEventListener("click", cerrarModal);

function abrirModal(lic){
  $("fId").value = lic ? lic.id : "";
  $("fCliente").value = lic ? lic.cliente : "";
  $("fEmail").value = lic ? (lic.email_cliente || "") : "";
  $("fProducto").value = lic ? (lic.producto || "CRM") : "CRM";
  $("fFecha").value = lic ? lic.fecha_expiracion : "";
  $("fLimite").value = lic ? lic.limite_dispositivos : 1;
  $("modalTitulo").textContent = lic ? "Editar licencia" : "Nueva licencia";
  $("modalOverlay").style.display = "flex";
}
function cerrarModal(){ $("modalOverlay").style.display = "none"; }

/* ---------------- DISPOSITIVOS VINCULADOS ---------------- */
let currentLicIdParaDispositivos = null;

function mostrarDispositivos(licId) {
  const lic = licencias.find(l => l.id === licId);
  if (!lic) return;
  currentLicIdParaDispositivos = licId;
  
  let dispositivos = [];
  try {
    const info = JSON.parse(lic.dispositivos_info || '{}');
    dispositivos = Object.keys(info).map(k => ({
      id: k,
      ...info[k]
    }));
  } catch(e) {}
  
  const tbody = $("dispositivosTableBody");
  tbody.innerHTML = "";
  
  const showDesvincular = hasPerm("desvincular_dispositivo");
  $("btnDesvincularTodos").style.display = (showDesvincular && dispositivos.length > 0) ? "inline-flex" : "none";
  
  if (dispositivos.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; padding:20px; color:var(--muted);">No hay dispositivos vinculados aún.</td></tr>`;
  } else {
    dispositivos.forEach(d => {
      let sysName = d.sistema_operativo || d.nombre || "Desconocido";
      let sysUser = d.usuario || "desconocido";
      let cpu = d.procesador || "N/A";
      
      const tr = document.createElement("tr");
      tr.style.borderBottom = "1px solid var(--border)";
      tr.innerHTML = `
        <td style="padding: 10px; vertical-align: top;">
          <div style="font-weight:600;">${d.ip || "Desconocida"}</div>
          <div style="font-size:11px; color:var(--muted);">Usuario SO: ${sysUser}</div>
        </td>
        <td style="padding: 10px; vertical-align: top;">
          <div>${sysName}</div>
          <div style="font-size:11px; color:var(--muted); max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">CPU: ${cpu}</div>
        </td>
        <td style="padding: 10px; vertical-align: top;">
          <div style="font-size:11px;">Primer: ${d.primer_uso || "N/A"}</div>
          <div style="font-size:11px; color:var(--muted);">Último: ${d.ultimo_uso || "N/A"}</div>
        </td>
        <td style="padding: 10px; text-align: center; vertical-align: middle;">
          ${showDesvincular 
            ? `<button class="btn-danger" style="font-size:11px; padding:4px 8px;" onclick="desvincularDispositivo('${d.id}')">Desvincular</button>`
            : `<span style="color:var(--muted); font-size:11px;">Sin permiso</span>`}
        </td>
      `;
      tbody.appendChild(tr);
    });
  }
  
  $("modalDispositivosOverlay").style.display = "flex";
}

$("btnCerrarDispositivos").addEventListener("click", () => {
  $("modalDispositivosOverlay").style.display = "none";
});

$("btnDesvincularTodos").addEventListener("click", async () => {
  const lic = licencias.find(l => l.id === currentLicIdParaDispositivos);
  if (!lic) return;
  
  customConfirm({
    title: "Desvincular Todos",
    message: `¿Desvincular TODOS los dispositivos de la licencia de "${lic.cliente}"?`,
    onAccept: async () => {
      try {
        await apiFetch(`/licencias/${lic.id}`, {
          method: "PUT",
          body: JSON.stringify({
            cliente: lic.cliente,
            fecha_expiracion: lic.fecha_expiracion,
            estado: lic.estado,
            limite_dispositivos: lic.limite_dispositivos,
            dispositivo_id: null,
            motivo: lic.motivo || null,
            dispositivos_info: "{}"
          })
        });
        showToast("Todos los dispositivos desvinculados.");
        $("modalDispositivosOverlay").style.display = "none";
        await cargarLicencias();
      } catch(err) {
        showToast(err.message, true);
      }
    }
  });
});

async function desvincularDispositivo(devId) {
  const lic = licencias.find(l => l.id === currentLicIdParaDispositivos);
  if (!lic) return;
  
  customConfirm({
    title: "Desvincular Dispositivo",
    message: `¿Desvincular este dispositivo de la licencia?`,
    onAccept: async () => {
      let info = {};
      try {
        info = JSON.parse(lic.dispositivos_info || '{}');
      } catch(e) {}
      
      delete info[devId];
      
      const registered = (lic.dispositivo_id || "").split(",").map(x => x.trim()).filter(x => x && x !== devId);
      
      try {
        await apiFetch(`/licencias/${lic.id}`, {
          method: "PUT",
          body: JSON.stringify({
            cliente: lic.cliente,
            fecha_expiracion: lic.fecha_expiracion,
            estado: lic.estado,
            limite_dispositivos: lic.limite_dispositivos,
            dispositivo_id: registered.join(",") || null,
            motivo: lic.motivo || null,
            dispositivos_info: JSON.stringify(info)
          })
        });
        showToast("Dispositivo desvinculado.");
        $("modalDispositivosOverlay").style.display = "none";
        await cargarLicencias();
        if (registered.length > 0) {
          mostrarDispositivos(lic.id);
        }
      } catch(err) {
        showToast(err.message, true);
      }
    }
  });
}

$("btnGuardarModal").addEventListener("click", async ()=>{
  const id = $("fId").value;
  const cliente = $("fCliente").value.trim();
  const email = $("fEmail").value.trim();
  const producto = $("fProducto").value;
  const fecha = $("fFecha").value;
  const limite = Number($("fLimite").value) || 1;

  if (!cliente || !email || !fecha){
    showToast("Completá cliente, email y fecha de expiración.", true);
    return;
  }

  try{
    if (id){
      const lic = licencias.find(l=>l.id === Number(id));
      await apiFetch(`/licencias/${id}`, {
        method: "PUT",
        body: JSON.stringify({
          cliente, fecha_expiracion: fecha,
          estado: lic ? lic.estado : "activa",
          limite_dispositivos: limite,
          dispositivo_id: lic ? lic.dispositivo_id || null : null,
          motivo: lic ? lic.motivo || null : null,
          dispositivos_info: lic ? lic.dispositivos_info || null : null
        }),
      });
      showToast("Licencia actualizada.");
    } else {
      const data = await apiFetch("/licencias/", {
        method: "POST",
        body: JSON.stringify({
          cliente, email_cliente: email, producto,
          fecha_expiracion: fecha, estado: "activa",
          limite_dispositivos: limite,
        }),
      });
      showToast(data.message || "Licencia creada.");
    }
    cerrarModal();
    cargarLicencias();
  }catch(err){ showToast(err.message, true); }
});

/* ---------------- TABS NAVIGATION & MULTI-ROLE SECTIONS ---------------- */

// Switch tab function
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    if (btn.getAttribute('data-tab') === tabId) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });
  
  document.querySelectorAll('.tab-content').forEach(c => {
    if (c.id === tabId) {
      c.classList.add('active');
    } else {
      c.classList.remove('active');
    }
  });
  
  // Close user form if switching away
  if (tabId !== 'tab-usuarios') {
    $("tabUserFormCard").style.display = "none";
  }
  
  // Load data based on active tab
  if (tabId === 'tab-licencias') {
    cargarLicencias();
  } else if (tabId === 'tab-usuarios') {
    cargarUsuariosPanelTab();
  } else if (tabId === 'tab-sesiones') {
    cargarSesionesActivas();
  } else if (tabId === 'tab-logs') {
    cargarLogsAuditoria();
  }
}

// Hook up tab buttons click event
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    switchTab(btn.getAttribute('data-tab'));
  });
});

// Redirect header button to tab
$("btnManageUsers").addEventListener("click", () => {
  switchTab("tab-usuarios");
});


/* ---------------- TAB 2: GESTIÓN DE USUARIOS ---------------- */
let tabPanelUsers = [];

async function cargarUsuariosPanelTab() {
  try {
    tabPanelUsers = await apiFetch("/panel/users");
    renderTabUsers();
  } catch(e) {
    showToast("Error al cargar usuarios de panel: " + e.message, true);
  }
}

function renderTabUsers() {
  const tbody = $("tabUsersTableBody");
  tbody.innerHTML = "";
  tabPanelUsers.forEach(u => {
    const tr = document.createElement("tr");
    tr.style.borderBottom = "1px solid var(--border)";
    
    let permList = [];
    for (const key in u.permissions) {
      if (u.permissions[key] === true) {
        permList.push(key.replace(/_/g, " "));
      }
    }
    const permTxt = u.role === "superadmin" ? "Acceso Total (Superadmin)" : (permList.length > 0 ? permList.join(", ") : "Ninguno");
    
    tr.innerHTML = `
      <td style="padding: 12px; font-weight: 600;">${u.username}</td>
      <td style="padding: 12px;"><span class="badge ${u.role === 'superadmin' ? 'badge-activa' : 'badge-expirada'}">${u.role}</span></td>
      <td style="padding: 12px; font-size: 12px; color: var(--muted); max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${permTxt}">${permTxt}</td>
      <td style="padding: 12px; text-align: center;">
        <button class="btn-ghost" style="padding: 4px 8px; font-size: 12px; margin-right: 4px;" onclick="editarTabPanelUser('${u.username}')">Editar</button>
        <button class="btn-danger" style="padding: 4px 8px; font-size: 12px;" onclick="eliminarTabPanelUser('${u.username}')">Eliminar</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

$("btnTabNewUser").addEventListener("click", () => {
  $("tabUserEditMode").value = "create";
  $("tabUserUsername").value = "";
  $("tabUserUsername").disabled = false;
  $("tabUserPassword").value = "";
  $("tabPwdLabelHelp").textContent = "(mínimo 4 caracteres)";
  $("tabUserRole").value = "admin";
  
  const checkboxes = ["ver_licencias", "crear_licencia", "editar_licencia", "suspender_licencia", "desvincular_dispositivo", "eliminar_licencia", "ver_sesiones", "desvincular_sesion", "ver_logs"];
  checkboxes.forEach(p => {
    $("tab_perm_" + p).checked = true;
    $("tab_perm_" + p).disabled = false;
  });
  
  $("tabUserFormCard").style.display = "block";
  $("tabUserError").style.display = "none";
  $("tabUserFormTitle").textContent = "Crear Nuevo Usuario";
  $("tabUserFormCard").scrollIntoView({ behavior: 'smooth' });
});

$("btnCancelTabUserForm").addEventListener("click", () => {
  $("tabUserFormCard").style.display = "none";
});

window.editarTabPanelUser = function(username) {
  const u = tabPanelUsers.find(x => x.username === username);
  if (!u) return;
  
  $("tabUserEditMode").value = "update";
  $("tabUserUsername").value = u.username;
  $("tabUserUsername").disabled = true;
  $("tabUserPassword").value = "";
  $("tabPwdLabelHelp").textContent = "(dejar vacío para mantener actual)";
  $("tabUserRole").value = u.role;
  
  const checkboxes = ["ver_licencias", "crear_licencia", "editar_licencia", "suspender_licencia", "desvincular_dispositivo", "eliminar_licencia", "ver_sesiones", "desvincular_sesion", "ver_logs"];
  checkboxes.forEach(p => {
    $("tab_perm_" + p).checked = u.permissions[p] !== false;
    $("tab_perm_" + p).disabled = u.role === "superadmin";
  });
  
  $("tabUserFormCard").style.display = "block";
  $("tabUserError").style.display = "none";
  $("tabUserFormTitle").textContent = `Editar Usuario: ${u.username}`;
  $("tabUserFormCard").scrollIntoView({ behavior: 'smooth' });
};

$("tabUserRole").addEventListener("change", function() {
  const isSuper = this.value === "superadmin";
  const checkboxes = ["ver_licencias", "crear_licencia", "editar_licencia", "suspender_licencia", "desvincular_dispositivo", "eliminar_licencia", "ver_sesiones", "desvincular_sesion", "ver_logs"];
  checkboxes.forEach(p => {
    if (isSuper) {
      $("tab_perm_" + p).checked = true;
      $("tab_perm_" + p).disabled = true;
    } else {
      $("tab_perm_" + p).disabled = false;
    }
  });
});

window.eliminarTabPanelUser = function(username) {
  if (username === USER.username) {
    showToast("No podés eliminar a tu propio usuario", true);
    return;
  }
  
  customConfirm({
    title: "Eliminar Usuario de Panel",
    message: `¿Eliminar al usuario "${username}"? Esto revocará su acceso inmediatamente.`,
    onAccept: async () => {
      try {
        await apiFetch(`/panel/users/${username}`, {
          method: "DELETE"
        });
        showToast("Usuario eliminado exitosamente.");
        await cargarUsuariosPanelTab();
      } catch(e) {
        showToast(e.message, true);
      }
    }
  });
};

$("btnSaveTabUser").addEventListener("click", async () => {
  const mode = $("tabUserEditMode").value;
  const username = $("tabUserUsername").value.trim();
  const password = $("tabUserPassword").value;
  const role = $("tabUserRole").value;
  
  const errBox = $("tabUserError");
  errBox.style.display = "none";
  
  if (mode === "create" && (!username || !password)) {
    errBox.textContent = "Completá todos los campos para crear el usuario.";
    errBox.style.display = "block";
    return;
  }
  
  const permissions = {};
  const checkboxes = ["ver_licencias", "crear_licencia", "editar_licencia", "suspender_licencia", "desvincular_dispositivo", "eliminar_licencia", "ver_sesiones", "desvincular_sesion", "ver_logs"];
  checkboxes.forEach(p => {
    permissions[p] = $("tab_perm_" + p).checked;
  });
  
  try {
    if (mode === "create") {
      await apiFetch("/panel/users", {
        method: "POST",
        body: JSON.stringify({
          username, password, role, permissions
        })
      });
      showToast("Usuario creado correctamente.");
    } else {
      const payload = { role, permissions };
      if (password.trim().length > 0) {
        payload.password = password;
      }
      await apiFetch(`/panel/users/${username}`, {
        method: "PUT",
        body: JSON.stringify(payload)
      });
      showToast("Usuario actualizado correctamente.");
    }
    $("tabUserFormCard").style.display = "none";
    await cargarUsuariosPanelTab();
  } catch(e) {
    errBox.textContent = e.message;
    errBox.style.display = "block";
  }
});


/* ---------------- TAB 3: SESIONES ACTIVAS ---------------- */

async function cargarSesionesActivas() {
  try {
    const sessions = await apiFetch("/panel/sessions");
    const tbody = $("sesionesTableBody");
    tbody.innerHTML = "";
    
    if (!sessions || sessions.length === 0) {
      $("emptySesionesMsg").style.display = "block";
      return;
    }
    $("emptySesionesMsg").style.display = "none";
    
    sessions.forEach(s => {
      const tr = document.createElement("tr");
      tr.style.borderBottom = "1px solid var(--border)";
      
      const esPropio = s.username === USER.username;
      const displayUser = esPropio ? `${s.username} <span style="color:var(--accent); font-weight:600; font-size:11px; margin-left:4px;">(Vos)</span>` : s.username;
      
      let uaFriendly = s.user_agent;
      if (s.user_agent.includes("Chrome/")) {
        uaFriendly = "Chrome";
        if (s.user_agent.includes("Windows")) uaFriendly += " (Windows)";
        else if (s.user_agent.includes("Macintosh")) uaFriendly += " (macOS)";
        else if (s.user_agent.includes("Linux")) uaFriendly += " (Linux)";
      } else if (s.user_agent.includes("Firefox/")) {
        uaFriendly = "Firefox";
        if (s.user_agent.includes("Windows")) uaFriendly += " (Windows)";
        else if (s.user_agent.includes("Linux")) uaFriendly += " (Linux)";
      } else if (s.user_agent.includes("Safari/") && !s.user_agent.includes("Chrome/")) {
        uaFriendly = "Safari";
        if (s.user_agent.includes("iPhone")) uaFriendly += " (iPhone)";
      }
      
      let lastActStr = "Recién";
      try {
        const diff = Math.floor((new Date() - new Date(s.last_active)) / 1000);
        if (diff > 60) {
          const mins = Math.floor(diff / 60);
          if (mins > 60) {
            lastActStr = `Hace ${Math.floor(mins / 60)}h`;
          } else {
            lastActStr = `Hace ${mins} min`;
          }
        } else if (diff > 5) {
          lastActStr = `Hace ${diff}s`;
        }
      } catch(e) {}
      
      tr.innerHTML = `
        <td style="padding: 12px; font-weight: 600;">${displayUser}</td>
        <td style="padding: 12px;"><span class="badge ${s.role.includes('superadmin') ? 'badge-activa' : 'badge-expirada'}">${s.role}</span></td>
        <td style="padding: 12px; font-family: monospace; font-size:12px;">${s.ip}</td>
        <td style="padding: 12px; font-size: 12px; color: var(--muted); max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${s.user_agent}">${uaFriendly}</td>
        <td style="padding: 12px; font-size: 12px;">${lastActStr}</td>
        <td style="padding: 12px; text-align: center;">
          ${esPropio ? '' : `<button class="btn-danger" style="padding: 4px 8px; font-size: 12px;" onclick="revocarSesion('${s.username}')">Desconectar</button>`}
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch(e) {
    showToast("Error al cargar sesiones activas: " + e.message, true);
  }
}

window.revocarSesion = function(username) {
  customConfirm({
    title: "Revocar Sesión",
    message: `¿Estás seguro de desconectar forzadamente al usuario "${username}"? Se le cerrará la sesión de forma inmediata.`,
    onAccept: async () => {
      try {
        await apiFetch(`/panel/sessions/${username}/revoke`, { method: "POST" });
        showToast(`Sesión de "${username}" revocada correctamente.`);
        await cargarSesionesActivas();
      } catch(e) {
        showToast(e.message, true);
      }
    }
  });
};

$("btnRefrescarSesiones").addEventListener("click", cargarSesionesActivas);


/* ---------------- TAB 4: LOGS DE AUDITORÍA ---------------- */
let allLogs = [];

async function cargarLogsAuditoria() {
  try {
    const limit = $("filtroLimiteLogs").value;
    allLogs = await apiFetch(`/panel/logs?limite=${limit}`);
    renderLogs();
  } catch(e) {
    showToast("Error al cargar logs de auditoría: " + e.message, true);
  }
}

function renderLogs() {
  const tbody = $("logsTableBody");
  tbody.innerHTML = "";
  
  const searchVal = $("buscarLogs").value.toLowerCase().trim();
  const filtered = allLogs.filter(log => {
    if (!searchVal) return true;
    return (
      (log.usuario && log.usuario.toLowerCase().includes(searchVal)) ||
      (log.accion && log.accion.toLowerCase().includes(searchVal)) ||
      (log.detalles && log.detalles.toLowerCase().includes(searchVal))
    );
  });
  
  if (filtered.length === 0) {
    $("emptyLogsMsg").style.display = "block";
    return;
  }
  $("emptyLogsMsg").style.display = "none";
  
  filtered.forEach(log => {
    const tr = document.createElement("tr");
    tr.style.borderBottom = "1px solid var(--border)";
    
    let fechaStr = log.fecha || "";
    try {
      const d = new Date(log.fecha);
      fechaStr = d.toLocaleString();
    } catch(e) {}
    
    tr.innerHTML = `
      <td style="padding: 10px; font-size: 12px; color: var(--muted); font-family: monospace; white-space: nowrap;">${fechaStr}</td>
      <td style="padding: 10px; font-weight: 600;">${log.usuario || "sistema"}</td>
      <td style="padding: 10px;"><span class="badge" style="background: rgba(255,255,255,0.05); color: var(--text); border: 1px solid var(--border); font-size:11px;">${log.accion || ""}</span></td>
      <td style="padding: 10px; font-size: 12px; color: var(--muted);">${log.detalles || ""}</td>
    `;
    tbody.appendChild(tr);
  });
}

$("btnRefrescarLogs").addEventListener("click", cargarLogsAuditoria);
$("buscarLogs").addEventListener("input", renderLogs);
$("filtroLimiteLogs").addEventListener("change", cargarLogsAuditoria);

// Register Service Worker for PWA
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/panel/sw.js')
      .then((reg) => console.log('Service Worker registrado con éxito:', reg.scope))
      .catch((err) => console.error('Error al registrar el Service Worker:', err));
  });
}

// Connection Status Monitor
window.addEventListener('online', updateOnlineStatus);
window.addEventListener('offline', updateOnlineStatus);

function updateOnlineStatus() {
  const isOnline = navigator.onLine;
  const banner = $("offlineBanner");
  if (banner) {
    banner.style.display = isOnline ? "none" : "block";
  }
}
// Initial check
updateOnlineStatus();
