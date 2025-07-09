/**
 * This script converts various proxy subscription formats into a sing-box JSON profile.
 * It is a completely self-contained, client-side tool with no external dependencies.
 * This version is adapted to work with the Tailwind CSS UI and includes theme toggling.
 */

// --- Global State & Constants ---
let ORIGINAL_BASE_STRUCTURE = null;
const ALLOWED_SS_METHODS = ["chacha20-ietf-poly1305", "aes-256-gcm", "2022-blake3-aes-256-gcm"];
const DEFAULT_HEADER = `//profile-title: base64:{PROFILE_NAME_BASE64}
//profile-update-interval: 1
//subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531
//support-url: https://t.me/yebekhe
//profile-web-page-url: ithub.com/itsyebekhe/PSG`;

// #############################################################################
// Dynamic UI & Core Conversion Logic (This part is correct and unchanged)
// #############################################################################
function createInputsForObject(o, c, p) { for (const k in o) { if (!o.hasOwnProperty(k)) continue; const v = o[k]; const a = p ? `${p}.${k}` : k; const f = document.createElement('div'); f.className = 'form-field p-4 mb-4 border border-gray-300 dark:border-gray-600 rounded-lg'; const l = document.createElement('label'); l.setAttribute('for', a); l.className = 'block mb-2 text-sm font-medium text-gray-700 dark:text-gray-300'; l.textContent = k; f.appendChild(l); const w = document.createElement('div'); w.className = 'input-wrapper'; let i; const t = typeof v; if (t === 'boolean') { i = document.createElement('input'); i.type = 'checkbox'; i.checked = v; i.className = 'form-checkbox h-5 w-5 text-blue-600 dark:text-blue-400 focus:ring-blue-500' } else if (t === 'number') { i = document.createElement('input'); i.type = 'number'; i.value = v; i.className = 'w-full p-2 rounded-md border border-gray-300 dark:border-gray-600 bg-gray-50 dark:bg-gray-700 font-mono text-sm' } else if (t === 'string') { i = document.createElement('input'); i.type = 'text'; i.value = v; i.className = 'w-full p-2 rounded-md border border-gray-300 dark:border-gray-600 bg-gray-50 dark:bg-gray-700 font-mono text-sm' } else if (Array.isArray(v) || t === 'object' && v !== null) { i = document.createElement('textarea'); i.value = JSON.stringify(v, null, 2); i.className = 'w-full p-2 rounded-md border border-gray-300 dark:border-gray-600 bg-gray-50 dark:bg-gray-700 font-mono text-xs h-32 resize-y' } if (i) { i.id = a; i.dataset.path = a; i.dataset.type = Array.isArray(v) ? 'array' : t; w.appendChild(i) } f.appendChild(w); c.appendChild(f) } }
function buildStructureEditor(d, e) { e.innerHTML = ''; for (const s in d) { if (!d.hasOwnProperty(s)) continue; if (s === 'outbounds') continue; const f = document.createElement('fieldset'); f.className = 'structure-section border border-gray-300 dark:border-gray-600 rounded-lg p-4 mb-4'; const l = document.createElement('legend'); l.className = 'text-md font-bold text-gray-700 dark:text-gray-300 px-2 -ml-2'; l.textContent = s.charAt(0).toUpperCase() + s.slice(1); f.appendChild(l); createInputsForObject(d[s], f, s); e.appendChild(f) } }
function getEditedStructure() { const e = JSON.parse(JSON.stringify(ORIGINAL_BASE_STRUCTURE)); document.querySelectorAll('#structure-editor [data-path]').forEach(i => { const p = i.dataset.path; const t = i.dataset.type; let v; if (t === 'boolean') { v = i.checked } else if (t === 'number') { v = Number(i.value) } else if (t === 'array' || t === 'object') { try { v = JSON.parse(i.value) } catch (e) { alert(`Invalid JSON format for "${p}". Please check your syntax.`); throw e } } else { v = i.value } setValueByPath(e, p, v) }); return e }
function setValueByPath(o, p, v) { const k = p.split('.'); const l = k.pop(); let c = o; for (const e of k) { if (!(e in c)) { c[e] = {} } c = c[e] } c[l] = v }
function decodeUrlSafeBase64(b) { let s = b.replace(/-/g, '+').replace(/_/g, '/'); const p = s.length % 4; if (p) { s += '='.repeat(4 - p) } return atob(s) }
function detectType(c) { const p = ["vmess", "vless", "trojan", "ss", "tuic", "hy2"]; for (const r of p) { if (c.startsWith(r + "://")) { return r } } return null }
function configParse(u) { const t = detectType(u); if (!t) return null; try { switch (t) { case 'vmess': return JSON.parse(atob(u.substring(8))); case 'ss': { const l = new URL(u); const n = l.username; let e, s; try {
            [e, s] = atob(n).split(':', 2) } catch (c) { try {
            [e, s] = decodeUrlSafeBase64(n).split(':', 2) } catch (a) {
            [e, s] = decodeURIComponent(n).split(':', 2) } } const o = l.hash ? decodeURIComponent(l.hash.substring(1)) : l.hostname; if (typeof s === 'undefined') s = ''; return { 'server_address': l.hostname, 'server_port': parseInt(l.port, 10), 'password': s, 'encryption_method': e, 'name': o } } case 'vless': case 'trojan': case 'tuic': case 'hy2': { const r = new URL(u); const p = Object.fromEntries(r.searchParams.entries()); return { 'scheme': r.protocol.replace(':', ''), 'hostname': r.hostname, 'port': parseInt(r.port, 10), 'username': decodeURIComponent(r.username), 'pass': decodeURIComponent(r.password), 'hash': decodeURIComponent(r.hash.substring(1)), 'params': p } } default: return null } } catch (e) { console.error(`Failed to parse ${t} config:`, u, e); return null } }
class ConfigWrapper { constructor(c) { this.type = detectType(c) || 'unknown'; this.decoded = configParse(c) } isValid() { return this.decoded !== null } getType() { return this.type } getTag() { let t; switch (this.type) { case 'vmess': t = this.decoded.ps; break; case 'ss': t = this.decoded.name; break; default: t = this.decoded.hash; break } return decodeURIComponent(t || 'Unknown Tag') } getServer() { switch (this.type) { case 'vmess': return this.decoded.add; case 'ss': return this.decoded.server_address; default: return this.decoded.hostname } } getPort() { let p; switch (this.type) { case 'ss': p = this.decoded.server_port; break; default: p = this.decoded.port; break } return parseInt(p, 10) } getUuid() { switch (this.type) { case 'vmess': return this.decoded.id; case 'vless': case 'trojan': case 'tuic': return this.decoded.username; default: return '' } } getPassword() { switch (this.type) { case 'trojan': return this.decoded.username; case 'ss': return this.decoded.password; case 'tuic': return this.decoded.pass; case 'hy2': return this.decoded.username; default: return '' } } getSni() { switch (this.type) { case 'vmess': return this.decoded.sni || this.getServer(); default: return this.decoded.params?.sni || this.getServer() } } getTransportType() { switch (this.type) { case 'vmess': return this.decoded.net; default: return this.decoded.params?.type || null } } getPath() { let p; switch (this.type) { case 'vmess': p = this.decoded.path || '/'; break; default: p = this.decoded.params?.path || '/'; break } return '/' + (p.startsWith('/') ? p.substring(1) : p) } getServiceName() { switch (this.type) { case 'vmess': return this.decoded.path || ''; default: return this.decoded.params?.serviceName || '' } } get(k, d = null) { if (this.type === 'ss' && k === 'encryption_method') { return this.decoded.encryption_method } return this.decoded?.[k] ?? d } getParam(k, d = null) { return this.decoded?.params?.[k] ?? d } }
function vmessToSingbox(c) { const o = { "tag": c.getTag(), "type": "vmess", "server": c.getServer(), "server_port": c.getPort(), "uuid": c.getUuid(), "security": "auto", "alter_id": parseInt(c.get('aid')) || 0 }; if (c.getPort() === 443 || c.get('tls') === 'tls') { o.tls = createTlsSettings(c) } if (["ws", "grpc", "http"].includes(c.getTransportType())) { o.transport = createTransportSettings(c); if (o.transport === null) return null } return o }
function vlessToSingbox(c) { const o = { "tag": c.getTag(), "type": "vless", "server": c.getServer(), "server_port": c.getPort(), "uuid": c.getUuid(), "flow": c.getParam('flow') ? "xtls-rprx-vision" : "", "packet_encoding": "xudp" }; if (c.getPort() === 443 || ['tls', 'reality'].includes(c.getParam('security'))) { o.tls = createTlsSettings(c); if (c.getParam('security') === 'reality' || c.getParam('pbk')) { o.flow = "xtls-rprx-vision"; o.tls.reality = { 'enabled': true, 'public_key': c.getParam('pbk', ''), 'short_id': c.getParam('sid', '') }; if (c.getParam('fp')) { o.tls.utls = o.tls.utls || {}; o.tls.utls.fingerprint = c.getParam('fp') } if (!o.tls.reality.public_key) return null } } if (["ws", "grpc", "http"].includes(c.getTransportType())) { o.transport = createTransportSettings(c); if (o.transport === null) return null } return o }
function trojanToSingbox(c) { const o = { "tag": c.getTag(), "type": "trojan", "server": c.getServer(), "server_port": c.getPort(), "password": c.getPassword() }; if (c.getPort() === 443 || c.getParam('security') === 'tls') { o.tls = createTlsSettings(c) } if (["ws", "grpc", "http"].includes(c.getTransportType())) { o.transport = createTransportSettings(c); if (o.transport === null) return null } return o }
function ssToSingbox(c) { const m = c.get('encryption_method'); if (!ALLOWED_SS_METHODS.includes(m)) { return null } return { "tag": c.getTag(), "type": "shadowsocks", "server": c.getServer(), "server_port": c.getPort(), "method": m, "password": c.getPassword() } }
function tuicToSingbox(c) { return { "tag": c.getTag(), "type": "tuic", "server": c.getServer(), "server_port": c.getPort(), "uuid": c.getUuid(), "password": c.getPassword(), "congestion_control": c.getParam("congestion_control", "bbr"), "udp_relay_mode": c.getParam("udp_relay_mode", "native"), "tls": { "enabled": true, "server_name": c.getSni(), "insecure": !!parseInt(c.getParam("allow_insecure", "0")), "alpn": c.getParam('alpn') ? c.getParam('alpn').split(',') : undefined } } }
function hy2ToSingbox(c) { const p = c.getParam('obfs-password'); if (!p) return null; return { "tag": c.getTag(), "type": "hysteria2", "server": c.getServer(), "server_port": c.getPort(), "password": c.getPassword(), "obfs": { "type": c.getParam('obfs'), "password": p }, "tls": { "enabled": true, "server_name": c.getSni(), "insecure": !!parseInt(c.getParam("insecure", "0")), "alpn": ["h3"] } } }
function createTlsSettings(c) { return { "enabled": true, "server_name": c.getSni(), "insecure": true, "utls": { "enabled": true, "fingerprint": "chrome" } } }
function createTransportSettings(c) { const t = c.getTransportType(); let r = null; switch (t) { case 'ws': r = { "type": "ws", "path": c.getPath(), "headers": { "Host": c.getSni() } }; break; case 'grpc': const s = c.getServiceName(); if (!s) return null; r = { "type": "grpc", "service_name": s }; break; case 'http': r = { "type": "http", "host": [c.getSni()], "path": c.getPath() }; break } return r }
function convertToSingboxObject(c) { const w = new ConfigWrapper(c); if (!w.isValid()) { return null } switch (w.getType()) { case "vmess": return vmessToSingbox(w); case "vless": return vlessToSingbox(w); case "trojan": return trojanToSingbox(w); case "ss": return ssToSingbox(w); case "tuic": return tuicToSingbox(w); case "hy2": return hy2ToSingbox(w); default: return null } }
function generateSingboxProfile(r, t, e, a, n) { let o; if (t === 'base64') { try { o = atob(r).split(/[\r\n]+/).filter(l => l.trim() !== '') } catch (c) { alert("Error: The input is not valid Base64 content."); return null } } else { o = r.split(/[\r\n]+/).filter(l => l.trim() !== '') } const i = JSON.parse(JSON.stringify(e)); const u = i.outbounds.find(s => s.type === 'urltest'); const p = i.outbounds.find(s => s.type === 'selector'); o.forEach(f => { const s = convertToSingboxObject(f); if (s !== null) { i.outbounds.push(s); const d = s.tag; if (u?.outbounds) u.outbounds.push(d); if (p?.outbounds) p.outbounds.push(d) } }); const b = btoa(unescape(encodeURIComponent(a))); const h = n.replace('{PROFILE_NAME_BASE64}', b); return `${h}\n\n${JSON.stringify(i,null,2)}` }

// --- Script Execution (UI Event Handlers) ---
document.addEventListener('DOMContentLoaded', () => {
    // Get all UI elements that actually exist
    const themeToggleBtn = document.getElementById('theme-toggle');
    const sunIcon = document.getElementById('sun-icon');
    const moonIcon = document.getElementById('moon-icon');
    const convertBtn = document.getElementById('convert-btn');
    const downloadBtn = document.getElementById('download-btn');
    const copyBtn = document.getElementById('copy-btn');
    const proxyConfigsInput = document.getElementById('proxy-configs');
    const profileNameInput = document.getElementById('profile-name');
    const headerEditor = document.getElementById('header-editor');
    const outputWrapper = document.getElementById('output-wrapper');
    const outputJsonEl = document.getElementById('output-json');
    const statusMessageEl = document.getElementById('status-message');
    const editorContainer = document.getElementById('structure-editor');

    // ** START: THEME TOGGLE LOGIC **
    const applyTheme = (theme) => {
        if (theme === 'dark') {
            document.documentElement.classList.add('dark');
            sunIcon.classList.add('hidden');
            moonIcon.classList.remove('hidden');
        } else {
            document.documentElement.classList.remove('dark');
            sunIcon.classList.remove('hidden');
            moonIcon.classList.add('hidden');
        }
    };

    // Check for saved theme in localStorage
    const savedTheme = localStorage.getItem('theme') || 'light';
    applyTheme(savedTheme);

    themeToggleBtn.addEventListener('click', () => {
        const currentTheme = document.documentElement.classList.contains('dark') ? 'dark' : 'light';
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        localStorage.setItem('theme', newTheme);
        applyTheme(newTheme);
    });
    // ** END: THEME TOGGLE LOGIC **

    headerEditor.value = DEFAULT_HEADER;

    fetch('structure.json')
        .then(response => {
            if (!response.ok) throw new Error(`Could not load structure.json: ${response.statusText}`);
            return response.json();
        })
        .then(data => {
            ORIGINAL_BASE_STRUCTURE = data;
            buildStructureEditor(data, editorContainer);
            statusMessageEl.classList.add('hidden');
            convertBtn.disabled = false;
        })
        .catch(error => {
            console.error("Error loading structure.json:", error);
            statusMessageEl.textContent = `CRITICAL ERROR: Failed to load 'structure.json'. Please ensure the file exists and is accessible.`;
            statusMessageEl.classList.remove('hidden');
            convertBtn.disabled = true;
        });

    convertBtn.addEventListener('click', () => {
        let baseStructure;
        try {
            baseStructure = getEditedStructure();
        } catch (e) {
            console.error("Could not generate profile:", e);
            return;
        }

        const rawInput = proxyConfigsInput.value.trim();
        const profileName = profileNameInput.value.trim();
        const inputFormat = document.querySelector('input[name="input-format"]:checked').value;
        const headerTemplate = headerEditor.value;

        if (!rawInput || !profileName) {
            alert("Please provide subscription content and a profile name.");
            return;
        }

        // Note: The original PHP code passed profile_name to the function, but the JS version was passing rawInput twice. Correcting this.
        const convertedProfile = generateSingboxProfile(rawInput, inputFormat, baseStructure, profileName, headerTemplate);

        if (convertedProfile) {
            outputJsonEl.textContent = convertedProfile;
            Prism.highlightElement(outputJsonEl);
            outputWrapper.classList.remove('hidden');
        }
    });

    copyBtn.addEventListener('click', () => {
        const textToCopy = outputJsonEl.textContent;
        navigator.clipboard.writeText(textToCopy).then(() => {
            const originalText = copyBtn.textContent;
            copyBtn.textContent = 'Copied!';
            setTimeout(() => {
                copyBtn.textContent = originalText;
            }, 2000);
        }).catch(err => {
            console.error('Failed to copy text: ', err);
            alert('Failed to copy text.');
        });
    });

    downloadBtn.addEventListener('click', () => {
        const content = outputJsonEl.textContent;
        const blob = new Blob([content], { type: 'application/json;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'profile.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    });
});
