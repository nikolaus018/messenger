// E2E Messenger frontend — production-ready module (readable, single source)
// WebCrypto: RSA-OAEP 4096, AES-GCM 256, PBKDF2-SHA256(200k)

(function () {
  'use strict';

  // -----------------------------
  // API client
  // -----------------------------
  const api = {
    token: null,
    setToken(t) { this.token = t; },
    headers(json = true) {
      const h = {};
      if (json) h['Content-Type'] = 'application/json';
      if (this.token) h['Authorization'] = 'Bearer ' + this.token;
      return h;
    },
    async _fetch(url, opts = {}) {
      const res = await fetch(url, opts);
      if (!res.ok) {
        let msg = res.statusText;
        try { const j = await res.json(); if (j && j.detail) msg = j.detail; } catch { try { msg = await res.text(); } catch {} }
        const err = new Error(msg); err.status = res.status; throw err;
      }
      return res;
    },
    async register(username, password, publicKeyJwk) {
      const res = await this._fetch('/register', { method: 'POST', headers: this.headers(), body: JSON.stringify({ username, password, public_key_jwk: publicKeyJwk }) });
      return res.json();
    },
    async login(username, password) {
      const res = await this._fetch('/login', { method: 'POST', headers: this.headers(), body: JSON.stringify({ username, password }) });
      return res.json();
    },
    async getUser(username) { const res = await fetch(`/users/${encodeURIComponent(username)}`); if (!res.ok) return null; return res.json(); },
    async friends() { const res = await this._fetch('/friends', { headers: this.headers() }); return res.json(); },
    async friendRequests() { const res = await this._fetch('/friends/requests', { headers: this.headers() }); return res.json(); },
    async friendRequest(to) { const res = await this._fetch('/friends/request', { method: 'POST', headers: this.headers(), body: JSON.stringify({ to }) }); return res.json(); },
    async friendRespond(requester, accept) { const res = await this._fetch('/friends/respond', { method: 'POST', headers: this.headers(), body: JSON.stringify({ requester, accept }) }); return res.json(); },
    async send(sender, recipient, ciphertext) { const res = await this._fetch('/messages', { method: 'POST', headers: this.headers(), body: JSON.stringify({ sender, recipient, ciphertext }) }); return res.json(); },
    async inbox(username, sinceId = null, limit = 200, beforeId = null) {
      const qp = new URLSearchParams({ username, limit: String(limit) });
      if (sinceId != null) qp.set('since_id', String(sinceId));
      if (beforeId != null) qp.set('before_id', String(beforeId));
      const res = await this._fetch(`/messages/inbox?${qp.toString()}`, { headers: this.headers() });
      return res.json();
    },
    async thread(withUser, sinceId = null, limit = 200, beforeId = null) {
      const qp = new URLSearchParams({ with: withUser, limit: String(limit) });
      if (sinceId != null) qp.set('since_id', String(sinceId));
      if (beforeId != null) qp.set('before_id', String(beforeId));
      const res = await this._fetch(`/messages/thread?${qp.toString()}`, { headers: this.headers() });
      return res.json();
    },
  };

  // -----------------------------
  // Binary/base64 helpers
  // -----------------------------
  function ab2b64(buf) { const bytes = new Uint8Array(buf); let s = ''; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s); }
  function b642ab(b64) { const s = atob(b64); const bytes = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i); return bytes.buffer; }
  function str2ab(str) { return new TextEncoder().encode(str).buffer; }
  function ab2str(buf) { return new TextDecoder().decode(buf); }

  // -----------------------------
  // Crypto helpers (WebCrypto)
  // -----------------------------
  async function pbkdf2Key(password, salt, iterations = 200000) {
    const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function generateRsaKeyPair() { return crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']); }
  async function exportJwk(key) { return crypto.subtle.exportKey('jwk', key); }
  async function importPublicKey(jwk) { return crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']); }
  async function importPrivateKey(jwk) { return crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']); }
  async function generateAesKey() { return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']); }
  async function importAesRaw(raw) { return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']); }
  async function encryptPrivateJwkWithPassword(privJwk, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await pbkdf2Key(password, salt);
    const pt = new TextEncoder().encode(JSON.stringify(privJwk));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, pt);
    return { salt: ab2b64(salt.buffer), iv: ab2b64(iv.buffer), ct: ab2b64(ct) };
  }
  async function decryptPrivateJwkWithPassword(blob, password) {
    const salt = new Uint8Array(b642ab(blob.salt));
    const iv = new Uint8Array(b642ab(blob.iv));
    const ct = b642ab(blob.ct);
    const key = await pbkdf2Key(password, salt);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return JSON.parse(ab2str(pt));
  }

  async function hybridEncrypt(recipientPubKey, plaintextStr, sender) {
    const aes = await generateAesKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aes, str2ab(plaintextStr));
    const aesRaw = await crypto.subtle.exportKey('raw', aes);
    const wrapped = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, recipientPubKey, aesRaw);
    return JSON.stringify({ v: 1, alg: 'RSA-OAEP+AES-GCM', sender, iv: ab2b64(iv.buffer), key: ab2b64(wrapped), ct: ab2b64(ct) });
  }
  async function hybridDecrypt(privateKey, blobStr) {
    const blob = JSON.parse(blobStr);
    const aesRaw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, b642ab(blob.key));
    const aes = await importAesRaw(aesRaw);
    const iv = new Uint8Array(b642ab(blob.iv));
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aes, b642ab(blob.ct));
    return { sender: blob.sender, text: ab2str(pt) };
  }

  // -----------------------------
  // Local storage helpers
  // -----------------------------
  function saveLocalEncPriv(enc) { localStorage.setItem('e2e.encryptedPrivateKey', JSON.stringify(enc)); }
  function getLocalEncPriv() { try { return JSON.parse(localStorage.getItem('e2e.encryptedPrivateKey')); } catch { return null; } }
  function saveLocalBasics(username, publicKeyJwk) { localStorage.setItem('e2e.publicKey', JSON.stringify(publicKeyJwk)); localStorage.setItem('e2e.username', username); }
  function loadLocalBasics() { let username = localStorage.getItem('e2e.username') || ''; let publicKeyJwk = null; try { publicKeyJwk = JSON.parse(localStorage.getItem('e2e.publicKey')); } catch { } return { username, publicKeyJwk }; }
  // -----------------------------
  // App state
  // -----------------------------
  const state = { username: null, token: null, publicKeyJwk: null, privateKey: null, ws: null, selectedFriend: null };
  const lastByFriend = {};
  const oldestByFriend = {};
  const loadingNewFor = {}; const seenByFriend = {};
  let latestFriends = [];

  // -----------------------------
  // UI helpers
  // -----------------------------
  function setMeLabel() { const el = document.getElementById('me-label'); if (el) el.textContent = state.username ? `Logged in as ${state.username}` : ''; }

  function renderFriends(list) {
    latestFriends = list || [];
    const targets = [document.getElementById('friends'), document.getElementById('friends-m')];
    for (const c of targets) {
      if (!c) continue; c.innerHTML = '';
      for (const f of list) {
        const btn = document.createElement('button'); btn.className = 'friend';
        const av = document.createElement('span'); av.className = 'avatar'; av.textContent = (f || '?').slice(0, 1).toUpperCase();
        const nm = document.createElement('span'); nm.className = 'friend-name'; nm.textContent = f;
        btn.appendChild(av); btn.appendChild(nm);
        btn.onclick = () => {
          state.selectedFriend = f; document.getElementById('chat-header').textContent = 'Chat with ' + f; document.getElementById('chat-log').innerHTML = '';
          lastByFriend[f] = lastByFriend[f] || null; oldestByFriend[f] = oldestByFriend[f] || null; seenByFriend[f] = new Set(); document.getElementById('composer').classList.remove('hidden');
          hideFriendsDrawer(); loadNewForFriend(f); bindScrollForHistory();
        };
        c.appendChild(btn);
      }
    }
  }

  function renderRequests(reqs) {
    const targets = [document.getElementById('requests'), document.getElementById('requests-m')];
    for (const c of targets) {
      if (!c) continue; c.innerHTML = '';
      for (const from of (reqs.incoming || [])) {
        const row = document.createElement('div'); row.style.display = 'flex'; row.style.alignItems = 'center'; row.style.justifyContent = 'space-between'; row.style.gap = '8px';
        const label = document.createElement('span'); label.textContent = from;
        const actions = document.createElement('div');
        const acc = document.createElement('button'); acc.textContent = 'Accept'; acc.className = 'btn small outline success'; acc.onclick = async () => { await api.friendRespond(from, true); await refreshFriends(); };
        const dec = document.createElement('button'); dec.textContent = 'Decline'; dec.className = 'btn small outline danger'; dec.onclick = async () => { await api.friendRespond(from, false); await refreshFriends(); };
        actions.appendChild(acc); actions.appendChild(dec);
        row.appendChild(label); row.appendChild(actions); c.appendChild(row);
      }
      for (const to of (reqs.outgoing || [])) { const row = document.createElement('div'); row.className = 'subtle'; row.textContent = `Pending: ${to}`; c.appendChild(row); }
    }
  }
  function appendTextBubble({ text, mine, createdAt }) {
    const log = document.getElementById('chat-log');
    const stick = (log.scrollHeight - log.scrollTop - log.clientHeight) < 80 || mine;
    const b = document.createElement('div');
    b.className = 'msg ' + (mine ? 'me' : 'you');
    const content = document.createElement('div');
    content.textContent = text;
    const meta = document.createElement('div');
    meta.className = 'time';
    meta.textContent = new Date(createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    b.appendChild(content);
    b.appendChild(meta);
    log.appendChild(b);
    if (stick) log.scrollTop = log.scrollHeight;
  }

  function appendImageBubble({ url, name, mine, createdAt }) {
    const log = document.getElementById('chat-log');
    const stick = (log.scrollHeight - log.scrollTop - log.clientHeight) < 80 || mine;
    const b = document.createElement('div');
    b.className = 'msg ' + (mine ? 'me' : 'you');
    const img = document.createElement('img');
    img.src = url;
    img.alt = name || 'image';
    img.className = 'img';
    img.style.cursor = 'zoom-in';
    img.onclick = () => openLightbox(url, name || 'image');
    const meta = document.createElement('div');
    meta.className = 'time';
    meta.textContent = new Date(createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    b.appendChild(img);
    b.appendChild(meta);
    log.appendChild(b);
    if (stick) log.scrollTop = log.scrollHeight;
  }

  function appendFileBubble({ meta, mine, createdAt }) {
    const log = document.getElementById('chat-log');
    const stick = (log.scrollHeight - log.scrollTop - log.clientHeight) < 80 || mine;
    const b = document.createElement('div');
    b.className = 'msg ' + (mine ? 'me' : 'you');
    const line = document.createElement('div');
    line.textContent = `📎 ${meta.name} (${Math.round(meta.size / 1024)} KB)`;
    const btn = document.createElement('button');
    btn.className = 'btn small ghost';
    btn.textContent = 'Download';
    btn.onclick = () => downloadAttachment(meta);
    line.appendChild(btn);
    const ts = document.createElement('div');
    ts.className = 'time';
    ts.textContent = new Date(createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    b.appendChild(line);
    b.appendChild(ts);
    log.appendChild(b);
    if (stick) log.scrollTop = log.scrollHeight;
  }
  function prependTextBubble({ text, mine, createdAt }) {
    const log = document.getElementById('chat-log'); const first = log.firstChild; const b = document.createElement('div'); b.className = 'msg ' + (mine ? 'me' : 'you');
    const content = document.createElement('div'); content.textContent = text;
    const meta = document.createElement('div'); meta.className = 'time'; meta.textContent = new Date(createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    b.appendChild(content); b.appendChild(meta); log.insertBefore(b, first);
  }
  function prependImageBubble({ url, name, mine, createdAt }) {
    const log = document.getElementById('chat-log'); const first = log.firstChild; const b = document.createElement('div'); b.className = 'msg ' + (mine ? 'me' : 'you');
    const img = document.createElement('img'); img.src = url; img.alt = name || 'image'; img.className = 'img'; img.style.cursor = 'zoom-in'; img.onclick = () => openLightbox(url, name || 'image');
    const meta = document.createElement('div'); meta.className = 'time'; meta.textContent = new Date(createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    b.appendChild(img); b.appendChild(meta); log.insertBefore(b, first);
  }
  function prependFileBubble({ meta, mine, createdAt }) {
    const log = document.getElementById('chat-log'); const first = log.firstChild; const b = document.createElement('div'); b.className = 'msg ' + (mine ? 'me' : 'you');
    const line = document.createElement('div'); line.textContent = `📎 ${meta.name} (${Math.round(meta.size / 1024)} KB) `;
    const btn = document.createElement('button'); btn.className = 'btn small ghost'; btn.textContent = 'Download'; btn.onclick = () => downloadAttachment(meta);
    line.appendChild(btn);
    const ts = document.createElement('div'); ts.className = 'time'; ts.textContent = new Date(createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    b.appendChild(line); b.appendChild(ts); log.insertBefore(b, first);
  }
  // Lightbox preview
  function openLightbox(url, name) {
    const lb = document.getElementById('lightbox');
    const img = document.getElementById('lightbox-img');
    const dl = document.getElementById('lightbox-download');
    const close = document.getElementById('lightbox-close');
    if (!lb || !img || !dl || !close) return;
    img.src = url; img.alt = name || 'image';
    dl.href = url; dl.download = name || 'image';
    lb.classList.add('show'); lb.setAttribute('aria-hidden', 'false');
    const onEsc = (e) => { if (e.key === 'Escape') closeLightbox(); };
    lb._esc = onEsc; window.addEventListener('keydown', onEsc);
    const backdrop = lb.querySelector('.lightbox-backdrop'); if (backdrop) backdrop.onclick = closeLightbox;
    close.onclick = closeLightbox;
  }
  function closeLightbox() {
    const lb = document.getElementById('lightbox'); if (!lb) return;
    lb.classList.remove('show'); lb.setAttribute('aria-hidden', 'true');
    const onEsc = lb._esc; if (onEsc) { window.removeEventListener('keydown', onEsc); lb._esc = null; }
    const img = document.getElementById('lightbox-img'); if (img) img.src = '';
  }

  // -----------------------------
  // Messaging
  // -----------------------------
  async function refreshFriends() { const f = await api.friends(); renderFriends(f.friends || []); const r = await api.friendRequests(); renderRequests(r); }

  async function loadNewForFriend(friend) {
    if (!friend) return;
    if (loadingNewFor[friend]) return;
    loadingNewFor[friend] = true;
    const since = lastByFriend[friend] || null;
    const rows = await api.thread(friend, since, 50);
    for (const r of rows) {
      try {
        let meta; try { meta = JSON.parse(r.ciphertext); } catch { }
        if (meta && meta.type === 'file') {
          const mine = meta.sender === state.username; if ((meta.sender !== friend && !mine)) continue;
          if (!seenByFriend[friend]) seenByFriend[friend] = new Set();
          if (seenByFriend[friend].has(r.id)) continue;
          if ((meta.mime || '').startsWith('image/')) { const blob = await decryptToBlob(meta); const url = URL.createObjectURL(blob); appendImageBubble({ url, name: meta.name, mine, createdAt: r.created_at }); }
          else { appendFileBubble({ meta, mine, createdAt: r.created_at }); }
          seenByFriend[friend].add(r.id);
        } else {
          const { sender, text } = await hybridDecrypt(state.privateKey, r.ciphertext);
          if (sender !== friend && sender !== state.username) continue;
          if (!seenByFriend[friend]) seenByFriend[friend] = new Set();
          if (seenByFriend[friend].has(r.id)) continue;
          appendTextBubble({ text, mine: sender === state.username, createdAt: r.created_at });
          seenByFriend[friend].add(r.id);
        }
        lastByFriend[friend] = r.id; if (!oldestByFriend[friend] || r.id < oldestByFriend[friend]) oldestByFriend[friend] = r.id;
      } catch (e) { console.warn('render fail', e); }
    }
    loadingNewFor[friend] = false;
  }
  async function sendChat() {
    const input = document.getElementById('chat-input'); const to = state.selectedFriend; if (!to) return; const msg = input.value.trim(); if (!msg) return;
    const user = await api.getUser(to); if (!user) { document.getElementById('chat-error').textContent = 'Recipient not found'; return; }
    const pubKey = await importPublicKey(user.public_key_jwk);
    try { const blob = await hybridEncrypt(pubKey, msg, state.username); await api.send(state.username, to, blob); }
    catch (e) { document.getElementById('chat-error').textContent = e.message || 'Send failed'; setTimeout(() => document.getElementById('chat-error').textContent = '', 2000); return; }
    input.value = ''; appendTextBubble({ text: msg, mine: true, createdAt: new Date().toISOString() });
  }

  function connectWS() {
    if (!state.token) return;
    const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws?token=${encodeURIComponent(state.token)}`);
    ws.onmessage = async (ev) => { try { const data = JSON.parse(ev.data); if (data.type === 'new_message') { const f = data.from; if (state.selectedFriend && f === state.selectedFriend) { await loadNewForFriend(f); } } else if (data.type === 'friend_request' || data.type === 'friend_response') { await refreshFriends(); } } catch { } };
    state.ws = ws;
  }

  // Infinite scroll older history
  let loadingOlder = false;
  function bindScrollForHistory() {
    const log = document.getElementById('chat-log'); if (!log) return;
    log.onscroll = async () => {
      if (log.scrollTop < 60 && !loadingOlder) {
        loadingOlder = true; const friend = state.selectedFriend; if (!friend) { loadingOlder = false; return; }
        const before = oldestByFriend[friend] || null; if (!before) { loadingOlder = false; return; }
        const rows = await api.thread(friend, null, 50, before);
        const prevHeight = log.scrollHeight;
        for (const r of rows) {
          try {
            let meta; try { meta = JSON.parse(r.ciphertext); } catch { }
            if (meta && meta.type === 'file') {
              const mine = meta.sender === state.username; if ((meta.sender !== friend && !mine)) continue;
              if (!seenByFriend[friend]) seenByFriend[friend] = new Set();
              if (seenByFriend[friend].has(r.id)) continue;
              if ((meta.mime || '').startsWith('image/')) { const blob = await decryptToBlob(meta); const url = URL.createObjectURL(blob); prependImageBubble({ url, name: meta.name, mine, createdAt: r.created_at }); }
              else { prependFileBubble({ meta, mine, createdAt: r.created_at }); }
              seenByFriend[friend].add(r.id);
            } else {
              const { sender, text } = await hybridDecrypt(state.privateKey, r.ciphertext);
              if (sender !== friend && sender !== state.username) continue;
              if (!seenByFriend[friend]) seenByFriend[friend] = new Set();
              if (seenByFriend[friend].has(r.id)) continue;
              prependTextBubble({ text, mine: sender === state.username, createdAt: r.created_at });
              seenByFriend[friend].add(r.id);
            }
            if (!oldestByFriend[friend] || r.id < oldestByFriend[friend]) oldestByFriend[friend] = r.id;
          } catch (e) { }
        }
        const newHeight = log.scrollHeight; log.scrollTop = newHeight - prevHeight; loadingOlder = false;
      }
    };
  }

  // -----------------------------
  // File upload (E2E encrypted) and download
  // -----------------------------
  const CHUNK = 1024 * 1024; // 1MB

  function setupUploadUI(name, size) {
    const wrap = document.getElementById('upload-progress'); const bar = document.getElementById('upload-bar'); const label = document.getElementById('upload-label'); const cancel = document.getElementById('upload-cancel');
    let canceled = false; wrap.classList.remove('hidden'); bar.style.width = '0%'; label.textContent = `${name} • ${Math.round(size / 1024 / 1024)} MB`;
    const onCancel = () => { canceled = true; wrap.classList.add('hidden'); };
    cancel.onclick = onCancel;
    return { update: (p) => { bar.style.width = `${Math.round(p)}%`; }, done: () => { bar.style.width = '100%'; setTimeout(() => wrap.classList.add('hidden'), 600); }, get canceled() { return canceled; } };
  }
  async function uploadEncryptedFile(file, to) {
    const user = await api.getUser(to); if (!user) { alert('Recipient not found'); return; }
    const pubKey = await importPublicKey(user.public_key_jwk);
    const aes = await generateAesKey(); const aesRaw = await crypto.subtle.exportKey('raw', aes);
    const wrappedKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pubKey, aesRaw);
    // Also wrap for sender so they can decrypt/view their own attachments later
    let wrappedKeySelf = null;
    try {
      if (state.publicKeyJwk) {
        const myPub = await importPublicKey(state.publicKeyJwk);
        wrappedKeySelf = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, myPub, aesRaw);
      }
    } catch {}
    const baseIv = crypto.getRandomValues(new Uint8Array(12));
    const total = Math.ceil(file.size / CHUNK);
    const init = await api._fetch('/uploads/init', { method: 'POST', headers: api.headers(), body: JSON.stringify({ recipient: to, filename: file.name, size: file.size, mime: file.type || null, total_chunks: total, base_iv: ab2b64(baseIv.buffer), key_wrapped: ab2b64(wrappedKey) }) });
    const { id } = await init.json();

    const ui = setupUploadUI(file.name, file.size);
    let index = 0; let offset = 0;
    while (offset < file.size) {
      if (ui.canceled) return;
      const end = Math.min(offset + CHUNK, file.size);
      const chunkBuf = await file.slice(offset, end).arrayBuffer();
      const iv = new Uint8Array(baseIv); new DataView(iv.buffer).setUint32(iv.byteLength - 4, index, false);
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aes, chunkBuf);
      await api._fetch(`/uploads/${id}/chunk?index=${index}`, { method: 'POST', headers: api.headers(false), body: ct });
      index++; offset = end; ui.update((offset / file.size) * 100);
    }
    await api._fetch(`/uploads/${id}/finish`, { method: 'POST', headers: api.headers() }); ui.done();

    const meta = { type: 'file', sender: state.username, name: file.name, size: file.size, mime: file.type || 'application/octet-stream', upload_id: id, key: ab2b64(wrappedKey), iv: ab2b64(baseIv.buffer), chunk: CHUNK, total: total };
    if (wrappedKeySelf) meta.key_self = ab2b64(wrappedKeySelf);
    await api.send(state.username, to, JSON.stringify(meta));
    const mine = true; if ((meta.mime || '').startsWith('image/')) { const blob = await decryptToBlob(meta); const url = URL.createObjectURL(blob); appendImageBubble({ url, name: meta.name, mine, createdAt: new Date().toISOString() }); } else { appendFileBubble({ meta, mine, createdAt: new Date().toISOString() }); }
  }

  async function decryptToBlob(meta) {
    let res; for (let i = 0; i < 4; i++) { try { res = await fetch(`/uploads/${meta.upload_id}`, { headers: api.headers() }); if (!res.ok) throw new Error('Download not ready'); break; } catch (e) { await new Promise(r => setTimeout(r, 250 * (i + 1))); } }
    if (!res || !res.ok) throw new Error('Download failed');
    const encBuf = await res.arrayBuffer();
    const wrapped = (meta.key_self && state.username === meta.sender) ? b642ab(meta.key_self) : b642ab(meta.key);
    const aesRaw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, state.privateKey, wrapped);
    const aes = await importAesRaw(aesRaw);
    const out = []; let offset = 0; const total = meta.total || Math.ceil(meta.size / meta.chunk);
    for (let i = 0; i < total; i++) {
      const expected = (i === total - 1) ? ((meta.size - i * meta.chunk) + 16) : (meta.chunk + 16);
      const iv = new Uint8Array(b642ab(meta.iv)); new DataView(iv.buffer).setUint32(iv.byteLength - 4, i, false);
      const ct = encBuf.slice(offset, offset + expected); offset += expected;
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aes, ct); out.push(new Uint8Array(pt));
    }
    let totalLen = 0; for (const a of out) totalLen += a.length; const merged = new Uint8Array(totalLen); let p = 0; for (const a of out) { merged.set(a, p); p += a.length; }
    return new Blob([merged], { type: meta.mime || 'application/octet-stream' });
  }

  async function downloadAttachment(meta) { const blob = await decryptToBlob(meta); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = meta.name || 'download'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 500); }
  // Composer keyboard behavior
  function setupComposerPinning() {
    const ta = document.getElementById('chat-input'); const composer = document.getElementById('composer'); if (!ta || !composer) return;
    function pin() { if (window.innerWidth < 900) { composer.classList.add('composer-fixed'); document.getElementById('chat-log').style.paddingBottom = '96px'; } }
    function unpin() { composer.classList.remove('composer-fixed'); document.getElementById('chat-log').style.paddingBottom = ''; }
    ta.addEventListener('focus', pin); ta.addEventListener('blur', unpin);
    if (window.visualViewport) { window.visualViewport.addEventListener('resize', () => { if (document.activeElement === ta && window.innerWidth < 900) pin(); }); }
  }

  // App bindings
  function showFriendsDrawer() { const el = document.getElementById('friends-drawer'); if (el) el.classList.remove('hidden'); }
  function hideFriendsDrawer() { const el = document.getElementById('friends-drawer'); if (el) el.classList.add('hidden'); }

  function bindAppEvents() {
    document.getElementById('chat-send').onclick = sendChat;
    document.getElementById('chat-input').addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat(); } });
    document.getElementById('attach-btn').onclick = () => document.getElementById('attach-input').click();
    document.getElementById('attach-input').onchange = async (e) => { const file = e.target.files && e.target.files[0]; if (!file) return; const to = state.selectedFriend; if (!to) { alert('Select a friend first'); e.target.value = ''; return; } await uploadEncryptedFile(file, to); e.target.value = ''; };
    document.getElementById('add-friend-btn').onclick = async () => { const to = document.getElementById('add-friend-username').value.trim(); if (!to) return; try { await api.friendRequest(to); document.getElementById('friend-error').textContent = 'Request sent'; setTimeout(() => document.getElementById('friend-error').textContent = '', 1200); } catch (e) { document.getElementById('friend-error').textContent = e.message || 'Failed'; setTimeout(() => document.getElementById('friend-error').textContent = '', 2000); } document.getElementById('add-friend-username').value = ''; await refreshFriends(); };
    const addM = document.getElementById('add-friend-btn-m'); if (addM) addM.onclick = async () => { const to = document.getElementById('add-friend-username-m').value.trim(); if (!to) return; try { await api.friendRequest(to); document.getElementById('friend-error-m').textContent = 'Request sent'; setTimeout(() => document.getElementById('friend-error-m').textContent = '', 1200); } catch (e) { document.getElementById('friend-error-m').textContent = e.message || 'Failed'; setTimeout(() => document.getElementById('friend-error-m').textContent = '', 2000); } document.getElementById('add-friend-username-m').value = ''; await refreshFriends(); };
    document.getElementById('export-btn').onclick = () => { const enc = getLocalEncPriv(); const basics = loadLocalBasics(); if (!enc || !basics.username || !basics.publicKeyJwk) { alert('No key to export.'); return; } const blob = new Blob([JSON.stringify({ username: basics.username, publicKey: basics.publicKeyJwk, encryptedPrivateKey: enc }, null, 2)], { type: 'application/json' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = `e2e-key-${basics.username}.json`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 500); };
    document.getElementById('import-btn-app').onclick = () => document.getElementById('import-file-app').click();
    document.getElementById('import-file-app').onchange = async (e) => { const file = e.target.files[0]; if (!file) return; try { const txt = await file.text(); const data = JSON.parse(txt); if (!data || !data.encryptedPrivateKey || !data.publicKey || !data.username) throw new Error('Invalid key file'); saveLocalEncPriv(data.encryptedPrivateKey); saveLocalBasics(data.username, data.publicKey); alert('Key imported. Login with your password.'); } catch (err) { alert('Import failed: ' + (err.message || 'Invalid file')); } e.target.value = ''; };
    document.getElementById('friends-toggle').onclick = showFriendsDrawer;
    const openF = document.getElementById('open-friends'); if (openF) openF.onclick = showFriendsDrawer;
    const closeF = document.getElementById('friends-close'); if (closeF) closeF.onclick = hideFriendsDrawer;
    document.getElementById('logout-btn').onclick = () => { state.token = null; api.setToken(null); state.privateKey = null; state.username = null; state.selectedFriend = null; document.getElementById('app').classList.add('hidden'); document.getElementById('auth').classList.remove('hidden'); document.getElementById('chat-log').innerHTML = ''; if (state.ws) { try { state.ws.close(); } catch { } state.ws = null; } setMeLabel(); };
    setupComposerPinning();
  }
  // Auth flows
  async function doLogin() {
    const btn = document.getElementById('login-btn'); const err = document.getElementById('login-error'); err.textContent = '';
    const username = document.getElementById('login-username').value.trim(); const password = document.getElementById('login-password').value;
    if (!username || !password) { err.textContent = 'Enter username and password'; return; }
    btn.setAttribute('disabled', '');
    try {
      const res = await api.login(username, password); api.setToken(res.token); state.token = res.token; state.username = res.username; setMeLabel();
      const enc = getLocalEncPriv(); if (!enc) { err.textContent = 'No local key found. Import your key file or register.'; return; }
      let privJwk; try { privJwk = await decryptPrivateJwkWithPassword(enc, password); } catch { err.textContent = 'Wrong password for local key'; return; }
      state.publicKeyJwk = JSON.parse(localStorage.getItem('e2e.publicKey'));
      state.privateKey = await importPrivateKey(privJwk);
      document.getElementById('auth').classList.add('hidden'); document.getElementById('app').classList.remove('hidden');
      bindAppEvents(); await refreshFriends(); connectWS();
    } catch (e) { err.textContent = e.message || 'Login failed'; }
    finally { btn.removeAttribute('disabled'); }
  }

  async function doRegister() {
    const btn = document.getElementById('register-btn'); const err = document.getElementById('register-error'); err.textContent = '';
    const username = document.getElementById('reg-username').value.trim(); const password = document.getElementById('reg-password').value;
    if (!username || !password) { err.textContent = 'Enter username and password'; return; }
    btn.setAttribute('disabled', '');
    try {
      const pair = await generateRsaKeyPair(); const pubJwk = await exportJwk(pair.publicKey); const privJwk = await exportJwk(pair.privateKey);
      const enc = await encryptPrivateJwkWithPassword(privJwk, password); saveLocalEncPriv(enc); saveLocalBasics(username, pubJwk);
      const res = await api.register(username, password, pubJwk); api.setToken(res.token); state.token = res.token; state.username = res.username; setMeLabel();
      state.publicKeyJwk = pubJwk; state.privateKey = await importPrivateKey(privJwk);
      document.getElementById('auth').classList.add('hidden'); document.getElementById('app').classList.remove('hidden');
      bindAppEvents(); await refreshFriends(); connectWS();
    } catch (e) { err.textContent = e.message || 'Registration failed'; }
    finally { btn.removeAttribute('disabled'); }
  }

  // Initial bindings
  window.addEventListener('DOMContentLoaded', () => {
    const basics = loadLocalBasics(); if (basics.username) { const u = document.getElementById('login-username'); if (u) u.value = basics.username; }
    setMeLabel();
    const lb = document.getElementById('login-btn'); if (lb) lb.onclick = doLogin;
    const rb = document.getElementById('register-btn'); if (rb) rb.onclick = doRegister;
    const impBtn = document.getElementById('import-btn'); const impInput = document.getElementById('import-file'); if (impBtn && impInput) {
      impBtn.onclick = () => impInput.click();
      impInput.onchange = async (e) => { const file = e.target.files && e.target.files[0]; if (!file) return; try { const txt = await file.text(); const data = JSON.parse(txt); if (!data || !data.encryptedPrivateKey || !data.publicKey || !data.username) throw new Error('Invalid key file'); saveLocalEncPriv(data.encryptedPrivateKey); saveLocalBasics(data.username, data.publicKey); const u = document.getElementById('login-username'); if (u) u.value = data.username; const le = document.getElementById('login-error'); if (le) { le.textContent = 'Key imported. Now login with your password.'; setTimeout(() => le.textContent = '', 2500); } } catch (err) { alert('Import failed: ' + (err.message || 'Invalid file')); } finally { e.target.value = ''; } };
    }
    const goReg = document.getElementById('goto-register'); if (goReg) goReg.onclick = () => { const lc = document.getElementById('login-card'); const rc = document.getElementById('register-card'); if (lc && rc) { lc.classList.add('hidden'); rc.classList.remove('hidden'); } };
    const goLog = document.getElementById('goto-login'); if (goLog) goLog.onclick = () => { const lc = document.getElementById('login-card'); const rc = document.getElementById('register-card'); if (lc && rc) { rc.classList.add('hidden'); lc.classList.remove('hidden'); } };
  });
})();
