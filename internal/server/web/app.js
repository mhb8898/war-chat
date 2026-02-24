// War Chat - E2E encrypted chat client (Messenger-style UX)

const API_BASE = window.location.origin;

function ensureCrypto() {
  if (!window.crypto || !window.crypto.subtle) {
    const msg = 'Web Crypto API is not available. Use HTTPS or open from localhost.';
    document.body.innerHTML = '<div style="padding:2rem;text-align:center;font-family:sans-serif"><h2>Security Required</h2><p>' + msg + '</p></div>';
    throw new Error(msg);
  }
}
const DB_NAME = 'war-chat';
const DB_VERSION = 6;
const STORE_MSGS = 'messages';
const STORE_KEYS = 'keys';
const STORE_KEYPAIRS = 'keypairs';
const STORE_PASSKEY_CREDS = 'passkey_credentials';
const STORE_GROUPS = 'groups';
const SESSION_USER = 'war-chat-username';
const SESSION_MNEMONIC = 'war-chat-mnemonic';
const SESSION_SEED = 'war-chat-seed';
// Use localStorage for username so it persists across tabs and refreshes
const STORAGE_USER = 'war-chat-username';
const PASSKEY_SESSION = 'war-chat-passkey-session';

let db = null;
let keys = null;
let ws = null;
let currentUsername = null;
let currentRecipient = null;
let pubkeyCache = {};
let pendingPasskeyCredentialId = null;

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onerror = () => reject(req.error);
    req.onsuccess = () => resolve(req.result);
    req.onupgradeneeded = (e) => {
      const database = e.target.result;
      if (!database.objectStoreNames.contains(STORE_MSGS)) {
        database.createObjectStore(STORE_MSGS, { keyPath: 'id' });
      }
      if (!database.objectStoreNames.contains(STORE_KEYS)) {
        database.createObjectStore(STORE_KEYS, { keyPath: 'username' });
      }
      if (!database.objectStoreNames.contains(STORE_KEYPAIRS)) {
        database.createObjectStore(STORE_KEYPAIRS, { keyPath: 'seed' });
      }
      if (!database.objectStoreNames.contains('sessions')) {
        database.createObjectStore('sessions', { keyPath: 'username' });
      }
      if (!database.objectStoreNames.contains(STORE_PASSKEY_CREDS)) {
        database.createObjectStore(STORE_PASSKEY_CREDS, { keyPath: 'credentialId' });
      }
      if (!database.objectStoreNames.contains(STORE_GROUPS)) {
        database.createObjectStore(STORE_GROUPS, { keyPath: 'id' });
      }
    };
  });
}

async function saveMessage(msg) {
  if (!currentUsername) return;
  const owner = currentUsername;
  const id = `${owner}:${msg.id}`;
  const enc = await encryptMessageForStorage(msg);
  if (!enc) {
    console.error('Message encryption failed - keys may not be ready');
    return;
  }
  const stored = { id, owner, encryptedPayload: enc.encryptedPayload, iv: enc.iv };
  const tx = db.transaction(STORE_MSGS, 'readwrite');
  tx.objectStore(STORE_MSGS).put(stored);
  return new Promise((resolve) => (tx.oncomplete = resolve));
}

async function getMessages(peer) {
  if (!currentUsername) return [];
  const raw = await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_MSGS, 'readonly');
    const req = tx.objectStore(STORE_MSGS).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
  const byOwner = raw.filter((m) => m.owner === currentUsername);
  const decrypted = [];
  for (const r of byOwner) {
    const m = await decryptMessageFromStorage(r);
    if (m && m.peer === peer) decrypted.push(m);
  }
  let all = decrypted.sort((a, b) => a.ts - b.ts);
  if (peer === currentUsername) {
    const seen = new Set();
    all = all.filter((m) => {
      const key = m.text + '|' + m.ts;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
  return all;
}

async function getConversations() {
  if (!currentUsername) return [];
  const raw = await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_MSGS, 'readonly');
    const req = tx.objectStore(STORE_MSGS).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
  const byOwner = raw.filter((m) => m.owner === currentUsername);
  const byPeer = {};
  for (const r of byOwner) {
    const m = await decryptMessageFromStorage(r);
    if (!m) continue;
    const ts = Number(m.ts) || 0;
    const id = m.id || '';
    const cur = byPeer[m.peer];
    if (!cur || ts > cur.lastTs || (ts === cur.lastTs && id > cur.lastId)) {
      byPeer[m.peer] = { peer: m.peer, lastMsg: m.text, lastTs: ts, lastId: id };
    }
  }
  const groups = await getAllGroups();
  for (const g of groups) {
    const peer = peerFromGroupId(g.id);
    if (!byPeer[peer]) {
      byPeer[peer] = { peer, lastMsg: 'No messages', lastTs: g.createdAt || 0, lastId: '', groupName: g.name };
    } else {
      byPeer[peer].groupName = g.name;
    }
  }
  return Object.values(byPeer).sort((a, b) => b.lastTs - a.lastTs);
}

const GROUP_PEER_PREFIX = 'group:';

function isGroupPeer(peer) {
  return typeof peer === 'string' && peer.startsWith(GROUP_PEER_PREFIX);
}

function groupPeerId(peer) {
  return isGroupPeer(peer) ? peer.slice(GROUP_PEER_PREFIX.length) : null;
}

function peerFromGroupId(groupId) {
  return GROUP_PEER_PREFIX + groupId;
}

async function generateSenderKeyRaw() {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  return { key, raw };
}

function base64ToArrayBuffer(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

function arrayBufferToBase64(buf) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
}

async function importSenderKeyFromBase64(b64) {
  const raw = base64ToArrayBuffer(b64);
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function saveGroup(record) {
  if (!db) return;
  const store = db.transaction(STORE_GROUPS, 'readwrite').objectStore(STORE_GROUPS);
  store.put(record);
  return new Promise((resolve) => { store.transaction.oncomplete = resolve; });
}

async function getGroup(groupId) {
  if (!db) return null;
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_GROUPS, 'readonly');
    tx.objectStore(STORE_GROUPS).get(groupId).onsuccess = (e) => resolve(e.target.result || null);
    tx.onerror = () => reject(tx.error);
  });
}

async function deleteGroup(groupId) {
  if (!db) return;
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_GROUPS, 'readwrite');
    tx.objectStore(STORE_GROUPS).delete(groupId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function getAllGroups() {
  if (!db) return [];
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_GROUPS, 'readonly');
    tx.objectStore(STORE_GROUPS).getAll().onsuccess = (e) => resolve(e.target.result || []);
    tx.onerror = () => reject(tx.error);
  });
}

function isLoggedIn() {
  return !!(sessionStorage.getItem(SESSION_USER) && keys);
}

function getStoredUsername() {
  return localStorage.getItem(STORAGE_USER) || sessionStorage.getItem(SESSION_USER);
}

function setStoredUsername(username) {
  if (username) {
    localStorage.setItem(STORAGE_USER, username);
    sessionStorage.setItem(SESSION_USER, username);
  } else {
    localStorage.removeItem(STORAGE_USER);
    sessionStorage.removeItem(SESSION_USER);
  }
}

// --- Router ---
function getRoute() {
  const hash = window.location.hash.slice(1) || 'chats';
  const [view, param] = hash.split('/');
  return { view: view || 'chats', param: param || null };
}

function navigate(view, param) {
  const hash = param ? `#${view}/${param}` : `#${view}`;
  window.location.hash = hash;
}

async function fetchUsers() {
  const resp = await fetch(`${API_BASE}/users`);
  if (!resp.ok) return [];
  const json = await resp.json();
  return (json.users || []).filter((u) => u && u !== currentUsername).sort((a, b) => a.localeCompare(b));
}

function renderUserList(users, query) {
  const list = document.getElementById('newChatUserList');
  const empty = document.getElementById('newChatUserListEmpty');
  if (!list || !empty) return;
  const q = (query || '').toLowerCase().trim();
  const filtered = q ? users.filter((u) => u.toLowerCase().includes(q)) : users;
  list.innerHTML = '';
  if (filtered.length === 0) {
    empty.classList.remove('hidden');
    return;
  }
  empty.classList.add('hidden');
  filtered.forEach((username) => {
    const li = document.createElement('li');
    li.className = 'user-row';
    li.innerHTML = `<div class="user-avatar">${(username[0] || '?').toUpperCase()}</div><span class="user-name">${escapeHtml(username)}</span>`;
    li.onclick = () => {
      document.getElementById('newChatModal').classList.remove('visible');
      document.getElementById('newChatSearchModal').value = '';
      navigate('chat', username);
    };
    list.appendChild(li);
  });
}

async function showNewChatModal() {
  const modal = document.getElementById('newChatModal');
  const searchInput = document.getElementById('newChatSearchModal');
  if (!modal || !searchInput) return;
  searchInput.value = '';
  modal.classList.add('visible');
  searchInput.focus();
  const users = await fetchUsers();
  renderUserList(users);
  const onSearch = () => renderUserList(users, searchInput.value);
  searchInput.oninput = onSearch;
  searchInput.onkeyup = onSearch;
}

let newGroupSelectedUsers = new Set();

async function showNewGroupModal() {
  const modal = document.getElementById('newGroupModal');
  const nameInput = document.getElementById('newGroupName');
  const listEl = document.getElementById('newGroupUserList');
  const emptyEl = document.getElementById('newGroupUserListEmpty');
  if (!modal || !nameInput || !listEl) return;
  nameInput.value = '';
  newGroupSelectedUsers = new Set();
  modal.classList.add('visible');
  nameInput.focus();
  const users = await fetchUsers();
  listEl.innerHTML = '';
  if (users.length === 0) {
    if (emptyEl) emptyEl.classList.remove('hidden');
    return;
  }
  if (emptyEl) emptyEl.classList.add('hidden');
  users.forEach((username) => {
    const li = document.createElement('li');
    li.style.display = 'flex';
    li.style.alignItems = 'center';
    li.style.gap = '0.5rem';
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.dataset.username = username;
    cb.onchange = () => {
      if (cb.checked) newGroupSelectedUsers.add(username);
      else newGroupSelectedUsers.delete(username);
    };
    li.appendChild(cb);
    li.appendChild(document.createElement('span')).textContent = username;
    li.onclick = () => { cb.checked = !cb.checked; cb.dispatchEvent(new Event('change')); };
    listEl.appendChild(li);
  });
}

async function createGroup() {
  const nameInput = document.getElementById('newGroupName');
  const modal = document.getElementById('newGroupModal');
  const groupName = (nameInput && nameInput.value.trim()) || '';
  if (!groupName) {
    alert('Enter a group name');
    return;
  }
  if (!keys || !currentUsername || !ws || ws.readyState !== WebSocket.OPEN) {
    alert('Not connected. Try again.');
    return;
  }
  const members = [currentUsername, ...Array.from(newGroupSelectedUsers)];
  if (members.length < 2) {
    alert('Add at least one member');
    return;
  }
  const groupId = crypto.randomUUID();
  ws.send(JSON.stringify({ type: 'create_group', groupId, name: groupName, members }));

  const { key: mySenderKey, raw: mySenderKeyRaw } = await generateSenderKeyRaw();
  const mySenderKeyB64 = arrayBufferToBase64(mySenderKeyRaw);

  for (const member of members) {
    if (member === currentUsername) continue;
    try {
      const pubkeyB64 = await getRecipientPubkey(member);
      const pub = await importPubkeyFromBase64(pubkeyB64);
      const sharedKey = await deriveSharedKey(keys.privateKey, pub);
      const bundle = {
        groupId,
        name: groupName,
        members,
        creator: currentUsername,
        senderKeys: { [currentUsername]: mySenderKeyB64 },
      };
      const plaintext = JSON.stringify(bundle);
      const { ciphertext, iv } = await encrypt(plaintext, sharedKey);
      const payload = btoa(String.fromCharCode.apply(null, new Uint8Array(ciphertext)));
      const nonce = btoa(String.fromCharCode.apply(null, new Uint8Array(iv)));
      ws.send(JSON.stringify({ type: 'group_invite', to: member, groupId, payload, nonce }));
    } catch (e) {
      console.error('Failed to send invite to ' + member, e);
    }
  }

  await saveGroup({
    id: groupId,
    name: groupName,
    members,
    createdBy: currentUsername,
    createdAt: Date.now(),
    mySenderKeyB64,
    senderKeys: {},
  });

  if (modal) modal.classList.remove('visible');
  if (nameInput) nameInput.value = '';
  newGroupSelectedUsers = new Set();
  navigate('chat', 'group/' + groupId);
}

let addMemberSelectedUser = null;

async function showAddMemberModal() {
  const modal = document.getElementById('addMemberModal');
  const listEl = document.getElementById('addMemberUserList');
  const emptyEl = document.getElementById('addMemberUserListEmpty');
  if (!modal || !listEl || !isGroupPeer(currentRecipient)) return;
  const groupId = groupPeerId(currentRecipient);
  const group = await getGroup(groupId);
  if (!group) return;
  addMemberSelectedUser = null;
  modal.classList.add('visible');
  const allUsers = await fetchUsers();
  const membersSet = new Set(group.members);
  const candidates = allUsers.filter((u) => !membersSet.has(u));
  listEl.innerHTML = '';
  if (candidates.length === 0) {
    if (emptyEl) emptyEl.classList.remove('hidden');
    return;
  }
  if (emptyEl) emptyEl.classList.add('hidden');
  candidates.forEach((username) => {
    const li = document.createElement('li');
    li.style.display = 'flex';
    li.style.alignItems = 'center';
    li.style.gap = '0.5rem';
    li.textContent = username;
    li.onclick = () => {
      addMemberSelectedUser = username;
      listEl.querySelectorAll('li').forEach((el) => el.classList.remove('selected'));
      li.classList.add('selected');
    };
    listEl.appendChild(li);
  });
}

async function addMemberToGroup() {
  if (!addMemberSelectedUser || !isGroupPeer(currentRecipient)) {
    alert('Select a user to add');
    return;
  }
  const groupId = groupPeerId(currentRecipient);
  const group = await getGroup(groupId);
  if (!group || !ws || ws.readyState !== WebSocket.OPEN || !keys) return;
  const newMember = addMemberSelectedUser;
  const newMembers = [...group.members, newMember];
  ws.send(JSON.stringify({ type: 'update_group', groupId, members: newMembers }));

  const senderKeysBundle = { ...(group.senderKeys || {}) };
  if (group.mySenderKeyB64) {
    senderKeysBundle[currentUsername] = group.mySenderKeyB64;
  }

  try {
    const pubkeyB64 = await getRecipientPubkey(newMember);
    const pub = await importPubkeyFromBase64(pubkeyB64);
    const sharedKey = await deriveSharedKey(keys.privateKey, pub);
    const bundle = {
      groupId,
      name: group.name,
      members: newMembers,
      creator: group.createdBy,
      senderKeys: senderKeysBundle,
    };
    const plaintext = JSON.stringify(bundle);
    const { ciphertext, iv } = await encrypt(plaintext, sharedKey);
    const payload = btoa(String.fromCharCode.apply(null, new Uint8Array(ciphertext)));
    const nonce = btoa(String.fromCharCode.apply(null, new Uint8Array(iv)));
    ws.send(JSON.stringify({ type: 'group_invite', to: newMember, groupId, payload, nonce }));
  } catch (e) {
    console.error('Failed to send invite to ' + newMember, e);
  }

  group.members = newMembers;
  await saveGroup(group);

  const modal = document.getElementById('addMemberModal');
  if (modal) modal.classList.remove('visible');
  addMemberSelectedUser = null;
  renderChatList(getSelectedPeerFromRoute());
}

async function leaveGroup() {
  if (!isGroupPeer(currentRecipient)) return;
  if (!confirm('Leave this group? You will stop receiving messages.')) return;
  const groupId = groupPeerId(currentRecipient);
  const group = await getGroup(groupId);
  if (!group || !ws || ws.readyState !== WebSocket.OPEN) return;
  const newMembers = group.members.filter((m) => m !== currentUsername);
  ws.send(JSON.stringify({ type: 'update_group', groupId, members: newMembers }));
  await deleteGroup(groupId);
  navigate('chats');
}

function render() {
  const { view, param } = getRoute();
  document.querySelectorAll('.view').forEach((v) => v.classList.remove('active'));

  if (!isLoggedIn() && view !== 'setup') {
    if (view === 'chat' && param) {
      sessionStorage.setItem('war-chat-redirect', param);
    }
    showView('setup');
    return;
  }

  if (view === 'setup' && isLoggedIn()) {
    navigate('chats');
    return;
  }

  switch (view) {
    case 'setup':
      showView('setup');
      break;
    case 'chats':
      showView('main');
      currentRecipient = null;
      renderMainView(null);
      break;
    case 'chat':
      if (param) {
        const peer = param.startsWith('group/') ? peerFromGroupId(param.slice(6)) : param;
        showView('main', peer);
        openChat(peer);
        renderMainView(peer);
      } else {
        navigate('chats');
      }
      break;
    case 'profile':
      showView('profile');
      renderProfile();
      break;
    default:
      showView('main');
      renderMainView(null);
  }
}

function getSelectedPeerFromRoute() {
  const { view, param } = getRoute();
  if (view !== 'chat' || !param) return null;
  return param.startsWith('group/') ? peerFromGroupId(param.slice(6)) : param;
}

async function renderMainView(selectedPeer) {
  const layout = document.getElementById('layoutSplit');
  const chatPane = document.getElementById('chat-pane');
  const chatEmpty = document.getElementById('chat-empty');
  if (layout) layout.classList.toggle('has-chat', !!selectedPeer);
  if (chatPane) chatPane.style.display = selectedPeer ? 'flex' : 'none';
  if (chatEmpty) chatEmpty.style.display = selectedPeer ? 'none' : 'flex';
  const peer = selectedPeer ?? getSelectedPeerFromRoute();
  await renderChatList(peer);
}

function showView(name, param) {
  document.querySelectorAll('.view').forEach((v) => v.classList.remove('active'));
  const el = document.getElementById('view-' + name);
  if (el) el.classList.add('active');

  document.body.classList.toggle('profile-active', name === 'profile');

  const header = document.getElementById('header');
  const actions = document.getElementById('headerActions');

  if (name === 'setup') {
    header.classList.add('hidden');
  } else {
    header.classList.remove('hidden');
  }

  if (name === 'main') {
    connectWS();
    let headerTitle = 'War Chat';
    if (param) {
      if (param === currentUsername) headerTitle = 'Saved Messages';
      else if (isGroupPeer(param)) {
        headerTitle = 'Group';
        getGroup(groupPeerId(param)).then((g) => {
          const h = document.querySelector('.header h1');
          if (h && g) h.textContent = g.name;
        });
      } else headerTitle = param;
    }
    document.querySelector('.header h1').textContent = headerTitle;
    const isMobile = window.matchMedia('(max-width: 768px)').matches;
    const newChatBtn = (isMobile && !param) ? '<button class="btn-icon" id="btnNewChatHeader" title="New chat">&#10133;</button>' : '';
    actions.innerHTML = (param ? '<button class="btn-icon" id="btnBack" title="Back">&#8592;</button>' : '') +
      (param && isGroupPeer(param) ? '<button class="btn-icon" id="btnAddMember" title="Add member">&#10133;</button><button class="btn-icon" id="btnLeaveGroup" title="Leave group">&#128473;</button>' : '') +
      newChatBtn +
      '<button class="btn-icon" id="btnProfile" title="Profile">&#9776;</button>' +
      '<button class="btn-icon" id="btnLogout" title="Log out">&#128274;</button>';
    const btnBack = document.getElementById('btnBack');
    if (btnBack) btnBack.onclick = () => navigate('chats');
    const btnAddMember = document.getElementById('btnAddMember');
    if (btnAddMember) btnAddMember.onclick = () => showAddMemberModal();
    const btnLeaveGroup = document.getElementById('btnLeaveGroup');
    if (btnLeaveGroup) btnLeaveGroup.onclick = () => leaveGroup();
    const btnNewChatHeader = document.getElementById('btnNewChatHeader');
    if (btnNewChatHeader) btnNewChatHeader.onclick = () => showNewChatModal();
    document.getElementById('btnProfile').onclick = () => navigate('profile');
    document.getElementById('btnLogout').onclick = () => logout();
  } else if (name === 'profile') {
    document.querySelector('.header h1').textContent = 'Profile';
    actions.innerHTML = '<button class="btn-icon" id="btnBackProfile" title="Back">&#8592;</button>' +
      '<button class="btn-icon" id="btnLogout" title="Log out">&#128274;</button>';
    document.getElementById('btnBackProfile').onclick = () => {
      document.querySelector('.header h1').textContent = 'War Chat';
      navigate('chats');
    };
    document.getElementById('btnLogout').onclick = () => logout();
  } else {
    actions.innerHTML = '';
  }
}

// --- Crypto ---
async function mnemonicToSeed(mnemonic) {
  ensureCrypto();
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(mnemonic.trim().toLowerCase()),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const seed = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: enc.encode('war-chat-identity'),
      iterations: 100000,
      hash: 'SHA-256',
    },
    key,
    256
  );
  return new Uint8Array(seed);
}

async function deriveKeypair(mnemonic) {
  const seed = await mnemonicToSeed(mnemonic);
  const seedKey = btoa(String.fromCharCode.apply(null, seed));

  const stored = await new Promise((resolve) => {
    const tx = db.transaction(STORE_KEYPAIRS, 'readonly');
    const req = tx.objectStore(STORE_KEYPAIRS).get(seedKey);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => resolve(null);
  });

  if (stored && stored.privateJwk && stored.publicJwk) {
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      stored.privateJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits', 'deriveKey']
    );
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      stored.publicJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      []
    );
    return { privateKey, publicKey, seedKey };
  }

  const kp = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits', 'deriveKey']
  );
  const privateJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  const publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  const tx = db.transaction(STORE_KEYPAIRS, 'readwrite');
  tx.objectStore(STORE_KEYPAIRS).put({ seed: seedKey, privateJwk, publicJwk });
  await new Promise((resolve) => (tx.oncomplete = resolve));
  return { privateKey: kp.privateKey, publicKey: kp.publicKey, seedKey };
}

async function generateKeypairForPasskey() {
  const kp = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits', 'deriveKey']
  );
  const privateJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  const publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  return { privateKey: kp.privateKey, publicKey: kp.publicKey, privateJwk, publicJwk };
}

async function restoreSession() {
  const username = getStoredUsername();
  if (!username) return false;
  const session = await new Promise((resolve) => {
    try {
      const tx = db.transaction('sessions', 'readonly');
      const req = tx.objectStore('sessions').get(username);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
  if (!session || !session.seedKey) return false;
  if (session.authMethod === 'passkey') return false;
  const stored = await new Promise((resolve) => {
    const tx = db.transaction(STORE_KEYPAIRS, 'readonly');
    const req = tx.objectStore(STORE_KEYPAIRS).get(session.seedKey);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => resolve(null);
  });
  if (!stored || !stored.privateJwk || !stored.publicJwk) return false;
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    stored.privateJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits', 'deriveKey']
  );
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    stored.publicJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );
  keys = { privateKey, publicKey };
  currentUsername = username;
  setStoredUsername(username);
  if (session.mnemonic) {
    sessionStorage.setItem(SESSION_MNEMONIC, session.mnemonic);
  }
  return true;
}

function restorePasskeySessionFromStorage() {
  try {
    const raw = sessionStorage.getItem(PASSKEY_SESSION);
    if (!raw) return false;
    const { username, privateJwk, publicJwk } = JSON.parse(raw);
    if (!username || !privateJwk || !publicJwk) return false;
    return { username, privateJwk, publicJwk };
  } catch {
    return false;
  }
}

async function restorePasskeySession() {
  const data = restorePasskeySessionFromStorage();
  if (!data) return false;
  try {
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      data.privateJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits', 'deriveKey']
    );
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      data.publicJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      []
    );
    keys = { privateKey, publicKey };
    currentUsername = data.username;
    setStoredUsername(data.username);
    return true;
  } catch {
    sessionStorage.removeItem(PASSKEY_SESSION);
    return false;
  }
}

function savePasskeySessionToStorage(username, privateJwk, publicJwk) {
  sessionStorage.setItem(PASSKEY_SESSION, JSON.stringify({ username, privateJwk, publicJwk }));
}

function resetSetupView() {
  document.getElementById('setup-mnemonic').classList.remove('hidden');
  document.getElementById('setup-passkey-div').classList.remove('hidden');
  document.getElementById('setup-register').classList.add('hidden');
  document.getElementById('setup-register-passkey-hint').classList.add('hidden');
  document.getElementById('btnRegister').classList.remove('hidden');
  document.getElementById('btnCreatePasskey').classList.add('hidden');
  document.getElementById('username').value = '';
  document.getElementById('mnemonic').value = '';
}

function logout() {
  keys = null;
  currentUsername = null;
  currentRecipient = null;
  setStoredUsername(null);
  sessionStorage.removeItem(SESSION_MNEMONIC);
  sessionStorage.removeItem(PASSKEY_SESSION);
  sessionStorage.removeItem('war-chat-redirect');
  pubkeyCache = {};
  clearMessageEncryptionKeyCache();
  if (ws) {
    ws.close();
    ws = null;
  }
  resetSetupView();
  navigate('setup');
  render();
}

async function saveSession(username, seedKey, mnemonic, authMethod, credentialId) {
  try {
    const tx = db.transaction('sessions', 'readwrite');
    const session = { username, seedKey: seedKey || 'passkey', authMethod: authMethod || 'mnemonic' };
    if (mnemonic) session.mnemonic = mnemonic;
    if (credentialId) session.credentialId = credentialId;
    tx.objectStore('sessions').put(session);
    await new Promise((resolve) => (tx.oncomplete = resolve));
  } catch (e) {
    console.error('Save session failed', e);
  }
}

// --- Passkey / WebAuthn PRF ---
const PRF_SALT = new TextEncoder().encode('war-chat-prf-salt');

function getRpId() {
  return window.location.hostname || 'localhost';
}

async function isPasskeySupported() {
  if (!window.PublicKeyCredential) return false;
  if (!window.isSecureContext) return false;
  try {
    if (typeof PublicKeyCredential.getClientCapabilities === 'function') {
      const caps = await PublicKeyCredential.getClientCapabilities('public-key');
      if (caps.extensions && Array.isArray(caps.extensions) && caps.extensions.includes('prf')) return true;
      if (caps.extensions && typeof caps.extensions === 'object' && caps.extensions.prf) return true;
    }
    return true;
  } catch {
    return true;
  }
}

async function deriveKeyFromPrf(prfResult) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', prfResult, 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode('war-chat-passkey-kdf'), iterations: 100000, hash: 'SHA-256' },
    key,
    256
  );
  return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function createPasskey(username) {
  const rpId = getRpId();
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const displayName = (username && username.trim()) || 'War Chat user';
  const publicKeyBase = {
    rp: { name: 'War Chat', id: rpId },
    user: { id: userId, name: displayName, displayName },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
  };
  const optionsWithPrf = {
    publicKey: {
      ...publicKeyBase,
      extensions: {
        prf: {
          eval: {
            first: PRF_SALT,
          },
        },
      },
    },
  };
  const optionsWithoutPrf = { publicKey: publicKeyBase };
  let credential;
  try {
    credential = await navigator.credentials.create(optionsWithPrf);
  } catch {
    credential = await navigator.credentials.create(optionsWithoutPrf);
  }
  if (!credential || !(credential instanceof PublicKeyCredential)) throw new Error('Passkey creation failed');
  const credentialId = btoa(String.fromCharCode.apply(null, new Uint8Array(credential.rawId)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const ext = credential.getClientExtensionResults();
  const prfResultRaw = ext.prf?.results?.first;
  if (prfResultRaw) {
    return { credentialId, prfResult: new Uint8Array(prfResultRaw), credential };
  }
  const fallbackKey = crypto.getRandomValues(new Uint8Array(32));
  const storedKeyB64 = btoa(String.fromCharCode.apply(null, fallbackKey));
  return { credentialId, prfResult: fallbackKey, storedKeyB64, credential };
}

async function authenticatePasskey() {
  const rpId = getRpId();
  const publicKeyBase = {
    rpId,
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    allowCredentials: [],
    userVerification: 'required',
  };
  const optionsWithPrf = {
    publicKey: {
      ...publicKeyBase,
      extensions: {
        prf: {
          eval: {
            first: PRF_SALT,
          },
        },
      },
    },
  };
  const optionsWithoutPrf = { publicKey: publicKeyBase };
  let assertion;
  try {
    assertion = await navigator.credentials.get(optionsWithPrf);
  } catch {
    assertion = await navigator.credentials.get(optionsWithoutPrf);
  }
  if (!assertion || !(assertion instanceof PublicKeyCredential)) return null;
  const credentialId = btoa(String.fromCharCode.apply(null, new Uint8Array(assertion.rawId)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const ext = assertion.getClientExtensionResults();
  const prfResultRaw = ext.prf?.results?.first;
  if (prfResultRaw) {
    return { credentialId, prfResult: new Uint8Array(prfResultRaw) };
  }
  return { credentialId, useStoredKey: true };
}

async function encryptKeypairWithPasskey(keypair, prfResult) {
  const key = await deriveKeyFromPrf(prfResult);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const plaintext = enc.encode(JSON.stringify({ privateJwk: keypair.privateJwk, publicJwk: keypair.publicJwk }));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return {
    encrypted: btoa(String.fromCharCode.apply(null, new Uint8Array(ct))),
    iv: btoa(String.fromCharCode.apply(null, iv)),
  };
}

async function decryptKeypairWithPasskey(encryptedB64, ivB64, prfResult) {
  const key = await deriveKeyFromPrf(prfResult);
  const ct = new Uint8Array([...atob(encryptedB64)].map((c) => c.charCodeAt(0)));
  const iv = new Uint8Array([...atob(ivB64)].map((c) => c.charCodeAt(0)));
  const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(dec));
}

async function storePasskeyCredential(credentialId, username, encrypted, iv, storedKeyB64) {
  const record = { credentialId, username: username || null, encryptedKeypair: encrypted, iv };
  if (storedKeyB64 != null) record.storedKeyB64 = storedKeyB64;
  const tx = db.transaction(STORE_PASSKEY_CREDS, 'readwrite');
  tx.objectStore(STORE_PASSKEY_CREDS).put(record);
  await new Promise((resolve) => (tx.oncomplete = resolve));
}

async function getPasskeyCredentialByCredentialId(credentialId) {
  return new Promise((resolve) => {
    const tx = db.transaction(STORE_PASSKEY_CREDS, 'readonly');
    const req = tx.objectStore(STORE_PASSKEY_CREDS).get(credentialId);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => resolve(null);
  });
}

async function updatePasskeyCredentialUsername(credentialId, username) {
  const rec = await getPasskeyCredentialByCredentialId(credentialId);
  if (!rec) return;
  rec.username = username;
  const tx = db.transaction(STORE_PASSKEY_CREDS, 'readwrite');
  tx.objectStore(STORE_PASSKEY_CREDS).put(rec);
  await new Promise((resolve) => (tx.oncomplete = resolve));
}

async function hasPasskeyCredentials() {
  return new Promise((resolve) => {
    const tx = db.transaction(STORE_PASSKEY_CREDS, 'readonly');
    const req = tx.objectStore(STORE_PASSKEY_CREDS).count();
    req.onsuccess = () => resolve(req.result > 0);
    req.onerror = () => resolve(false);
  });
}

async function restoreSessionWithPasskeyFromResult(result) {
  if (!result) return false;
  const { credentialId, prfResult, useStoredKey } = result;
  const rec = await getPasskeyCredentialByCredentialId(credentialId);
  if (!rec || !rec.username) return false;
  let keypair;
  if (prfResult) {
    keypair = await decryptKeypairWithPasskey(rec.encryptedKeypair, rec.iv, prfResult);
  } else if (useStoredKey && rec.storedKeyB64) {
    const storedKey = new Uint8Array([...atob(rec.storedKeyB64)].map((c) => c.charCodeAt(0)));
    keypair = await decryptKeypairWithPasskey(rec.encryptedKeypair, rec.iv, storedKey);
  } else {
    return false;
  }
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    keypair.privateJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits', 'deriveKey']
  );
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    keypair.publicJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );
  keys = { privateKey, publicKey };
  currentUsername = rec.username;
  setStoredUsername(rec.username);
  savePasskeySessionToStorage(rec.username, keypair.privateJwk, keypair.publicJwk);
  await saveSession(rec.username, 'passkey', null, 'passkey', credentialId);
  return true;
}

async function restoreSessionWithPasskey() {
  const result = await authenticatePasskey();
  return result ? restoreSessionWithPasskeyFromResult(result) : false;
}

/** If server no longer has this user (e.g. key was removed), re-register with same username and pubkey. Uses existing /keys/ and /register. */
async function ensureRegisteredWithServer() {
  if (!currentUsername || !keys?.publicKey) return;
  const keysResp = await fetch(`${API_BASE}/keys/${encodeURIComponent(currentUsername)}`);
  if (keysResp.ok) return; // already registered
  if (keysResp.status !== 404) return;
  const pubkey = await exportPubkeyToBase64(keys.publicKey);
  const regResp = await fetch(`${API_BASE}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: currentUsername, pubkey }),
  });
  if (regResp.status === 409) {
    throw new Error('Username was taken by another user. Sign in with a different account.');
  }
  if (!regResp.ok) {
    const msg = await regResp.text();
    throw new Error(msg || 'Registration failed');
  }
}

async function deriveSharedKey(privateKey, publicKey) {
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: publicKey },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function deriveMessageEncryptionKey(privateKey, publicKey) {
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: publicKey },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

let msgEncKeyCache = null;

async function getMessageEncryptionKey() {
  if (!keys?.privateKey || !keys?.publicKey) return null;
  if (msgEncKeyCache) return msgEncKeyCache;
  msgEncKeyCache = await deriveMessageEncryptionKey(keys.privateKey, keys.publicKey);
  return msgEncKeyCache;
}

function clearMessageEncryptionKeyCache() {
  msgEncKeyCache = null;
}

async function encryptMessageForStorage(msg) {
  const key = await getMessageEncryptionKey();
  if (!key) return null;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const plaintext = enc.encode(JSON.stringify({ from: msg.from, text: msg.text, ts: msg.ts, peer: msg.peer }));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return {
    encryptedPayload: btoa(String.fromCharCode.apply(null, new Uint8Array(ct))),
    iv: btoa(String.fromCharCode.apply(null, iv)),
  };
}

async function migratePlainMessagesToEncrypted() {
  if (!keys?.privateKey || !currentUsername) return;
  const raw = await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_MSGS, 'readonly');
    const req = tx.objectStore(STORE_MSGS).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
  const toMigrate = raw.filter((m) => m.owner === currentUsername && m.text && !m.encryptedPayload);
  if (toMigrate.length === 0) return;
  const encrypted = [];
  for (const m of toMigrate) {
    const enc = await encryptMessageForStorage(m);
    if (enc) encrypted.push({ id: m.id, owner: m.owner, encryptedPayload: enc.encryptedPayload, iv: enc.iv });
  }
  if (encrypted.length > 0) {
    const tx = db.transaction(STORE_MSGS, 'readwrite');
    for (const rec of encrypted) tx.objectStore(STORE_MSGS).put(rec);
    await new Promise((resolve) => (tx.oncomplete = resolve));
  }
}

async function decryptMessageFromStorage(record) {
  if (record.encryptedPayload && record.iv) {
    const key = await getMessageEncryptionKey();
    if (!key) return null;
    try {
      const ct = new Uint8Array([...atob(record.encryptedPayload)].map((c) => c.charCodeAt(0)));
      const iv = new Uint8Array([...atob(record.iv)].map((c) => c.charCodeAt(0)));
      const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
      const payload = JSON.parse(new TextDecoder().decode(dec));
      return { id: record.id, owner: record.owner, ...payload };
    } catch {
      return null;
    }
  }
  return record;
}

async function encrypt(plaintext, sharedKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    sharedKey,
    enc.encode(plaintext)
  );
  return { ciphertext: ct, iv: iv };
}

async function decrypt(ciphertextB64, ivB64, sharedKey) {
  const ciphertext = new Uint8Array([...atob(ciphertextB64)].map((c) => c.charCodeAt(0)));
  const iv = new Uint8Array([...atob(ivB64)].map((c) => c.charCodeAt(0)));
  const dec = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    sharedKey,
    ciphertext
  );
  return new TextDecoder().decode(dec);
}

async function getRecipientPubkey(username) {
  if (pubkeyCache[username]) return pubkeyCache[username];
  const resp = await fetch(`${API_BASE}/keys/${encodeURIComponent(username)}`);
  if (!resp.ok) throw new Error('User not found');
  const json = await resp.json();
  pubkeyCache[username] = json.pubkey;
  return json.pubkey;
}

async function importPubkeyFromBase64(b64) {
  try {
    const json = JSON.parse(atob(b64));
    return crypto.subtle.importKey('jwk', json, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  } catch {
    return null;
  }
}

async function exportPubkeyToBase64(pubKey) {
  const jwk = await crypto.subtle.exportKey('jwk', pubKey);
  return btoa(JSON.stringify(jwk));
}

function showQR(text) {
  const container = document.getElementById('qrcode');
  if (!container) return;
  container.innerHTML = '';
  if (typeof QRCode !== 'undefined') {
    new QRCode(container, { text, width: 128, height: 128 });
  }
}

function generateMnemonic() {
  const words = (typeof WORDLISTS !== 'undefined' && WORDLISTS['english']) ? WORDLISTS['english'] : [];
  if (words.length === 0) throw new Error('Wordlist not loaded');
  return Array.from({ length: 12 }, () => words[Math.floor(Math.random() * words.length)]).join(' ');
}

function escapeHtml(s) {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

function formatMessage(text) {
  if (!text || typeof text !== 'string') return '';
  const escaped = escapeHtml(text);
  const parts = escaped.split('```');
  let result = '';
  for (let i = 0; i < parts.length; i++) {
    if (i % 2 === 1) {
      result += '<pre class="msg-code"><code>' + parts[i] + '</code></pre>';
    } else {
      result += parts[i].replace(/\n/g, '<br>');
    }
  }
  return result;
}

function formatTime(ts) {
  const d = new Date(ts);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) {
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

// --- View renderers ---
async function renderChatList(selectedPeer) {
  const list = document.getElementById('chat-list');
  const empty = document.getElementById('chat-list-empty');
  if (!list) return;
  const convos = await getConversations();

  list.innerHTML = '';
  if (convos.length === 0) {
    empty.classList.remove('hidden');
  } else {
    empty.classList.add('hidden');
    for (const c of convos) {
      const li = document.createElement('li');
      const isSelf = c.peer === currentUsername;
      const isGroup = isGroupPeer(c.peer);
      const displayName = isSelf ? 'Saved Messages' : (c.groupName || (isGroup ? 'Group' : c.peer));
      const navParam = isGroup ? 'group/' + groupPeerId(c.peer) : c.peer;
      li.className = 'chat-row' + (c.peer === selectedPeer ? ' selected' : '');
      li.innerHTML = `
        <div class="chat-avatar">${isSelf ? '&#128190;' : (isGroup ? '&#128101;' : (c.peer[0] || '?').toUpperCase())}</div>
        <div class="chat-info">
          <div class="chat-name">${escapeHtml(displayName)}</div>
          <div class="chat-preview">${escapeHtml(c.lastMsg || 'No messages')}</div>
        </div>
        <div class="chat-time">${formatTime(c.lastTs)}</div>
      `;
      li.onclick = () => navigate('chat', navParam);
      list.appendChild(li);
    }
  }
}

async function getSessionAuthMethod() {
  const session = await new Promise((resolve) => {
    try {
      const tx = db.transaction('sessions', 'readonly');
      const req = tx.objectStore('sessions').get(currentUsername);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    } catch { resolve(null); }
  });
  return session?.authMethod || 'mnemonic';
}

function renderProfile() {
  document.getElementById('profileUsername').textContent = currentUsername || '';
  const link = `${API_BASE}/u/${currentUsername}`;
  document.getElementById('chatLink').textContent = link;
  showQR(link);
  document.getElementById('btnCopyLink').onclick = () => {
    navigator.clipboard.writeText(link);
    alert('Link copied!');
  };
  getSessionAuthMethod().then(async (authMethod) => {
    const session = await new Promise((resolve) => {
      try {
        const tx = db.transaction('sessions', 'readonly');
        const req = tx.objectStore('sessions').get(currentUsername);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => resolve(null);
      } catch { resolve(null); }
    });
    const hasRecoveryPhrase = !!(session?.mnemonic || sessionStorage.getItem(SESSION_MNEMONIC));
    const recoverySection = document.getElementById('profile-recovery-section');
    const passkeySection = document.getElementById('profile-passkey-section');
    const addPasskeySection = document.getElementById('profile-add-passkey-section');
    const exportBackupBtn = document.getElementById('btnExportBackup');
    if (authMethod === 'passkey') {
      if (hasRecoveryPhrase) {
        if (recoverySection) recoverySection.classList.remove('hidden');
        if (passkeySection) passkeySection.classList.add('hidden');
        if (exportBackupBtn) exportBackupBtn.disabled = false;
        if (exportBackupBtn) exportBackupBtn.title = '';
      } else {
        if (recoverySection) recoverySection.classList.add('hidden');
        if (passkeySection) passkeySection.classList.remove('hidden');
        if (exportBackupBtn) exportBackupBtn.disabled = true;
        if (exportBackupBtn) exportBackupBtn.title = 'Add a recovery phrase first to export backup.';
      }
      if (addPasskeySection) addPasskeySection.classList.add('hidden');
    } else {
      if (recoverySection) recoverySection.classList.remove('hidden');
      if (passkeySection) passkeySection.classList.add('hidden');
      const pkSupported = await isPasskeySupported();
      if (addPasskeySection && pkSupported) addPasskeySection.classList.remove('hidden');
      else if (addPasskeySection) addPasskeySection.classList.add('hidden');
      if (exportBackupBtn) exportBackupBtn.disabled = false;
      if (exportBackupBtn) exportBackupBtn.title = '';
    }
  });
  document.getElementById('btnShowMnemonic').onclick = async () => {
    let mnemonic = sessionStorage.getItem(SESSION_MNEMONIC);
    if (!mnemonic) {
      const session = await new Promise((resolve) => {
        try {
          const tx = db.transaction('sessions', 'readonly');
          const req = tx.objectStore('sessions').get(currentUsername);
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => resolve(null);
        } catch { resolve(null); }
      });
      mnemonic = session && session.mnemonic ? session.mnemonic : null;
    }
    const el = document.getElementById('mnemonicDisplay');
    if (mnemonic) {
      el.textContent = mnemonic;
      el.classList.remove('hidden');
    } else {
      alert('Recovery phrase not stored. Log in with your phrase to store it.');
    }
  };
  const btnAddRecoveryPhrase = document.getElementById('btnAddRecoveryPhrase');
  if (btnAddRecoveryPhrase) btnAddRecoveryPhrase.onclick = addRecoveryPhraseForPasskeyUser;
  const btnAddPasskey = document.getElementById('btnAddPasskey');
  if (btnAddPasskey) btnAddPasskey.onclick = addPasskeyForMnemonicUser;
  document.getElementById('btnExportBackup').onclick = exportBackup;
  document.getElementById('btnRestoreBackup').onclick = restoreBackup;
}

async function addRecoveryPhraseForPasskeyUser() {
  const mnemonic = prompt('Enter a 12-word recovery phrase (or generate one on the setup screen and paste it):');
  if (!mnemonic || !mnemonic.trim()) return;
  try {
    const backup = {
      username: currentUsername,
      privateJwk: await crypto.subtle.exportKey('jwk', keys.privateKey),
      publicJwk: await crypto.subtle.exportKey('jwk', keys.publicKey),
    };
    const key = await deriveBackupKey(mnemonic);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(JSON.stringify(backup))
    );
    const blob = JSON.stringify({ iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) });
    navigator.clipboard.writeText(btoa(blob));
    sessionStorage.setItem(SESSION_MNEMONIC, mnemonic);
    const session = await new Promise((resolve) => {
      try {
        const tx = db.transaction('sessions', 'readonly');
        const req = tx.objectStore('sessions').get(currentUsername);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => resolve(null);
      } catch { resolve(null); }
    });
    if (session) {
      session.mnemonic = mnemonic;
      const tx = db.transaction('sessions', 'readwrite');
      tx.objectStore('sessions').put(session);
      await new Promise((r) => (tx.oncomplete = r));
    }
    alert('Backup copied to clipboard. Save your phrase and backup in a safe place. You can now export backup.');
    renderProfile();
  } catch (e) {
    alert('Failed: ' + (e.message || e));
  }
}

async function addPasskeyForMnemonicUser() {
  try {
    const { credentialId, prfResult, storedKeyB64 } = await createPasskey(currentUsername);
    const privateJwk = await crypto.subtle.exportKey('jwk', keys.privateKey);
    const publicJwk = await crypto.subtle.exportKey('jwk', keys.publicKey);
    const { encrypted, iv } = await encryptKeypairWithPasskey({ privateJwk, publicJwk }, prfResult);
    await storePasskeyCredential(credentialId, currentUsername, encrypted, iv, storedKeyB64);
    alert('Passkey added. You can now sign in with passkey on this device.');
    renderProfile();
  } catch (e) {
    alert('Failed to add passkey: ' + (e.message || e));
  }
}

async function deriveBackupKey(mnemonic) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(mnemonic.trim().toLowerCase()),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode('war-chat-backup'), iterations: 100000, hash: 'SHA-256' },
    key,
    256
  );
  return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function exportBackup() {
  let mnemonic = sessionStorage.getItem(SESSION_MNEMONIC);
  if (!mnemonic) {
    const session = await new Promise((resolve) => {
      try {
        const tx = db.transaction('sessions', 'readonly');
        const req = tx.objectStore('sessions').get(currentUsername);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => resolve(null);
      } catch { resolve(null); }
    });
    mnemonic = session && session.mnemonic ? session.mnemonic : null;
  }
  if (!mnemonic) {
    alert('Recovery phrase not stored. Use "Show recovery phrase" after logging in with your phrase.');
    return;
  }
  try {
    let privateJwk, publicJwk;
    if (keys) {
      privateJwk = await crypto.subtle.exportKey('jwk', keys.privateKey);
      publicJwk = await crypto.subtle.exportKey('jwk', keys.publicKey);
    } else {
      const kp = await deriveKeypair(mnemonic);
      privateJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
      publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    }
    const backup = { username: currentUsername, privateJwk, publicJwk };
    const key = await deriveBackupKey(mnemonic);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(JSON.stringify(backup))
    );
    const blob = JSON.stringify({ iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) });
    navigator.clipboard.writeText(btoa(blob));
    alert('Backup copied to clipboard. Save it somewhere safe.');
  } catch (e) {
    alert('Export failed: ' + e.message);
  }
}

async function restoreBackup() {
  const mnemonic = prompt('Enter your 12-word phrase:');
  if (!mnemonic) return;
  const backupB64 = document.getElementById('restoreBackup').value.trim();
  if (!backupB64) return alert('Paste your backup first');
  try {
    const { iv, ct } = JSON.parse(atob(backupB64));
    const key = await deriveBackupKey(mnemonic);
    const dec = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(iv) },
      key,
      new Uint8Array(ct)
    );
    const backup = JSON.parse(new TextDecoder().decode(dec));
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      backup.privateJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits', 'deriveKey']
    );
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      backup.publicJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      []
    );
    keys = { privateKey, publicKey };
    currentUsername = backup.username;
    setStoredUsername(backup.username);
    const seed = await mnemonicToSeed(mnemonic);
    const seedKey = btoa(String.fromCharCode.apply(null, seed));
    const tx = db.transaction(STORE_KEYPAIRS, 'readwrite');
    tx.objectStore(STORE_KEYPAIRS).put({
      seed: seedKey,
      privateJwk: backup.privateJwk,
      publicJwk: backup.publicJwk,
    });
    await new Promise((r) => (tx.oncomplete = r));
    const regResp = await fetch(`${API_BASE}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: backup.username, pubkey: btoa(JSON.stringify(backup.publicJwk)) }),
    });
    if (!regResp.ok) {
      const msg = await regResp.text();
      throw new Error(msg || 'Registration failed');
    }
    document.getElementById('restoreBackup').value = '';
    alert('Restored!');
    const redirect = sessionStorage.getItem('war-chat-redirect');
    if (redirect) {
      sessionStorage.removeItem('war-chat-redirect');
      navigate('chat', redirect);
    } else {
      navigate('chats');
    }
  } catch (e) {
    alert('Restore failed: ' + e.message);
  }
}

function getMessagesContainer() {
  return document.getElementById('messages');
}

function getMessagesInner() {
  const container = getMessagesContainer();
  if (!container) return null;
  let inner = container.querySelector('.messages-inner');
  if (!inner) {
    inner = document.createElement('div');
    inner.className = 'messages-inner';
    container.appendChild(inner);
  }
  return inner;
}

async function openChat(recipient) {
  currentRecipient = recipient;
  const msgs = await getMessages(recipient);
  const container = getMessagesContainer();
  const inner = getMessagesInner();
  if (container && inner) {
    inner.innerHTML = '';
    const isSelf = recipient === currentUsername;
    msgs.forEach((m) => {
      const div = document.createElement('div');
      if (isSelf) {
        div.className = 'msg note';
        div.innerHTML = formatMessage(m.text);
      } else {
        div.className = 'msg ' + (m.from === currentUsername ? 'sent' : 'received');
        div.innerHTML = `<span class="meta">${escapeHtml(m.from)}</span><br>${formatMessage(m.text)}`;
      }
      inner.appendChild(div);
    });
    container.scrollTop = container.scrollHeight;
  }
}

function renderMessage(m, isNoteToSelf) {
  const container = getMessagesContainer();
  const inner = getMessagesInner();
  if (!container || !inner) return;
  const div = document.createElement('div');
  const isSelf = m.peer === currentUsername;
  if (isSelf || isNoteToSelf) {
    div.className = 'msg note';
  } else {
    div.className = 'msg ' + (m.from === currentUsername ? 'sent' : 'received');
  }
  div.innerHTML = (isSelf || isNoteToSelf) ? formatMessage(m.text) : `<span class="meta">${escapeHtml(m.from)}</span><br>${formatMessage(m.text)}`;
  inner.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

// --- WebSocket ---
function connectWS() {
  if (ws && ws.readyState === WebSocket.OPEN) {
    registerWS();
    return;
  }
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${proto}//${window.location.host}/ws`);

  ws.onopen = () => registerWS();

  ws.onmessage = async (e) => {
    const msg = JSON.parse(e.data);
    if (msg.type === 'offline_messages') {
      for (const m of msg.messages || []) {
        await handleIncoming(m);
      }
      renderChatList(getSelectedPeerFromRoute());
    } else if (msg.type === 'incoming') {
      await handleIncoming(msg);
      renderChatList(getSelectedPeerFromRoute());
    } else if (msg.type === 'group_invite') {
      await handleGroupInvite(msg);
      renderChatList(getSelectedPeerFromRoute());
    } else if (msg.type === 'incoming_group') {
      await handleIncomingGroup(msg);
      renderChatList(getSelectedPeerFromRoute());
    }
  };

  ws.onclose = () => {
    setTimeout(connectWS, 3000);
  };
}

async function registerWS() {
  if (!ws || ws.readyState !== WebSocket.OPEN || !currentUsername) return;
  const pubkey = keys ? await exportPubkeyToBase64(keys.publicKey) : '';
  ws.send(JSON.stringify({ type: 'register', username: currentUsername, pubkey }));
}

function playNotificationSound() {
  try {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    if (!Ctx) return;
    const ctx = new Ctx();
    const osc = ctx.createOscillator();
    osc.frequency.value = 800;
    osc.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.1);
  } catch (_) {}
}

function maybeNotify(from, text) {
  if (document.hidden && 'Notification' in window) {
    if (Notification.permission === 'granted') {
      new Notification('War Chat', { body: 'Message from ' + from });
    } else if (Notification.permission === 'default') {
      Notification.requestPermission().then((p) => {
        if (p === 'granted') new Notification('War Chat', { body: 'Message from ' + from });
      });
    }
  }
  playNotificationSound();
}

async function handleIncoming(msg) {
  if (msg.type === 'group_invite') {
    await handleGroupInvite(msg);
    return;
  }
  if (msg.type === 'incoming_group') {
    await handleIncomingGroup(msg);
    return;
  }
  if (msg.from === currentUsername) return; // Saved Messages: ignore self-messages from server
  let text = '[encrypted]';
  try {
    const senderPubkeyB64 = await getRecipientPubkey(msg.from);
    const senderPub = await importPubkeyFromBase64(senderPubkeyB64);
    if (senderPub && keys) {
      const sharedKey = await deriveSharedKey(keys.privateKey, senderPub);
      text = await decrypt(msg.payload, msg.nonce, sharedKey);
    }
  } catch (e) {
    console.error(e);
  }
  const m = {
    id: msg.id || 'msg-' + Date.now(),
    from: msg.from,
    text,
    ts: msg.ts || Date.now(),
    peer: msg.from,
  };
  await saveMessage(m);
  if (msg.from === currentRecipient) {
    renderMessage(m, m.peer === currentUsername);
  }
  if (msg.from !== currentRecipient || document.hidden) {
    maybeNotify(msg.from, text);
  }
  if (msg.id && ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'delivered', ids: [msg.id] }));
  }
}

async function handleGroupInvite(msg) {
  if (!keys || !msg.from || !msg.payload || !msg.nonce) return;
  try {
    const senderPubkeyB64 = await getRecipientPubkey(msg.from);
    const senderPub = await importPubkeyFromBase64(senderPubkeyB64);
    if (!senderPub) return;
    const sharedKey = await deriveSharedKey(keys.privateKey, senderPub);
    const plaintext = await decrypt(msg.payload, msg.nonce, sharedKey);
    const bundle = JSON.parse(plaintext);
    const groupId = bundle.groupId;
    if (!groupId) return;
    const existing = await getGroup(groupId);
    if (bundle.members && bundle.name) {
      await saveGroup({
        id: groupId,
        name: bundle.name,
        members: bundle.members,
        createdBy: bundle.creator || msg.from,
        createdAt: Date.now(),
        mySenderKeyB64: null,
        senderKeys: bundle.senderKeys || {},
      });
    } else if (existing && bundle.senderKeys) {
      existing.senderKeys = existing.senderKeys || {};
      Object.assign(existing.senderKeys, bundle.senderKeys);
      await saveGroup(existing);
    }
  } catch (e) {
    console.error('Group invite decrypt failed', e);
  }
}

async function handleIncomingGroup(msg) {
  const groupId = msg.groupId;
  if (!groupId || !msg.from || !msg.payload || !msg.nonce) return;
  const group = await getGroup(groupId);
  if (!group || !group.senderKeys || !group.senderKeys[msg.from]) return;
  let text = '[encrypted]';
  try {
    const senderKey = await importSenderKeyFromBase64(group.senderKeys[msg.from]);
    text = await decrypt(msg.payload, msg.nonce, senderKey);
  } catch (e) {
    console.error('Group message decrypt failed', e);
  }
  const peer = peerFromGroupId(groupId);
  const m = {
    id: msg.id || 'msg-' + Date.now(),
    from: msg.from,
    text,
    ts: msg.ts || Date.now(),
    peer,
  };
  await saveMessage(m);
  if (peer === currentRecipient) {
    renderMessage(m, false);
  }
  if (peer !== currentRecipient || document.hidden) {
    maybeNotify(msg.from + ' (group)', text);
  }
  if (msg.id && ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'delivered', ids: [msg.id] }));
  }
}

async function sendMessage() {
  const input = document.getElementById('messageInput');
  const text = (input && input.value.trim()) || '';
  if (!text || !currentRecipient || !keys) return;

  const isSelf = currentRecipient === currentUsername;
  const isGroup = isGroupPeer(currentRecipient);

  const m = {
    id: 'local-' + Date.now(),
    from: currentUsername,
    text,
    ts: Date.now(),
    peer: currentRecipient,
  };

  if (isSelf) {
    await saveMessage(m);
    renderMessage(m, true);
    input.value = '';
    renderChatList(getSelectedPeerFromRoute());
    return;
  }

  if (!ws || ws.readyState !== WebSocket.OPEN) return;

  if (isGroup) {
    const groupId = groupPeerId(currentRecipient);
    let group = await getGroup(groupId);
    if (!group) {
      alert('Group not found');
      return;
    }
    let senderKey = null;
    if (group.mySenderKeyB64) {
      senderKey = await importSenderKeyFromBase64(group.mySenderKeyB64);
    } else {
      const { key, raw } = await generateSenderKeyRaw();
      senderKey = key;
      group.mySenderKeyB64 = arrayBufferToBase64(raw);
      group.senderKeys = group.senderKeys || {};
      group.senderKeys[currentUsername] = group.mySenderKeyB64;
      await saveGroup(group);
      for (const member of group.members) {
        if (member === currentUsername) continue;
        try {
          const pubkeyB64 = await getRecipientPubkey(member);
          const pub = await importPubkeyFromBase64(pubkeyB64);
          const sharedKey = await deriveSharedKey(keys.privateKey, pub);
          const bundle = { groupId, senderKeys: { [currentUsername]: group.mySenderKeyB64 } };
          const plaintext = JSON.stringify(bundle);
          const { ciphertext, iv } = await encrypt(plaintext, sharedKey);
          const payload = btoa(String.fromCharCode.apply(null, new Uint8Array(ciphertext)));
          const nonce = btoa(String.fromCharCode.apply(null, new Uint8Array(iv)));
          ws.send(JSON.stringify({ type: 'group_invite', to: member, groupId, payload, nonce }));
        } catch (e) {
          console.error('Failed to send sender key to ' + member, e);
        }
      }
    }
    const { ciphertext, iv } = await encrypt(text, senderKey);
    const payload = btoa(String.fromCharCode.apply(null, new Uint8Array(ciphertext)));
    const nonce = btoa(String.fromCharCode.apply(null, new Uint8Array(iv)));
    ws.send(JSON.stringify({ type: 'group_send', groupId, payload, nonce }));
    await saveMessage(m);
    renderMessage(m, false);
    input.value = '';
    renderChatList(getSelectedPeerFromRoute());
    return;
  }

  try {
    const recipientPubkeyB64 = await getRecipientPubkey(currentRecipient);
    const recipientPub = await importPubkeyFromBase64(recipientPubkeyB64);
    if (!recipientPub) throw new Error('Could not load recipient key');
    const sharedKey = await deriveSharedKey(keys.privateKey, recipientPub);
    const { ciphertext, iv } = await encrypt(text, sharedKey);
    const payload = btoa(String.fromCharCode.apply(null, new Uint8Array(ciphertext)));
    const nonce = btoa(String.fromCharCode.apply(null, new Uint8Array(iv)));

    ws.send(JSON.stringify({ type: 'send', to: currentRecipient, payload, nonce }));

    await saveMessage(m);
    renderMessage(m, false);
    input.value = '';
    renderChatList(getSelectedPeerFromRoute());
  } catch (e) {
    alert('Send failed: ' + e.message);
  }
}

// --- Init ---
async function init() {
  ensureCrypto();
  db = await openDB();

  const params = new URLSearchParams(window.location.search);
  const to = params.get('to') || params.get('u');
  if (to) {
    sessionStorage.setItem('war-chat-redirect', to);
    params.delete('to');
    params.delete('u');
    const cleanSearch = params.toString() ? '?' + params.toString() : '';
    history.replaceState(null, '', window.location.pathname + cleanSearch + (window.location.hash || ''));
  }

  if (!keys) {
    const passkeyRestored = await restorePasskeySession();
    if (!passkeyRestored && getStoredUsername()) {
      await restoreSession();
    }
  }
  if (keys && currentUsername) {
    ensureRegisteredWithServer().catch((e) => console.warn('Ensure registered:', e));
    migratePlainMessagesToEncrypted().catch((e) => console.warn('Message migration failed:', e));
  }

  const btnUsePasskey = document.getElementById('btnUsePasskey');
  if (btnUsePasskey) btnUsePasskey.onclick = () => {
    document.getElementById('setup-mnemonic').classList.add('hidden');
    document.getElementById('setup-passkey-div').classList.add('hidden');
    document.getElementById('setup-register').classList.remove('hidden');
    document.getElementById('setup-register-passkey-hint').classList.remove('hidden');
    document.getElementById('btnRegister').classList.add('hidden');
    document.getElementById('btnCreatePasskey').classList.remove('hidden');
  };
  const btnCreatePasskey = document.getElementById('btnCreatePasskey');
  if (btnCreatePasskey) btnCreatePasskey.onclick = async () => {
    try {
      const usernameInput = document.getElementById('username');
      if (!usernameInput) return;
      const username = usernameInput.value.trim().toLowerCase();
      if (!username) return alert('Enter a username first');
      const { credentialId, prfResult, storedKeyB64 } = await createPasskey(username);
      const kp = await generateKeypairForPasskey();
      const { encrypted, iv } = await encryptKeypairWithPasskey({ privateJwk: kp.privateJwk, publicJwk: kp.publicJwk }, prfResult);
      await storePasskeyCredential(credentialId, username, encrypted, iv, storedKeyB64);
      keys = { privateKey: kp.privateKey, publicKey: kp.publicKey };
      pendingPasskeyCredentialId = credentialId;
      const pubkey = await exportPubkeyToBase64(keys.publicKey);
      const regResp = await fetch(`${API_BASE}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, pubkey }),
      });
      if (!regResp.ok) {
        const msg = await regResp.text();
        throw new Error(msg || 'Registration failed');
      }
      currentUsername = username;
      setStoredUsername(username);
      savePasskeySessionToStorage(username, kp.privateJwk, kp.publicJwk);
      await saveSession(username, 'passkey', null, 'passkey', credentialId);
      pendingPasskeyCredentialId = null;
      const redirect = sessionStorage.getItem('war-chat-redirect');
      if (redirect) {
        sessionStorage.removeItem('war-chat-redirect');
        navigate('chat', redirect);
      } else {
        navigate('chats');
      }
    } catch (e) {
      document.getElementById('setup-mnemonic').classList.remove('hidden');
      document.getElementById('setup-passkey-div').classList.remove('hidden');
      document.getElementById('setup-register').classList.add('hidden');
      document.getElementById('setup-register-passkey-hint').classList.add('hidden');
      document.getElementById('btnRegister').classList.remove('hidden');
      document.getElementById('btnCreatePasskey').classList.add('hidden');
      alert('Passkey failed: ' + (e.message || e));
    }
  };
  const btnSignInPasskey = document.getElementById('btnSignInPasskey');
  if (btnSignInPasskey) btnSignInPasskey.onclick = async () => {
    try {
      const result = await authenticatePasskey();
      if (!result) {
        alert('No passkey found or authentication failed.');
        return;
      }
      if (await restoreSessionWithPasskeyFromResult(result)) {
        await ensureRegisteredWithServer();
        migratePlainMessagesToEncrypted().catch((e) => console.warn('Message migration failed:', e));
        render();
      } else {
        alert('No passkey found or authentication failed.');
      }
    } catch (e) {
      alert(e.message || 'Passkey sign-in failed.');
    }
  };

  document.getElementById('btnGenerate').onclick = () => {
    document.getElementById('mnemonic').value = generateMnemonic();
  };

  document.getElementById('btnContinue').onclick = async () => {
    const mnemonic = document.getElementById('mnemonic').value.trim();
    if (!mnemonic) return alert('Enter your 12-word phrase');
    const kp = await deriveKeypair(mnemonic);
    keys = kp;
    sessionStorage.setItem(SESSION_MNEMONIC, mnemonic);
    const existingUser = getStoredUsername();
    if (existingUser) {
      currentUsername = existingUser;
      await saveSession(existingUser, kp.seedKey, mnemonic);
      const pubkey = await exportPubkeyToBase64(keys.publicKey);
      const regResp = await fetch(`${API_BASE}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: existingUser, pubkey }),
      });
      if (!regResp.ok) {
        const msg = await regResp.text();
        return alert(msg || 'Registration failed');
      }
      migratePlainMessagesToEncrypted().catch((e) => console.warn('Message migration failed:', e));
      const redirect = sessionStorage.getItem('war-chat-redirect');
      if (redirect) {
        sessionStorage.removeItem('war-chat-redirect');
        navigate('chat', redirect);
      } else {
        navigate('chats');
      }
    } else {
      document.getElementById('setup-register').classList.remove('hidden');
      document.getElementById('setup-register-passkey-hint').classList.add('hidden');
      document.getElementById('btnRegister').classList.remove('hidden');
      document.getElementById('btnCreatePasskey').classList.add('hidden');
    }
  };

  document.getElementById('btnRegister').onclick = async () => {
    const username = document.getElementById('username').value.trim().toLowerCase();
    if (!username) return alert('Choose a username');
    const pubkey = await exportPubkeyToBase64(keys.publicKey);
    const resp = await fetch(`${API_BASE}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, pubkey }),
    });
    if (!resp.ok) {
      const msg = await resp.text();
      return alert(msg || 'Registration failed');
    }
    currentUsername = username;
    setStoredUsername(username);
    if (pendingPasskeyCredentialId) {
      await updatePasskeyCredentialUsername(pendingPasskeyCredentialId, username);
      await saveSession(username, 'passkey', null, 'passkey', pendingPasskeyCredentialId);
      pendingPasskeyCredentialId = null;
    } else {
      await saveSession(username, keys.seedKey, sessionStorage.getItem(SESSION_MNEMONIC));
    }
    const redirect = sessionStorage.getItem('war-chat-redirect');
    if (redirect) {
      sessionStorage.removeItem('war-chat-redirect');
      navigate('chat', redirect);
    } else {
      navigate('chats');
    }
  };

  document.getElementById('btnNewChat').onclick = () => showNewChatModal();
  document.getElementById('btnNewGroup').onclick = () => showNewGroupModal();

  const newChatModal = document.getElementById('newChatModal');
  if (newChatModal) {
    document.getElementById('btnNewChatModalCancel').onclick = () => {
      newChatModal.classList.remove('visible');
      document.getElementById('newChatSearchModal').value = '';
    };
    newChatModal.onclick = (e) => {
      if (e.target === newChatModal) {
        newChatModal.classList.remove('visible');
        document.getElementById('newChatSearchModal').value = '';
      }
    };
  }

  const newGroupModal = document.getElementById('newGroupModal');
  if (newGroupModal) {
    document.getElementById('btnNewGroupCancel').onclick = () => {
      newGroupModal.classList.remove('visible');
      document.getElementById('newGroupName').value = '';
      newGroupSelectedUsers = new Set();
    };
    document.getElementById('btnNewGroupCreate').onclick = () => createGroup();
    newGroupModal.onclick = (e) => {
      if (e.target === newGroupModal) {
        newGroupModal.classList.remove('visible');
        document.getElementById('newGroupName').value = '';
        newGroupSelectedUsers = new Set();
      }
    };
  }

  const addMemberModal = document.getElementById('addMemberModal');
  if (addMemberModal) {
    document.getElementById('btnAddMemberCancel').onclick = () => {
      addMemberModal.classList.remove('visible');
      addMemberSelectedUser = null;
    };
    document.getElementById('btnAddMemberConfirm').onclick = () => addMemberToGroup();
    addMemberModal.onclick = (e) => {
      if (e.target === addMemberModal) {
        addMemberModal.classList.remove('visible');
        addMemberSelectedUser = null;
      }
    };
  }

  document.getElementById('btnSend').onclick = sendMessage;
  document.getElementById('messageInput').onkeydown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  window.addEventListener('hashchange', render);
  const footer = document.getElementById('appFooter');
  if (footer) {
    fetch(`${API_BASE}/version`).then((r) => r.ok ? r.json() : {}).then((d) => {
      footer.textContent = d.version ? `War Chat ${d.version}` : 'War Chat';
    }).catch(() => { footer.textContent = 'War Chat'; });
  }
  render();
}

document.addEventListener('DOMContentLoaded', init);
