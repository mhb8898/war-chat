// War Chat - thin app coordinator (routing, view visibility, DOM updates)

import { state } from './state.js';
import { API_BASE } from './config.js';
import { SESSION_MNEMONIC } from './config.js';
import { getRoute, navigate } from './router.js';
import * as auth from './auth.js';
import * as db from './db.js';
import * as groups from './groups.js';
import * as ws from './ws.js';
import * as api from './api.js';
import * as passkey from './passkey.js';
import { escapeHtml, formatMessage, formatTime } from './utils.js';

export { navigate, getRoute };

export function getSelectedPeerFromRoute() {
  const { view, param } = getRoute();
  if (view !== 'chat' || !param) return null;
  if (param === 'group') return null;
  return param.startsWith('group/') ? groups.peerFromGroupId(param.slice(6)) : param;
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

function showQR(text) {
  const container = document.getElementById('qrcode');
  if (!container) return;
  container.innerHTML = '';
  if (typeof window !== 'undefined' && typeof QRCode !== 'undefined') {
    new QRCode(container, { text, width: 128, height: 128 });
  }
}

async function getSessionAuthMethod() {
  const session = await db.getSession(state.currentUsername);
  return session?.authMethod || 'mnemonic';
}

// --- Render helpers ---

export function renderMessage(m, isNoteToSelf) {
  const container = getMessagesContainer();
  const inner = getMessagesInner();
  if (!container || !inner) return;
  const div = document.createElement('div');
  const isSelf = m.peer === state.currentUsername;
  if (isSelf || isNoteToSelf || m.from === '_system') {
    div.className = 'msg note';
  } else {
    div.className = 'msg ' + (m.from === state.currentUsername ? 'sent' : 'received');
  }
  div.innerHTML = (isSelf || isNoteToSelf || m.from === '_system') ? formatMessage(m.text) : `<span class="meta">${escapeHtml(m.from)}</span><br>${formatMessage(m.text)}`;
  inner.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

export async function renderGroupInvites() {
  const section = document.getElementById('group-invites-section');
  const listEl = document.getElementById('group-invites-list');
  if (!section || !listEl) return;
  const invites = await db.getPendingGroupInvites();
  if (invites.length === 0) {
    section.classList.add('hidden');
    return;
  }
  section.classList.remove('hidden');
  listEl.innerHTML = '';
  for (const inv of invites) {
    const li = document.createElement('li');
    li.className = 'group-invite-row';
    li.innerHTML = `
      <div class="group-invite-info">
        <div class="group-invite-text">${escapeHtml(inv.from)} invited you to "${escapeHtml(inv.name)}"</div>
      </div>
      <div class="group-invite-actions">
        <button type="button" data-action="accept" data-testid="group-invite-accept" data-group-id="${escapeHtml(inv.id)}">Accept</button>
        <button type="button" data-action="decline" data-testid="group-invite-decline" data-group-id="${escapeHtml(inv.id)}">Decline</button>
      </div>
    `;
    li.querySelector('[data-action="accept"]').onclick = (e) => {
      e.stopPropagation();
      groups.acceptGroupInvite(inv).then(() => {
        renderGroupInvites();
        renderChatList(getSelectedPeerFromRoute());
        navigate('chat', 'group/' + inv.id);
      }).catch((err) => {
        console.error(err);
        alert('Accept failed: ' + (err && err.message));
      });
    };
    li.querySelector('[data-action="decline"]').onclick = (e) => {
      e.stopPropagation();
      groups.declineGroupInvite(inv.id).then(() => {
        renderGroupInvites();
        renderChatList(getSelectedPeerFromRoute());
      }).catch((err) => {
        console.error(err);
        alert('Decline failed: ' + (err && err.message));
      });
    };
    listEl.appendChild(li);
  }
}

export async function renderChatList(selectedPeer) {
  const list = document.getElementById('chat-list');
  const empty = document.getElementById('chat-list-empty');
  if (!list) return;
  await renderGroupInvites();
  const convos = await db.getConversations();

  list.innerHTML = '';
  if (convos.length === 0) {
    empty.classList.remove('hidden');
  } else {
    empty.classList.add('hidden');
    for (const c of convos) {
      const li = document.createElement('li');
      const isSelf = c.peer === state.currentUsername;
      const isGroup = groups.isGroupPeer(c.peer);
      const displayName = isSelf ? 'Saved Messages' : (c.groupName || (isGroup ? 'Group' : c.peer));
      const navParam = isGroup ? 'group/' + groups.groupPeerId(c.peer) : c.peer;
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

export async function renderMainView(selectedPeer) {
  const layout = document.getElementById('layoutSplit');
  const chatPane = document.getElementById('chat-pane');
  const chatEmpty = document.getElementById('chat-empty');
  if (layout) layout.classList.toggle('has-chat', !!selectedPeer);
  if (chatPane) chatPane.style.display = selectedPeer ? 'flex' : 'none';
  if (chatEmpty) chatEmpty.style.display = selectedPeer ? 'none' : 'flex';
  const peer = selectedPeer ?? getSelectedPeerFromRoute();
  await renderChatList(peer);
}

export async function openChat(recipient) {
  state.currentRecipient = recipient;
  const msgs = await db.getMessages(recipient);
  const container = getMessagesContainer();
  const inner = getMessagesInner();
  if (container && inner) {
    inner.innerHTML = '';
    const isSelf = recipient === state.currentUsername;
    msgs.forEach((m) => {
      const div = document.createElement('div');
      if (isSelf) {
        div.className = 'msg note';
        div.innerHTML = formatMessage(m.text);
      } else if (m.from === '_system') {
        div.className = 'msg note';
        div.innerHTML = formatMessage(m.text);
      } else {
        div.className = 'msg ' + (m.from === state.currentUsername ? 'sent' : 'received');
        div.innerHTML = `<span class="meta">${escapeHtml(m.from)}</span><br>${formatMessage(m.text)}`;
      }
      inner.appendChild(div);
    });
    container.scrollTop = container.scrollHeight;
  }
}

export function showView(name, param) {
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
    ws.connectWS();
    let headerTitle = 'War Chat';
    if (param) {
      if (param === state.currentUsername) headerTitle = 'Saved Messages';
      else if (groups.isGroupPeer(param)) {
        headerTitle = 'Group';
        db.getGroup(groups.groupPeerId(param)).then((g) => {
          const h = document.querySelector('.header h1');
          if (h && g) h.textContent = g.name;
        });
      } else headerTitle = param;
    }
    const h1 = document.querySelector('.header h1');
    if (h1) h1.textContent = headerTitle;
    const isMobile = typeof window !== 'undefined' && window.matchMedia('(max-width: 768px)').matches;
    const newChatBtn = (isMobile && !param) ? '<button class="btn-icon" id="btnNewChatHeader" title="New chat">&#10133;</button>' : '';
    actions.innerHTML = (param ? '<button class="btn-icon" id="btnBack" title="Back">&#8592;</button>' : '') +
      (param && groups.isGroupPeer(param) ? '<button class="btn-icon" id="btnAddMember" title="Add member">&#10133;</button><button class="btn-icon" id="btnLeaveGroup" title="Leave group">&#128473;</button>' : '') +
      newChatBtn +
      '<button class="btn-icon" id="btnProfile" title="Profile">&#9776;</button>' +
      '<button class="btn-icon" id="btnLogout" title="Log out">&#128274;</button>';
    const btnBack = document.getElementById('btnBack');
    if (btnBack) btnBack.onclick = () => navigate('chats');
    const btnAddMember = document.getElementById('btnAddMember');
    if (btnAddMember) btnAddMember.onclick = () => showAddMemberModal();
    const btnLeaveGroup = document.getElementById('btnLeaveGroup');
    if (btnLeaveGroup) btnLeaveGroup.onclick = () => leaveGroupAndNavigate();
    const btnNewChatHeader = document.getElementById('btnNewChatHeader');
    if (btnNewChatHeader) btnNewChatHeader.onclick = () => showNewChatModal();
    const btnProfile = document.getElementById('btnProfile');
    if (btnProfile) btnProfile.onclick = () => navigate('profile');
    const btnLogout = document.getElementById('btnLogout');
    if (btnLogout) btnLogout.onclick = () => doLogout();
  } else if (name === 'profile') {
    const h1 = document.querySelector('.header h1');
    if (h1) h1.textContent = 'Profile';
    actions.innerHTML = '<button class="btn-icon" id="btnBackProfile" title="Back">&#8592;</button>' +
      '<button class="btn-icon" id="btnLogout" title="Log out">&#128274;</button>';
    const btnBackProfile = document.getElementById('btnBackProfile');
    if (btnBackProfile) btnBackProfile.onclick = () => {
      const h = document.querySelector('.header h1');
      if (h) h.textContent = 'War Chat';
      navigate('chats');
    };
    const btnLogoutProfile = document.getElementById('btnLogout');
    if (btnLogoutProfile) btnLogoutProfile.onclick = () => doLogout();
  } else {
    actions.innerHTML = '';
  }
}

async function leaveGroupAndNavigate() {
  if (!groups.isGroupPeer(state.currentRecipient)) return;
  if (!confirm('Leave this group? You will stop receiving messages.')) return;
  await groups.leaveGroup();
  navigate('chats');
  render();
}

function doLogout() {
  auth.logout();
  resetSetupView();
  navigate('setup');
  render();
}

export function resetSetupView() {
  const setupMnemonic = document.getElementById('setup-mnemonic');
  const setupPasskeyDiv = document.getElementById('setup-passkey-div');
  const setupRegister = document.getElementById('setup-register');
  const setupRegisterPasskeyHint = document.getElementById('setup-register-passkey-hint');
  const btnRegister = document.getElementById('btnRegister');
  const btnCreatePasskey = document.getElementById('btnCreatePasskey');
  const usernameInput = document.getElementById('username');
  const mnemonicInput = document.getElementById('mnemonic');
  if (setupMnemonic) setupMnemonic.classList.remove('hidden');
  if (setupPasskeyDiv) setupPasskeyDiv.classList.remove('hidden');
  if (setupRegister) setupRegister.classList.add('hidden');
  if (setupRegisterPasskeyHint) setupRegisterPasskeyHint.classList.add('hidden');
  if (btnRegister) btnRegister.classList.remove('hidden');
  if (btnCreatePasskey) btnCreatePasskey.classList.add('hidden');
  if (usernameInput) usernameInput.value = '';
  if (mnemonicInput) mnemonicInput.value = '';
}

export function render() {
  const { view, param } = getRoute();
  document.querySelectorAll('.view').forEach((v) => v.classList.remove('active'));

  if (!auth.isLoggedIn() && view !== 'setup') {
    if (view === 'chat' && param) {
      sessionStorage.setItem('war-chat-redirect', param);
    }
    showView('setup');
    return;
  }

  if (view === 'setup' && auth.isLoggedIn()) {
    navigate('chats');
    return;
  }

  switch (view) {
    case 'setup':
      showView('setup');
      break;
    case 'chats':
      showView('main');
      state.currentRecipient = null;
      renderMainView(null);
      break;
    case 'chat':
      if (param) {
        if (param === 'group') {
          navigate('chats');
          break;
        }
        const peer = param.startsWith('group/') ? groups.peerFromGroupId(param.slice(6)) : param;
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

// --- Profile (backup/restore/recovery) ---

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

export function renderProfile() {
  const profileUsername = document.getElementById('profileUsername');
  if (profileUsername) profileUsername.textContent = state.currentUsername || '';
  const link = `${API_BASE}/u/${state.currentUsername}`;
  const chatLink = document.getElementById('chatLink');
  if (chatLink) chatLink.textContent = link;
  showQR(link);
  const btnCopyLink = document.getElementById('btnCopyLink');
  if (btnCopyLink) btnCopyLink.onclick = () => {
    navigator.clipboard.writeText(link);
    alert('Link copied!');
  };
  getSessionAuthMethod().then(async (authMethod) => {
    const session = await db.getSession(state.currentUsername);
    const hasRecoveryPhrase = !!(session?.mnemonic || sessionStorage.getItem(SESSION_MNEMONIC));
    const recoverySection = document.getElementById('profile-recovery-section');
    const passkeySection = document.getElementById('profile-passkey-section');
    const addPasskeySection = document.getElementById('profile-add-passkey-section');
    const exportBackupBtn = document.getElementById('btnExportBackup');
    if (authMethod === 'passkey') {
      if (hasRecoveryPhrase) {
        if (recoverySection) recoverySection.classList.remove('hidden');
        if (passkeySection) passkeySection.classList.add('hidden');
        if (exportBackupBtn) { exportBackupBtn.disabled = false; exportBackupBtn.title = ''; }
      } else {
        if (recoverySection) recoverySection.classList.add('hidden');
        if (passkeySection) passkeySection.classList.remove('hidden');
        if (exportBackupBtn) { exportBackupBtn.disabled = true; exportBackupBtn.title = 'Add a recovery phrase first to export backup.'; }
      }
      if (addPasskeySection) addPasskeySection.classList.add('hidden');
    } else {
      if (recoverySection) recoverySection.classList.remove('hidden');
      if (passkeySection) passkeySection.classList.add('hidden');
      const pkSupported = await passkey.isPasskeySupported();
      if (addPasskeySection && pkSupported) addPasskeySection.classList.remove('hidden');
      else if (addPasskeySection) addPasskeySection.classList.add('hidden');
      if (exportBackupBtn) { exportBackupBtn.disabled = false; exportBackupBtn.title = ''; }
    }
  });
  const btnShowMnemonic = document.getElementById('btnShowMnemonic');
  if (btnShowMnemonic) btnShowMnemonic.onclick = async () => {
    let mnemonic = sessionStorage.getItem(SESSION_MNEMONIC);
    if (!mnemonic) {
      const session = await db.getSession(state.currentUsername);
      mnemonic = session && session.mnemonic ? session.mnemonic : null;
    }
    const el = document.getElementById('mnemonicDisplay');
    if (mnemonic) {
      if (el) { el.textContent = mnemonic; el.classList.remove('hidden'); }
    } else {
      alert('Recovery phrase not stored. Log in with your phrase to store it.');
    }
  };
  const btnAddRecoveryPhrase = document.getElementById('btnAddRecoveryPhrase');
  if (btnAddRecoveryPhrase) btnAddRecoveryPhrase.onclick = addRecoveryPhraseForPasskeyUser;
  const btnAddPasskey = document.getElementById('btnAddPasskey');
  if (btnAddPasskey) btnAddPasskey.onclick = addPasskeyForMnemonicUser;
  const btnExportBackup = document.getElementById('btnExportBackup');
  if (btnExportBackup) btnExportBackup.onclick = exportBackup;
  const btnRestoreBackup = document.getElementById('btnRestoreBackup');
  if (btnRestoreBackup) btnRestoreBackup.onclick = restoreBackup;
}

async function addRecoveryPhraseForPasskeyUser() {
  const mnemonic = prompt('Enter a 12-word recovery phrase (or generate one on the setup screen and paste it):');
  if (!mnemonic || !mnemonic.trim()) return;
  try {
    const backup = {
      username: state.currentUsername,
      privateJwk: await crypto.subtle.exportKey('jwk', state.keys.privateKey),
      publicJwk: await crypto.subtle.exportKey('jwk', state.keys.publicKey),
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
    const session = await db.getSession(state.currentUsername);
    if (session) {
      session.mnemonic = mnemonic;
      await db.saveSession(state.currentUsername, session.seedKey, mnemonic, session.authMethod, session.credentialId);
    }
    alert('Backup copied to clipboard. Save your phrase and backup in a safe place. You can now export backup.');
    renderProfile();
  } catch (e) {
    alert('Failed: ' + (e.message || e));
  }
}

async function addPasskeyForMnemonicUser() {
  try {
    const { credentialId, prfResult, storedKeyB64 } = await passkey.createPasskey(state.currentUsername);
    const privateJwk = await crypto.subtle.exportKey('jwk', state.keys.privateKey);
    const publicJwk = await crypto.subtle.exportKey('jwk', state.keys.publicKey);
    const { encrypted, iv } = await passkey.encryptKeypairWithPasskey({ privateJwk, publicJwk }, prfResult);
    await passkey.storePasskeyCredential(credentialId, state.currentUsername, encrypted, iv, storedKeyB64);
    alert('Passkey added. You can now sign in with passkey on this device.');
    renderProfile();
  } catch (e) {
    alert('Failed to add passkey: ' + (e.message || e));
  }
}

async function exportBackup() {
  let mnemonic = sessionStorage.getItem(SESSION_MNEMONIC);
  if (!mnemonic) {
    const session = await db.getSession(state.currentUsername);
    mnemonic = session && session.mnemonic ? session.mnemonic : null;
  }
  if (!mnemonic) {
    alert('Recovery phrase not stored. Use "Show recovery phrase" after logging in with your phrase.');
    return;
  }
  try {
    let privateJwk, publicJwk;
    if (state.keys) {
      privateJwk = await crypto.subtle.exportKey('jwk', state.keys.privateKey);
      publicJwk = await crypto.subtle.exportKey('jwk', state.keys.publicKey);
    } else {
      const kp = await auth.deriveKeypair(mnemonic);
      privateJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
      publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    }
    const backup = { username: state.currentUsername, privateJwk, publicJwk };
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
  const restoreBackupEl = document.getElementById('restoreBackup');
  const backupB64 = restoreBackupEl && restoreBackupEl.value.trim();
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
    state.keys = { privateKey, publicKey };
    state.currentUsername = backup.username;
    auth.setStoredUsername(backup.username);
    const seed = await (await import('./crypto.js')).mnemonicToSeed(mnemonic);
    const seedKey = btoa(String.fromCharCode.apply(null, seed));
    await db.putKeypair({
      seed: seedKey,
      privateJwk: backup.privateJwk,
      publicJwk: backup.publicJwk,
    });
    const regResp = await fetch(`${API_BASE}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: backup.username, pubkey: btoa(JSON.stringify(backup.publicJwk)) }),
    });
    if (!regResp.ok) {
      const msg = await regResp.text();
      throw new Error(msg || 'Registration failed');
    }
    if (restoreBackupEl) restoreBackupEl.value = '';
    alert('Restored!');
    const redirect = sessionStorage.getItem('war-chat-redirect');
    if (redirect) {
      sessionStorage.removeItem('war-chat-redirect');
      navigate('chat', redirect);
    } else {
      navigate('chats');
    }
    render();
  } catch (e) {
    alert('Restore failed: ' + e.message);
  }
}

// --- Modals and send (called from main.js after bindings) ---

let newGroupSelectedUsers = new Set();
let addMemberSelectedUser = null;

export async function showNewChatModal() {
  const modal = document.getElementById('newChatModal');
  const searchInput = document.getElementById('newChatSearchModal');
  if (!modal || !searchInput) return;
  searchInput.value = '';
  modal.classList.add('visible');
  searchInput.focus();
  const users = await api.fetchUsers();
  renderUserList(users);
  const onSearch = () => renderUserList(users, searchInput.value);
  searchInput.oninput = onSearch;
  searchInput.onkeyup = onSearch;
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

export async function showNewGroupModal() {
  const modal = document.getElementById('newGroupModal');
  const nameInput = document.getElementById('newGroupName');
  const listEl = document.getElementById('newGroupUserList');
  const emptyEl = document.getElementById('newGroupUserListEmpty');
  if (!modal || !nameInput || !listEl) return;
  nameInput.value = '';
  newGroupSelectedUsers = new Set();
  modal.classList.add('visible');
  nameInput.focus();
  const users = await api.fetchUsers();
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

export async function createGroupFromModal() {
  const nameInput = document.getElementById('newGroupName');
  const modal = document.getElementById('newGroupModal');
  const groupName = (nameInput && nameInput.value.trim()) || '';
  if (!groupName) {
    alert('Enter a group name');
    return;
  }
  const members = [state.currentUsername, ...Array.from(newGroupSelectedUsers)];
  if (members.length < 2) {
    alert('Add at least one member');
    return;
  }
  try {
    const { groupId } = await groups.createGroup(groupName, members);
    if (modal) modal.classList.remove('visible');
    if (nameInput) nameInput.value = '';
    newGroupSelectedUsers = new Set();
    navigate('chat', 'group/' + groupId);
    render();
  } catch (e) {
    alert(e.message || 'Create group failed');
  }
}

export async function showAddMemberModal() {
  const modal = document.getElementById('addMemberModal');
  const listEl = document.getElementById('addMemberUserList');
  const emptyEl = document.getElementById('addMemberUserListEmpty');
  if (!modal || !listEl || !groups.isGroupPeer(state.currentRecipient)) return;
  const groupId = groups.groupPeerId(state.currentRecipient);
  const group = await db.getGroup(groupId);
  if (!group) return;
  addMemberSelectedUser = null;
  modal.classList.add('visible');
  const allUsers = await api.fetchUsers();
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

export async function addMemberToGroupFromModal() {
  if (!addMemberSelectedUser || !groups.isGroupPeer(state.currentRecipient)) {
    alert('Select a user to add');
    return;
  }
  try {
    await groups.addMemberToGroup(addMemberSelectedUser);
    const modal = document.getElementById('addMemberModal');
    if (modal) modal.classList.remove('visible');
    addMemberSelectedUser = null;
    renderChatList(getSelectedPeerFromRoute());
  } catch (e) {
    alert(e.message || 'Add member failed');
  }
}

export async function sendMessageFromInput() {
  const input = document.getElementById('messageInput');
  const text = (input && input.value.trim()) || '';
  if (!text) return;
  try {
    const result = await ws.sendMessage(text);
    if (input) input.value = '';
    if (result) {
      renderMessage(result.message, result.isNoteToSelf);
      if (result.refreshChatList) renderChatList(getSelectedPeerFromRoute());
    }
  } catch (e) {
    alert(e.message || 'Send failed');
  }
}

// Wire WS callback for incoming messages
ws.setOnMessageCallback((payload) => {
  if (payload.type === 'refresh-chat-list') {
    renderChatList(getSelectedPeerFromRoute());
  } else if (payload.type === 'incoming-message' && payload.message) {
    if (payload.showInCurrentView) {
      renderMessage(payload.message, payload.isNoteToSelf);
    }
    renderChatList(getSelectedPeerFromRoute());
  }
});
