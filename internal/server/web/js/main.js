// War Chat - entry point: init, bind setup/modals/send, hashchange, render

import './components/index.js'; // register web components

import { ensureCrypto } from './crypto.js';
import { openDB } from './db.js';
import { state } from './state.js';
import { API_BASE } from './config.js';
import { SESSION_MNEMONIC } from './config.js';
import * as auth from './auth.js';
import * as api from './api.js';
import * as passkey from './passkey.js';
import { navigate, render, resetSetupView, showNewChatModal, showNewGroupModal, createGroupFromModal, showAddMemberModal, addMemberToGroupFromModal, sendMessageFromInput, leaveGroupAndNavigate, doLogout, renderGroupInvites, renderChatList, getSelectedPeerFromRoute } from './app.js';
import * as groups from './groups.js';
import { generateMnemonic } from './utils.js';
import { encryptMessageForStorage } from './crypto-storage.js';

async function migratePlainMessagesToEncrypted() {
  if (!state.keys?.privateKey || !state.currentUsername) return;
  const raw = await (await import('./db.js')).getAllMessagesRaw();
  const toMigrate = raw.filter((m) => m.owner === state.currentUsername && m.text && !m.encryptedPayload);
  if (toMigrate.length === 0) return;
  for (const m of toMigrate) {
    const msg = { from: m.from, text: m.text, ts: m.ts, peer: m.peer };
    const enc = await encryptMessageForStorage(msg);
    if (enc) {
      await (await import('./db.js')).putMessage({
        id: m.id,
        owner: m.owner,
        encryptedPayload: enc.encryptedPayload,
        iv: enc.iv,
      });
    }
  }
}

async function init() {
  ensureCrypto();
  await openDB();

  const params = new URLSearchParams(window.location.search);
  const to = params.get('to') || params.get('u');
  if (to) {
    sessionStorage.setItem('war-chat-redirect', to);
    params.delete('to');
    params.delete('u');
    const cleanSearch = params.toString() ? '?' + params.toString() : '';
    history.replaceState(null, '', window.location.pathname + cleanSearch + (window.location.hash || ''));
  }

  if (!state.keys) {
    const passkeyRestored = await auth.restorePasskeySession();
    if (!passkeyRestored && auth.getStoredUsername()) {
      await auth.restoreSession();
    }
  }
  if (state.keys && state.currentUsername) {
    api.ensureRegisteredWithServer().catch((e) => console.warn('Ensure registered:', e));
    migratePlainMessagesToEncrypted().catch((e) => console.warn('Message migration failed:', e));
  }

  // Setup: Use passkey
  const btnUsePasskey = document.getElementById('btnUsePasskey');
  if (btnUsePasskey) btnUsePasskey.onclick = () => {
    document.getElementById('setup-mnemonic')?.classList.add('hidden');
    document.getElementById('setup-passkey-div')?.classList.add('hidden');
    document.getElementById('setup-register')?.classList.remove('hidden');
    document.getElementById('setup-register-passkey-hint')?.classList.remove('hidden');
    document.getElementById('btnRegister')?.classList.add('hidden');
    document.getElementById('btnCreatePasskey')?.classList.remove('hidden');
  };

  // Setup: Create passkey
  const btnCreatePasskey = document.getElementById('btnCreatePasskey');
  if (btnCreatePasskey) btnCreatePasskey.onclick = async () => {
    try {
      const usernameInput = document.getElementById('username');
      if (!usernameInput) return;
      const username = usernameInput.value.trim().toLowerCase();
      if (!username) return alert('Enter a username first');
      const { credentialId, prfResult, storedKeyB64 } = await passkey.createPasskey(username);
      const kp = await auth.generateKeypairForPasskey();
      const { encrypted, iv } = await passkey.encryptKeypairWithPasskey({ privateJwk: kp.privateJwk, publicJwk: kp.publicJwk }, prfResult);
      await passkey.storePasskeyCredential(credentialId, username, encrypted, iv, storedKeyB64);
      state.keys = { privateKey: kp.privateKey, publicKey: kp.publicKey };
      state.pendingPasskeyCredentialId = credentialId;
      const pubkey = await (await import('./crypto.js')).exportPubkeyToBase64(state.keys.publicKey);
      const regResp = await fetch(`${API_BASE}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, pubkey }),
      });
      if (!regResp.ok) {
        const msg = await regResp.text();
        throw new Error(msg || 'Registration failed');
      }
      state.currentUsername = username;
      auth.setStoredUsername(username);
      auth.savePasskeySessionToStorage(username, kp.privateJwk, kp.publicJwk);
      await auth.saveSession(username, 'passkey', null, 'passkey', credentialId);
      state.pendingPasskeyCredentialId = null;
      const redirect = sessionStorage.getItem('war-chat-redirect');
      if (redirect) {
        sessionStorage.removeItem('war-chat-redirect');
        navigate('chat', redirect);
      } else {
        navigate('chats');
      }
      render();
    } catch (e) {
      resetSetupView();
      alert('Passkey failed: ' + (e.message || e));
    }
  };

  // Setup: Sign in with passkey
  const btnSignInPasskey = document.getElementById('btnSignInPasskey');
  if (btnSignInPasskey) btnSignInPasskey.onclick = async () => {
    try {
      const result = await passkey.authenticatePasskey();
      if (!result) {
        alert('No passkey found or authentication failed.');
        return;
      }
      if (await auth.restoreSessionWithPasskeyFromResult(result)) {
        await api.ensureRegisteredWithServer();
        migratePlainMessagesToEncrypted().catch((e) => console.warn('Message migration failed:', e));
        render();
      } else {
        alert('No passkey found or authentication failed.');
      }
    } catch (e) {
      alert(e.message || 'Passkey sign-in failed.');
    }
  };

  // Setup: Generate mnemonic
  const btnGenerate = document.getElementById('btnGenerate');
  if (btnGenerate) btnGenerate.onclick = () => {
    const mnemonicEl = document.getElementById('mnemonic');
    if (mnemonicEl) mnemonicEl.value = generateMnemonic();
  };

  // Setup: Continue (mnemonic)
  const btnContinue = document.getElementById('btnContinue');
  if (btnContinue) btnContinue.onclick = async () => {
    const mnemonicEl = document.getElementById('mnemonic');
    const mnemonic = (mnemonicEl && mnemonicEl.value.trim()) || '';
    if (!mnemonic) return alert('Enter your 12-word phrase');
    const kp = await auth.deriveKeypair(mnemonic);
    state.keys = kp;
    sessionStorage.setItem(SESSION_MNEMONIC, mnemonic);
    const existingUser = auth.getStoredUsername();
    if (existingUser) {
      state.currentUsername = existingUser;
      await auth.saveSession(existingUser, kp.seedKey, mnemonic);
      const pubkey = await (await import('./crypto.js')).exportPubkeyToBase64(state.keys.publicKey);
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
      render();
    } else {
      document.getElementById('setup-register')?.classList.remove('hidden');
      document.getElementById('setup-register-passkey-hint')?.classList.add('hidden');
      document.getElementById('btnRegister')?.classList.remove('hidden');
      document.getElementById('btnCreatePasskey')?.classList.add('hidden');
    }
  };

  // Setup: Register (username)
  const btnRegister = document.getElementById('btnRegister');
  if (btnRegister) btnRegister.onclick = async () => {
    const usernameInput = document.getElementById('username');
    const username = (usernameInput && usernameInput.value.trim().toLowerCase()) || '';
    if (!username) return alert('Choose a username');
    const pubkey = await (await import('./crypto.js')).exportPubkeyToBase64(state.keys.publicKey);
    const resp = await fetch(`${API_BASE}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, pubkey }),
    });
    if (!resp.ok) {
      const msg = await resp.text();
      return alert(msg || 'Registration failed');
    }
    state.currentUsername = username;
    auth.setStoredUsername(username);
    if (state.pendingPasskeyCredentialId) {
      await passkey.updatePasskeyCredentialUsername(state.pendingPasskeyCredentialId, username);
      await auth.saveSession(username, 'passkey', null, 'passkey', state.pendingPasskeyCredentialId);
      state.pendingPasskeyCredentialId = null;
    } else {
      await auth.saveSession(username, state.keys.seedKey, sessionStorage.getItem(SESSION_MNEMONIC));
    }
    const redirect = sessionStorage.getItem('war-chat-redirect');
    if (redirect) {
      sessionStorage.removeItem('war-chat-redirect');
      navigate('chat', redirect);
    } else {
      navigate('chats');
    }
    render();
  };

  // Main: New chat / New group
  const btnNewChat = document.getElementById('btnNewChat');
  if (btnNewChat) btnNewChat.onclick = () => showNewChatModal();
  const btnNewGroup = document.getElementById('btnNewGroup');
  if (btnNewGroup) btnNewGroup.onclick = () => showNewGroupModal();

  // Header actions (war-chat-header component)
  document.addEventListener('war-chat-header-action', (e) => {
    const action = e.detail?.action;
    if (action === 'back') navigate('chats');
    else if (action === 'add-member') showAddMemberModal();
    else if (action === 'leave-group') leaveGroupAndNavigate();
    else if (action === 'new-chat') showNewChatModal();
    else if (action === 'profile') navigate('profile');
    else if (action === 'logout') doLogout();
  });

  // Chat list selection (war-chat-chat-list component)
  document.addEventListener('war-chat-select-peer', (e) => {
    if (e.detail?.peer) navigate('chat', e.detail.peer);
  });

  // Group invites (war-chat-group-invites component)
  document.addEventListener('war-chat-group-invite-accept', (e) => {
    const inv = e.detail?.invite;
    if (!inv?.id) return;
    groups.acceptGroupInvite(inv).then(() => {
      renderGroupInvites();
      renderChatList(getSelectedPeerFromRoute());
      navigate('chat', 'group/' + inv.id);
    }).catch((err) => {
      console.error(err);
      alert('Accept failed: ' + (err && err.message));
    });
  });
  document.addEventListener('war-chat-group-invite-decline', (e) => {
    const inv = e.detail?.invite;
    if (!inv?.id) return;
    groups.declineGroupInvite(inv.id).then(() => {
      renderGroupInvites();
      renderChatList(getSelectedPeerFromRoute());
    }).catch((err) => {
      console.error(err);
      alert('Decline failed: ' + (err && err.message));
    });
  });

  // Modals
  const newChatModal = document.getElementById('newChatModal');
  if (newChatModal) {
    const btnCancel = document.getElementById('btnNewChatModalCancel');
    if (btnCancel) btnCancel.onclick = () => {
      newChatModal.removeAttribute('open');
      const search = document.getElementById('newChatSearchModal');
      if (search) search.value = '';
    };
    newChatModal.onclick = (e) => {
      if (e.target === newChatModal) {
        newChatModal.removeAttribute('open');
        const search = document.getElementById('newChatSearchModal');
        if (search) search.value = '';
      }
    };
  }

  const newGroupModal = document.getElementById('newGroupModal');
  if (newGroupModal) {
    const btnCancel = document.getElementById('btnNewGroupCancel');
    if (btnCancel) btnCancel.onclick = () => {
      newGroupModal.removeAttribute('open');
      const nameInput = document.getElementById('newGroupName');
      if (nameInput) nameInput.value = '';
    };
    const btnCreate = document.getElementById('btnNewGroupCreate');
    if (btnCreate) btnCreate.onclick = () => createGroupFromModal();
    newGroupModal.onclick = (e) => {
      if (e.target === newGroupModal) {
        newGroupModal.removeAttribute('open');
        const nameInput = document.getElementById('newGroupName');
        if (nameInput) nameInput.value = '';
      }
    };
  }

  const addMemberModal = document.getElementById('addMemberModal');
  if (addMemberModal) {
    const btnCancel = document.getElementById('btnAddMemberCancel');
    if (btnCancel) btnCancel.onclick = () => {
      addMemberModal.removeAttribute('open');
    };
    const btnConfirm = document.getElementById('btnAddMemberConfirm');
    if (btnConfirm) btnConfirm.onclick = () => addMemberToGroupFromModal();
    addMemberModal.onclick = (e) => {
      if (e.target === addMemberModal) {
        addMemberModal.removeAttribute('open');
      }
    };
  }

  // Send message
  const btnSend = document.getElementById('btnSend');
  if (btnSend) btnSend.onclick = () => sendMessageFromInput();
  const messageInput = document.getElementById('messageInput');
  if (messageInput) messageInput.onkeydown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessageFromInput();
    }
  };

  window.addEventListener('hashchange', () => render());

  const footer = document.getElementById('appFooter');
  if (footer) {
    fetch(`${API_BASE}/version`).then((r) => r.ok ? r.json() : {}).then((d) => {
      footer.textContent = d.version ? `War Chat ${d.version}` : 'War Chat';
    }).catch(() => { footer.textContent = 'War Chat'; });
  }

  render();
}

if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', init);
}
