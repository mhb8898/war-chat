// War Chat - setup flow (passkey, mnemonic, register)

import { state } from './state.js';
import { API_BASE } from './config.js';
import { SESSION_MNEMONIC } from './config.js';
import * as auth from './auth.js';
import * as api from './api.js';
import * as passkey from './passkey.js';
import { generateMnemonic } from './utils.js';

let callbacks = { navigate: () => {}, render: () => {}, migratePlainMessagesToEncrypted: () => Promise.resolve() };

export function setSetupCallbacks(cbs) {
  callbacks = { ...callbacks, ...cbs };
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

export function initSetup() {
  const btnUsePasskey = document.getElementById('btnUsePasskey');
  if (btnUsePasskey) btnUsePasskey.onclick = () => {
    document.getElementById('setup-mnemonic')?.classList.add('hidden');
    document.getElementById('setup-passkey-div')?.classList.add('hidden');
    document.getElementById('setup-register')?.classList.remove('hidden');
    document.getElementById('setup-register-passkey-hint')?.classList.remove('hidden');
    document.getElementById('btnRegister')?.classList.add('hidden');
    document.getElementById('btnCreatePasskey')?.classList.remove('hidden');
  };

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
        callbacks.navigate('chat', redirect);
      } else {
        callbacks.navigate('chats');
      }
      callbacks.render();
    } catch (e) {
      resetSetupView();
      alert('Passkey failed: ' + (e.message || e));
    }
  };

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
        callbacks.migratePlainMessagesToEncrypted().catch((e) => console.warn('Message migration failed:', e));
        callbacks.render();
      } else {
        alert('No passkey found or authentication failed.');
      }
    } catch (e) {
      alert(e.message || 'Passkey sign-in failed.');
    }
  };

  const btnGenerate = document.getElementById('btnGenerate');
  if (btnGenerate) btnGenerate.onclick = () => {
    const mnemonicEl = document.getElementById('mnemonic');
    if (mnemonicEl) mnemonicEl.value = generateMnemonic();
  };

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
      callbacks.migratePlainMessagesToEncrypted().catch((e) => console.warn('Message migration failed:', e));
      const redirect = sessionStorage.getItem('war-chat-redirect');
      if (redirect) {
        sessionStorage.removeItem('war-chat-redirect');
        callbacks.navigate('chat', redirect);
      } else {
        callbacks.navigate('chats');
      }
      callbacks.render();
    } else {
      document.getElementById('setup-register')?.classList.remove('hidden');
      document.getElementById('setup-register-passkey-hint')?.classList.add('hidden');
      document.getElementById('btnRegister')?.classList.remove('hidden');
      document.getElementById('btnCreatePasskey')?.classList.remove('hidden');
    }
  };

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
      callbacks.navigate('chat', redirect);
    } else {
      callbacks.navigate('chats');
    }
    callbacks.render();
  };
}
