// War Chat - setup flow (passkey, mnemonic, register, approval)

import { state } from './state.js';
import { API_BASE } from './config.js';
import { SESSION_MNEMONIC } from './config.js';
import * as auth from './auth.js';
import * as api from './api.js';
import * as passkey from './passkey.js';
import { generateMnemonic } from './utils.js';

let callbacks = { navigate: () => {}, render: () => {}, migratePlainMessagesToEncrypted: () => Promise.resolve() };
let pollTimer = null;

export function setSetupCallbacks(cbs) {
  callbacks = { ...callbacks, ...cbs };
}

export function resetSetupView() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  const setupMnemonic = document.getElementById('setup-mnemonic');
  const setupPasskeyDiv = document.getElementById('setup-passkey-div');
  const setupRegister = document.getElementById('setup-register');
  const setupRegisterPasskeyHint = document.getElementById('setup-register-passkey-hint');
  const setupPending = document.getElementById('setup-pending');
  const setupCard = document.querySelector('.setup-card');
  const btnRegister = document.getElementById('btnRegister');
  const btnCreatePasskey = document.getElementById('btnCreatePasskey');
  const usernameInput = document.getElementById('username');
  const mnemonicInput = document.getElementById('mnemonic');
  const mnemonicError = document.getElementById('setup-mnemonic-error');
  const introDiv = document.getElementById('setup-intro-div');
  const introText = document.getElementById('introText');
  if (setupMnemonic) setupMnemonic.classList.remove('hidden');
  if (setupPasskeyDiv) setupPasskeyDiv.classList.remove('hidden');
  if (setupRegister) setupRegister.classList.add('hidden');
  if (setupRegisterPasskeyHint) setupRegisterPasskeyHint.classList.add('hidden');
  if (setupPending) setupPending.classList.add('hidden');
  if (setupCard) { setupCard.style.display = ''; }
  if (btnRegister) btnRegister.classList.remove('hidden');
  if (btnCreatePasskey) btnCreatePasskey.classList.add('hidden');
  if (usernameInput) usernameInput.value = '';
  if (mnemonicInput) mnemonicInput.value = '';
  if (mnemonicError) {
    mnemonicError.textContent = '';
    mnemonicError.classList.add('hidden');
  }
  if (introDiv) introDiv.classList.add('hidden');
  if (introText) introText.value = '';
}

function showMnemonicError(msg) {
  const el = document.getElementById('setup-mnemonic-error');
  if (!el) return;
  el.textContent = msg || '';
  el.classList.toggle('hidden', !msg);
}

function validateMnemonic(mnemonic) {
  const trimmed = (mnemonic || '').trim().toLowerCase();
  if (!trimmed) return { ok: false, error: 'Enter your 12-word phrase.' };
  const words = trimmed.split(/\s+/);
  if (words.length !== 12) return { ok: false, error: 'Phrase must be exactly 12 words.' };
  return { ok: true, mnemonic: trimmed };
}

// Show the pending-approval screen and poll until approved/denied.
function showPendingApproval(username, pubkey, onApproved) {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;

  const setupCard = document.querySelector('.setup-card');
  const pendingSection = document.getElementById('setup-pending');
  const pendingStatus = document.getElementById('setup-pending-status');
  if (setupCard) setupCard.style.display = 'none';
  if (pendingSection) pendingSection.classList.remove('hidden');
  if (pendingStatus) pendingStatus.textContent = '';

  let resolved = false;
  pollTimer = setInterval(async () => {
    if (resolved) return;
    try {
      const resp = await fetch(`${API_BASE}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, pubkey }),
      });
      const data = await resp.json().catch(() => ({}));
      if (resp.ok && data.status === 'ok') {
        resolved = true;
        clearInterval(pollTimer);
        pollTimer = null;
        onApproved();
      } else if (resp.status === 403) {
        resolved = true;
        clearInterval(pollTimer);
        pollTimer = null;
        if (pendingSection) pendingSection.classList.add('hidden');
        if (setupCard) setupCard.style.display = '';
        alert('Your registration request was denied. You can try again.');
      }
    } catch (e) {
      console.warn('Poll error:', e);
    }
  }, 5000);
}

async function registerAndHandleResponse(username, pubkey, intro, onApproved) {
  const body = { username, pubkey };
  if (intro) body.intro = intro;
  const resp = await fetch(`${API_BASE}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (resp.status === 202) {
    // Pending approval
    showPendingApproval(username, pubkey, onApproved);
    return 'pending';
  }
  if (!resp.ok) {
    const msg = await resp.text();
    throw new Error(msg || 'Registration failed');
  }
  return 'ok';
}

function completeLogin(redirect) {
  callbacks.migratePlainMessagesToEncrypted().catch((e) => console.warn('Message migration failed:', e));
  if (redirect) {
    sessionStorage.removeItem('war-chat-redirect');
    callbacks.navigate('chat', redirect);
  } else {
    callbacks.navigate('chats');
  }
  callbacks.render();
}

export function initSetup() {
  // Show intro field when approval is required
  if (state.requireApproval) {
    document.getElementById('setup-intro-div')?.classList.remove('hidden');
  }

  // Resume pending approval state (e.g. after page refresh while waiting).
  const pendingJson = sessionStorage.getItem('war-chat-pending');
  if (pendingJson) {
    sessionStorage.removeItem('war-chat-pending');
    try {
      const { username, pubkey } = JSON.parse(pendingJson);
      if (username && pubkey) {
        const redirect = sessionStorage.getItem('war-chat-redirect');
        showPendingApproval(username, pubkey, async () => {
          // Re-derive keys from passkey on approval.
          // User will need to sign in again after approval.
          state.currentUsername = username;
          auth.setStoredUsername(username);
          completeLogin(redirect);
        });
      }
    } catch (_) { /* ignore bad JSON */ }
  }

  const btnUsePasskey = document.getElementById('btnUsePasskey');
  if (btnUsePasskey) btnUsePasskey.onclick = () => {
    document.getElementById('setup-mnemonic')?.classList.add('hidden');
    document.getElementById('setup-passkey-div')?.classList.add('hidden');
    document.getElementById('setup-register')?.classList.remove('hidden');
    document.getElementById('setup-register-passkey-hint')?.classList.remove('hidden');
    document.getElementById('btnRegister')?.classList.add('hidden');
    document.getElementById('btnCreatePasskey')?.classList.remove('hidden');
    if (state.requireApproval) {
      document.getElementById('setup-intro-div')?.classList.remove('hidden');
    }
  };

  const btnCreatePasskey = document.getElementById('btnCreatePasskey');
  if (btnCreatePasskey) btnCreatePasskey.onclick = async () => {
    try {
      const usernameInput = document.getElementById('username');
      if (!usernameInput) return;
      const username = usernameInput.value.trim().toLowerCase();
      if (!username) return alert('Enter a username first');
      const intro = document.getElementById('introText')?.value.trim() || '';
      const { credentialId, prfResult, storedKeyB64 } = await passkey.createPasskey(username);
      const kp = await auth.generateKeypairForPasskey();
      const { encrypted, iv } = await passkey.encryptKeypairWithPasskey({ privateJwk: kp.privateJwk, publicJwk: kp.publicJwk }, prfResult);
      await passkey.storePasskeyCredential(credentialId, username, encrypted, iv, storedKeyB64);
      state.keys = { privateKey: kp.privateKey, publicKey: kp.publicKey };
      state.pendingPasskeyCredentialId = credentialId;
      const pubkey = await (await import('./crypto.js')).exportPubkeyToBase64(state.keys.publicKey);

      const redirect = sessionStorage.getItem('war-chat-redirect');
      const onApproved = async () => {
        state.currentUsername = username;
        auth.setStoredUsername(username);
        auth.savePasskeySessionToStorage(username, kp.privateJwk, kp.publicJwk);
        await auth.saveSession(username, 'passkey', null, 'passkey', credentialId);
        state.pendingPasskeyCredentialId = null;
        completeLogin(redirect);
      };

      const result = await registerAndHandleResponse(username, pubkey, intro, onApproved);
      if (result === 'ok') {
        await onApproved();
      }
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
        // Check registration status before proceeding.
        const username = state.currentUsername;
        const keys = state.keys;
        const pubkey = keys?.publicKey
          ? await (await import('./crypto.js')).exportPubkeyToBase64(keys.publicKey)
          : null;
        if (username && pubkey) {
          const checkResp = await fetch(`${API_BASE}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, pubkey }),
          });
          if (checkResp.status === 202) {
            // Pending — clear session so render shows setup view.
            state.currentUsername = null;
            state.keys = null;
            auth.setStoredUsername(null);
            sessionStorage.removeItem('war-chat-passkey-session');
            const redirect = sessionStorage.getItem('war-chat-redirect');
            showPendingApproval(username, pubkey, async () => {
              state.currentUsername = username;
              state.keys = keys;
              auth.setStoredUsername(username);
              completeLogin(redirect);
            });
            callbacks.render();
            return;
          }
          if (checkResp.status === 403) {
            state.currentUsername = null;
            state.keys = null;
            auth.setStoredUsername(null);
            sessionStorage.removeItem('war-chat-passkey-session');
            alert('Your registration request was denied.');
            callbacks.render();
            return;
          }
        }
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
    const raw = (mnemonicEl && mnemonicEl.value) || '';
    const { ok, mnemonic, error } = validateMnemonic(raw);
    if (!ok) {
      showMnemonicError(error);
      return;
    }
    showMnemonicError('');
    let kp;
    try {
      kp = await auth.deriveKeypair(mnemonic);
    } catch (e) {
      showMnemonicError(e.message || 'Invalid phrase. Check your 12 words.');
      return;
    }
    state.keys = kp;
    sessionStorage.setItem(SESSION_MNEMONIC, mnemonic);
    const existingUser = auth.getStoredUsername();
    if (existingUser) {
      const pubkey = await (await import('./crypto.js')).exportPubkeyToBase64(state.keys.publicKey);

      const redirect = sessionStorage.getItem('war-chat-redirect');
      const onApproved = async () => {
        state.currentUsername = existingUser;
        await auth.saveSession(existingUser, kp.seedKey, mnemonic);
        completeLogin(redirect);
      };

      const intro = document.getElementById('introText')?.value.trim() || '';
      const result = await registerAndHandleResponse(existingUser, pubkey, intro, onApproved);
      if (result === 'ok') {
        await onApproved();
      }
    } else {
      document.getElementById('setup-register')?.classList.remove('hidden');
      document.getElementById('setup-register-passkey-hint')?.classList.add('hidden');
      document.getElementById('btnRegister')?.classList.remove('hidden');
      if (state.requireApproval) {
        document.getElementById('setup-intro-div')?.classList.remove('hidden');
      }
    }
  };

  const btnRegister = document.getElementById('btnRegister');
  if (btnRegister) btnRegister.onclick = async () => {
    const usernameInput = document.getElementById('username');
    const username = (usernameInput && usernameInput.value.trim().toLowerCase()) || '';
    if (!username) return alert('Choose a username');
    const pubkey = await (await import('./crypto.js')).exportPubkeyToBase64(state.keys.publicKey);
    const intro = document.getElementById('introText')?.value.trim() || '';

    const redirect = sessionStorage.getItem('war-chat-redirect');
    const onApproved = async () => {
      state.currentUsername = username;
      auth.setStoredUsername(username);
      if (state.pendingPasskeyCredentialId) {
        await passkey.updatePasskeyCredentialUsername(state.pendingPasskeyCredentialId, username);
        await auth.saveSession(username, 'passkey', null, 'passkey', state.pendingPasskeyCredentialId);
        state.pendingPasskeyCredentialId = null;
      } else {
        await auth.saveSession(username, state.keys.seedKey, sessionStorage.getItem(SESSION_MNEMONIC));
      }
      completeLogin(redirect);
    };

    try {
      const result = await registerAndHandleResponse(username, pubkey, intro, onApproved);
      if (result === 'ok') {
        await onApproved();
      }
    } catch (e) {
      alert(e.message || 'Registration failed');
    }
  };
}
