// War Chat - entry point: init, bind setup/modals/send, hashchange, render

import './components/index.js'; // register web components
import { initTheme } from './theme.js';

import { ensureCrypto } from './crypto.js';
import { openDB } from './db.js';
import { state } from './state.js';
import { API_BASE } from './config.js';
import * as auth from './auth.js';
import * as api from './api.js';
import { navigate, render, showNewChatModal, showNewGroupModal, createGroupFromModal, showAddMemberModal, addMemberToGroupFromModal, sendMessageFromInput, leaveGroupAndNavigate, doLogout, deleteChatWithPeer, deleteMessageInChat, renderGroupInvites, renderChatList, getSelectedPeerFromRoute, startVideoChat, getRoute } from './app.js';
import { showNewMeetingModal } from './meeting.js';
import * as groups from './groups.js';
import { initSetup, setSetupCallbacks } from './setup.js';
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

  const config = await api.fetchConfig();
  if (config) state.requireInvite = config.requireInvite === true;

  const params = new URLSearchParams(window.location.search);
  const to = params.get('to') || params.get('u');
  if (to) {
    sessionStorage.setItem('war-chat-redirect', to);
    params.delete('to');
    params.delete('u');
  }
  const invite = params.get('invite');
  if (invite) {
    sessionStorage.setItem('war-chat-invite', invite);
    params.delete('invite');
  }
  if (to || invite) {
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

    const roomRedirect = sessionStorage.getItem('war-chat-room-redirect');
    if (roomRedirect) {
      sessionStorage.removeItem('war-chat-room-redirect');
      window.location.hash = `#room/${roomRedirect}`;
    }
  }

  setSetupCallbacks({ navigate, render, migratePlainMessagesToEncrypted });
  initSetup();

  // Main: New chat / New group / New meeting
  const btnNewChat = document.getElementById('btnNewChat');
  if (btnNewChat) btnNewChat.onclick = () => showNewChatModal();
  const btnNewGroup = document.getElementById('btnNewGroup');
  if (btnNewGroup) btnNewGroup.onclick = () => showNewGroupModal();
  const btnNewMeeting = document.getElementById('btnNewMeeting');
  if (btnNewMeeting) btnNewMeeting.onclick = () => showNewMeetingModal();

  // Header actions (war-chat-header component)
  document.addEventListener('war-chat-header-action', (e) => {
    const action = e.detail?.action;
    if (action === 'back') {
      const v = getRoute().view;
      if (v === 'video' || v === 'room') {
        import('./hrt.js').then((m) => m.endVideoCall());
      } else {
        navigate('chats');
      }
    } else if (action === 'video-chat') {
      const peer = getSelectedPeerFromRoute();
      if (!peer) return;
      if (groups.isGroupPeer(peer)) {
        alert('Video chat is only available for 1:1 chats.');
        return;
      }
      startVideoChat(peer);
    }
    else if (action === 'add-member') showAddMemberModal();
    else if (action === 'leave-group') leaveGroupAndNavigate();
    else if (action === 'new-chat') showNewChatModal();
    else if (action === 'new-group') showNewGroupModal();
    else if (action === 'profile') navigate('profile');
    else if (action === 'logout') {
      const v = getRoute().view;
      if (v === 'video' || v === 'room') {
        import('./hrt.js').then((m) => { m.endVideoCall(); doLogout(); });
      } else {
        doLogout();
      }
    }
    else if (action === 'delete-chat') {
      const param = getSelectedPeerFromRoute();
      if (!param) return;
      const peer = param.startsWith('group/') ? groups.peerFromGroupId(param.slice(6)) : param;
      if (!confirm('Delete this chat and all messages?')) return;
      deleteChatWithPeer(peer);
    }
  });

  // Chat list selection (war-chat-chat-list component)
  document.addEventListener('war-chat-select-peer', (e) => {
    if (e.detail?.peer) navigate('chat', e.detail.peer);
  });

  // Chat list row menu (delete chat, video chat)
  document.addEventListener('war-chat-chat-action', (e) => {
    const { peer, action } = e.detail || {};
    if (!peer) return;
    if (action === 'delete-chat') {
      if (!confirm('Delete this chat and all messages?')) return;
      deleteChatWithPeer(peer);
    } else if (action === 'video-chat') {
      if (groups.isGroupPeer(peer)) {
        alert('Video chat is only available for 1:1 chats.');
        return;
      }
      startVideoChat(peer);
    }
  });

  // Message context menu (delete single message)
  document.addEventListener('war-chat-message-action', (e) => {
    const { action, peer, msgId } = e.detail || {};
    if (action === 'delete' && peer && msgId) deleteMessageInChat(peer, msgId);
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

  // Send message (delegate so Send works from any chat pane instance, e.g. after view changes)
  document.addEventListener('click', (e) => {
    if (e.target && e.target.id === 'btnSend') {
      sendMessageFromInput();
    }
  });
  document.addEventListener('keydown', (e) => {
    if (e.target && e.target.id === 'messageInput' && e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessageFromInput();
    }
  });

  window.addEventListener('hashchange', () => render());

  const footer = document.getElementById('appFooter');
  if (footer) {
    fetch(`${API_BASE}/version`).then((r) => r.ok ? r.json() : {}).then((d) => {
      footer.textContent = d.version ? `Personal Chat ${d.version}` : 'Personal Chat';
    }).catch(() => { footer.textContent = 'Personal Chat'; });
  }

  render();
  initTheme();
}

if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', init);
}
