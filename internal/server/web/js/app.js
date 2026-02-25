// War Chat - thin app coordinator (routing, view visibility, DOM updates)

import { state } from './state.js';
import { getRoute, navigate } from './router.js';
import * as auth from './auth.js';
import * as db from './db.js';
import * as groups from './groups.js';
import * as ws from './ws.js';
import { resolveInMain } from './dom.js';
import * as profile from './profile.js';
import * as modals from './modals.js';
import { resetSetupView } from './setup.js';

profile.setPostRestoreCallback((redirect) => {
  if (redirect) navigate('chat', redirect);
  else navigate('chats');
  render();
});

modals.setModalsCallbacks({
  navigate,
  render,
  renderChatList,
  getSelectedPeerFromRoute,
});

export { navigate, getRoute };
export { showNewChatModal, showNewGroupModal, showAddMemberModal, createGroupFromModal, addMemberToGroupFromModal } from './modals.js';

export function getSelectedPeerFromRoute() {
  const { view, param } = getRoute();
  if (view !== 'chat' || !param) return null;
  if (param === 'group') return null;
  return param.startsWith('group/') ? groups.peerFromGroupId(param.slice(6)) : param;
}

function getMessagesContainer() {
  return resolveInMain('messages');
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

// --- Render helpers ---

export function renderMessage(m, isNoteToSelf) {
  const container = getMessagesContainer();
  const inner = getMessagesInner();
  if (!container || !inner) return;
  const isSelf = m.peer === state.currentUsername;
  const kind = (isSelf || isNoteToSelf || m.from === '_system') ? 'note' : (m.from === state.currentUsername ? 'sent' : 'received');
  const el = document.createElement('war-chat-message');
  el.setAttribute('from', m.from || '');
  el.setAttribute('text', m.text || '');
  el.setAttribute('kind', kind);
  el.dataset.peer = m.peer || '';
  el.dataset.msgId = m.id || '';
  inner.appendChild(el);
  container.scrollTop = container.scrollHeight;
}

export async function renderGroupInvites() {
  const el = resolveInMain('group-invites-section');
  if (!el || el.tagName !== 'WAR-CHAT-GROUP-INVITES') return;
  const invites = await db.getPendingGroupInvites();
  el.invites = invites;
}

export async function renderChatList(selectedPeer) {
  const chatListEl = resolveInMain('chat-list');
  if (!chatListEl || chatListEl.tagName !== 'WAR-CHAT-CHAT-LIST') return;
  await renderGroupInvites();
  const convos = await db.getConversations();
  chatListEl.conversations = convos;
  chatListEl.selectedPeer = selectedPeer;
  chatListEl.currentUsername = state.currentUsername;
}

export async function renderMainView(selectedPeer) {
  const layout = resolveInMain('layoutSplit');
  const chatPane = resolveInMain('chat-pane');
  const chatEmpty = resolveInMain('chat-empty');
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
      const kind = isSelf || m.from === '_system' ? 'note' : (m.from === state.currentUsername ? 'sent' : 'received');
      const el = document.createElement('war-chat-message');
      el.setAttribute('from', m.from || '');
      el.setAttribute('text', m.text || '');
      el.setAttribute('kind', kind);
      el.dataset.peer = recipient;
      el.dataset.msgId = m.id || '';
      inner.appendChild(el);
    });
    container.scrollTop = container.scrollHeight;
  }
}

export function showView(name, param) {
  document.querySelectorAll('.view').forEach((v) => v.classList.remove('active'));
  const el = document.getElementById('view-' + name);
  if (el) el.classList.add('active');

  document.body.classList.toggle('profile-active', name === 'profile');

  const headerEl = document.getElementById('header');
  const headerWrapper = headerEl?.closest('header');

  if (name === 'setup') {
    if (headerWrapper) headerWrapper.classList.add('hidden');
  } else {
    if (headerWrapper) headerWrapper.classList.remove('hidden');
  }

  if (name === 'main') {
    ws.connectWS();
    let headerTitle = 'War Chat';
    if (param) {
      if (param === state.currentUsername) headerTitle = 'Saved Messages';
      else if (groups.isGroupPeer(param)) {
        headerTitle = 'Group';
        db.getGroup(groups.groupPeerId(param)).then((g) => {
          if (headerEl && g) headerEl.setAttribute('title', g.name);
        });
      } else headerTitle = param;
    }
    if (headerEl) {
      headerEl.setAttribute('title', headerTitle);
      headerEl.toggleAttribute('show-back', !!param);
      headerEl.toggleAttribute('show-add-member', !!(param && groups.isGroupPeer(param)));
      headerEl.toggleAttribute('show-leave-group', !!(param && groups.isGroupPeer(param)));
      const isMobile = typeof window !== 'undefined' && window.matchMedia('(max-width: 768px)').matches;
      headerEl.toggleAttribute('show-new-chat', isMobile && !param);
      headerEl.setAttribute('show-profile', '');
      headerEl.setAttribute('show-logout', '');
    }
    const layoutSplit = resolveInMain('layoutSplit');
    const chatPane = resolveInMain('chat-pane');
    const chatEmpty = resolveInMain('chat-empty');
    if (layoutSplit) layoutSplit.classList.toggle('has-chat', !!param);
    if (chatPane) chatPane.style.display = param ? 'flex' : 'none';
    if (chatEmpty) chatEmpty.style.display = param ? 'none' : 'flex';
  } else if (name === 'profile') {
    if (headerEl) {
      headerEl.setAttribute('title', 'Profile');
      headerEl.removeAttribute('show-back');
      headerEl.removeAttribute('show-add-member');
      headerEl.removeAttribute('show-leave-group');
      headerEl.removeAttribute('show-new-chat');
      headerEl.removeAttribute('show-profile');
      headerEl.setAttribute('show-back', '');
      headerEl.setAttribute('show-logout', '');
    }
  } else {
    if (headerEl) {
      headerEl.removeAttribute('show-back');
      headerEl.removeAttribute('show-add-member');
      headerEl.removeAttribute('show-leave-group');
      headerEl.removeAttribute('show-new-chat');
      headerEl.removeAttribute('show-profile');
      headerEl.removeAttribute('show-logout');
    }
  }
}

async function leaveGroupAndNavigate() {
  if (!groups.isGroupPeer(state.currentRecipient)) return;
  if (!confirm('Leave this group? You will stop receiving messages.')) return;
  await groups.leaveGroup();
  navigate('chats');
  render();
}

export { leaveGroupAndNavigate };

/** Delete all messages with a peer (chat or user). Caller should navigate away if viewing that chat. */
export async function deleteChatWithPeer(peer) {
  await db.deleteMessagesWithPeer(peer);
  const current = getSelectedPeerFromRoute();
  const currentPeer = current && (current.startsWith('group/') ? groups.peerFromGroupId(current.slice(6)) : current);
  if (currentPeer === peer) {
    navigate('chats');
  }
  render();
}

/** Delete a single message in the current conversation. */
export async function deleteMessageInChat(peer, msgId) {
  await db.deleteMessage(peer, msgId);
  if (state.currentRecipient === peer) {
    const msgs = await db.getMessages(peer);
    const container = getMessagesContainer();
    const inner = getMessagesInner();
    if (container && inner) {
      inner.innerHTML = '';
      const isSelf = peer === state.currentUsername;
      msgs.forEach((m) => {
        const kind = isSelf || m.from === '_system' ? 'note' : (m.from === state.currentUsername ? 'sent' : 'received');
        const el = document.createElement('war-chat-message');
        el.setAttribute('from', m.from || '');
        el.setAttribute('text', m.text || '');
        el.setAttribute('kind', kind);
        el.dataset.peer = peer;
        el.dataset.msgId = m.id || '';
        inner.appendChild(el);
      });
      container.scrollTop = container.scrollHeight;
    }
  }
}

function doLogout() {
  auth.logout();
  resetSetupView();
  navigate('setup');
  render();
}

export { doLogout };

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
      profile.renderProfile();
      break;
    default:
      showView('main');
      renderMainView(null);
  }
}

// --- Send (called from main.js) ---

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
