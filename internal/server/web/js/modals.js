// War Chat - modals (new chat, new group, add member)

import { state } from './state.js';
import * as api from './api.js';
import * as groups from './groups.js';
import * as db from './db.js';
import { escapeHtml } from './utils.js';

let callbacks = { navigate: () => {}, render: () => {}, renderChatList: () => {}, getSelectedPeerFromRoute: () => null };

export function setModalsCallbacks(cbs) {
  callbacks = { ...callbacks, ...cbs };
}

let newGroupSelectedUsers = new Set();
let addMemberSelectedUser = null;

export async function showNewChatModal() {
  const modal = document.getElementById('newChatModal');
  const searchInput = document.getElementById('newChatSearchModal');
  if (!modal || !searchInput) return;
  searchInput.value = '';
  modal.setAttribute('open', '');
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
      document.getElementById('newChatModal')?.removeAttribute('open');
      document.getElementById('newChatSearchModal').value = '';
      callbacks.navigate('chat', username);
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
  modal.setAttribute('open', '');
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
    if (modal) modal.removeAttribute('open');
    if (nameInput) nameInput.value = '';
    newGroupSelectedUsers = new Set();
    callbacks.navigate('chat', 'group/' + groupId);
    callbacks.render();
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
  modal.setAttribute('open', '');
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
    if (modal) modal.removeAttribute('open');
    addMemberSelectedUser = null;
    callbacks.renderChatList(callbacks.getSelectedPeerFromRoute());
  } catch (e) {
    alert(e.message || 'Add member failed');
  }
}
