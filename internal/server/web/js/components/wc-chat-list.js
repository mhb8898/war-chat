// War Chat - chat list (conversations) component

import { escapeHtml, formatTime } from '../utils.js';
import { isGroupPeer, groupPeerId } from '../groups.js';
import { showMenu } from './wc-menu.js';

customElements.define('war-chat-chat-list', class WarChatChatList extends HTMLElement {
  constructor() {
    super();
    this._conversations = [];
    this._selectedPeer = null;
    this._currentUsername = null;
  }

  set conversations(value) {
    this._conversations = Array.isArray(value) ? value : [];
    this.render();
  }

  set selectedPeer(value) {
    this._selectedPeer = value;
    this.render();
  }

  set currentUsername(value) {
    this._currentUsername = value;
    this.render();
  }

  connectedCallback() {
    this.render();
  }

  render() {
    const list = this._conversations || [];
    const selected = this._selectedPeer;
    const currentUsername = this._currentUsername;
    const empty = this.querySelector('[data-empty]') || document.createElement('div');
    if (!empty.dataset.empty) {
      empty.dataset.empty = 'true';
      empty.className = 'empty-state hidden';
      empty.textContent = 'No chats yet. Start a new chat above.';
    }
    this.innerHTML = '';
    if (list.length === 0) {
      empty.classList.remove('hidden');
      this.appendChild(empty);
      return;
    }
    empty.classList.add('hidden');
    for (const c of list) {
      const isSelf = c.peer === currentUsername;
      const isGroup = isGroupPeer(c.peer);
      const displayName = isSelf ? 'Saved Messages' : (c.groupName || (isGroup ? 'Group' : c.peer));
      const navParam = isGroup ? 'group/' + groupPeerId(c.peer) : c.peer;
      const li = document.createElement('li');
      li.className = 'chat-row' + (c.peer === selected ? ' selected' : '');
      li.innerHTML = `
        <div class="chat-avatar">${isSelf ? '&#128190;' : (isGroup ? '&#128101;' : (c.peer[0] || '?').toUpperCase())}</div>
        <div class="chat-info">
          <div class="chat-name">${escapeHtml(displayName)}</div>
          <div class="chat-preview">${escapeHtml(c.lastMsg || 'No messages')}</div>
        </div>
        <div class="chat-time">${formatTime(c.lastTs)}</div>
        ${!isSelf ? '<button type="button" class="chat-row-menu-btn btn-icon" title="Options">&#8942;</button>' : ''}
      `;
      const menuBtn = li.querySelector('.chat-row-menu-btn');
      const rowPeer = c.peer;
      li.onclick = (e) => {
        if (e.target.closest('.chat-row-menu-btn')) return;
        this.dispatchEvent(new CustomEvent('war-chat-select-peer', { detail: { peer: navParam }, bubbles: true }));
      };
      if (menuBtn) {
        menuBtn.onclick = (e) => {
          e.stopPropagation();
          e.preventDefault();
          const items = [{ label: 'Delete chat', action: 'delete-chat' }];
          showMenu(menuBtn, items, (action) => {
            this.dispatchEvent(new CustomEvent('war-chat-chat-action', { detail: { peer: rowPeer, action }, bubbles: true }));
          });
        };
      }
      this.appendChild(li);
    }
  }
});
