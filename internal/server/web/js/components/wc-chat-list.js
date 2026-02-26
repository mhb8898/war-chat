// War Chat - chat list (conversations) component

import { formatTime } from '../utils.js';
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
    this.replaceChildren();
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
      const avatar = document.createElement('div');
      avatar.className = 'chat-avatar';
      avatar.textContent = isSelf ? '\u{1F4E6}' : (isGroup ? '\u{1F465}' : (c.peer[0] || '?').toUpperCase());
      const info = document.createElement('div');
      info.className = 'chat-info';
      const nameEl = document.createElement('div');
      nameEl.className = 'chat-name';
      nameEl.textContent = displayName;
      const previewEl = document.createElement('div');
      previewEl.className = 'chat-preview';
      previewEl.textContent = c.lastMsg || 'No messages';
      info.appendChild(nameEl);
      info.appendChild(previewEl);
      const timeEl = document.createElement('div');
      timeEl.className = 'chat-time';
      timeEl.textContent = formatTime(c.lastTs);
      li.appendChild(avatar);
      li.appendChild(info);
      li.appendChild(timeEl);
      const rowPeer = c.peer;
      if (!isSelf) {
        const menuBtn = document.createElement('button');
        menuBtn.type = 'button';
        menuBtn.className = 'chat-row-menu-btn btn-icon';
        menuBtn.title = 'Options';
        menuBtn.textContent = '\u22EE';
        menuBtn.onclick = (e) => {
          e.stopPropagation();
          e.preventDefault();
          const items = [{ label: 'Video chat', action: 'video-chat' }, { label: 'Delete chat', action: 'delete-chat' }];
          showMenu(menuBtn, items, (action) => {
            this.dispatchEvent(new CustomEvent('war-chat-chat-action', { detail: { peer: rowPeer, action }, bubbles: true }));
          });
        };
        li.appendChild(menuBtn);
      }
      li.onclick = (e) => {
        if (e.target.closest('.chat-row-menu-btn')) return;
        this.dispatchEvent(new CustomEvent('war-chat-select-peer', { detail: { peer: navParam }, bubbles: true }));
      };
      this.appendChild(li);
    }
  }
});
