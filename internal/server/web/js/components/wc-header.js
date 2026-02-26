// War Chat - header with title and three-dot menu (Telegram-style)

import { showMenu } from './wc-menu.js';

customElements.define('war-chat-header', class WarChatHeader extends HTMLElement {
  static get observedAttributes() {
    return ['title', 'show-back', 'show-add-member', 'show-leave-group', 'show-new-chat', 'show-profile', 'show-logout'];
  }

  connectedCallback() {
    this.render();
  }

  attributeChangedCallback() {
    if (this.isConnected) this.render();
  }

  buildMenuItems() {
    const showBack = this.hasAttribute('show-back');
    const showAddMember = this.hasAttribute('show-add-member');
    const showLeaveGroup = this.hasAttribute('show-leave-group');
    const showNewChat = this.hasAttribute('show-new-chat');
    const showProfile = this.hasAttribute('show-profile');
    const showLogout = this.hasAttribute('show-logout');
    const items = [];
    if (showNewChat) {
      items.push({ label: 'New chat', action: 'new-chat' });
      items.push({ label: 'New group', action: 'new-group' });
    }
    if (showAddMember) items.push({ label: 'Add member', action: 'add-member' });
    if (showLeaveGroup) items.push({ label: 'Leave group', action: 'leave-group' });
    if (showBack) {
      items.push({ label: 'Video chat', action: 'video-chat' });
      items.push({ label: 'Delete chat', action: 'delete-chat' });
    }
    if (showProfile) items.push({ label: 'Profile', action: 'profile' });
    if (showLogout) items.push({ label: 'Log out', action: 'logout' });
    return items;
  }

  render() {
    const titleText = this.getAttribute('title') || 'War Chat';
    const showBack = this.hasAttribute('show-back');
    const items = this.buildMenuItems();
    this.replaceChildren();
    const h1 = document.createElement('h1');
    h1.textContent = titleText;
    this.appendChild(h1);
    const actions = document.createElement('div');
    actions.className = 'header-actions';
    actions.id = 'headerActions';
    if (showBack) {
      const backBtn = document.createElement('button');
      backBtn.className = 'btn-icon';
      backBtn.setAttribute('data-action', 'back');
      backBtn.title = 'Back';
      backBtn.textContent = '\u2190';
      backBtn.onclick = () => this.dispatchEvent(new CustomEvent('war-chat-header-action', { detail: { action: 'back' }, bubbles: true }));
      actions.appendChild(backBtn);
    }
    if (items.length > 0) {
      const menuBtn = document.createElement('button');
      menuBtn.className = 'btn-icon btn-menu-toggle';
      menuBtn.id = 'headerMenuToggle';
      menuBtn.title = 'Menu';
      menuBtn.textContent = '\u22EE';
      menuBtn.onclick = (e) => {
        e.stopPropagation();
        showMenu(menuBtn, items, (action) => {
          this.dispatchEvent(new CustomEvent('war-chat-header-action', { detail: { action }, bubbles: true }));
        });
      };
      actions.appendChild(menuBtn);
    }
    this.appendChild(actions);
  }
});
