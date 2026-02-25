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
    if (showBack) items.push({ label: 'Delete chat', action: 'delete-chat' });
    if (showProfile) items.push({ label: 'Profile', action: 'profile' });
    if (showLogout) items.push({ label: 'Log out', action: 'logout' });
    return items;
  }

  render() {
    const title = this.getAttribute('title') || 'War Chat';
    const showBack = this.hasAttribute('show-back');
    const items = this.buildMenuItems();
    let html = `<h1>${title}</h1><div class="header-actions" id="headerActions">`;
    if (showBack) html += '<button class="btn-icon" data-action="back" title="Back">&#8592;</button>';
    if (items.length > 0) {
      html += '<button class="btn-icon btn-menu-toggle" id="headerMenuToggle" title="Menu">&#8942;</button>';
    }
    html += '</div>';
    this.innerHTML = html;
    const backBtn = this.querySelector('[data-action="back"]');
    if (backBtn) {
      backBtn.onclick = () => this.dispatchEvent(new CustomEvent('war-chat-header-action', { detail: { action: 'back' }, bubbles: true }));
    }
    const menuBtn = this.querySelector('#headerMenuToggle');
    if (menuBtn && items.length > 0) {
      menuBtn.onclick = (e) => {
        e.stopPropagation();
        showMenu(menuBtn, items, (action) => {
          this.dispatchEvent(new CustomEvent('war-chat-header-action', { detail: { action }, bubbles: true }));
        });
      };
    }
  }
});
