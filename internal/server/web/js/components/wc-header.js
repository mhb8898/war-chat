// War Chat - header with title and action buttons

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

  render() {
    const title = this.getAttribute('title') || 'War Chat';
    const showBack = this.hasAttribute('show-back');
    const showAddMember = this.hasAttribute('show-add-member');
    const showLeaveGroup = this.hasAttribute('show-leave-group');
    const showNewChat = this.hasAttribute('show-new-chat');
    const showProfile = this.hasAttribute('show-profile');
    const showLogout = this.hasAttribute('show-logout');
    let html = `<h1>${title}</h1><div class="header-actions" id="headerActions">`;
    if (showBack) html += '<button class="btn-icon" data-action="back" title="Back">&#8592;</button>';
    if (showAddMember) html += '<button class="btn-icon" data-action="add-member" title="Add member">&#10133;</button>';
    if (showLeaveGroup) html += '<button class="btn-icon" data-action="leave-group" title="Leave group">&#128473;</button>';
    if (showNewChat) html += '<button class="btn-icon" data-action="new-chat" title="New chat">&#10133;</button>';
    if (showProfile) html += '<button class="btn-icon" data-action="profile" title="Profile">&#9776;</button>';
    if (showLogout) html += '<button class="btn-icon" data-action="logout" title="Log out">&#128274;</button>';
    html += '</div>';
    this.innerHTML = html;
    this.querySelectorAll('[data-action]').forEach((btn) => {
      btn.onclick = () => this.dispatchEvent(new CustomEvent('war-chat-header-action', { detail: { action: btn.dataset.action }, bubbles: true }));
    });
  }
});
