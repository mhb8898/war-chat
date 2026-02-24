// War Chat - group invites list (accept/decline)

import { escapeHtml } from '../utils.js';

customElements.define('war-chat-group-invites', class WarChatGroupInvites extends HTMLElement {
  constructor() {
    super();
    this._invites = [];
  }

  set invites(value) {
    this._invites = Array.isArray(value) ? value : [];
    this.render();
  }

  connectedCallback() {
    this.render();
  }

  render() {
    const list = this._invites || [];
    const section = this;
    let title = this.querySelector('.group-invites-title');
    let ul = this.querySelector('ul');
    if (!title) {
      title = document.createElement('div');
      title.className = 'group-invites-title';
      title.textContent = 'Group invites';
    }
    if (!ul) {
      ul = document.createElement('ul');
      ul.className = 'group-invites-list';
    }

    if (list.length === 0) {
      section.classList.add('hidden');
      ul.innerHTML = '';
      if (!title.parentNode) section.appendChild(title);
      if (!ul.parentNode) section.appendChild(ul);
      return;
    }

    section.classList.remove('hidden');
    section.dataset.testid = 'group-invites-section';
    ul.innerHTML = '';
    for (const inv of list) {
      const li = document.createElement('li');
      li.className = 'group-invite-row';
      li.innerHTML = `
        <div class="group-invite-info">
          <div class="group-invite-text">${escapeHtml(inv.from)} invited you to "${escapeHtml(inv.name)}"</div>
        </div>
        <div class="group-invite-actions">
          <button type="button" data-action="accept" data-testid="group-invite-accept" data-group-id="${escapeHtml(inv.id)}">Accept</button>
          <button type="button" data-action="decline" data-testid="group-invite-decline" data-group-id="${escapeHtml(inv.id)}">Decline</button>
        </div>
      `;
      li.querySelector('[data-action="accept"]').onclick = (e) => {
        e.stopPropagation();
        this.dispatchEvent(new CustomEvent('war-chat-group-invite-accept', { detail: { invite: inv }, bubbles: true }));
      };
      li.querySelector('[data-action="decline"]').onclick = (e) => {
        e.stopPropagation();
        this.dispatchEvent(new CustomEvent('war-chat-group-invite-decline', { detail: { invite: inv }, bubbles: true }));
      };
      ul.appendChild(li);
    }
    if (!ul.parentNode) section.appendChild(ul);
  }
});
