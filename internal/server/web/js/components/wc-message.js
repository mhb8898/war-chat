// War Chat - single message bubble component

import { formatMessage, escapeHtml } from '../utils.js';

customElements.define('war-chat-message', class WarChatMessage extends HTMLElement {
  static get observedAttributes() {
    return ['from', 'text', 'ts', 'kind'];
  }

  connectedCallback() {
    this.render();
  }

  attributeChangedCallback() {
    if (this.isConnected) this.render();
  }

  render() {
    const from = this.getAttribute('from') || '';
    const text = this.getAttribute('text') || '';
    const kind = this.getAttribute('kind') || 'note'; // sent | received | note
    this.className = 'msg ' + kind;
    const isNote = kind === 'note';
    this.innerHTML = isNote
      ? formatMessage(text)
      : `<span class="meta">${escapeHtml(from)}</span><br>${formatMessage(text)}`;
  }
});
