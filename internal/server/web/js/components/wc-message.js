// War Chat - single message bubble component

import { formatMessage, escapeHtml } from '../utils.js';
import { showMenu } from './wc-menu.js';

customElements.define('war-chat-message', class WarChatMessage extends HTMLElement {
  static get observedAttributes() {
    return ['from', 'text', 'ts', 'kind'];
  }

  connectedCallback() {
    this.render();
    this._boundContextMenu = this._handleContextMenu.bind(this);
    this._boundTouchStart = this._handleTouchStart.bind(this);
    this._boundTouchEnd = this._handleTouchEnd.bind(this);
    this.addEventListener('contextmenu', this._boundContextMenu);
    this.addEventListener('touchstart', this._boundTouchStart, { passive: true });
    this.addEventListener('touchend', this._boundTouchEnd);
    this.addEventListener('touchcancel', this._boundTouchEnd);
  }

  disconnectedCallback() {
    this.removeEventListener('contextmenu', this._boundContextMenu);
    this.removeEventListener('touchstart', this._boundTouchStart);
    this.removeEventListener('touchend', this._boundTouchEnd);
    this.removeEventListener('touchcancel', this._boundTouchEnd);
    if (this._longPressTimer) clearTimeout(this._longPressTimer);
  }

  _handleContextMenu(e) {
    e.preventDefault();
    this._openMessageMenu();
  }

  _longPressTimer = null;
  _handleTouchStart() {
    if (this._longPressTimer) clearTimeout(this._longPressTimer);
    this._longPressTimer = setTimeout(() => {
      this._longPressTimer = null;
      this._openMessageMenu();
    }, 500);
  }
  _handleTouchEnd() {
    if (this._longPressTimer) {
      clearTimeout(this._longPressTimer);
      this._longPressTimer = null;
    }
  }

  _openMessageMenu() {
    const peer = this.dataset.peer;
    const msgId = this.dataset.msgId;
    if (!peer) return;
    showMenu(this, [{ label: 'Delete', action: 'delete' }], (action) => {
      if (action === 'delete') {
        this.dispatchEvent(new CustomEvent('war-chat-message-action', {
          detail: { action: 'delete', peer, msgId },
          bubbles: true,
        }));
      }
    });
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
