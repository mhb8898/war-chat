// War Chat - base modal with slot for content

customElements.define('war-chat-modal', class WarChatModal extends HTMLElement {
  static get observedAttributes() {
    return ['open'];
  }

  connectedCallback() {
    if (!this.shadowRoot) {
      this.attachShadow({ mode: 'open' });
      this.shadowRoot.innerHTML = `
        <style>
          :host {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(0,0,0,0.6);
            backdrop-filter: blur(4px);
            -webkit-backdrop-filter: blur(4px);
            z-index: 100;
            align-items: center;
            justify-content: center;
            padding: 1.5rem;
          }
          :host([open]) { display: flex; }
          .modal-inner {
            background: var(--surface-2, #181828);
            border: 1px solid var(--border, #23233a);
            border-radius: 20px;
            padding: 1.75rem;
            max-width: 360px;
            width: 100%;
            box-shadow: 0 24px 64px rgba(0,0,0,0.45);
          }
          ::slotted(*) { margin: 0; }
        </style>
        <div class="modal-inner">
          <slot></slot>
        </div>
      `;
    }
  }

  attributeChangedCallback(name, oldVal, newVal) {
    if (name === 'open') {
      this.classList.toggle('visible', this.hasAttribute('open'));
    }
  }

  open() {
    this.setAttribute('open', '');
  }

  close() {
    this.removeAttribute('open');
  }
});
