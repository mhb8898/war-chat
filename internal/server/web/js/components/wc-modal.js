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
          :host { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.6); z-index: 100; align-items: center; justify-content: center; padding: 1rem; }
          :host([open]) { display: flex; }
          .modal-inner { background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 1.5rem; max-width: 320px; width: 100%; }
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
