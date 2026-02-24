// War Chat - chat pane (messages container + input bar)

customElements.define('war-chat-chat-pane', class WarChatChatPane extends HTMLElement {
  connectedCallback() {
    if (this.innerHTML.trim()) return;
    this.innerHTML = `
      <div id="messages"><div class="messages-inner"></div></div>
      <div class="input-bar">
        <textarea id="messageInput" placeholder="Type a message..." rows="1"></textarea>
        <button id="btnSend">Send</button>
      </div>
    `;
  }
});
