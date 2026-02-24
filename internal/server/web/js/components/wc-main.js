// War Chat - main layout (sidebar + content area)

customElements.define('war-chat-main', class WarChatMain extends HTMLElement {
  connectedCallback() {
    if (this.innerHTML.trim()) return;
    this.innerHTML = `
      <div class="layout-split" id="layoutSplit">
        <aside class="sidebar">
          <div class="new-chat-form">
            <button id="btnNewChat" style="width:100%">New chat</button>
            <button id="btnNewGroup" style="width:100%;margin-top:0.25rem">New group</button>
          </div>
          <div id="group-invites-section" class="group-invites-section hidden" data-testid="group-invites-section">
            <div class="group-invites-title">Group invites</div>
            <ul id="group-invites-list" class="group-invites-list"></ul>
          </div>
          <ul id="chat-list" class="chat-list"></ul>
          <div id="chat-list-empty" class="empty-state hidden">No chats yet. Start a new chat above.</div>
        </aside>
        <div class="content-area">
          <div id="chat-pane" class="view-chat">
            <div id="messages"><div class="messages-inner"></div></div>
            <div class="input-bar">
              <textarea id="messageInput" placeholder="Type a message..." rows="1"></textarea>
              <button id="btnSend">Send</button>
            </div>
          </div>
          <div id="chat-empty" class="empty-state" style="flex:1;display:flex;align-items:center;justify-content:center;">Select a chat or start a new one</div>
        </div>
      </div>
    `;
  }
});
