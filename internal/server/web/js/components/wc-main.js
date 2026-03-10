// War Chat - main layout (sidebar + content area)

customElements.define('war-chat-main', class WarChatMain extends HTMLElement {
  connectedCallback() {
    if (this.innerHTML.trim()) return;
    this.innerHTML = `
      <div class="layout-split" id="layoutSplit">
        <aside class="sidebar">
          <div class="new-chat-form">
            <button id="btnNewChat">New chat</button>
            <button id="btnNewGroup">New group</button>
            <button id="btnNewMeeting">New meeting</button>
          </div>
          <war-chat-group-invites id="group-invites-section" class="group-invites-section hidden"></war-chat-group-invites>
          <war-chat-chat-list id="chat-list" class="chat-list"></war-chat-chat-list>
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
