// War Chat - setup / login view (passkey default, 12-word fallback)

customElements.define('war-chat-setup', class WarChatSetup extends HTMLElement {
  connectedCallback() {
    if (this.innerHTML.trim()) return;
    this.innerHTML = `
      <h2>Welcome</h2>
      <p class="setup-intro">Sign in or create an account with your passkey.</p>
      <div id="setup-passkey-div" class="setup-primary">
        <button id="btnSignInPasskey" class="btn-primary">Log in</button>
        <button id="btnUsePasskey" class="btn-primary btn-secondary">Register</button>
      </div>
      <div id="setup-mnemonic-toggle" class="setup-fallback">
        <button type="button" id="btnToggleMnemonic" class="btn-link">Having trouble with passkey? Use 12-word recovery phrase</button>
      </div>
      <div id="setup-mnemonic" class="hidden setup-mnemonic-box">
        <p class="setup-help">Enter your 12 words from backup, or generate a new phrase below to create a new identity.</p>
        <textarea id="mnemonic" placeholder="word1 word2 word3 ..." rows="3"></textarea>
        <p id="setup-mnemonic-error" class="setup-error hidden"></p>
        <div class="setup-mnemonic-actions">
          <button id="btnGenerate">Generate new phrase</button>
          <button id="btnContinue">Continue</button>
        </div>
      </div>
      <div id="setup-register" class="hidden">
        <h2>Choose username</h2>
        <p id="setup-register-passkey-hint" class="hidden setup-hint">Enter username, then create passkey.</p>
        <input type="text" id="username" placeholder="Username" maxlength="32">
        <div class="setup-register-actions">
          <button id="btnRegister">Register</button>
          <button id="btnCreatePasskey" class="hidden">Create passkey</button>
        </div>
      </div>
    `;
  }
});
