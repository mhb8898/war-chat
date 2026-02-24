// War Chat - setup / login view (mnemonic, passkey, register)

customElements.define('war-chat-setup', class WarChatSetup extends HTMLElement {
  connectedCallback() {
    if (this.innerHTML.trim()) return;
    this.innerHTML = `
      <h2>Welcome</h2>
      <div id="setup-passkey-div">
        <p>Sign in or create account with passkey:</p>
        <button id="btnSignInPasskey">Sign in with passkey</button>
        <button id="btnUsePasskey">Create passkey</button>
      </div>
      <div id="setup-mnemonic">
        <p style="margin:1rem 0 0.5rem;opacity:0.8">Or use 12-word recovery phrase:</p>
        <textarea id="mnemonic" placeholder="word1 word2 word3 ..." rows="3"></textarea>
        <button id="btnGenerate">Generate new identity</button>
        <button id="btnContinue">Continue</button>
      </div>
      <div id="setup-register" class="hidden">
        <h2>Choose username</h2>
        <p id="setup-register-passkey-hint" class="hidden" style="opacity:0.8;font-size:0.9rem">Enter username, then create passkey.</p>
        <input type="text" id="username" placeholder="Username" maxlength="32">
        <button id="btnRegister">Register</button>
        <button id="btnCreatePasskey" class="hidden">Create passkey</button>
      </div>
    `;
  }
});
