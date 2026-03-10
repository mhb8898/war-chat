// War Chat - setup / login view (passkey + mnemonic side-by-side)

customElements.define('war-chat-setup', class WarChatSetup extends HTMLElement {
  connectedCallback() {
    if (this.innerHTML.trim()) return;
    const tpl = [
      '<div class="setup-card">',
      '  <div class="setup-brand">',
      '    <h1>Personal Chat</h1>',
      '    <p>End-to-end encrypted messaging</p>',
      '  </div>',
      '  <div class="setup-cols">',
      '    <div id="setup-passkey-div" class="setup-col">',
      '      <h3>Passkey</h3>',
      '      <p class="setup-help">Requires internet to set up.</p>',
      '      <div class="setup-passkey-actions">',
      '        <button id="btnSignInPasskey" class="btn-primary">Log in</button>',
      '        <button id="btnUsePasskey" class="btn-primary btn-secondary">Register</button>',
      '      </div>',
      '    </div>',
      '    <div class="setup-divider" aria-hidden="true">or</div>',
      '    <div id="setup-mnemonic" class="setup-col">',
      '      <h3>12-word phrase</h3>',
      '      <p class="setup-help">Works offline. Enter existing phrase or generate a new one.</p>',
      '      <textarea id="mnemonic" placeholder="word1 word2 word3 ..." rows="3"></textarea>',
      '      <p id="setup-mnemonic-error" class="setup-error hidden"></p>',
      '      <div class="setup-mnemonic-actions">',
      '        <button id="btnGenerate">Generate</button>',
      '        <button id="btnContinue">Continue</button>',
      '      </div>',
      '    </div>',
      '  </div>',
      '  <div id="setup-register" class="hidden">',
      '    <div class="setup-register-card">',
      '      <h2>Choose username</h2>',
      '      <p id="setup-register-passkey-hint" class="hidden setup-hint">Enter username, then create passkey.</p>',
      '      <input type="text" id="username" placeholder="Username" maxlength="32">',
      '      <div id="setup-invite-div" class="hidden">',
      '        <input type="text" id="inviteToken" placeholder="Invite token" maxlength="64" autocomplete="off">',
      '      </div>',
      '      <div class="setup-register-actions">',
      '        <button id="btnRegister">Register</button>',
      '        <button id="btnCreatePasskey" class="hidden">Create passkey</button>',
      '      </div>',
      '    </div>',
      '  </div>',
      '</div>',
    ].join('\n');
    this.innerHTML = tpl;
  }
});
