// War Chat - profile view (link, QR, recovery, backup)

customElements.define('war-chat-profile', class WarChatProfile extends HTMLElement {
  connectedCallback() {
    if (this.innerHTML.trim()) return;
    this.innerHTML = `
      <div class="profile-inner">
        <h2>Profile</h2>
        <div class="profile-section">
          <p class="profile-section-title">Account</p>
          <p><strong>Username:</strong> <span id="profileUsername"></span></p>
          <p>Share this link so others can message you:</p>
          <div class="link-box" id="chatLink"></div>
          <button id="btnCopyLink">Copy link</button>
          <div id="qrcode"></div>
        </div>
        <div class="profile-section" id="profile-recovery-section">
          <p class="profile-section-title">Recovery phrase</p>
          <p>Your 12-word phrase. Save it to restore on another device.</p>
          <button id="btnShowMnemonic">Show recovery phrase</button>
          <div id="mnemonicDisplay" class="link-box hidden"></div>
        </div>
        <div class="profile-section hidden" id="profile-passkey-section">
          <p class="profile-section-title">Recovery phrase</p>
          <p>You use a passkey. Add a recovery phrase for backup?</p>
          <button id="btnAddRecoveryPhrase">Add recovery phrase as backup</button>
        </div>
        <div class="profile-section hidden" id="profile-add-passkey-section">
          <p class="profile-section-title">Passkey</p>
          <p>Add passkey for easier sign-in on this device.</p>
          <button id="btnAddPasskey">Add passkey</button>
        </div>
        <div class="profile-section">
          <p class="profile-section-title">Use on another device</p>
          <p>Export backup (encrypted). On the new device, enter your phrase and restore.</p>
          <button id="btnExportBackup">Export backup</button>
          <p>Restore: enter your 12-word phrase and paste the backup:</p>
          <textarea id="restoreBackup" placeholder="Paste backup here" rows="2"></textarea>
          <button id="btnRestoreBackup">Restore from backup</button>
        </div>
        <div class="profile-section">
          <p class="profile-section-title">Danger zone</p>
          <button id="btnDeleteMyAccount" class="btn-danger">Delete my account</button>
          <p class="profile-danger-hint">This will remove your username from the server and all local data on this device. You can create a new account (same or different name) later.</p>
        </div>
      </div>
    `;
  }
});
