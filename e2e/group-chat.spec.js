// @ts-check
const { test, expect } = require('@playwright/test');

const USER_ALICE = 'e2e-alice-' + Date.now();
const USER_BOB = 'e2e-bob-' + Date.now();
const GROUP_NAME = 'E2E Test Group';

async function registerUser(page, username) {
  await expect(page.locator('#view-setup')).toBeVisible();
  await page.locator('#btnGenerate').click();
  await page.waitForTimeout(300);
  await page.locator('#btnContinue').click();
  await expect(page.locator('#username')).toBeVisible({ timeout: 5000 });
  await page.locator('#username').fill(username);
  await page.locator('#btnRegister').click();
  await expect(page.locator('#chat-list')).toBeVisible({ timeout: 10000 });
  // Ensure main view and sidebar are ready (group-invites-section lives in sidebar)
  await expect(page.locator('#view-main.active')).toBeVisible({ timeout: 5000 });
  await expect(page.locator('.sidebar')).toBeVisible({ timeout: 5000 });
}

test.describe('Group chat E2E', () => {
  test('app loads and registration works', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('#view-setup')).toBeVisible();
    await page.locator('#btnGenerate').click();
    await page.waitForTimeout(200);
    await page.locator('#btnContinue').click();
    await expect(page.locator('#username')).toBeVisible({ timeout: 5000 });
    await page.locator('#username').fill('e2e-smoke-' + Date.now());
    await page.locator('#btnRegister').click();
    await expect(page.locator('#chat-list')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('#btnNewGroup')).toBeVisible();
  });

  test('two users: create group, invite, accept, send message', async ({ browser }) => {
    const contextA = await browser.newContext();
    const contextB = await browser.newContext();
    const pageA = await contextA.newPage();
    const pageB = await contextB.newPage();

    try {
      await pageA.goto('/');
      await pageB.goto('/');

      await registerUser(pageA, USER_ALICE);
      await registerUser(pageB, USER_BOB);

      // Allow both WebSockets to connect and register so the server can deliver the invite to Bob
      await pageA.waitForTimeout(4000);

      await pageA.locator('#btnNewGroup').click();
      await expect(pageA.locator('#newGroupModal')).toHaveClass(/visible/);
      await pageA.locator('#newGroupName').fill(GROUP_NAME);

      const bobRow = pageA.locator('#newGroupUserList li').filter({ hasText: USER_BOB }).first();
      await expect(bobRow).toBeVisible({ timeout: 5000 });
      await bobRow.click();

      await pageA.locator('#btnNewGroupCreate').click();
      await expect(pageA.locator('#newGroupModal')).not.toHaveClass(/visible/);

      await expect(pageA.locator('#messageInput')).toBeVisible({ timeout: 5000 });

      // Wait for Bob to receive the group invite: section is in DOM but hidden until invites exist
      const invitesSection = pageB.locator('#group-invites-section');
      await invitesSection.waitFor({ state: 'attached', timeout: 15000 });
      await expect(invitesSection).not.toHaveClass(/hidden/, { timeout: 25000 });
      await expect(invitesSection).toContainText(USER_ALICE);
      await expect(invitesSection).toContainText(GROUP_NAME);

      const acceptBtn = pageB.locator('#group-invites-section [data-action="accept"]').first();
      await acceptBtn.click();

      await expect(pageB.locator('#group-invites-section')).toHaveClass(/hidden/, { timeout: 10000 });

      await expect(pageB.locator('#messageInput')).toBeVisible({ timeout: 5000 });
      await expect(pageB.locator('.messages-inner')).toContainText('You joined the group');

      // Send message after Bob has joined so his client can decrypt and display it
      await pageA.locator('#messageInput').fill('Hello from alice');
      await pageA.locator('#btnSend').click();

      await expect(pageB.locator('.messages-inner')).toContainText('Hello from alice');
    } finally {
      await contextA.close();
      await contextB.close();
    }
  });

  test('decline group invite removes it', async ({ browser }) => {
    const contextA = await browser.newContext();
    const contextB = await browser.newContext();
    const pageA = await contextA.newPage();
    const pageB = await contextB.newPage();

    try {
      await pageA.goto('/');
      await pageB.goto('/');

      const userA = 'e2e-decline-a-' + Date.now();
      const userB = 'e2e-decline-b-' + Date.now();

      await registerUser(pageA, userA);
      await registerUser(pageB, userB);

      await pageA.waitForTimeout(4000);

      await pageA.locator('#btnNewGroup').click();
      await pageA.locator('#newGroupName').fill('Decline Test');
      await pageA.locator('#newGroupUserList li').filter({ hasText: userB }).first().click();
      await pageA.locator('#btnNewGroupCreate').click();

      // Wait for Bob to receive the invite (section becomes visible when invites exist)
      const declineInvitesSection = pageB.locator('#group-invites-section');
      await declineInvitesSection.waitFor({ state: 'attached', timeout: 15000 });
      await expect(declineInvitesSection).not.toHaveClass(/hidden/, { timeout: 25000 });

      await pageB.locator('#group-invites-section [data-action="decline"]').first().click();

      await expect(pageB.locator('#group-invites-section')).toHaveClass(/hidden/, { timeout: 10000 });
      await expect(pageB.locator('#group-invites-list li')).toHaveCount(0);
    } finally {
      await contextA.close();
      await contextB.close();
    }
  });
});
