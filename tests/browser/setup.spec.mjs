import { test, expect } from '@playwright/test';
import { mockAPI, client } from './fixtures.mjs';
import en from '../../panel/web/src/locales/en.json' with { type: 'json' };
import ru from '../../panel/web/src/locales/ru.json' with { type: 'json' };

for (const [lang, t] of Object.entries({ en, ru })) {
  test.describe(lang, () => {
    let errors;
    const wizard = page => page.getByRole('region', { name: t['setup.title'], exact: true });
    async function next(page) { await wizard(page).getByRole('button', { name: t['setup.next'], exact: true }).click(); }
    async function importStep(page) { await next(page); await next(page); }
    test.beforeEach(async ({ page }) => {
      await page.addInitScript(lang => {
        localStorage.setItem('vt-lang', lang);
        Object.defineProperty(navigator, 'clipboard', { configurable: true, value: {
          writeText: async () => { throw new DOMException('Clipboard denied', 'NotAllowedError'); }
        }});
      }, lang);
      errors = await mockAPI(page);
      await page.goto('/#clients');
      await expect(wizard(page)).toBeVisible();
    });
    test.afterEach(async () => { if (errors) expect(errors).toEqual([]); });

    test('complete four steps; require both manual confirmations', async ({ page }) => {
      await expect(wizard(page).getByRole('button', { name: t['setup.back'], exact: true })).toBeDisabled();
      await importStep(page); await next(page);
      const done = wizard(page).getByRole('button', { name: t['setup.confirm'], exact: true });
      await expect(done).toBeDisabled();
      await page.getByLabel(t['setup.opened'], { exact: true }).check();
      await expect(done).toBeDisabled();
      await page.getByLabel(t['setup.transfer'], { exact: true }).check();
      await done.click();
      await expect(wizard(page).getByRole('status')).toHaveText(t['setup.done']);
      await page.getByLabel(t['setup.opened'], { exact: true }).uncheck();
      await expect(wizard(page).getByRole('status')).toHaveCount(0);
    });

    test('denied clipboard shows manual copy; global hide removes text and QR', async ({ page }) => {
      await importStep(page);
      await wizard(page).getByRole('button', { name: t['setup.reveal'], exact: true }).click();
      await expect(wizard(page).getByRole('img')).toBeVisible();
      await wizard(page).getByRole('button', { name: t['common.copy'].replace('{what}', t['setup.format.vless']), exact: true }).click();
      await expect(wizard(page).getByRole('textbox')).toHaveValue(client().vless.link);
      // The client-card control must hide the wizard too, including fallback textarea.
      await page.getByRole('region', { name: 'main', exact: true }).getByRole('button', { name: t['cl.hideSecrets'], exact: true }).first().click();
      await expect(wizard(page).getByRole('img')).toHaveCount(0);
      await expect(wizard(page).getByRole('textbox')).toHaveCount(0);
      await expect(wizard(page)).not.toContainText(client().vless.link);
    });

    test('missing Clipboard API offers a selectable manual payload', async ({ page }) => {
      await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined }));
      await importStep(page);
      await wizard(page).getByRole('button', { name: t['common.copy'].replace('{what}', t['setup.format.vless']), exact: true }).click();
      await expect(wizard(page).getByRole('textbox')).toHaveValue(client().vless.link);
    });

    test('disabled client cannot proceed through the connection guide', async ({ page }) => {
      await page.route('**/api/clients/alice', route => route.fulfill({ json: client('alice', true) }));
      await page.getByRole('button').filter({ hasText: 'alice' }).click();
      await expect(wizard(page)).toContainText(t['cl.imp.disabled']);
      await expect(wizard(page).getByRole('combobox')).toHaveCount(0);
      await expect(wizard(page).getByRole('button', { name: t['setup.next'], exact: true })).toHaveCount(0);
    });

    test('successful clipboard copies the payload while it remains masked', async ({ page }) => {
      await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', { configurable: true, value: {
        writeText: async value => { window.copiedPayload = value; }
      }}));
      await importStep(page);
      await wizard(page).getByRole('button', { name: t['common.copy'].replace('{what}', t['setup.format.vless']), exact: true }).click();
      await expect.poll(() => page.evaluate(() => window.copiedPayload)).toBe(client().vless.link);
      await expect(wizard(page).getByRole('textbox')).toHaveCount(0);
      await expect(wizard(page)).not.toContainText(client().vless.link);
    });

    test('router JSON download contains the selected account; changing format resets reveal', async ({ page }) => {
      await page.getByLabel(t['setup.devicePrompt'], { exact: true }).selectOption('router');
      await next(page);
      await page.getByLabel(t['setup.appPrompt'], { exact: true }).selectOption('awg');
      await next(page);
      const download = page.waitForEvent('download');
      await wizard(page).getByRole('button', { name: t['setup.download'], exact: true }).click();
      const file = await download;
      expect(file.suggestedFilename()).toBe('Veiltrium-Test-main-awg.json');
      const stream = await file.createReadStream(); const chunks = [];
      for await (const chunk of stream) chunks.push(chunk);
      expect(JSON.parse(Buffer.concat(chunks).toString())).toEqual(client().hysteria2.awg_group);
      await wizard(page).getByRole('button', { name: t['setup.reveal'], exact: true }).click();
      await wizard(page).getByRole('button', { name: t['setup.back'], exact: true }).click();
      await page.getByLabel(t['setup.appPrompt'], { exact: true }).selectOption('vless');
      await next(page);
      await expect(wizard(page).getByRole('img')).toHaveCount(0);
    });

    test('switching clients clears revealed data and restarts the guide', async ({ page }) => {
      await importStep(page);
      await wizard(page).getByRole('button', { name: t['setup.reveal'], exact: true }).click();
      await page.getByRole('button').filter({ hasText: 'alice' }).click();
      await expect(page.getByLabel(t['setup.devicePrompt'], { exact: true })).toBeVisible();
      await importStep(page);
      await expect(wizard(page).getByRole('img')).toHaveCount(0);
      await wizard(page).getByRole('button', { name: t['setup.reveal'], exact: true }).click();
      await expect(wizard(page)).toContainText(client('alice').vless.link);
      await expect(wizard(page)).not.toContainText(client().vless.link);
    });

    test('guide and client card fit the viewport at each step', async ({ page }) => {
      for (let step = 1; step <= 4; step++) {
        await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
        if (step < 4) await next(page);
      }
    });
  });
}
