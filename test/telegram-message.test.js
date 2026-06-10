import test from 'node:test';
import assert from 'node:assert/strict';

import { buildApprovalMessage, requiredEnv } from '../src/telegram-message.js';

test('requiredEnv lists the secrets used by the Telegram gate', () => {
  assert.deepEqual(requiredEnv, ['TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID']);
});

test('buildApprovalMessage includes run context and approval URL', () => {
  const message = buildApprovalMessage({
    repo: 'nerveband/secret-gate',
    refName: 'main',
    actor: 'nerveband',
    workflow: 'Secret Gate',
    runUrl: 'https://github.com/nerveband/secret-gate/actions/runs/1',
    reason: 'Deploy production',
  });

  assert.match(message, /Secret Gate approval requested/);
  assert.match(message, /Repo: nerveband\/secret-gate/);
  assert.match(message, /Branch: main/);
  assert.match(message, /Actor: nerveband/);
  assert.match(message, /Reason: Deploy production/);
  assert.match(message, /Approve or reject in GitHub:/);
  assert.match(message, /https:\/\/github.com\/nerveband\/secret-gate\/actions\/runs\/1/);
});

test('buildApprovalMessage falls back cleanly when reason is omitted', () => {
  const message = buildApprovalMessage({
    repo: 'nerveband/secret-gate',
    refName: 'main',
    actor: 'nerveband',
    workflow: 'Secret Gate',
    runUrl: 'https://github.com/nerveband/secret-gate/actions/runs/1',
  });

  assert.match(message, /Reason: Manual gate check/);
});
