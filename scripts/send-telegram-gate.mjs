#!/usr/bin/env node
import { buildApprovalMessage, requiredEnv } from '../src/telegram-message.js';

const missing = requiredEnv.filter((name) => !process.env[name]);

if (missing.length > 0) {
  console.error(`Missing required environment variable(s): ${missing.join(', ')}`);
  process.exit(1);
}

const runUrl = `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`;
const text = buildApprovalMessage({
  repo: process.env.GITHUB_REPOSITORY,
  refName: process.env.GITHUB_REF_NAME,
  actor: process.env.GITHUB_ACTOR,
  workflow: process.env.GITHUB_WORKFLOW,
  runUrl,
  reason: process.env.GATE_REASON,
});

const body = new URLSearchParams({
  chat_id: process.env.TELEGRAM_CHAT_ID,
  text,
  disable_web_page_preview: 'true',
});

if (process.env.TELEGRAM_THREAD_ID) {
  body.set('message_thread_id', process.env.TELEGRAM_THREAD_ID);
}

const response = await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
  method: 'POST',
  body,
});

const result = await response.json();

if (!response.ok || !result.ok) {
  console.error(JSON.stringify(result, null, 2));
  process.exit(1);
}

console.log(`Telegram gate message sent to chat ${process.env.TELEGRAM_CHAT_ID}`);
