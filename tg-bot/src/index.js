import { Bot } from 'grammy';
import fetch from 'node-fetch';

// ── Configuration ────────────────────────────────────────────
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const ADMIN_API_URL = process.env.ADMIN_API_URL ?? 'http://admin-api:8080';
const ADMIN_API_TOKEN = process.env.ADMIN_API_TOKEN;

if (!BOT_TOKEN) {
  console.error('TELEGRAM_BOT_TOKEN is not set');
  process.exit(1);
}
if (!ADMIN_API_TOKEN) {
  console.error('ADMIN_API_TOKEN is not set');
  process.exit(1);
}

// Comma-separated list of allowed Telegram user IDs
const ADMIN_IDS = new Set(
  (process.env.ADMIN_IDS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map(Number),
);

if (ADMIN_IDS.size === 0) {
  console.warn('WARNING: ADMIN_IDS is empty — bot will reject all users');
}

// ── Bot setup ────────────────────────────────────────────────
const bot = new Bot(BOT_TOKEN);

// ── Auth middleware ──────────────────────────────────────────
bot.use(async (ctx, next) => {
  const userId = ctx.from?.id;
  if (!userId || !ADMIN_IDS.has(userId)) {
    await ctx.reply('Access denied. You are not authorised to use this bot.');
    return;
  }
  return next();
});

// ── API helpers ──────────────────────────────────────────────
async function apiGet(path) {
  const res = await fetch(`${ADMIN_API_URL}${path}`, {
    headers: {
      'x-admin-token': ADMIN_API_TOKEN,
      'x-actor': 'telegram-bot',
    },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res.json();
}

async function apiPost(path, body) {
  const res = await fetch(`${ADMIN_API_URL}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-admin-token': ADMIN_API_TOKEN,
      'x-actor': 'telegram-bot',
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res.json();
}

async function apiDelete(path) {
  const res = await fetch(`${ADMIN_API_URL}${path}`, {
    method: 'DELETE',
    headers: {
      'x-admin-token': ADMIN_API_TOKEN,
      'x-actor': 'telegram-bot',
    },
  });
  if (res.status === 204) return;
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status}: ${text}`);
  }
}

// Find an AllowedIp record by IP string or numeric ID
async function resolveRecord(ipOrId) {
  const list = await apiGet('/allowed-ips');
  const asNum = parseInt(ipOrId, 10);

  if (!isNaN(asNum)) {
    return list.find((r) => r.id === asNum) ?? null;
  }
  return list.find((r) => r.ip === ipOrId.trim()) ?? null;
}

// ── Commands ─────────────────────────────────────────────────
bot.command('start', (ctx) => ctx.reply('Private DNS Admin Bot. Use /help.'));

bot.command('help', (ctx) =>
  ctx.reply(
    [
      'Available commands:',
      '',
      '/listip — list all allowed IPs',
      '/addip <ip> [label] — add an IP to the allowlist',
      '/delip <ip_or_id> — remove an IP from the allowlist',
      '/help — show this message',
    ].join('\n'),
  ),
);

bot.command('listip', async (ctx) => {
  try {
    const list = await apiGet('/allowed-ips');
    if (!list.length) {
      return ctx.reply('No IPs in the allowlist.');
    }
    const lines = list.map(
      (r) =>
        `[${r.id}] ${r.ip}${r.label ? ` — ${r.label}` : ''} (${r.enabled ? 'enabled' : 'DISABLED'})`,
    );
    await ctx.reply(`Allowed IPs (${list.length}):\n\n${lines.join('\n')}`);
  } catch (err) {
    await ctx.reply(`Error: ${err.message}`);
  }
});

bot.command('addip', async (ctx) => {
  const args = ctx.match?.trim();
  if (!args) {
    return ctx.reply('Usage: /addip <ip> [label]');
  }
  const parts = args.split(/\s+/);
  const ip = parts[0];
  const label = parts.slice(1).join(' ') || undefined;

  try {
    const record = await apiPost('/allowed-ips', { ip, label });
    await ctx.reply(
      `Added: [${record.id}] ${record.ip}${label ? ` — ${label}` : ''}`,
    );
  } catch (err) {
    await ctx.reply(`Error: ${err.message}`);
  }
});

bot.command('delip', async (ctx) => {
  const arg = ctx.match?.trim();
  if (!arg) {
    return ctx.reply('Usage: /delip <ip_or_id>');
  }

  try {
    const record = await resolveRecord(arg);
    if (!record) {
      return ctx.reply(`Not found: ${arg}`);
    }
    await apiDelete(`/allowed-ips/${record.id}`);
    await ctx.reply(`Removed: [${record.id}] ${record.ip}`);
  } catch (err) {
    await ctx.reply(`Error: ${err.message}`);
  }
});

// ── Start polling ────────────────────────────────────────────
bot.catch((err) => {
  console.error('Bot error:', err.message);
});

bot.start({
  onStart: () => console.log('Telegram bot started'),
});
