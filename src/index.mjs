/**
 * Black_Wall remote MCP — hosted MCP-over-HTTP (Streamable HTTP) so ANY
 * MCP-capable agent can add the pre-signature payment verdict as a tool with
 * just a URL — no install, no signup. Zero-key free tier (verdicts under $10);
 * amounts at/over the paywall return an x402 challenge the agent pays with its
 * own wallet (pass the settled payment back as an `X-PAYMENT` header). Fully
 * autonomous: an agent discovers the URL, calls the tool, and pays — no human.
 *
 * This Worker is a THIN transport + proxy: it speaks the minimal MCP JSON-RPC
 * (initialize / tools/list / tools/call / ping) over HTTP and forwards
 * forecast_payment calls to the live x402 oracle. All decision logic + the
 * Ed25519 signed receipt come from the oracle unchanged.
 *
 * `dispatch()` is PURE (message in -> response out, oracle via injected fetch),
 * so it is unit-tested without a network or a Worker runtime.
 */

const DEFAULT_ORACLE = 'https://blackwall-free.onrender.com/v1/forecast-payment';
const SERVER_INFO = { name: 'blackwall-x402-mcp', version: '0.1.0' };
const DEFAULT_PROTOCOL = '2025-06-18';
const KEY_URL = 'https://blackwall-free.onrender.com/.well-known/blackwall-receipt-key.json';

const FORECAST_TOOL = {
  name: 'forecast_payment',
  description:
    'Pre-signature x402 payment verdict: GO / HOLD / STOP for paying a ' +
    'counterparty, from settlement reputation, price-anomaly (quoted vs the ' +
    "payee's own median), and OFAC sanctions — with a third-party-verifiable " +
    'Ed25519 signed receipt. Verdict only; never takes custody. Free under $10 ' +
    'at risk; over that, returns an x402 payment challenge.',
  inputSchema: {
    type: 'object',
    properties: {
      counterparty: { type: 'string', description: 'recipient wallet from the 402' },
      amount: { type: 'string', description: 'amount as a decimal string, e.g. "0.09"' },
      asset: { type: 'string', description: 'e.g. USDC' },
      chain: { type: 'string', description: 'e.g. base' },
      payer: { type: 'string', description: "agent's EVM wallet (optional; binds settlement)" },
      resource: { type: 'string', description: "what's being paid for" },
      agent_id: { type: 'string', description: 'caller DID/identity' },
      context: { type: 'object', description: '{quoted_price_history, expected_recipient}' },
    },
    required: ['counterparty', 'amount', 'asset', 'chain'],
  },
};

const ok = (id, result) => ({ jsonrpc: '2.0', id, result });
const err = (id, code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });

function verdictText(d) {
  const head = `${d.verdict} (score ${d.score})`;
  const reasons = Array.isArray(d.reasons) ? d.reasons.slice(0, 3).join('; ') : '';
  return (
    `Black_Wall verdict: ${head}` +
    (reasons ? `\n${reasons}` : '') +
    (d.receipt_id ? `\nreceipt: ${d.receipt_id}` : '') +
    (d.signed_receipt ? `\nsigned receipt is third-party-verifiable at ${KEY_URL}` : '')
  );
}

async function handleToolCall(id, params, ctx) {
  const name = params && params.name;
  if (name !== 'forecast_payment') {
    return err(id, -32602, `unknown tool: ${name}`);
  }
  const args = (params && params.arguments) || {};
  let res;
  try {
    const headers = { 'content-type': 'application/json' };
    if (ctx.paymentHeader) headers['X-PAYMENT'] = ctx.paymentHeader;
    res = await ctx.fetchImpl(ctx.oracleUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(args),
    });
  } catch (e) {
    // A payment guardrail that can't reach the oracle must NOT imply "GO".
    // Surface a tool error (no verdict) so the agent does not proceed on a phantom pass.
    return ok(id, {
      content: [{ type: 'text', text: `Black_Wall oracle unreachable: ${e && e.message ? e.message : e}. No verdict — do not treat as GO.` }],
      isError: true,
    });
  }

  let data;
  try { data = await res.json(); } catch { data = null; }

  if (res.status === 402) {
    // Free tier exceeded: hand the x402 challenge to the agent to pay + retry.
    // A 402 is a PAYMENT GATE, never a cleared verdict. Strip any verdict-shaped
    // fields from the body so a misbehaving/poisoned 402 can NEVER surface as a
    // phantom GO in structuredContent — only the x402 challenge passes through.
    const challenge = {};
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      for (const [k, v] of Object.entries(data)) {
        if (k === 'verdict' || k === 'score' || k === 'reasons' || k === 'receipt_id' || k === 'signed_receipt') continue;
        challenge[k] = v;
      }
    }
    return ok(id, {
      content: [{
        type: 'text',
        text:
          'Payment required (x402): this amount is above the free tier. Settle the ' +
          'x402 challenge below with your wallet, then retry this tool with the settled ' +
          'payment in an X-PAYMENT header.',
      }],
      structuredContent: challenge,
    });
  }

  if (!res.ok || !data || typeof data !== 'object' || data.verdict == null) {
    const msg = (data && (data.error || data.message)) || `HTTP ${res.status}`;
    return ok(id, {
      content: [{ type: 'text', text: `Black_Wall oracle error: ${msg}. No verdict — do not treat as GO.` }],
      isError: true,
    });
  }

  return ok(id, {
    content: [{ type: 'text', text: verdictText(data) }],
    structuredContent: data,
  });
}

/**
 * Pure MCP JSON-RPC dispatch. Returns a response object, or null for a
 * notification (no id / notifications/*) which gets an empty 202.
 * ctx = { fetchImpl, oracleUrl, paymentHeader? }
 */
export async function dispatch(msg, ctx) {
  if (!msg || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') {
    return err(msg && msg.id != null ? msg.id : null, -32600, 'invalid request');
  }
  const { id, method, params } = msg;
  const isNotification = id === undefined || id === null;

  switch (method) {
    case 'initialize':
      return ok(id, {
        protocolVersion: (params && params.protocolVersion) || DEFAULT_PROTOCOL,
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
      });
    case 'notifications/initialized':
    case 'notifications/cancelled':
      return null; // notification — no response
    case 'ping':
      return ok(id, {});
    case 'tools/list':
      return ok(id, { tools: [FORECAST_TOOL] });
    case 'tools/call':
      // A notification (no id) is fire-and-forget: MUST NOT get a response and
      // MUST NOT trigger a (potentially paid) upstream oracle call.
      if (isNotification) return null;
      return await handleToolCall(id, params, ctx);
    default:
      if (isNotification) return null;
      return err(id, -32601, `method not found: ${method}`);
  }
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Mcp-Session-Id, X-PAYMENT, Authorization',
  'Access-Control-Expose-Headers': 'Mcp-Session-Id',
};

export default {
  async fetch(request, env) {
    const oracleUrl = (env && env.ORACLE_URL) || DEFAULT_ORACLE;

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }
    // GET on the MCP endpoint: no server-initiated stream in this stateless
    // server. Return 405 (spec-compliant: server MAY not support GET/SSE).
    if (request.method === 'GET') {
      return new Response('Black_Wall remote MCP. POST JSON-RPC here (initialize / tools/list / tools/call).', {
        status: 405, headers: { ...CORS, 'content-type': 'text/plain', Allow: 'POST, OPTIONS' },
      });
    }
    if (request.method !== 'POST') {
      return new Response('method not allowed', { status: 405, headers: { ...CORS, Allow: 'POST, OPTIONS' } });
    }

    let body;
    try { body = await request.json(); }
    catch { return json(err(null, -32700, 'parse error'), 400); }

    const paymentHeader = request.headers.get('X-PAYMENT') || null;
    // Wrap the global fetch: passing it as `ctx.fetchImpl` and calling
    // `ctx.fetchImpl(...)` rebinds `this` to `ctx`, which the Cloudflare Workers
    // runtime rejects ("Illegal invocation"). A wrapper calls fetch with the
    // correct global `this`. (Node tolerates the bare reference; Workers does not.)
    const ctx = { fetchImpl: (u, i) => fetch(u, i), oracleUrl, paymentHeader };

    // Support a JSON-RPC batch (array) as well as a single message.
    if (Array.isArray(body)) {
      const out = [];
      for (const m of body) {
        const r = await dispatch(m, ctx);
        if (r) out.push(r);
      }
      return out.length ? json(out, 200) : new Response(null, { status: 202, headers: CORS });
    }

    const resp = await dispatch(body, ctx);
    if (!resp) return new Response(null, { status: 202, headers: CORS });
    return json(resp, 200);
  },
};

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...CORS, 'content-type': 'application/json' },
  });
}
