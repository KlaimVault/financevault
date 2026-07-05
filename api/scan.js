// FinanceVault — secure document scanner
// Runs on Vercel. Reads the Anthropic key from an env var (NEVER in the frontend).
// Set it in Vercel:  Project → Settings → Environment Variables → ANTHROPIC_API_KEY
//
// Abuse protection built in:
//   • same-site origin/referer check (blocks requests from other websites)
//   • best-effort per-IP rate limit (20 scans / minute)
//   • request size cap (rejects oversized uploads before hitting the paid API)
// For hard guarantees across regions, back the limiter with Vercel KV / Upstash.

const WINDOW_MS = 60 * 1000;
const MAX_PER_WINDOW = 20;
const MAX_BASE64 = 7000000;          // ~5MB image; frontend already downscales
const hits = new Map();              // ip -> [timestamps]  (resets on cold start)

function rateLimited(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter(t => now - t < WINDOW_MS);
  arr.push(now);
  hits.set(ip, arr);
  if (hits.size > 5000) hits.clear();  // keep memory bounded
  return arr.length > MAX_PER_WINDOW;
}

function sameSite(req) {
  const host = req.headers.host || '';
  const src = req.headers.origin || req.headers.referer || '';
  if (!src) return true;                          // no header → can't judge, allow
  try {
    const h = new URL(src).host;
    return h === host || h.endsWith('.vercel.app'); // own domain + preview URLs
  } catch (e) { return false; }
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', 'same-origin');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  if (!sameSite(req)) return res.status(403).json({ error: 'Forbidden' });

  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
  if (rateLimited(ip)) return res.status(429).json({ error: 'Too many scans — wait a minute and try again.' });

  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) return res.status(500).json({ error: 'Server not configured: ANTHROPIC_API_KEY missing' });

  try {
    const { image, media } = req.body || {};
    if (!image) return res.status(400).json({ error: 'No image provided' });
    if (typeof image !== 'string' || image.length > MAX_BASE64)
      return res.status(413).json({ error: 'Image too large — retake the photo.' });

    const today = new Date().toISOString().slice(0, 10);
    const prompt = `You are reading a financial document (a bill, invoice, receipt, insurance card, medical statement, or tax form) for a personal finance app.

Return ONLY a JSON object — no prose, no markdown, no code fences — with these exact keys:
{
  "docType": one of "bill","receipt","insurance","medical","tax","banking","investment","legal","property","vehicle","warranty","id","statement","other",
  "vendor": the company or biller name (short, e.g. "NV Energy"),
  "amount": the TOTAL AMOUNT DUE or total charged, as a number only (no $ or commas). Use the amount the person must pay — not account numbers, dates, or partial line items. If none, use null.
  "dueDate": the payment DUE DATE in strict YYYY-MM-DD format, or null if there is none. Today is ${today}; interpret 2-digit years sensibly.
  "category": best fit from ["Housing","Utilities","Insurance","Auto","Medical","Groceries","Dining","Phone/Internet","Subscriptions","Credit Card","Loan","Taxes","Childcare","Pets","Entertainment","Shopping","Home","Travel","Banking","Income","Savings","Personal","Other"],
  "accountNumber": the account or invoice number if clearly shown, else null,
  "summary": one short plain sentence describing the document
}

Be precise about the amount — do not confuse a zip code, account number, phone number, or partial cents with the amount due. If the document clearly shows a "Total Due" or "Amount Due", use that.`;

    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': key,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 600,
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'base64', media_type: media || 'image/jpeg', data: image } },
            { type: 'text', text: prompt }
          ]
        }]
      })
    });

    if (!r.ok) {
      const t = await r.text();
      return res.status(502).json({ error: 'Claude API error', detail: t.slice(0, 300) });
    }

    const data = await r.json();
    let text = (data.content || []).filter(b => b.type === 'text').map(b => b.text).join('').trim();
    text = text.replace(/```json|```/g, '').trim();

    let parsed;
    try { parsed = JSON.parse(text); }
    catch (e) { const m = text.match(/\{[\s\S]*\}/); parsed = m ? JSON.parse(m[0]) : {}; }

    if (parsed.amount != null) {
      const n = parseFloat(String(parsed.amount).replace(/[^0-9.\-]/g, ''));
      parsed.amount = isNaN(n) ? null : n;
    }
    return res.status(200).json(parsed);

  } catch (err) {
    return res.status(500).json({ error: 'Scan failed', detail: String(err).slice(0, 200) });
  }
}
