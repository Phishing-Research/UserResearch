// server.js (ESM, Node 18+)
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { GoogleGenerativeAI } from '@google/generative-ai';

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// --- health
app.get('/health', (_req, res) => res.status(200).send('OK'));

// --- list models via REST (works regardless of SDK version)
app.get('/api/models-rest', async (_req, res) => {
    try {
        const key = process.env.GOOGLE_API_KEY;
        if (!key) return res.status(503).json({ error: 'GOOGLE_API_KEY not set' });
        const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(key)}`);
        const text = await r.text();
        if (!r.ok) return res.status(r.status).json({ error: 'List models failed', body: text });
        const data = JSON.parse(text);
        const usable = (data.models || []).filter(m => (m.supportedGenerationMethods || []).includes('generateContent'));
        res.json({ count: usable.length, models: usable.map(m => m.name) });
    } catch (e) {
        res.status(500).json({ error: String(e?.message || e) });
    }
});

const apiKey = process.env.GOOGLE_API_KEY;
if (!apiKey) {
    console.warn('WARNING: Missing GOOGLE_API_KEY. /api/phishing will return 503 until you set it.');
}
const genAI = apiKey ? new GoogleGenerativeAI(apiKey) : null;

// Try these in order if GEMINI_MODEL is not set (covers v1beta availables too)
const CANDIDATE_MODELS = [
    'gemini-1.5-flash-latest',
    'gemini-1.5-flash',
    'gemini-1.5-pro-latest',
    'gemini-1.5-pro',
    'gemini-1.0-pro',
    'gemini-pro'
];

let MODEL_IN_USE = process.env.GEMINI_MODEL || null;
let model = null;

// Validate a model by doing a tiny JSON-mode call
async function tryModel(name) {
    try {
        const m = genAI.getGenerativeModel({ model: name });
        const resp = await m.generateContent({
            contents: [{ role: 'user', parts: [{ text: 'Return {"ok":true} exactly.' }] }],
            generationConfig: { responseMimeType: 'application/json' }
        });
        const txt = resp.response.text();
        const parsed = JSON.parse(txt);
        if (parsed && parsed.ok === true) return m;
    } catch (e) {
        // swallow & continue trying others
    }
    return null;
}

async function initModel() {
    if (!genAI) return;
    if (MODEL_IN_USE) {
        const m = await tryModel(MODEL_IN_USE);
        if (m) { model = m; console.log(`[init] Using requested model: ${MODEL_IN_USE}`); return; }
        console.warn(`[init] Requested model "${MODEL_IN_USE}" failed. Will try candidates…`);
    }
    for (const candidate of CANDIDATE_MODELS) {
        const m = await tryModel(candidate);
        if (m) {
            MODEL_IN_USE = candidate;
            model = m;
            console.log(`[init] Selected working model: ${candidate}`);
            return;
        }
    }
    console.error('[init] No candidate models worked. Check your SDK version and API key access.');
}

app.get('/api/ping-gen', async (_req, res) => {
    try {
        if (!model) return res.status(503).json({ error: 'Model not initialized' });
        const resp = await model.generateContent({
            contents: [{ role: 'user', parts: [{ text: 'Return {"ok":true} exactly.' }] }],
            generationConfig: { responseMimeType: 'application/json' }
        });
        res.type('application/json').send(resp.response.text());
    } catch (e) {
        res.status(500).json({ error: String(e?.message || e) });
    }
});

// --- prompt
const SYSTEM_INSTRUCTIONS = `
You are a phishing email classifier.
analyze the email and return the following JSON format exactly.
Return exactly:
{
  "results": [
    { "id": mailID, "isPhishing": true/false, "confidence": confidenceScore, "reasons": ["short reason"] }
  ]
}
In the reasons give a detailed explanation of either why you flagged it as a phishing email or why it is a legitimate email
it is important to give a thorough explanation of how you came to your conclusion.
Some examples of phishing indicators are: credential theft, payment scams, spoofed brands/domains, urgency/threats, odd links/attachments,
mismatched sender name vs address, typosquatting, requests to bypass official channels.
`;

// --- main API
app.post('/api/phishing', async (req, res) => {
    try {
        if (!apiKey) return res.status(503).json({ error: 'GOOGLE_API_KEY not set on server' });
        if (!model)  return res.status(503).json({ error: 'Model not initialized yet. Try again in a moment.' });

        const { emails } = req.body || {};
        if (!Array.isArray(emails)) return res.status(400).json({ error: 'Expected { emails: [...] }' });

        const compact = emails.map(e => ({
            id: e?.id,
            sender: e?.sender ?? '',
            senderEmail: e?.senderEmail ?? '',
            subject: e?.subject ?? '',
            body: e?.snippet ?? ''
        }));

        const contents = [
            { role: 'user', parts: [{ text: SYSTEM_INSTRUCTIONS }] },
            { role: 'user', parts: [{ text: JSON.stringify({ emails: compact }) }] }
        ];

        const resp = await model.generateContent({
            contents,
            generationConfig: { responseMimeType: 'application/json' }
        });

        const txt = resp.response.text();
        let parsed;
        try {
            parsed = JSON.parse(txt);
        } catch (e) {
            console.error('[api/phishing] JSON parse failed:', e, '\nRAW:', txt);
            return res.status(502).json({ error: 'Model returned non-JSON', raw: txt.slice(0, 1000) });
        }
        if (!parsed || !Array.isArray(parsed.results)) {
            console.error('[api/phishing] malformed JSON:', parsed);
            return res.status(502).json({ error: 'Malformed JSON from model', parsed });
        }

        const clamp01 = n => {
            const x = Number(n);
            if (!Number.isFinite(x)) return 0;
            return Math.max(0, Math.min(1, x));
        };
        parsed.results = parsed.results.map(r => ({
            id: r?.id,
            isPhishing: !!r?.isPhishing,
            confidence: clamp01(r?.confidence),
            reasons: Array.isArray(r?.reasons) ? r.reasons.slice(0, 8) : []
        }));

        res.json(parsed);
    } catch (err) {
        console.error('[api/phishing] server error:', err);
        res.status(500).json({ error: 'Server error', details: String(err?.message || err) });
    }
});

const PORT = Number(process.env.PORT) || 8787;
app.listen(PORT, async () => {
    console.log(`Phish API listening on http://localhost:${PORT}`);
    await initModel();
    console.log(`Model in use: ${MODEL_IN_USE || '(none)'}`);
});
