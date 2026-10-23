'use strict';
// argocd-readonly-pod-terminal
// A read-only, shell-free terminal into Kubernetes pods for ArgoCD users.
//
// - Users log in with their ArgoCD account; ArgoCD verifies the token.
// - Which applications (and so which pods) a user can open is decided by ArgoCD RBAC itself:
//   apps are listed with the *user's own* token, so they only see what they may `get`.
// - Commands are parsed here, checked against an allow-list and executed through the
//   Kubernetes exec API as an argv array — never through a shell.
// - Anything after `|` is applied by this server to the text output, not in the pod.
// - Every command is written to the audit log.
const express = require('express');
const axios = require('axios');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const k8s = require('@kubernetes/client-node');

const PORT = Number(process.env.PORT || 3000);
const ARGOCD_SERVER = process.env.ARGOCD_SERVER || 'https://argocd-server.argocd.svc.cluster.local';
const ARGOCD_INSECURE = process.env.ARGOCD_INSECURE === 'true';          // self-signed in-cluster cert
const AUDIT_LOG_FILE = process.env.AUDIT_LOG_FILE || '';                 // optional, e.g. /data/audit.log
const BASE_PATH = (process.env.BASE_PATH || '').replace(/\/$/, '');      // e.g. /terminal behind an ingress

const argocd = axios.create({
  baseURL: ARGOCD_SERVER,
  httpsAgent: new https.Agent({ rejectUnauthorized: !ARGOCD_INSECURE }),
  timeout: 15000,
});
const asUser = token => ({ headers: { Authorization: `Bearer ${token}` } });

function audit(user, msg) {
  const line = `${new Date().toISOString()} [audit] ${user}: ${msg}`;
  console.log(line);
  if (AUDIT_LOG_FILE) fs.appendFile(AUDIT_LOG_FILE, line + '\n', () => {});
}

const kc = new k8s.KubeConfig();
try { kc.loadFromCluster(); } catch (_) { kc.loadFromDefault(); }
const core = kc.makeApiClient(k8s.CoreV1Api);

const RO_COMMANDS = ['ls', 'cat', 'head', 'tail', 'grep', 'find', 'stat', 'du', 'wc', 'pwd', 'cd'];
// options that take a separate value argument (the value must not be mistaken for a path)
const RO_OPT_VALUE = {
  head: ['-n', '-c'], tail: ['-n', '-c'], grep: ['-e', '-m', '-A', '-B', '-C'], du: ['-d'],
  find: ['-name', '-iname', '-path', '-ipath', '-type', '-maxdepth', '-mindepth', '-mtime', '-mmin', '-size', '-newer', '-user', '-group', '-perm'],
};
const RO_BLOCKED_ARGS = {
  find: /^-(delete|exec|execdir|ok|okdir|fprint|fprint0|fprintf|fls)$/,
  tail: /^(-f|-F|--follow(=.*)?|--retry)$/,
  grep: /^(-f|--file(=.*)?)$/,
};
const RO_MAX_OUTPUT = 512 * 1024;
const RO_TIMEOUT_MS = 20000;
const RO_CACHE_MS = 30000;

// Split a command line into words (quotes supported); shell operators are rejected, not run.
function roTokenize(line) {
  const words = []; let cur = ''; let quote = null; let has = false;
  for (const ch of line) {
    if (quote) { if (ch === quote) quote = null; else cur += ch; continue; }
    if (ch === '"' || ch === "'") { quote = ch; has = true; continue; }
    if (/\s/.test(ch)) { if (has) { words.push(cur); cur = ''; has = false; } continue; }
    if (ch === '|') { if (has) { words.push(cur); cur = ''; has = false; } words.push(RO_PIPE); continue; }
    if (';&><`$\\'.includes(ch)) throw new Error(`'${ch}' is not supported — this is a read-only terminal (no redirects or command chaining; only | into grep/head/tail/wc/sort/uniq)`);
    cur += ch; has = true;
  }
  if (quote) throw new Error('Unclosed quote');
  if (has) words.push(cur);
  return words;
}

// ── Pipes ──
// `cmd | filter | filter`: only the first command runs in the pod. Everything after a `|` is
// applied here, in Node, to that command's text output — no shell, nothing runs in the pod.
const RO_PIPE = Symbol('pipe');
const RO_FILTERS = ['grep', 'head', 'tail', 'wc', 'sort', 'uniq'];

function roSplitPipeline(words) {
  const stages = [[]];
  for (const w of words) { if (w === RO_PIPE) stages.push([]); else stages[stages.length - 1].push(w); }
  if (stages.some(s => !s.length)) throw new Error('Empty command around |');
  return stages;
}

const roNum = (v, def) => { const n = parseInt(v, 10); return Number.isFinite(n) && n >= 0 ? n : def; };

function roApplyFilter(words, text) {
  const [cmd, ...args] = words;
  if (!RO_FILTERS.includes(cmd)) throw new Error(`'${cmd}' can't be used after |. Allowed after |: ${RO_FILTERS.join(', ')}`);
  let lines = text.replace(/\n$/, '').split('\n'); if (text === '') lines = [];
  const flags = new Set(); const pos = []; const val = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (['-n', '-m', '-A', '-B', '-C', '-e'].includes(a) && i + 1 < args.length) { val[a] = args[++i]; continue; }
    if (/^-\d+$/.test(a)) { val['-n'] = a.slice(1); continue; }           // head -20 / tail -20
    if (/^-[a-zA-Z]+$/.test(a)) { for (const f of a.slice(1)) flags.add(f); continue; }
    pos.push(a);
  }
  switch (cmd) {
    case 'head': return lines.slice(0, roNum(val['-n'], 10)).join('\n');
    case 'tail': {
      const n = String(val['-n'] || '10');
      return (n.startsWith('+') ? lines.slice(roNum(n.slice(1), 1) - 1) : lines.slice(-roNum(n, 10) || lines.length)).join('\n');
    }
    case 'wc': {
      const l = lines.length, w = text.split(/\s+/).filter(Boolean).length, c = Buffer.byteLength(text);
      if (flags.has('l')) return String(l); if (flags.has('w')) return String(w); if (flags.has('c')) return String(c);
      return `${l} ${w} ${c}`;
    }
    case 'sort': {
      let out = [...lines].sort(flags.has('n') ? (a, b) => parseFloat(a) - parseFloat(b) : undefined);
      if (flags.has('r')) out.reverse();
      if (flags.has('u')) out = [...new Set(out)];
      return out.join('\n');
    }
    case 'uniq': {
      const out = [];
      for (const l of lines) { const last = out[out.length - 1]; if (last && last.l === l) last.n++; else out.push({ l, n: 1 }); }
      return out.map(x => (flags.has('c') ? `${String(x.n).padStart(7)} ${x.l}` : x.l)).join('\n');
    }
    case 'grep': {
      const pat = val['-e'] ?? pos[0];
      if (pat === undefined) throw new Error('usage: ... | grep [-i -v -n -c -w -F] <pattern>');
      let src = flags.has('F') ? pat.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') : pat;
      if (flags.has('w')) src = `\\b(?:${src})\\b`;
      let re; try { re = new RegExp(src, flags.has('i') ? 'i' : ''); } catch (e) { throw new Error(`grep: invalid pattern: ${e.message}`); }
      const hits = [];
      lines.forEach((l, i) => { if (re.test(l) !== flags.has('v')) hits.push(flags.has('n') ? `${i + 1}:${l}` : l); });
      if (val['-m']) hits.splice(roNum(val['-m'], hits.length));
      return flags.has('c') ? String(hits.length) : hits.join('\n');
    }
  }
  return text;
}

// Turn the user's command into an argv with absolute paths (exec has no working directory).
function roBuildArgv(words, cwd) {
  const [cmd, ...args] = words;
  if (!RO_COMMANDS.includes(cmd)) throw new Error(`'${cmd}' is not allowed. Allowed: ${RO_COMMANDS.join(', ')}`);
  const abs = p => path.posix.resolve(cwd, p);
  const out = [cmd]; const optVal = RO_OPT_VALUE[cmd] || []; const blocked = RO_BLOCKED_ARGS[cmd];
  let positional = 0; let paths = 0; let endOfOpts = false; let findExpr = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (blocked && blocked.test(a)) throw new Error(`'${cmd} ${a}' is not allowed in the read-only terminal`);
    if (!endOfOpts && a === '--') { endOfOpts = true; out.push(a); continue; }
    if (cmd === 'find' && (findExpr || /^[-(!)]/.test(a))) {
      findExpr = true; out.push(a);
      if (optVal.includes(a) && i + 1 < args.length) out.push(args[++i]);
      continue;
    }
    if (!endOfOpts && a.startsWith('-') && a !== '-') {
      out.push(a);
      if (optVal.includes(a) && i + 1 < args.length) out.push(args[++i]);
      continue;
    }
    positional++;
    if (cmd === 'grep' && positional === 1 && !args.includes('-e')) { out.push(a); continue; } // the pattern
    out.push(abs(a)); paths++;
  }
  // commands that default to the current directory when no path is given
  if (!paths && ['ls', 'find', 'du'].includes(cmd)) {
    if (cmd === 'find') out.splice(1, 0, cwd); else out.push(cwd);
  }
  if (!paths && ['cat', 'head', 'tail', 'stat', 'wc'].includes(cmd)) throw new Error(`usage: ${cmd} <file>`);
  if (cmd === 'grep' && !paths) throw new Error('usage: grep [options] <pattern> <file|dir>  (use -r for folders)');
  return out;
}

function roExec(namespace, pod, container, argv) {
  const exec = new k8s.Exec(kc);
  const { Writable } = require('stream');
  return new Promise((resolve) => {
    let out = ''; let truncated = false; let done = false; let ws = null;
    const sink = () => new Writable({ write(chunk, _enc, cb) {
      if (out.length < RO_MAX_OUTPUT) out += chunk.toString(); else truncated = true;
      cb();
    } });
    const finish = (status) => {
      if (done) return; done = true; clearTimeout(timer);
      try { ws && ws.close(); } catch (_) {}
      if (out.length > RO_MAX_OUTPUT) { out = out.slice(0, RO_MAX_OUTPUT); truncated = true; }
      const ok = !status || status.status === 'Success';
      resolve({ output: out + (truncated ? '\n… output truncated (512 KB limit) — use head/tail/grep to narrow it' : ''), ok, status: ok ? 'ok' : (status.message || 'command failed') });
    };
    const timer = setTimeout(() => { out += '\n… stopped after 20 s'; finish({ status: 'Failure', message: 'timeout' }); }, RO_TIMEOUT_MS);
    exec.exec(namespace, pod, container, argv, sink(), sink(), null, false, finish)
      .then(socket => { ws = socket; ws.on('close', () => setTimeout(() => finish(), 200)); })
      .catch(err => { out += String(err.message || err); finish({ status: 'Failure', message: err.message }); });
  });
}

// ── Access checks (ArgoCD RBAC decides, using the user's own token) ───────────
const treeCache = new Map(); // `${token-hash}:${app}` -> { pods, until }
const tokenKey = t => crypto.createHash('sha256').update(t).digest('hex').slice(0, 16);

async function userApps(token) {
  const { data } = await argocd.get('/api/v1/applications', asUser(token));
  return (data.items || []).map(a => ({ name: a.metadata?.name, project: a.spec?.project })).filter(a => a.name);
}

async function appPods(token, app) {
  const key = `${tokenKey(token)}:${app}`;
  const hit = treeCache.get(key);
  if (hit && hit.until > Date.now()) return hit.pods;
  const { data } = await argocd.get(`/api/v1/applications/${encodeURIComponent(app)}/resource-tree`, asUser(token));
  const pods = (data.nodes || []).filter(n => n.kind === 'Pod').map(n => ({ namespace: n.namespace, name: n.name }));
  treeCache.set(key, { pods, until: Date.now() + 30000 });
  if (treeCache.size > 2000) treeCache.delete(treeCache.keys().next().value);
  return pods;
}

// The pod must belong to an application the user can read in ArgoCD.
async function checkPod(token, app, namespace, pod) {
  try {
    if (!(await appPods(token, app)).some(p => p.namespace === namespace && p.name === pod)) {
      const e = new Error('Pod does not belong to this application'); e.status = 403; throw e;
    }
  } catch (e) {
    if (e.response?.status === 403 || e.response?.status === 404) { const x = new Error('No access to this application'); x.status = 403; throw x; }
    throw e;
  }
}

// ── HTTP ───────────────────────────────────────────────────────────────────────
const app = express();
app.use(express.json({ limit: '16kb' }));
const router = express.Router();
router.use(express.static(path.join(__dirname, 'public')));

router.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  try {
    const { data } = await argocd.post('/api/v1/session', { username, password });
    audit(username, 'login');
    res.json({ token: data.token, username });
  } catch (err) {
    res.status(err.response?.status === 401 ? 401 : 502).json({ error: err.response?.status === 401 ? 'Invalid username or password' : 'ArgoCD not reachable' });
  }
});

// Every other API call needs a valid ArgoCD token (verified by ArgoCD itself).
router.use('/api', async (req, res, next) => {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const token = h.slice(7);
  try {
    const { data } = await argocd.get('/api/v1/session/userinfo', asUser(token));
    if (!data.loggedIn) return res.status(401).json({ error: 'Session expired' });
    req.user = data.username; req.token = token; next();
  } catch (_) { res.status(401).json({ error: 'Unauthorized' }); }
});

router.get('/api/apps', async (req, res) => {
  try { res.json((await userApps(req.token)).sort((a, b) => a.name.localeCompare(b.name))); }
  catch (err) { res.status(502).json({ error: err.message }); }
});

router.get('/api/pods', async (req, res) => {
  try {
    const appName = String(req.query.app || '');
    const out = [];
    for (const p of await appPods(req.token, appName)) {
      try {
        const { body } = await core.readNamespacedPod(p.name, p.namespace);
        if (body.status?.phase === 'Running') out.push({ ...p, containers: (body.spec?.containers || []).map(c => c.name) });
      } catch (_) { /* pod gone */ }
    }
    res.json(out);
  } catch (err) { res.status(err.response?.status === 403 ? 403 : 502).json({ error: err.message }); }
});

router.post('/api/exec', async (req, res) => {
  const { app: appName, namespace, pod, container } = req.body || {};
  let cwd = path.posix.normalize(String(req.body?.cwd || '/')); if (!cwd.startsWith('/')) cwd = '/';
  const line = String(req.body?.command || '').trim();
  try {
    if (!appName || !namespace || !pod || !container) return res.status(400).json({ error: 'Select an application, pod and container first' });
    if (line.length > 1000) return res.status(400).json({ error: 'Command too long' });
    await checkPod(req.token, appName, namespace, pod);
    let stages;
    try { const words = roTokenize(line); if (!words.length) return res.json({ output: '', ok: true, cwd }); stages = roSplitPipeline(words); }
    catch (e) { return res.json({ output: e.message, ok: false, cwd }); }
    const [first, ...filters] = stages;
    if (first[0] === 'cd') {
      if (filters.length) return res.json({ output: 'cd cannot be used with |', ok: false, cwd });
      const target = path.posix.resolve(cwd, first[1] || '/');
      const r = await roExec(namespace, pod, container, ['ls', '-d', '--', target + '/']);
      audit(req.user, `${namespace}/${pod}/${container} cd ${target} -> ${r.ok ? 'ok' : 'fail'}`);
      return r.ok ? res.json({ output: '', ok: true, cwd: target }) : res.json({ output: `cd: ${target}: not a directory or not found`, ok: false, cwd });
    }
    let argv = null;
    try {
      if (first[0] !== 'pwd') argv = roBuildArgv(first, cwd);
      filters.forEach(f => { if (!RO_FILTERS.includes(f[0])) throw new Error(`'${f[0]}' can't be used after |. Allowed after |: ${RO_FILTERS.join(', ')}`); });
    } catch (e) { return res.json({ output: e.message, ok: false, cwd }); }
    audit(req.user, `${namespace}/${pod}/${container} ${argv ? argv.join(' ') : 'pwd'}${filters.map(f => ' | ' + f.join(' ')).join('')}`);
    const r = argv ? await roExec(namespace, pod, container, argv) : { output: cwd, ok: true };
    let output = r.output;
    try { for (const f of filters) output = roApplyFilter(f, output); }
    catch (e) { return res.json({ output: e.message, ok: false, cwd }); }
    res.json({ output, ok: r.ok, cwd });
  } catch (err) { res.status(err.status || 502).json({ error: err.message }); }
});

// Tab completion: command names for the first word, otherwise names in the folder being typed.
router.post('/api/complete', async (req, res) => {
  const { app: appName, namespace, pod, container } = req.body || {};
  let cwd = path.posix.normalize(String(req.body?.cwd || '/')); if (!cwd.startsWith('/')) cwd = '/';
  const line = String(req.body?.line || '').slice(0, 1000);
  try {
    if (!appName || !namespace || !pod || !container) return res.json({ matches: [] });
    await checkPod(req.token, appName, namespace, pod);
    const seg = line.split('|').pop();
    const word = seg.match(/(\S*)$/)[1];
    if (!seg.trim() || seg.trim() === word) {
      const pool = line.includes('|') ? RO_FILTERS : [...RO_COMMANDS, 'help', 'clear', 'exit'];
      return res.json({ base: '', matches: pool.filter(c => c.startsWith(word)).map(c => c + ' ') });
    }
    const slash = word.lastIndexOf('/');
    const dirPart = slash >= 0 ? word.slice(0, slash + 1) : '';
    const prefix = word.slice(slash + 1);
    const r = await roExec(namespace, pod, container, ['ls', '-1Ap', '--', path.posix.resolve(cwd, dirPart || '.') + '/']);
    if (!r.ok) return res.json({ base: dirPart, matches: [] });
    const matches = r.output.split('\n').map(s => s.trim()).filter(Boolean)
      .filter(n => n.startsWith(prefix) && (prefix.startsWith('.') || !n.startsWith('.')))
      .map(n => (n.endsWith('/') ? n : n + ' '));
    res.json({ base: dirPart, matches: matches.slice(0, 200) });
  } catch (err) { res.status(err.status || 502).json({ error: err.message }); }
});

router.get('/healthz', (_req, res) => res.send('ok'));
router.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.use(BASE_PATH || '/', router);
if (require.main === module) app.listen(PORT, () => console.log(`argocd-readonly-pod-terminal on :${PORT}${BASE_PATH || '/'}`));
module.exports = { roTokenize, roSplitPipeline, roBuildArgv, roApplyFilter, RO_COMMANDS, RO_FILTERS };
