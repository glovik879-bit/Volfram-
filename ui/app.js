'use strict';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const TOKEN = new URLSearchParams(location.search).get('t') || '';
const ANDROID = document.documentElement.classList.contains('android');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const ICONS = {
  home:'<path d="m3 10 9-7 9 7v10a2 2 0 0 1-2 2h-4v-7H9v7H5a2 2 0 0 1-2-2z"/>',
  server:'<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01"/>',
  layers:'<path d="m12 3 9 5-9 5-9-5 9-5z"/><path d="m3 13 9 5 9-5"/><path d="m3 17.5 9 5 9-5" opacity=".5"/>',
  route:'<circle cx="6" cy="19" r="3"/><path d="M9 19h8.5a3.5 3.5 0 0 0 0-7h-11a3.5 3.5 0 0 1 0-7H15"/><circle cx="18" cy="5" r="3"/>',
  activity:'<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
  terminal:'<rect x="2" y="3" width="20" height="18" rx="3"/><path d="m7 9 3 3-3 3M13 15h4"/>',
  settings:'<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
  down:'<path d="M12 4v16"/><path d="m6 14 6 6 6-6"/>',
  up:'<path d="M12 20V4"/><path d="m6 10 6-6 6 6"/>',
  power:'<path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.77.04"/>',
  globe:'<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
  shield:'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
  database:'<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0 0 18 0V5"/><path d="M3 12a9 3 0 0 0 18 0"/>',
  send:'<path d="m22 2-7 20-4-9-9-4z"/><path d="M22 2 11 13"/>',
  clipboard:'<rect x="8" y="2" width="8" height="4" rx="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/>',
  zap:'<path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/>',
  plus:'<path d="M12 5v14M5 12h14"/>',
  search:'<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
  link:'<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
  refresh:'<path d="M21 12a9 9 0 0 1-15.5 6.2L3 16"/><path d="M3 12a9 9 0 0 1 15.5-6.2L21 8"/><path d="M21 3v5h-5"/><path d="M3 21v-5h5"/>',
  sparkles:'<path d="M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9z"/><path d="M19 3v4M17 5h4M5 17v4M3 19h4"/>',
  unlock:'<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>',
  ban:'<circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/>',
  'arrow-right':'<path d="M5 12h14"/><path d="m12 5 7 7-7 7"/>',
  check:'<path d="M20 6 9 17l-5-5"/>',
  x:'<path d="M18 6 6 18M6 6l12 12"/>',
  copy:'<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
  trash:'<path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
  plug:'<path d="M12 22v-5"/><path d="M9 8V2M15 8V2"/><path d="M18 8v5a6 6 0 0 1-12 0V8z"/>',
  dns:'<rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3M12 12V8"/>',
  sliders:'<path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6"/>',
  folder:'<path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.7-.9l-.8-1.2A2 2 0 0 0 7.9 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2z"/>',
  edit:'<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
  code:'<path d="m16 18 6-6-6-6M8 6l-6 6 6 6"/>',
  external:'<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
  alert:'<path d="m21.7 18-8-14a2 2 0 0 0-3.4 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3z"/><path d="M12 9v4M12 17h.01"/>',
  info:'<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>',
  pin:'<path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0z"/><circle cx="12" cy="10" r="3"/>',
  calendar:'<rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/>',
  lock:'<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  'chevron-right':'<path d="m9 6 6 6-6 6"/>',
  'chevron-left':'<path d="m15 6-6 6 6 6"/>',
  grid:'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  'shield-off':'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M4 4l16 16"/>',
};
const icon = n => `<svg class="ic" viewBox="0 0 24 24" aria-hidden="true">${ICONS[n] || ''}</svg>`;
function hydrate(root = document) { $$('i[data-icon]', root).forEach(el => { if (!el.firstChild) el.innerHTML = icon(el.dataset.icon); }); }

const PROTO = {
  vless:['VLESS','#9fb0ff'], vmess:['VMess','#86c5f0'], trojan:['Trojan','#f29a86'], ss:['Shadowsocks','#86d4a8'],
  hysteria2:['Hysteria2','#ecc373'], hysteria:['Hysteria','#e3a56b'], tuic:['TUIC','#7fcfcb'], wireguard:['WireGuard','#b9dc7a'],
  anytls:['AnyTLS','#dda2cc'], naive:['Naïve','#9fd3bf'], socks:['SOCKS5','#c9c7bf'],
};
const protoBadge = p => { const [l, c] = PROTO[p] || [p, '#999']; return `<span class="proto" style="--pc:${c}">${esc(l)}</span>`; };

function fmtBytes(n) {
  n = Number(n) || 0;
  const u = ['Б','КБ','МБ','ГБ','ТБ']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n.toFixed(0) : n.toFixed(n < 10 ? 2 : n < 100 ? 1 : 0)) + ' ' + u[i];
}
const fmtSpeed = n => fmtBytes(n) + '/с';
function fmtDur(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), x = s % 60;
  return [h, m, x].map(v => String(v).padStart(2, '0')).join(':');
}
function ago(ts) {
  if (!ts) return 'никогда';
  const d = Date.now() / 1000 - ts;
  if (d < 60) return 'только что';
  if (d < 3600) return Math.floor(d / 60) + ' мин назад';
  if (d < 86400) return Math.floor(d / 3600) + ' ч назад';
  return Math.floor(d / 86400) + ' дн назад';
}
const ccFlag = cc => (cc && /^[a-z]{2}$/i.test(cc)) ? String.fromCodePoint(...[...cc.toUpperCase()].map(c => 0x1F1A5 + c.charCodeAt(0))) : '';
function splitFlag(name) {
  const m = String(name || '').match(/^\s*((?:[\u{1F1E6}-\u{1F1FF}]{2})|\u{1F3F4}[\u{E0061}-\u{E007A}]+\u{E007F})\s*(.*)$/u);
  return m ? [m[1], m[2] || name] : ['', name];
}
function pingHTML(d, testing) {
  let cls = '', txt = '—';
  if (testing) { cls = 'testing'; txt = '···'; }
  else if (d > 0) { cls = d < 200 ? 'good' : d < 500 ? 'mid' : 'bad'; txt = d + ' мс'; }
  else if (d < 0) { cls = 'fail'; txt = 'нет ответа'; }
  return `<span class="ping ${cls}"><span class="bars"><i></i><i></i><i></i><i></i></span>${txt}</span>`;
}

async function api(path, body, method) {
  const opt = { method: method || (body !== undefined ? 'POST' : 'GET'), headers: { 'X-Token': TOKEN } };
  if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  let j; try { j = await r.json(); } catch { throw new Error('Нет ответа от приложения'); }
  if (!j.ok) { const e = new Error(j.error || 'Ошибка'); e.code = j.code; throw e; }
  return j.data;
}

function toast(kind, text, ms = 3800) {
  const el = document.createElement('div');
  el.className = 'toast ' + kind;
  el.innerHTML = icon(kind === 'ok' ? 'check' : kind === 'error' ? 'alert' : 'info') + `<span>${esc(text)}</span>`;
  $('#toasts').appendChild(el);
  setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 300); }, ms);
}

const S = {
  settings: {}, servers: [], subs: [], selected: '', status: { state: 'idle' }, admin: false, versions: {}, ip: null,
  stats: { up: 0, down: 0, upTotal: 0, downTotal: 0, conns: 0 }, testing: new Set(), page: 'home', group: 'all',
  search: '', logs: [], logLevel: 'all', logSrc: 'all', subUpdating: new Set(), coresReady: false, platform: '',
};
const hist = { down: new Array(60).fill(0), up: new Array(60).fill(0) };
const byId = id => S.servers.find(s => s.id === id);
const MODE_L = ANDROID ? { proxy: 'Локальный прокси', tun: 'VPN' } : { proxy: 'Системный прокси', tun: 'TUN' };
const ROUTE_L = { smart: 'Умный', global: 'Глобальный', blocked: 'Блок-лист РФ' };

async function loadState() {
  const st = await api('/api/state');
  Object.assign(S, { settings: st.settings, servers: st.servers || [], subs: st.subs || [], selected: st.selected,
    status: st.status, admin: st.admin, versions: st.versions, ip: st.ip, coresReady: st.coresReady, platform: st.platform, lanIPs: st.lanIPs || [] });
  renderAll();
  if (!S.ip && S.status.state === 'idle') api('/api/ip', {}).catch(() => {});
}

function go(page) {
  S.page = page;
  const navPage = ANDROID && (page === 'conns' || page === 'logs') ? 'settings' : page;
  $$('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.page === navPage));
  $$('.page').forEach(p => p.classList.toggle('active', p.id === 'page-' + page));
  if (page === 'conns') refreshConns();
  if (page === 'logs') renderLogs(true);
  if (page === 'home') requestAnimationFrame(() => { drawChart(); drawMap(); });
}
$$('.nav-item').forEach(b => b.addEventListener('click', () => go(b.dataset.page)));
$$('[data-goto]').forEach(b => b.addEventListener('click', () => go(b.dataset.goto)));

if (ANDROID) {
  window.volframBack = () => {
    if ($('#modalLayer').classList.contains('open')) { closeModal(); return true; }
    if (S.page === 'conns' || S.page === 'logs') { go('settings'); return true; }
    if (S.page !== 'home') { go('home'); return true; }
    return false;
  };
  window.volframImport = text => {
    text = String(text || '').trim();
    if (!text) return;
    const links = text.split(/\s+/).filter(l => /^[a-z][a-z0-9+.-]*:\/\//i.test(l));
    const items = links.length ? links : [text.slice(0, 60)];
    const nameOf = l => { const h = l.indexOf('#'); if (h < 0) return ''; try { return decodeURIComponent(l.slice(h + 1)); } catch { return l.slice(h + 1); } };
    const shown = items.slice(0, 6).map(l => { const m = l.match(/^([a-z0-9+.-]+):\/\/([^/?#@]*@)?([^/?#:]*)/i); const nm = nameOf(l).slice(0, 60); return (m ? `${m[1]}://${m[3] || '…'}` : l) + (nm ? ' · ' + nm : ''); });
    const n = items.length;
    openModal(`<h3>${icon('plus')}Добавить из другого приложения?</h3>
      <div class="m-sub">Другое приложение или сайт передал ${n > 1 ? n + ' ' + plural(n, 'ссылку', 'ссылки', 'ссылок') : 'ссылку'}. Добавляйте только то, чему доверяете.</div>
      <div class="imp-list">${shown.map(l => `<div>${esc(l)}</div>`).join('')}${n > 6 ? `<div>…и ещё ${n - 6}</div>` : ''}</div>
      <div class="m-foot"><button class="btn ghost" data-close-modal>Отмена</button><button class="btn primary" id="impGo">${icon('check')}Добавить</button></div>`, m => {
      m.dataset.nofocus = '1';
      $('#impGo', m).onclick = async () => {
        closeModal();
        try { importDone(await api('/api/servers/add', { text })); go('servers'); } catch (e) { toast('error', e.message, 6000); }
      };
    });
  };
  let fullH = innerHeight;
  addEventListener('resize', () => { fullH = Math.max(fullH, innerHeight); document.documentElement.classList.toggle('kb', innerHeight < fullH * 0.78); });
  addEventListener('orientationchange', () => { fullH = 0; });
}

let tbLastDown = 0;
$('#titlebar').addEventListener('mousedown', e => {
  if (e.button !== 0 || e.target.closest('.win-ctl, button, a, input')) return;
  const now = Date.now();
  if (now - tbLastDown < 450) { tbLastDown = 0; if (window.__volframMax) window.__volframMax().then(syncMax); return; }
  tbLastDown = now;
  if (window.__volframDrag) window.__volframDrag();
});
function syncMax(m) { document.body.classList.toggle('maximized', !!m); }
$('#wcMin').onclick = () => window.__volframMin && window.__volframMin();
$('#wcMax').onclick = () => window.__volframMax && window.__volframMax().then(syncMax);
$('#wcClose').onclick = () => window.__volframClose ? window.__volframClose() : api('/api/quit', {});

function renderAll() {
  renderStatus(); renderServerNow(); renderServers(); renderSubs(); renderRouting(); renderSettings(); renderBadges(); renderIP(); renderStats();
  $('#aboutVer').textContent = 'v' + (S.versions.app || '');
  $('#aboutCores').textContent = `Ядра: sing-box ${S.versions.singbox || '?'} · Xray-core ${S.versions.xray || '?'}`;
  $('#sideFoot').textContent = `sing-box ${S.versions.singbox || ''} · Xray ${S.versions.xray || ''}`;
}
function renderBadges() {
  $('#badgeServers').textContent = S.servers.length;
  $('#badgeSubs').textContent = S.subs.length;
  $('#badgeConns').textContent = S.stats.conns || 0;
  $('#scMode').textContent = S.settings.mode === 'tun' ? 'TUN' : 'Прокси';
  $('#scRouting').textContent = ROUTE_L[S.settings.routing] || '';
}

const WM = window.WORLD;
const regionName = (() => { try { const d = new Intl.DisplayNames(['ru'], { type: 'region' }); return cc => { try { return d.of(cc); } catch { return cc; } }; } catch { return cc => cc; } })();
function flagCC(name) {
  const f = splitFlag(name)[0]; if (!f) return '';
  const cp = [...f].map(c => c.codePointAt(0));
  return cp.length === 2 && cp.every(c => c >= 0x1F1E6 && c <= 0x1F1FF) ? String.fromCharCode(cp[0] - 0x1F1A5, cp[1] - 0x1F1A5) : '';
}
function mapCountry() {
  if (S.status.state === 'connected' && S.ip && S.ip.cc) return S.ip.cc.toUpperCase();
  const sv = byId(S.status.serverId || S.selected);
  return sv ? flagCC(sv.name) : '';
}
function drawMap() {
  const c = $('#worldMap'); if (!c || !c.offsetParent || !WM) return;
  const [ctx, W, H] = setupCanvas(c); ctx.clearRect(0, 0, W, H);
  const cc = mapCountry(), ci = cc ? WM.codes.indexOf(cc) + 1 : 0, st = S.status.state;
  let cs = Math.min((W * 0.96) / WM.cols, (H * 0.9) / WM.rows);
  let ox = (W - cs * WM.cols) / 2 + cs * 2, oy = (H - cs * WM.rows) / 2 + H * 0.03;
  if (W / H < 1.3) {
    cs = Math.max((W * 2.4) / WM.cols, 3);
    const p = (cc && WM.pts[cc]) || [30, 50];
    const cx = (p[0] - WM.lon0) / WM.step, cy = (WM.lat0 - p[1]) / WM.step;
    ox = Math.min(0, Math.max(W - WM.cols * cs, W * 0.5 - cx * cs));
    oy = Math.min(H * 0.12, Math.max(H * 0.88 - WM.rows * cs, H * 0.5 - cy * cs));
  }
  const r = Math.max(0.7, cs * 0.27), cells = WM.cells, cols = WM.cols;
  const cb = c.getBoundingClientRect(), holes = [];
  for (const el of [$('#heroTitle'), $('#heroSub'), $('#timer')]) {
    if (!el || !el.firstChild) continue;
    const rg = document.createRange(); rg.selectNodeContents(el);
    for (const q of rg.getClientRects()) holes.push([q.left - cb.left - 10, q.top - cb.top - 6, q.right - cb.left + 12, q.bottom - cb.top + 6]);
  }
  const hidden = (x, y) => holes.some(h => x > h[0] && x < h[2] && y > h[1] && y < h[3]);
  const layer = (pred, color) => {
    ctx.fillStyle = color; ctx.beginPath();
    for (let i = 0; i < cells.length; i++) {
      const v = cells.charCodeAt(i); if (v === 32 || !pred(v - 48)) continue;
      const x = ox + (i % cols + .5) * cs, y = oy + ((i / cols | 0) + .5) * cs;
      if (holes.length && hidden(x, y)) continue;
      ctx.moveTo(x + r, y); ctx.arc(x, y, r, 0, 6.2832);
    }
    ctx.fill();
  };
  layer(v => v !== ci, 'rgba(238,237,232,.15)');
  if (ci) layer(v => v === ci, st === 'connected' ? 'rgba(207,245,74,.92)' : 'rgba(238,237,232,.55)');
  const pin = $('#mapPin'), p = cc && WM.pts[cc];
  if (p) {
    const x = ox + ((p[0] - WM.lon0) / WM.step) * cs, y = oy + ((WM.lat0 - p[1]) / WM.step) * cs;
    pin.style.transform = `translate(${x.toFixed(1)}px,${y.toFixed(1)}px)`;
    const city = st === 'connected' && S.ip && S.ip.city ? S.ip.city + ', ' : '';
    const lb = $('#pinLabel');
    lb.innerHTML = `<b>${esc(cc)}</b><span>${esc(city + regionName(cc))}</span>`;
    pin.hidden = false;
    lb.style.maxWidth = (W - 16) + 'px';
    const lw = lb.offsetWidth;
    let left = 14, top = -12;
    if (x + 14 + lw > W - 8) left = -14 - lw;
    if (x + left < 8) { left = Math.max(8 - x, Math.min(-lw / 2, W - 8 - lw - x)); top = 12; }
    lb.style.left = left.toFixed(1) + 'px'; lb.style.top = top + 'px';
  } else pin.hidden = true;
  pin.dataset.state = st;
}
function renderStatus() {
  const st = S.status.state || 'idle';
  const orb = $('#orb'), hero = $('#hero');
  orb.dataset.state = st; hero.dataset.state = st;
  const sv = byId(S.status.serverId || S.selected);
  const titles = { idle: 'Не подключено', connecting: 'Подключение…', connected: 'Защищено', stopping: 'Отключение…' };
  $('#heroTitle').textContent = titles[st] || st;
  let sub = 'Выберите сервер и нажмите кнопку';
  if (st === 'connected' && sv) sub = `${sv.name} · ${MODE_L[S.status.mode] || ''}`;
  else if (st === 'connecting' && sv) sub = sv.name;
  else if (st === 'idle' && S.status.error) sub = S.status.error;
  else if (!S.coresReady) sub = 'Подготовка ядер…';
  $('#heroSub').textContent = sub; $('#heroSub').title = sub;
  $('#heroSub').classList.toggle('err', st === 'idle' && !!S.status.error);
  $('#orbLabel').textContent = { idle: 'Подключить', connecting: 'Отменить', connected: 'Отключить', stopping: 'Отключение…' }[st];
  orb.setAttribute('aria-label', st === 'connected' ? 'Отключиться' : 'Подключиться');
  const tb = $('#tbStatus');
  tb.className = 'tb-status ' + st;
  $('.txt', tb).textContent = st === 'connected' ? `Подключено · ${sv ? sv.name : ''}` : titles[st];
  $$('#segMode button').forEach(b => b.classList.toggle('on', b.dataset.v === S.settings.mode));
  $$('#segRouting button').forEach(b => b.classList.toggle('on', b.dataset.v === S.settings.routing));
  tickTimer(); drawMap();
}
function tickTimer() {
  const t = S.status.state === 'connected' && S.status.since ? fmtDur(Date.now() - S.status.since) : '00:00:00';
  $('#timer').textContent = t;
}
setInterval(tickTimer, 1000);

function renderServerNow() {
  const sv = byId(S.selected);
  const el = $('#serverNow');
  if (!sv) {
    el.innerHTML = `<div class="panel-head"><div class="label">Сервер</div></div>
      <div class="sn-main"><div class="sn-flag">${icon('server')}</div><div class="sn-body"><div class="sn-name sn-empty">Серверов пока нет</div><div class="sn-host">Добавьте ссылку или подписку</div></div></div>
      <button class="btn primary sn-go" data-act="add">${icon('plus')}Добавить сервер</button>`;
  } else {
    const [flag, name] = splitFlag(sv.name), cc = flagCC(sv.name);
    el.innerHTML = `<div class="panel-head"><div class="label">Текущий сервер</div><button class="icon-btn" data-act="test" title="Проверить задержку">${icon('zap')}</button></div>
      <div class="sn-main"><div class="sn-flag">${flag ? esc(flag) : icon('globe')}</div>
        <div class="sn-body"><div class="sn-name" title="${esc(sv.name)}">${esc(name)}</div><div class="sn-host">${cc ? esc(regionName(cc)) + ' · ' : ''}${esc(sv.host)}</div></div></div>
      <div class="sn-rows"><div><span class="k">Протокол</span><span class="v">${protoBadge(sv.proto)}${(sv.tags || []).slice(0, 2).map(t => `<span class="tag">${esc(t)}</span>`).join('')}</span></div>
        <div><span class="k">Задержка</span><span class="v" id="snPing">${pingHTML(sv.delay, S.testing.has(sv.id))}</span></div></div>
      <button class="btn ghost sn-go" data-act="change"><span>Сменить сервер</span>${icon('chevron-right')}</button>`;
  }
  el.onclick = e => {
    const a = e.target.closest('[data-act]'); if (!a) return;
    if (a.dataset.act === 'add') openAdd();
    if (a.dataset.act === 'change') go('servers');
    if (a.dataset.act === 'test') testServers([sv.id]);
  };
  drawMap();
}

function renderStats() {
  const s = S.stats;
  $('#stDown').textContent = fmtSpeed(s.down); $('#stUp').textContent = fmtSpeed(s.up);
  $('#stRx').textContent = fmtBytes(s.downTotal); $('#stTx').textContent = fmtBytes(s.upTotal);
  $('#scDown').textContent = fmtSpeed(s.down); $('#scUp').textContent = fmtSpeed(s.up);
  $('#badgeConns').textContent = s.conns || 0;
}

function renderIP() {
  const el = $('#ipCard'), st = S.status.state, ip = S.ip;
  const ready = st === 'connected' || st === 'idle';
  const head = `<div class="panel-head"><div class="label">Внешний IP</div>${ready ? `<button class="icon-btn" id="ipRefresh" title="Обновить">${icon('refresh')}</button>` : ''}</div>`;
  if (ready && ip && ip.ip) {
    el.innerHTML = `${head}<div class="ip-main">${esc(ip.ip)}</div>
      <div class="ip-rows"><div><span>Провайдер</span><b title="${esc(ip.isp || '')}">${esc(ip.isp || '—')}</b></div></div>`;
  } else {
    el.innerHTML = `${head}<div class="ip-main dim">${ready && ip && ip.error ? 'не определён' : 'определение…'}</div>`;
  }
  const b = $('#ipRefresh'); if (b) b.onclick = () => { S.ip = null; renderIP(); api('/api/ip', {}).catch(() => {}); };
  drawMap();
}

function setupCanvas(c) {
  const r = c.getBoundingClientRect(), d = window.devicePixelRatio || 1;
  const w = Math.max(10, Math.round(r.width * d)), h = Math.max(10, Math.round(r.height * d));
  if (c.width !== w || c.height !== h) { c.width = w; c.height = h; }
  const ctx = c.getContext('2d'); ctx.setTransform(d, 0, 0, d, 0, 0);
  return [ctx, r.width, r.height];
}
function niceMax(v) { if (v <= 0) return 1024 * 16; const p = Math.pow(2, Math.ceil(Math.log2(v * 1.15))); return Math.max(p, 1024 * 16); }
function pathSeries(ctx, data, w, h, top, max, pad) {
  const n = data.length, step = (w - pad) / (n - 1);
  const pts = data.map((v, i) => [pad + i * step, top + h - (v / max) * h]);
  ctx.beginPath(); ctx.moveTo(pts[0][0], pts[0][1]);
  for (let i = 1; i < n; i++) { const [x0, y0] = pts[i - 1], [x1, y1] = pts[i]; const cx = (x0 + x1) / 2; ctx.bezierCurveTo(cx, y0, cx, y1, x1, y1); }
  return pts;
}
function drawChart() {
  const c = $('#chart'); if (!c || !c.offsetParent) return;
  const [ctx, W, H] = setupCanvas(c);
  ctx.clearRect(0, 0, W, H);
  const top = 6, bottom = 16, pad = 52, h = H - top - bottom;
  const max = niceMax(Math.max(...hist.down, ...hist.up));
  ctx.font = '500 10px "JetBrains Mono", monospace'; ctx.textBaseline = 'middle';
  for (let i = 0; i <= 3; i++) {
    const y = top + (h * i) / 3;
    ctx.strokeStyle = 'rgba(238,237,232,.06)'; ctx.beginPath(); ctx.moveTo(pad, y + .5); ctx.lineTo(W, y + .5); ctx.stroke();
    ctx.fillStyle = 'rgba(238,237,232,.38)'; ctx.textAlign = 'left'; ctx.fillText(fmtSpeed(max * (1 - i / 3)).replace(' ', '\u2009'), 0, y);
  }
  ctx.fillStyle = 'rgba(238,237,232,.32)'; ctx.textAlign = 'left'; ctx.fillText('−60 с', pad, H - 5); ctx.textAlign = 'right'; ctx.fillText('сейчас', W, H - 5);
  const series = [[hist.up, '238,237,232', .05, 1.25], [hist.down, '207,245,74', .14, 1.6]];
  for (const [data, rgb, fa, lw] of series) {
    const pts = pathSeries(ctx, data, W, h, top, max, pad);
    ctx.lineTo(W, top + h); ctx.lineTo(pad, top + h); ctx.closePath();
    const g = ctx.createLinearGradient(0, top, 0, top + h); g.addColorStop(0, `rgba(${rgb},${fa})`); g.addColorStop(1, `rgba(${rgb},0)`);
    ctx.fillStyle = g; ctx.fill();
    pathSeries(ctx, data, W, h, top, max, pad);
    ctx.strokeStyle = `rgba(${rgb},${lw > 1.5 ? 1 : .55})`; ctx.lineWidth = lw; ctx.stroke();
    const last = pts[pts.length - 1]; ctx.fillStyle = `rgb(${rgb})`; ctx.fillRect(last[0] - 4, last[1] - 2, 4, 4);
  }
}
function drawSpark() {
  const c = $('#spark'); if (!c.offsetParent) return;
  const [ctx, W, H] = setupCanvas(c); ctx.clearRect(0, 0, W, H);
  const max = niceMax(Math.max(...hist.down, ...hist.up));
  for (const [data, col] of [[hist.up, 'rgba(238,237,232,.45)'], [hist.down, '#cff54a']]) {
    pathSeries(ctx, data.slice(-30), W, H - 4, 2, max, 0);
    ctx.strokeStyle = col; ctx.lineWidth = 1.3; ctx.stroke();
  }
}
window.addEventListener('resize', () => { drawChart(); drawSpark(); drawMap(); });

$('#orb').addEventListener('click', async () => {
  const st = S.status.state;
  try {
    if (st === 'connected' || st === 'connecting') await api('/api/disconnect', {});
    else if (st === 'idle') {
      if (!S.servers.length) { openAdd(); return; }
      await api('/api/connect', {});
    }
  } catch (e) { handleConnectError(e); }
});
function handleConnectError(e) {
  if (e.code === 'need_admin') openNeedAdmin(); else toast('error', e.message, 6000);
}
async function patchSettings(p, quiet) {
  try {
    const r = await api('/api/settings', p);
    Object.assign(S.settings, p); renderStatus(); renderBadges();
    if (r && r.restart && !quiet) toast('info', 'Настройки применены — переподключение…');
    return true;
  } catch (e) { toast('error', e.message); return false; }
}
$('#segMode').addEventListener('click', e => { const b = e.target.closest('button'); if (b && b.dataset.v !== S.settings.mode) { patchSettings({ mode: b.dataset.v }).then(() => { if (b.dataset.v === 'tun' && !S.admin && !ANDROID) toast('info', 'TUN-режиму нужны права администратора — Volfram предложит перезапуск при подключении', 6000); }); } });
$('#segRouting').addEventListener('click', e => { const b = e.target.closest('button'); if (b && b.dataset.v !== S.settings.routing) patchSettings({ routing: b.dataset.v }).then(renderRouting); });

function groupsList() {
  const g = [{ id: 'all', name: 'Все', n: S.servers.length }];
  const manual = S.servers.filter(s => !s.subId).length;
  if (manual) g.push({ id: 'manual', name: 'Добавленные вручную', n: manual });
  for (const sub of S.subs) g.push({ id: sub.id, name: sub.name, n: S.servers.filter(s => s.subId === sub.id).length });
  return g;
}
function visibleServers() {
  let list = S.servers;
  if (S.group === 'manual') list = list.filter(s => !s.subId);
  else if (S.group !== 'all') list = list.filter(s => s.subId === S.group);
  const q = S.search.trim().toLowerCase();
  if (q) list = list.filter(s => (s.name + ' ' + s.host + ' ' + s.proto + ' ' + (s.tags || []).join(' ')).toLowerCase().includes(q));
  const sort = S.settings.sort || 'default';
  if (sort === 'delay') list = [...list].sort((a, b) => (a.delay > 0 ? a.delay : 1e9) - (b.delay > 0 ? b.delay : 1e9));
  if (sort === 'name') list = [...list].sort((a, b) => splitFlag(a.name)[1].localeCompare(splitFlag(b.name)[1], 'ru'));
  return list;
}
function srvCard(s) {
  const [flag, name] = splitFlag(s.name);
  const live = S.status.state === 'connected' && S.status.serverId === s.id;
  const sel = s.id === S.selected;
  return `<div class="srv${sel ? ' sel' : ''}${live ? ' live' : ''}" data-id="${esc(s.id)}" tabindex="0">
    <div class="srv-top">${protoBadge(s.proto)}<span class="sp"></span>${live ? '<span class="live-pill">В РАБОТЕ</span>' : ''}<span class="srv-ping">${pingHTML(s.delay, S.testing.has(s.id))}</span></div>
    <div><div class="srv-name" title="${esc(s.name)}">${flag ? esc(flag) + ' ' : ''}${esc(name)}</div><div class="srv-host">${esc(s.host)}:${s.port}</div></div>
    <div class="srv-bot"><div class="tags">${(s.tags || []).map(t => `<span class="tag">${esc(t)}</span>`).join('')}</div>
      <div class="srv-act">
        <button class="icon-btn" data-a="test" title="Проверить задержку">${icon('zap')}</button>
        <button class="icon-btn" data-a="copy" title="Копировать ссылку">${icon('copy')}</button>
        <button class="icon-btn" data-a="info" title="Конфигурация">${icon('code')}</button>
        <button class="icon-btn" data-a="rename" title="Переименовать">${icon('edit')}</button>
        <button class="icon-btn danger" data-a="del" title="Удалить">${icon('trash')}</button>
      </div></div></div>`;
}
function renderServers() {
  const groups = groupsList();
  if (!groups.find(g => g.id === S.group)) S.group = 'all';
  $('#srvGroups').innerHTML = groups.map(g => `<button class="chip${g.id === S.group ? ' active' : ''}" data-g="${esc(g.id)}" title="${esc(g.name)}"><span class="ell">${esc(g.name)}</span><span class="n">${g.n}</span></button>`).join('');
  $('#srvSort').value = S.settings.sort || 'default';
  const list = visibleServers();
  const n = S.servers.length;
  $('#srvSub').textContent = n ? `${n} ${plural(n, 'сервер', 'сервера', 'серверов')} · ${S.subs.length} ${plural(S.subs.length, 'подписка', 'подписки', 'подписок')}` : 'Список пуст';
  if (!n) {
    $('#srvGrid').innerHTML = `<div class="empty"><div class="e-ic">${icon('server')}</div><h3>Добавьте первый сервер</h3><div>Вставьте ссылку <code>vless://</code>, <code>vmess://</code>, <code>ss://</code>, <code>hy2://</code>… или адрес подписки</div><div class="actions"><button class="btn ghost" data-e="paste">${icon('clipboard')}Из буфера</button><button class="btn primary" data-e="add">${icon('plus')}Добавить</button></div></div>`;
  } else if (!list.length) {
    $('#srvGrid').innerHTML = `<div class="empty"><div class="e-ic">${icon('search')}</div><h3>Ничего не найдено</h3><div>Измените запрос или выберите другую группу</div></div>`;
  } else {
    $('#srvGrid').innerHTML = list.map(srvCard).join('');
  }
  renderBadges();
}
function plural(n, a, b, c) { const m10 = n % 10, m100 = n % 100; return m10 === 1 && m100 !== 11 ? a : m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20) ? b : c; }
function updatePing(id) {
  const s = byId(id); if (!s) return;
  const el = $(`.srv[data-id="${CSS.escape(id)}"] .srv-ping`);
  if (el) el.innerHTML = pingHTML(s.delay, S.testing.has(id));
  if (id === S.selected) { const p = $('#snPing'); if (p) p.innerHTML = pingHTML(s.delay, S.testing.has(id)); }
}
$('#srvGroups').addEventListener('click', e => { const b = e.target.closest('[data-g]'); if (b) { S.group = b.dataset.g; renderServers(); } });
$('#srvSearch').addEventListener('input', e => { S.search = e.target.value; renderServers(); });
$('#srvSort').addEventListener('change', e => { S.settings.sort = e.target.value; patchSettings({ sort: e.target.value }, true); renderServers(); });
$('#srvGrid').addEventListener('click', async e => {
  const em = e.target.closest('[data-e]');
  if (em) { em.dataset.e === 'add' ? openAdd() : pasteImport(); return; }
  const card = e.target.closest('.srv'); if (!card) return;
  const id = card.dataset.id, s = byId(id), a = e.target.closest('[data-a]');
  if (a) {
    e.stopPropagation();
    const act = a.dataset.a;
    if (act === 'test') testServers([id]);
    if (act === 'copy') copyLink(s);
    if (act === 'info') openInfo(s);
    if (act === 'rename') openRename(s);
    if (act === 'del') confirmModal('Удалить сервер?', `«${s.name}» будет удалён из списка.` + (s.subId ? ' Он вернётся при следующем обновлении подписки.' : ''), 'Удалить', async () => { await api('/api/servers/delete', { ids: [id] }); toast('ok', 'Сервер удалён'); });
    return;
  }
  if (id === S.selected) return;
  try { const r = await api('/api/select', { id }); S.selected = id; renderServers(); renderServerNow(); renderStatus(); if (r.reconnect) toast('info', 'Переключение на ' + s.name); } catch (er) { toast('error', er.message); }
});
$('#srvGrid').addEventListener('dblclick', async e => {
  const card = e.target.closest('.srv'); if (!card || e.target.closest('[data-a]')) return;
  if (S.status.state === 'idle') { try { await api('/api/connect', { id: card.dataset.id }); } catch (er) { handleConnectError(er); } }
});
async function copyLink(s) {
  try { await navigator.clipboard.writeText(s.link); toast('ok', 'Ссылка скопирована'); }
  catch { try { await api('/api/clipboard/copy', { id: s.id }); toast('ok', 'Ссылка скопирована'); } catch (e) { toast('error', e.message); } }
}
async function testServers(ids) {
  if (!S.servers.length) return;
  try { const r = await api('/api/servers/test', { ids }); if (r.count > 1) toast('info', `Тест задержки: ${r.count} ${plural(r.count, 'сервер', 'сервера', 'серверов')}`); } catch (e) { toast('error', e.message); }
}
$('#btnTest').onclick = () => { const v = visibleServers(); testServers(v.length === S.servers.length ? [] : v.map(s => s.id)); };
$('#btnAdd').onclick = () => openAdd();
$('#btnPaste').onclick = () => pasteImport();
async function pasteImport() {
  try { const r = await api('/api/clipboard/import', {}); importDone(r); }
  catch (e) { toast('error', e.message); }
}
function importDone(r) {
  const parts = [];
  if (r.added) parts.push(`${r.added} ${plural(r.added, 'сервер', 'сервера', 'серверов')}`);
  if (r.subs) parts.push(`${r.subs} ${plural(r.subs, 'подписка', 'подписки', 'подписок')}`);
  toast('ok', 'Добавлено: ' + (parts.join(' и ') || 'ничего нового'));
  if (r.errors && r.errors.length) toast('error', `Пропущено ${r.errors.length}: ${r.errors[0]}`, 6000);
}
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeModal();
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'v' && !e.target.closest('input,textarea') && !$('#modalLayer').classList.contains('open')) { e.preventDefault(); pasteImport(); }
});

function renderSubs() {
  const el = $('#subList');
  if (!S.subs.length) {
    el.innerHTML = `<div class="empty"><div class="e-ic">${icon('layers')}</div><h3>Подписок пока нет</h3><div>Подписка автоматически загружает и обновляет список серверов. Вставьте ссылку от провайдера в поле выше.</div></div>`;
    return;
  }
  el.innerHTML = S.subs.map(s => {
    const used = (s.upload || 0) + (s.download || 0), total = s.total || 0;
    const pct = total ? Math.min(100, used / total * 100) : 0;
    const days = s.expire ? Math.ceil((s.expire * 1000 - Date.now()) / 86400000) : null;
    const upd = S.subUpdating.has(s.id);
    const initial = esc((splitFlag(s.name)[1] || '?').trim().charAt(0).toUpperCase());
    return `<div class="card sub" data-id="${esc(s.id)}">
      <div class="sub-head"><div class="sub-ic">${initial}</div><div class="sub-title"><div class="sub-name" title="${esc(s.name)}">${esc(s.name)}</div><div class="sub-url" title="${esc(s.url)}">${esc(s.url)}</div></div>
        <div class="actions">${s.webPage ? `<button class="icon-btn" data-a="web" title="Сайт провайдера">${icon('external')}</button>` : ''}
          <button class="icon-btn${upd ? ' spin' : ''}" data-a="upd" title="Обновить">${icon('refresh')}</button>
          <button class="icon-btn" data-a="edit" title="Изменить">${icon('edit')}</button>
          <button class="icon-btn danger" data-a="del" title="Удалить">${icon('trash')}</button></div></div>
      <div class="sub-meta">
        <div class="sm"><div class="sm-l">Серверов</div><div class="sm-v">${S.servers.filter(x => x.subId === s.id).length}</div></div>
        <div class="sm"><div class="sm-l">Обновлено</div><div class="sm-v">${upd ? 'обновление…' : ago(s.updated)}</div></div>
        <div class="sm"><div class="sm-l">Истекает</div><div class="sm-v" style="${days !== null && days <= 3 ? 'color:var(--err)' : ''}">${s.expire ? new Date(s.expire * 1000).toLocaleDateString('ru-RU') + (days !== null ? ` · ${days > 0 ? days + ' дн' : 'истекла'}` : '') : 'бессрочно'}</div></div>
      </div>
      ${total || used ? `<div><div class="bar-row"><span>Трафик: ${fmtBytes(used)}${total ? ' из ' + fmtBytes(total) : ''}</span><span>${total ? pct.toFixed(0) + '%' : '∞'}</span></div><div class="bar${!total ? ' inf' : pct > 85 ? ' warn' : ''}"><b style="width:${total ? pct : 100}%"></b></div></div>` : ''}
      ${s.announce ? `<div class="sub-ann">${esc(s.announce)}</div>` : ''}
      ${s.error ? `<div class="sub-err">${esc(s.error)}</div>` : ''}
    </div>`;
  }).join('');
}
$('#subList').addEventListener('click', async e => {
  const a = e.target.closest('[data-a]'); if (!a) return;
  const id = a.closest('.sub').dataset.id, s = S.subs.find(x => x.id === id);
  if (a.dataset.a === 'upd') { try { await api('/api/subs/update', { id }); toast('ok', 'Подписка обновлена'); } catch (er) { toast('error', er.message, 6000); } }
  if (a.dataset.a === 'web') api('/api/open', { url: s.webPage });
  if (a.dataset.a === 'edit') openSubEdit(s);
  if (a.dataset.a === 'del') confirmModal('Удалить подписку?', `«${s.name}» и все её серверы будут удалены.`, 'Удалить', async () => { await api('/api/subs/delete', { id }); toast('ok', 'Подписка удалена'); });
});
$('#btnSubAdd').onclick = async () => {
  const url = $('#subUrl').value.trim(), name = $('#subName').value.trim();
  if (!url) { $('#subUrl').focus(); return; }
  const b = $('#btnSubAdd'); b.disabled = true;
  try { await api('/api/subs/add', { url, name }); $('#subUrl').value = ''; $('#subName').value = ''; toast('ok', 'Подписка добавлена'); }
  catch (e) { toast('error', e.message, 6000); }
  b.disabled = false;
};
$('#subUrl').addEventListener('keydown', e => { if (e.key === 'Enter') $('#btnSubAdd').click(); });
$('#btnSubsUpdateAll').onclick = async () => {
  if (!S.subs.length) { toast('info', 'Нет подписок для обновления'); return; }
  try { await api('/api/subs/update', {}); toast('ok', 'Все подписки обновлены'); } catch (e) { toast('error', e.message, 6000); }
};

function renderRouting() {
  $$('.route-card').forEach(c => c.classList.toggle('on', c.dataset.v === S.settings.routing));
  $('#optAds').checked = !!S.settings.blockAds;
  const fill = (id, arr) => { const el = $(id); if (document.activeElement !== el) el.value = (arr || []).join('\n'); };
  fill('#ruleProxy', S.settings.proxyDomains); fill('#ruleDirect', S.settings.directDomains); fill('#ruleBlock', S.settings.blockDomains);
  if (ANDROID) {
    const n = (S.settings.apps || []).length, m = S.settings.appMode || 'off';
    const apps = `${n} ${plural(n, 'приложение', 'приложения', 'приложений')}`;
    $('#appsDesc').textContent = m === 'bypass' && n ? `Мимо VPN: ${apps}` : m === 'only' && n ? `Через VPN только ${apps}` : 'Все приложения идут через VPN';
  }
}
$('#btnApps').onclick = () => openApps();
$('#routeModes').addEventListener('click', e => { const c = e.target.closest('.route-card'); if (c && c.dataset.v !== S.settings.routing) patchSettings({ routing: c.dataset.v }).then(renderRouting); });
$('#optAds').addEventListener('change', e => patchSettings({ blockAds: e.target.checked }));
let rulesTimer = null;
function rulesState(kind, text) { const el = $('#rulesState'); el.className = 'save-state ' + kind; $('span', el).textContent = text; }
async function saveRules() {
  clearTimeout(rulesTimer); rulesTimer = null;
  const lines = id => $(id).value.split('\n').map(x => x.trim()).filter(Boolean);
  const p = { proxyDomains: lines('#ruleProxy'), directDomains: lines('#ruleDirect'), blockDomains: lines('#ruleBlock') };
  if (JSON.stringify(p) === JSON.stringify({ proxyDomains: S.settings.proxyDomains || [], directDomains: S.settings.directDomains || [], blockDomains: S.settings.blockDomains || [] })) { rulesState('', 'Правила применяются автоматически'); return; }
  rulesState('busy', 'Сохранение…');
  if (await patchSettings(p, true)) rulesState('ok', S.status.state === 'connected' ? 'Сохранено и применено' : 'Сохранено — применится при подключении');
  else rulesState('bad', 'Не удалось сохранить');
}
['#ruleProxy', '#ruleDirect', '#ruleBlock'].forEach(id => {
  $(id).addEventListener('input', () => { rulesState('busy', 'Изменения…'); clearTimeout(rulesTimer); rulesTimer = setTimeout(saveRules, 1200); });
  $(id).addEventListener('blur', () => { if (rulesTimer) saveRules(); });
});

let connTimer = null, connData = [];
async function refreshConns() {
  clearTimeout(connTimer);
  if (S.page !== 'conns') return;
  try { const r = await api('/api/connections'); connData = r.connections || []; } catch { connData = []; }
  renderConns();
  connTimer = setTimeout(refreshConns, 1500);
}
function renderConns() {
  const q = ($('#connSearch').value || '').toLowerCase();
  const now = Date.now();
  let list = connData.map(c => ({ ...c, host: c.metadata.host || c.metadata.destinationIP, port: c.metadata.destinationPort }));
  if (q) list = list.filter(c => (c.host + ' ' + (c.chains || []).join(' ') + ' ' + c.rule + ' ' + (c.metadata.processPath || '')).toLowerCase().includes(q));
  list.sort((a, b) => new Date(b.start) - new Date(a.start));
  $('#connSub').textContent = S.status.state === 'connected' ? `${connData.length} ${plural(connData.length, 'активное соединение', 'активных соединения', 'активных соединений')}` : 'VPN не подключён';
  if (!list.length) {
    $('#connBody').innerHTML = `<div class="tbl-empty">${S.status.state === 'connected' ? 'Нет активных соединений' : 'Подключитесь, чтобы видеть соединения в реальном времени'}</div>`;
    return;
  }
  $('#connBody').innerHTML = list.slice(0, 300).map(c => {
    const route = (c.chains || [])[0] || '';
    const rc = route === 'proxy' ? 'proxy' : route === 'direct' ? 'direct' : 'reject';
    const proc = (c.metadata.processPath || '').split(/[\\/]/).pop();
    const dur = fmtDur(now - new Date(c.start).getTime()).replace(/^00:/, '');
    return `<div class="conn-row"><div class="c-host" title="${esc(c.host)}:${esc(c.port)}">${esc(c.host)}<small>${esc(c.port)}${proc ? ' · ' + esc(proc) : ''}${c.metadata.destinationIP && c.metadata.host ? ' · ' + esc(c.metadata.destinationIP) : ''}</small></div>
      <span class="c-net">${esc(c.metadata.network)}</span><span class="c-route ${rc}">${route === 'proxy' ? 'VPN' : route === 'direct' ? 'Напрямую' : esc(route || '—')}</span>
      <span class="c-rule" title="${esc(c.rule)} ${esc(c.rulePayload || '')}">${esc(c.rule || '—')}</span>
      <span class="num">${fmtBytes(c.download)}</span><span class="num">${fmtBytes(c.upload)}</span><span class="num">${dur}</span>
      <button class="icon-btn danger" data-close="${esc(c.id)}" title="Закрыть">${icon('x')}</button></div>`;
  }).join('');
}
$('#connSearch').addEventListener('input', renderConns);
$('#connBody').addEventListener('click', async e => { const b = e.target.closest('[data-close]'); if (b) { await api('/api/connections?id=' + encodeURIComponent(b.dataset.close), undefined, 'DELETE').catch(() => {}); refreshConns(); } });
$('#btnConnCloseAll').onclick = async () => { await api('/api/connections', undefined, 'DELETE').catch(() => {}); toast('ok', 'Соединения закрыты'); refreshConns(); };

function logLine(l) {
  const t = new Date(l.t).toLocaleTimeString('ru-RU', { hour12: false });
  let msg = l.msg;
  if (l.src === 'sing-box') msg = msg.replace(/^[+-]\d{4} \d{4}-\d\d-\d\d \d\d:\d\d:\d\d(\.\d+)?\s+/, '').replace(/^(TRACE|DEBUG|INFO|WARN|ERROR|FATAL|PANIC)\s+/, '');
  if (l.src === 'xray') msg = msg.replace(/^\d{4}\/\d\d\/\d\d \d\d:\d\d:\d\d(\.\d+)?\s+/, '').replace(/^\[(Info|Warning|Error|Debug)\]\s+/, '');
  const src = { 'sing-box': 'sing-box', xray: 'xray', app: 'volfram' }[l.src] || l.src;
  return `<div class="ll ${esc(l.level)}"><span class="t">${t}</span><span class="s ${esc(l.src)}">${esc(src)}</span><span class="lv">${esc(l.level === 'warn' ? 'warn' : l.level)}</span><span class="m">${esc(msg)}</span></div>`;
}
const logPass = l => (S.logSrc === 'all' || l.src === S.logSrc) && (S.logLevel === 'all' || (S.logLevel === 'error' ? ['error', 'fatal', 'panic'].includes(l.level) : S.logLevel === 'warn' ? ['warn', 'error', 'fatal', 'panic'].includes(l.level) : l.level === 'info' || l.level === 'debug'));
function renderLogs() {
  const v = $('#logView');
  const list = S.logs.filter(logPass).slice(-800);
  v.innerHTML = list.length ? list.map(logLine).join('') : `<div class="tbl-empty">Журнал пуст</div>`;
  if ($('#logAuto').checked) v.scrollTop = v.scrollHeight;
}
let logQueue = [], logFlush = null;
function pushLog(l) {
  S.logs.push(l); if (S.logs.length > 2000) S.logs.splice(0, 500);
  if (S.page !== 'logs' || !logPass(l)) return;
  logQueue.push(l);
  if (!logFlush) logFlush = setTimeout(() => {
    const v = $('#logView'); const empty = v.querySelector('.tbl-empty'); if (empty) empty.remove();
    v.insertAdjacentHTML('beforeend', logQueue.map(logLine).join('')); logQueue = []; logFlush = null;
    while (v.childElementCount > 900) v.firstElementChild.remove();
    if ($('#logAuto').checked) v.scrollTop = v.scrollHeight;
  }, 150);
}
$('#logLevels').addEventListener('click', e => { const b = e.target.closest('.chip'); if (!b) return; S.logLevel = b.dataset.v; $$('#logLevels .chip').forEach(x => x.classList.toggle('active', x === b)); renderLogs(); });
$('#logSrc').addEventListener('click', e => { const b = e.target.closest('.chip'); if (!b) return; S.logSrc = b.dataset.v; $$('#logSrc .chip').forEach(x => x.classList.toggle('active', x === b)); renderLogs(); });
$('#btnLogClear').onclick = async () => { await api('/api/logs', undefined, 'DELETE').catch(() => {}); S.logs = []; renderLogs(); };
$('#btnLogCopy').onclick = async () => {
  const text = S.logs.filter(logPass).map(l => `${new Date(l.t).toISOString()} [${l.src}] ${l.level.toUpperCase()} ${l.msg}`).join('\n');
  try { await navigator.clipboard.writeText(text); } catch { await api('/api/clipboard/copy', { text }).catch(() => {}); }
  toast('ok', 'Журнал скопирован');
};

function renderSettings() {
  $$('[data-set]').forEach(el => {
    const k = el.dataset.set, v = S.settings[k];
    if (document.activeElement === el) return;
    if (el.type === 'checkbox') el.checked = !!v; else el.value = v ?? '';
  });
  const lb = $('#lanBox');
  if (lb) {
    const on = !!S.settings.allowLan && !ANDROID;
    lb.hidden = !on;
    if (on) {
      const port = (S.settings.mixedPort || 10808) + 1, ips = S.lanIPs || [];
      $('#lanAddr').textContent = ips.length ? ips.map(ip => ip + ':' + port).join(', ') : 'IP этого компьютера, порт ' + port;
      $('#lanUser').textContent = S.settings.lanUser || '—';
      $('#lanPass').textContent = S.settings.lanPass || '—';
    }
  }
}
$('#lanCopy') && ($('#lanCopy').onclick = () => {
  const ip = (S.lanIPs || [])[0] || '<IP>', port = (S.settings.mixedPort || 10808) + 1;
  api('/api/clipboard/copy', { text: `socks5://${S.settings.lanUser}:${S.settings.lanPass}@${ip}:${port}` }).then(() => toast('ok', 'Скопировано: SOCKS5 с логином и паролем')).catch(e => toast('error', e.message));
});
$('#btnVpnSettings') && ($('#btnVpnSettings').onclick = () => api('/api/vpnsettings', {}).catch(e => toast('error', e.message)));
$$('[data-set]').forEach(el => el.addEventListener('change', () => {
  const k = el.dataset.set;
  let v = el.type === 'checkbox' ? el.checked : el.type === 'number' ? parseInt(el.value, 10) : el.value.trim();
  if (el.type === 'number' && !Number.isFinite(v)) { renderSettings(); return; }
  patchSettings({ [k]: v }).then(ok => { if (!ok) renderSettings(); else toast('ok', 'Сохранено', 1600); });
}));
$('#btnOpenData').onclick = () => api('/api/open', { url: 'data' });
$('#btnQuit').onclick = () => window.__volframQuit ? window.__volframQuit() : api('/api/quit', {});
(function aboutLogo() { const src = $('.logo').cloneNode(true); src.removeAttribute('class'); $('.about-logo').innerHTML = ''; $('.about-logo').appendChild(src); })();

let appsCache = null;
function openApps() {
  let mode = S.settings.appMode || 'off', q = '', showSys = false;
  const sel = new Set(S.settings.apps || []);
  openModal(`<h3>${icon('grid')}Приложения</h3>
    <div class="m-sub">Какие приложения пускать через VPN. Банковские приложения, исключённые из VPN, не видят подключение и работают как обычно.</div>
    <div class="seg three am-mode" id="amMode"><button data-v="off">Все</button><button data-v="bypass">Кроме выбранных</button><button data-v="only">Только выбранные</button></div>
    <div class="am-tools"><label class="search"><i data-icon="search"></i><input id="amSearch" placeholder="Поиск приложений" autocomplete="off"></label><label class="check"><input type="checkbox" id="amSys"><span>Системные</span></label></div>
    <div class="app-list" id="amList"><div class="am-empty">Загрузка списка приложений…</div></div>
    <div class="m-foot"><span class="am-count" id="amCount"></span><button class="btn ghost" data-close-modal>Отмена</button><button class="btn primary" id="amSave">${icon('check')}Сохранить</button></div>`, m => {
    m.dataset.nofocus = '1'; m.classList.add('apps-modal');
    const list = $('#amList', m);
    let order = [];
    const sync = () => {
      $$('#amMode button', m).forEach(b => b.classList.toggle('on', b.dataset.v === mode));
      list.classList.toggle('off', mode === 'off');
      $('#amCount', m).textContent = mode === 'off' ? 'Через VPN идут все приложения' : `Выбрано: ${sel.size}`;
    };
    const render = () => {
      const ql = q.toLowerCase();
      const items = order.filter(a => (showSys || !a.sys || sel.has(a.pkg)) && (!ql || (a.label + ' ' + a.pkg).toLowerCase().includes(ql)));
      list.innerHTML = items.length ? items.map(a => `<label class="app-row"><img loading="lazy" alt="${esc((a.label || '?').trim().charAt(0).toUpperCase())}" src="/api/appicon?pkg=${encodeURIComponent(a.pkg)}&t=${encodeURIComponent(TOKEN)}"><span class="an"><b>${esc(a.label)}</b><small>${esc(a.pkg)}</small></span><input type="checkbox" data-pkg="${esc(a.pkg)}"${sel.has(a.pkg) ? ' checked' : ''}></label>`).join('') : `<div class="am-empty">${order.length ? 'Ничего не найдено' : 'Список приложений недоступен'}</div>`;
    };
    $('#amMode', m).onclick = e => { const b = e.target.closest('button'); if (b) { mode = b.dataset.v; sync(); } };
    $('#amSearch', m).oninput = e => { q = e.target.value.trim(); render(); };
    $('#amSys', m).onchange = e => { showSys = e.target.checked; render(); };
    list.addEventListener('error', e => { const im = e.target; if (im.tagName === 'IMG') im.replaceWith(Object.assign(document.createElement('i'), { className: 'app-ph', textContent: im.alt })); }, true);
    list.addEventListener('change', e => { const c = e.target.closest('input[data-pkg]'); if (!c) return; c.checked ? sel.add(c.dataset.pkg) : sel.delete(c.dataset.pkg); if (mode === 'off' && sel.size) mode = 'bypass'; sync(); });
    $('#amSave', m).onclick = async () => { if (await patchSettings({ appMode: mode, apps: [...sel] })) { closeModal(); renderRouting(); toast('ok', 'Сохранено', 1600); } };
    sync();
    (appsCache ? Promise.resolve(appsCache) : api('/api/apps')).then(a => {
      appsCache = (a || []).slice().sort((x, y) => x.label.localeCompare(y.label, 'ru'));
      order = [...appsCache.filter(x => sel.has(x.pkg)), ...appsCache.filter(x => !sel.has(x.pkg))];
      render();
    }).catch(e => { list.innerHTML = `<div class="am-empty">${esc(e.message)}</div>`; });
  });
}

function openModal(html, mount) {
  const L = $('#modalLayer');
  L.innerHTML = `<div class="modal" role="dialog" aria-modal="true">${html}</div>`;
  L.classList.add('open'); hydrate(L);
  L.onclick = e => { if (e.target === L) closeModal(); };
  $$('[data-close-modal]', L).forEach(b => b.onclick = closeModal);
  if (mount) mount(L.firstElementChild);
  const f = L.querySelector('textarea,input'); if (f && !L.firstElementChild.dataset.nofocus) setTimeout(() => f.focus(), 30);
}
function closeModal() { const L = $('#modalLayer'); L.classList.remove('open'); L.innerHTML = ''; }
function openAdd() {
  const protos = ['VLESS', 'Reality', 'XHTTP', 'VMess', 'Trojan', 'Shadowsocks', 'SS-2022', 'Hysteria2', 'Hysteria', 'TUIC v5', 'WireGuard', 'AnyTLS', ...(ANDROID ? [] : ['NaïveProxy']), 'SOCKS5', 'gRPC', 'WebSocket', 'HTTPUpgrade', 'mKCP'];
  openModal(`<h3>${icon('plus')}Добавить серверы</h3>
    <div class="m-sub">Вставьте одну или несколько ссылок (по одной на строку), base64-блок или адрес подписки <code>https://…</code></div>
    <textarea id="addText" spellcheck="false" placeholder="vless://…&#10;hy2://…&#10;https://provider.example/sub/…"></textarea>
    <div class="proto-cloud">${protos.map(p => `<span class="tag">${p}</span>`).join('')}</div>
    <div class="m-foot"><button class="btn ghost" data-close-modal>Отмена</button><button class="btn ghost" id="addPaste">${icon('clipboard')}Из буфера</button><button class="btn primary" id="addGo">${icon('check')}Добавить</button></div>`, m => {
    $('#addGo', m).onclick = async () => {
      const text = $('#addText', m).value; if (!text.trim()) return;
      const b = $('#addGo', m); b.disabled = true;
      try { const r = await api('/api/servers/add', { text }); closeModal(); importDone(r); go('servers'); }
      catch (e) { toast('error', e.message, 6000); b.disabled = false; }
    };
    $('#addPaste', m).onclick = async () => { closeModal(); await pasteImport(); };
  });
}
function openRename(s) {
  openModal(`<h3>${icon('edit')}Переименовать</h3><div class="m-sub">${esc(s.host)}:${s.port}</div><input class="input" id="rnName" style="width:100%" value="${esc(s.name)}">
    <div class="m-foot"><button class="btn ghost" data-close-modal>Отмена</button><button class="btn primary" id="rnGo">${icon('check')}Сохранить</button></div>`, m => {
    const go2 = async () => { await api('/api/servers/rename', { id: s.id, name: $('#rnName', m).value }).catch(e => toast('error', e.message)); closeModal(); };
    $('#rnGo', m).onclick = go2; $('#rnName', m).onkeydown = e => { if (e.key === 'Enter') go2(); };
  });
}
function openSubEdit(s) {
  openModal(`<h3>${icon('edit')}Подписка</h3><div class="m-sub">Название и адрес подписки</div>
    <div class="field"><label>Название</label><input class="input" id="seName" value="${esc(s.name)}"></div>
    <div class="field" style="margin-top:12px"><label>Адрес</label><input class="input mono" id="seUrl" value="${esc(s.url)}"></div>
    <div class="m-foot"><button class="btn ghost" data-close-modal>Отмена</button><button class="btn primary" id="seGo">${icon('check')}Сохранить</button></div>`, m => {
    $('#seGo', m).onclick = async () => { await api('/api/subs/edit', { id: s.id, name: $('#seName', m).value, url: $('#seUrl', m).value }).catch(e => toast('error', e.message)); closeModal(); };
  });
}
async function openInfo(s) {
  let data; try { data = await api('/api/servers/config?id=' + encodeURIComponent(s.id)); } catch (e) { toast('error', e.message); return; }
  openModal(`<h3>${icon('code')}${esc(splitFlag(s.name)[1])}</h3><div class="m-sub">${protoBadge(s.proto)} &nbsp;Ядро: <b>${esc(data.core)}</b> · ${esc(s.host)}:${s.port}</div>
    <div class="pre">${esc(JSON.stringify(data.outbound, null, 2))}</div>
    <div class="m-foot"><button class="btn ghost" id="infCopy">${icon('copy')}Копировать ссылку</button><button class="btn primary" data-close-modal>Готово</button></div>`, m => { $('#infCopy', m).onclick = () => copyLink(s); });
}
function confirmModal(title, text, okLabel, fn) {
  openModal(`<h3>${icon('alert')}${esc(title)}</h3><div class="m-sub">${esc(text)}</div><div class="m-foot"><button class="btn ghost" data-close-modal>Отмена</button><button class="btn danger-ghost" id="cfGo">${icon('trash')}${esc(okLabel)}</button></div>`, m => {
    $('#cfGo', m).onclick = async () => { try { await fn(); } catch (e) { toast('error', e.message); } closeModal(); };
  });
}
function openNeedAdmin() {
  openModal(`<div class="warn-ic">${icon('shield')}</div><h3>Нужны права администратора</h3>
    <div class="m-sub">TUN-режим создаёт виртуальный сетевой адаптер и направляет через VPN весь трафик системы — игры, мессенджеры, любые программы. Для этого Windows требует права администратора.</div>
    <div class="m-foot"><button class="btn ghost" id="naProxy">${icon('globe')}Использовать системный прокси</button><button class="btn primary" id="naGo">${icon('shield')}Перезапустить от администратора</button></div>`, m => {
    $('#naGo', m).onclick = async () => { try { await api('/api/admin/restart', {}); } catch (e) { toast('error', e.message.includes('cancel') || e.message.includes('отмен') ? 'Запуск от администратора отменён' : e.message); } closeModal(); };
    $('#naProxy', m).onclick = async () => { closeModal(); if (await patchSettings({ mode: 'proxy' }, true)) api('/api/connect', {}).catch(handleConnectError); };
  });
}

function onEvent(ev) {
  const d = ev.data;
  switch (ev.type) {
    case 'hello': break;
    case 'status': {
      const prev = S.status.state; S.status = d;
      if (d.state !== 'connected') { S.stats.up = S.stats.down = 0; S.stats.conns = 0; renderStats(); }
      if (d.state === 'connected' && prev !== 'connected') { hist.down.fill(0); hist.up.fill(0); S.ip = null; toast('ok', 'VPN подключён'); }
      if (d.state === 'idle' && prev !== 'idle') { S.ip = null; api('/api/ip', {}).catch(() => {}); }
      renderStatus(); renderServers(); renderIP(); if (S.page === 'conns') refreshConns();
      break;
    }
    case 'stats':
      S.stats = d;
      if (S.status.state === 'connected') { hist.down.push(d.down); hist.down.shift(); hist.up.push(d.up); hist.up.shift(); }
      renderStats(); drawChart(); drawSpark();
      break;
    case 'servers': S.servers = d.servers || []; S.subs = d.subs || []; S.selected = d.selected; renderServers(); renderSubs(); renderServerNow(); renderStatus(); break;
    case 'delay': { const s = byId(d.id); if (s) s.delay = d.delay; S.testing.delete(d.id); updatePing(d.id); break; }
    case 'testing':
      if (d.active) (d.ids || []).forEach(id => { S.testing.add(id); updatePing(id); });
      else { const ids = [...S.testing]; S.testing.clear(); ids.forEach(updatePing); if (S.settings.sort === 'delay') renderServers(); }
      break;
    case 'log': pushLog(d); break;
    case 'ip': S.ip = d; renderIP(); break;
    case 'toast': toast(d.kind, d.text, 6000); break;
    case 'needAdmin': openNeedAdmin(); break;
    case 'settings': S.settings = d; renderSettings(); renderRouting(); renderStatus(); renderBadges(); break;
    case 'subUpdating': if (d.active) S.subUpdating.add(d.id); else S.subUpdating.delete(d.id); renderSubs(); break;
    case 'cores': S.coresReady = d.ready; renderStatus(); break;
  }
}
function connectEvents() {
  const es = new EventSource('/api/events?t=' + encodeURIComponent(TOKEN));
  let first = true;
  es.onmessage = m => { try { const ev = JSON.parse(m.data); if (ev.type === 'hello' && !first) loadState().catch(() => {}); first = false; onEvent(ev); } catch {} };
  es.onerror = () => {};
}

hydrate();
setInterval(() => { if (S.page === 'conns') renderConns(); }, 1000);
loadState().then(async () => {
  try { S.logs = await api('/api/logs'); } catch {}
  connectEvents();
  drawChart(); drawSpark();
}).catch(e => toast('error', 'Не удалось загрузить состояние: ' + e.message, 8000));
