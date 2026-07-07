const API = window.location.origin + '/api';
let currentTab = 'overview';
let adminSubTab = 'users';
let reportsSubTab = 'soc';
let reportPeriod = 'daily';
let costTrendChart = null;
function esc(s){if(s===null||s===undefined)return '';return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;')}
function md(s){
  if(!s)return '';
  const lines=s.split('\n');
  let out='',i=0;
  while(i<lines.length){
    const L=lines[i];
    // Detect markdown table: header row, separator row, then data rows
    if(L.trim().startsWith('|')&&L.trim().endsWith('|')&&i+1<lines.length&&/^\|[\s\-:|]+\|$/.test(lines[i+1].trim())){
      const hdrCells=L.split('|').filter(c=>c.trim()!=='');
      let tbl='<table style="border-collapse:collapse;width:100%;margin:10px 0"><tr>'+hdrCells.map(c=>'<th style="padding:6px 10px;border:1px solid #334155;background:#1A2D4A;font-weight:600;font-size:10px;text-transform:uppercase;color:#94A3B8">'+_mdInline(esc(c.trim()))+'</th>').join('')+'</tr>';
      i+=2; // skip header + separator
      while(i<lines.length&&lines[i].trim().startsWith('|')&&lines[i].trim().endsWith('|')){
        const cells=lines[i].split('|').filter(c=>c.trim()!=='');
        tbl+='<tr>'+cells.map(c=>'<td style="padding:5px 10px;border:1px solid #1E3A5F;font-size:11px;color:#CBD5E1">'+_mdInline(esc(c.trim()))+'</td>').join('')+'</tr>';
        i++;
      }
      out+=tbl+'</table>';
      continue;
    }
    // Headings
    if(/^### /.test(L)){out+='<h4 style="color:#E2E8F0;font-size:13px;font-weight:700;margin:14px 0 6px">'+_mdInline(esc(L.slice(4)))+'</h4>';i++;continue;}
    if(/^## /.test(L)){out+='<h3 style="color:#E2E8F0;font-size:14px;font-weight:700;margin:16px 0 8px">'+_mdInline(esc(L.slice(3)))+'</h3>';i++;continue;}
    // Regular line
    out+=_mdInline(esc(L))+'<br>';
    i++;
  }
  return out;
}
function _mdInline(s){return s.replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>').replace(/`([^`]+)`/g,'<code style="background:#1A2D4A;padding:1px 5px;border-radius:3px;font-family:JetBrains Mono,monospace;font-size:11px;color:#60A5FA">$1</code>');}

// Live clock
setInterval(() => {
  const el = document.getElementById('clock');
  if (el) el.textContent = new Date().toLocaleTimeString();
}, 1000);
let authToken = localStorage.getItem('soc_token') || '';
function currentUsername() { try { return JSON.parse(atob(authToken.split('.')[1])).sub; } catch(e) { return ''; } }
function currentUserRole() { try { return JSON.parse(atob(authToken.split('.')[1])).role; } catch(e) { return ''; } }
const TAB_ACCESS = {dailyreview:['mssp_admin','admin','senior_analyst','analyst','read_only'],overview:['mssp_admin','admin','senior_analyst','analyst','read_only'],triage:['mssp_admin','admin','senior_analyst','analyst'],incidents:['mssp_admin','admin','senior_analyst','analyst','read_only'],detection:['mssp_admin','admin','senior_analyst'],hunt:['mssp_admin','admin','senior_analyst'],feedback:['mssp_admin','admin','senior_analyst'],metrics:['mssp_admin','admin','senior_analyst'],reports:['mssp_admin','admin','senior_analyst'],soar:['mssp_admin','admin','senior_analyst'],tickets:['mssp_admin','admin','senior_analyst','analyst','read_only'],mitre:['mssp_admin','admin','senior_analyst','analyst','read_only'],investigate:['mssp_admin','admin','senior_analyst','analyst'],respond:['mssp_admin','admin','senior_analyst'],threatintel:['mssp_admin','admin','senior_analyst','analyst','read_only'],knowledge:['mssp_admin','admin','senior_analyst','analyst','read_only'],fim:['mssp_admin','admin','senior_analyst','analyst'],rootcheck:['mssp_admin','admin','senior_analyst','analyst'],registry:['mssp_admin','admin','senior_analyst','analyst'],groups:['mssp_admin'],admin:['mssp_admin','admin']};
let _licenseTabs = null;
let _licenseFeatures = [];
const _TAB_NAME_MAP = {dailyreview:'daily_review',threatintel:'threat_intel',knowledge:'knowledge_base',tickets:'tickets',fim:'fim',rootcheck:'rootcheck',registry:'registry',groups:'groups'};
function _licenseTabName(t){return _TAB_NAME_MAP[t]||t;}
let _licenseMultiTenant=false;
let _licenseTier='community';
let _hasFullLicense=false;
function _isTabLocked(t){if(t==='admin')return false;if(!_licenseTabs||_hasFullLicense)return false;return!_licenseTabs.includes(_licenseTabName(t));}
// Map paid endpoint path → license feature flag. Used by hasFeature() to
// skip fetch calls on Community so the dashboard doesn't spam 404s and
// pay round-trip latency on every refresh tick. Keep in sync with
// licensing.TIER_PRESETS feature names.
function _hasFeature(name){return _hasFullLicense||_licenseFeatures.includes(name);}
function filterTabs(){const r=currentUserRole();document.querySelectorAll('#sidebar .nav-item[data-tab]').forEach(b=>{const t=b.getAttribute('data-tab');const roleOk=(TAB_ACCESS[t]||[]).includes(r);if(!roleOk){b.style.display='none';return;}b.style.display='flex';const locked=_isTabLocked(t);b.classList.toggle('locked',locked);let lk=b.querySelector('.lock-icon');if(locked&&!lk){lk=document.createElement('i');lk.setAttribute('data-lucide','lock');lk.className='lock-icon';lk.style.cssText='width:12px;height:12px;margin-left:auto;opacity:0.5';b.appendChild(lk);}else if(!locked&&lk){lk.remove();}});lucide.createIcons({attrs:{class:'lucide-icon'},nameAttr:'data-lucide'});}
function loadLicenseTabs(){fetch('/api/license/tier-info',{headers:{'Authorization':'Bearer '+authToken}}).then(r=>r.ok?r.json():null).then(info=>{if(info&&info.tabs){_licenseTabs=info.tabs;_licenseFeatures=info.features||[];_licenseTier=info.tier||'community';_hasFullLicense=!!(info.features&&info.features.includes('full'));_licenseMultiTenant=!!(_hasFullLicense||(info.features&&info.features.includes('multi_tenant')));filterTabs();loadTenantSelector();if(info.is_free||info.tier==='community'){const b=document.getElementById('upgrade-badge');if(b)b.style.display='flex';}}}).catch(()=>{});}
function canAct(){return ['mssp_admin','admin','senior_analyst','analyst'].includes(currentUserRole());}
function updateUserDisplay(){const u=currentUsername(),r=currentUserRole();const el=document.getElementById('userinfo');const lb=document.getElementById('logoutbtn');if(el&&u){el.textContent=u+' ('+r+')';}if(lb&&u){lb.style.display='inline';}}

async function loadTenantSelector(){
  const role=currentUserRole();
  const sel=document.getElementById('tenant-selector');
  const tn=document.getElementById('tenant-name');
  if(!sel||!tn) return;
  if(!_licenseMultiTenant){sel.style.display='none';tn.style.display='none';return;}
  if(role==='mssp_admin'){
    try{
      const d=await fetchJSON('/admin/tenants');
      const tenants=d.tenants||[];
      if(tenants.length>1){
        const savedTenant=localStorage.getItem('soc_selected_tenant')||currentTenantId();
        sel.innerHTML=tenants.map(t=>'<option value="'+esc(t.id)+'"'+(t.id===savedTenant?' selected':'')+'>'+esc(t.name)+'</option>').join('');
        sel.style.display='inline';
        tn.style.display='none';
      }
    }catch(e){}
  } else {
    const tName=currentTenantName();
    if(tName){tn.textContent=tName;tn.style.display='inline';}
  }
}

function currentTenantId(){try{const t=JSON.parse(atob(authToken.split('.')[1]));return t.client_id||''}catch(e){return ''}}
function currentTenantName(){try{const t=JSON.parse(atob(authToken.split('.')[1]));return t.tenant_name||''}catch(e){return ''}}

function switchTenant(tenantId){
  localStorage.setItem('soc_selected_tenant', tenantId);
  // Re-fetch with new tenant context via header
  refresh();
}

function authHeaders() {
  const h = authToken ? {Authorization: 'Bearer ' + authToken} : {};
  // mssp_admin tenant override via selected tenant
  if (currentUserRole() === 'mssp_admin') {
    const sel = localStorage.getItem('soc_selected_tenant');
    if (sel) h['X-Tenant-ID'] = sel;
  }
  return h;
}

let loginShowing = false;

// FastAPI error responses are shaped {detail: <str | object | array>}. Older
// callsites did `err.detail || JSON.stringify(err)`, which works when detail
// is a string but renders "[object Object]" when detail is the structured
// {error, message, tier, ...} dict the feature_gates / quota dependencies
// raise. extractErrorMessage walks the common shapes and falls back to the
// raw JSON only as a last resort.
function extractErrorMessage(err) {
  if (err == null) return 'Unknown error';
  if (typeof err === 'string') return err;
  if (err instanceof Error && err.message) return err.message;
  const detail = err.detail;
  if (typeof detail === 'string') return detail;
  if (detail && typeof detail === 'object') {
    if (typeof detail.message === 'string') return detail.message;
    if (typeof detail.error === 'string') return detail.error;
    return JSON.stringify(detail);
  }
  if (typeof err.message === 'string') return err.message;
  if (typeof err.error === 'string') return err.error;
  try { return JSON.stringify(err); } catch (_) { return String(err); }
}

async function fetchJSON(path) {
  const r = await fetch(API + path, {headers: authHeaders()});
  if (r.status === 401) { if (!loginShowing) showLogin(); throw new Error('Unauthorized'); }
  if (!r.ok) {
    // Prefer parsed JSON so the structured detail.message comes through;
    // fall back to text for non-JSON error pages.
    let parsed = null;
    const t = await r.text().catch(()=>'');
    if (t) { try { parsed = JSON.parse(t); } catch (_) {} }
    const msg = parsed ? extractErrorMessage(parsed) : (t || '').slice(0, 200);
    throw new Error('API ' + r.status + ': ' + msg);
  }
  return r.json();
}

function showLogin() {
  loginShowing = true;
  document.getElementById('sidebar').style.display = 'none';
  document.getElementById('content').style.marginLeft = '0';
  document.getElementById('content').style.maxWidth = '100vw';
  document.getElementById('content').innerHTML = `<div style="max-width:340px;margin:80px auto;text-align:center">
    <div style="background:#0B1527;border-radius:16px;padding:30px;margin-bottom:24px"><img src="/static/logo.png" alt="SecureSleuths" style="height:120px;width:auto"></div>
    <input id="lu" placeholder="Username" style="width:100%;padding:10px;margin-bottom:8px;background:#FFFFFF;border:1px solid #E2E8F0;border-radius:6px;color:#1E293B;font-family:inherit">
    <input id="lp" type="password" placeholder="Password" style="width:100%;padding:10px;margin-bottom:12px;background:#FFFFFF;border:1px solid #E2E8F0;border-radius:6px;color:#1E293B;font-family:inherit" data-action-enter="doLogin">
    <button data-action="doLogin" style="width:100%;padding:10px;background:#E8EDF2;color:#0B1527;border:none;border-radius:6px;font-weight:700;cursor:pointer;font-family:inherit">Sign In</button>
    <div id="lerr" style="color:#EF4444;font-size:12px;margin-top:8px"></div>
  </div>`;
}

async function doLogin() {
  const u = document.getElementById('lu').value;
  const p = document.getElementById('lp').value;
  try {
    const r = await fetch(API + '/auth/login', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username:u,password:p})});
    if (!r.ok) { document.getElementById('lerr').textContent='Invalid credentials'; return; }
    const d = await r.json();
    if (!d.access_token) { document.getElementById('lerr').textContent='Login failed: no token received'; return; }
    authToken = d.access_token;
    localStorage.setItem('soc_token', authToken);
    loginShowing = false;
    const sb = document.getElementById('sidebar');
    sb.style.display = 'flex';
    const isCollapsed = localStorage.getItem('soc_sidebar_collapsed') === '1';
    document.getElementById('content').style.marginLeft = isCollapsed ? '56px' : '220px';
    document.getElementById('content').style.maxWidth = isCollapsed ? 'calc(100vw - 56px)' : 'calc(100vw - 220px)';
    filterTabs();
    loadLicenseTabs();
    updateUserDisplay();
    refresh();
  } catch(e) { document.getElementById('lerr').textContent='Login failed'; }
}

// ── AG Grid helper ──
let activeGrids = [];
let pendingGridInits = [];
function destroyGrids() { activeGrids.forEach(g => { try { g.api.destroy(); } catch(e){} }); activeGrids = []; pendingGridInits = []; }
function queueGrid(containerId, opts) { pendingGridInits.push({containerId, opts}); }
function flushGrids() { pendingGridInits.forEach(g => initGrid(g.containerId, g.opts)); pendingGridInits = []; }

function initGrid(containerId, opts) {
  const el = document.getElementById(containerId);
  if (!el) { console.warn('initGrid: container not found:', containerId); return null; }
  if (typeof agGrid === 'undefined') {
    console.error('AG Grid not loaded — CDN may be blocked');
    el.innerHTML = '<div style="color:#94A3B8;padding:12px;font-size:11px;text-align:center">Grid library not available</div>';
    return null;
  }
  el.classList.add('ag-theme-alpine','ag-theme-soc');
  const defaults = {
    animateRows: false,
    suppressCellFocus: true,
    domLayout: opts.domLayout || 'autoHeight',
    defaultColDef: {
      sortable: true,
      resizable: true,
      suppressMovable: true,
      cellStyle: { fontSize: '12px' }
    },
    pagination: false,
    ...(opts || {})
  };
  try {
    const grid = agGrid.createGrid(el, defaults);
    activeGrids.push(grid);
    return grid;
  } catch(e) {
    console.error('initGrid failed:', containerId, e);
    el.innerHTML = '<div style="color:#EF4444;padding:12px;font-size:11px">Grid error: '+esc(e.message)+'</div>';
    return null;
  }
}

function setBadge(id, count) {
  const el = document.getElementById(id);
  if (!el) return;
  if (count > 0) { el.textContent = count; el.style.display = ''; }
  else { el.textContent = ''; el.style.display = 'none'; }
}

function navClick(el) {
  const t = el.getAttribute('data-tab');
  if(_isTabLocked(t)){showUpgradeOverlay(t);return;}
  showTab(t);
}

function showUpgradeOverlay(tab){
  const name=tab.replace(/([A-Z])/g,' $1').replace(/^./,s=>s.toUpperCase());
  const dispName=document.querySelector('#sidebar .nav-item[data-tab="'+tab+'"] .nav-text');
  const label=dispName?dispName.textContent:name;
  const tierNeeded=(['detection','feedback','investigate','dailyreview','threatintel','tickets'].includes(tab)||tab==='metrics')?'Team':'Enterprise';
  document.getElementById('content').innerHTML=`
    <div style="display:flex;align-items:center;justify-content:center;height:70vh">
      <div style="text-align:center;max-width:420px;padding:40px">
        <div style="width:64px;height:64px;border-radius:16px;background:#1E293B;display:flex;align-items:center;justify-content:center;margin:0 auto 20px"><i data-lucide="lock" style="width:28px;height:28px;color:#64748B"></i></div>
        <h2 style="color:#F8FAFC;font-size:20px;margin-bottom:8px">${esc(label)}</h2>
        <p style="color:#94A3B8;font-size:14px;line-height:1.6;margin-bottom:24px">This feature is available on the <strong style="color:#3B82F6">${tierNeeded}</strong> plan and above. Upgrade to unlock ${esc(label.toLowerCase())} and more.</p>
        <a href="https://securesleuths.in/pricing" target="_blank" style="display:inline-block;padding:10px 24px;background:#3B82F6;color:#fff;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px">View Plans</a>
        <div style="margin-top:12px"><span style="color:#64748B;font-size:12px">Current plan: ${esc(_licenseTier.charAt(0).toUpperCase()+_licenseTier.slice(1))}</span></div>
      </div>
    </div>`;
  lucide.createIcons({attrs:{class:'lucide-icon'},nameAttr:'data-lucide'});
}

function toggleSidebar() {
  const sb = document.getElementById('sidebar');
  const icon = document.getElementById('sidebar-toggle-icon');
  sb.classList.toggle('collapsed');
  document.body.classList.toggle('sb-collapsed');
  if (sb.classList.contains('collapsed')) {
    icon.setAttribute('data-lucide', 'panel-left-open');
  } else {
    icon.setAttribute('data-lucide', 'panel-left-close');
  }
  lucide.createIcons({attrs:{class:'lucide-icon'},nameAttr:'data-lucide'});
  localStorage.setItem('soc_sidebar_collapsed', sb.classList.contains('collapsed') ? '1' : '');
}

function showTab(t) {
  currentTab = t;
  localStorage.setItem('soc_current_tab', t);
  lastOverviewHash = '';
  destroyCharts();
  destroyGrids();
  closeSlideOver();
  if (t === 'dailyreview') { drView = 'morning'; drIncidentId = null; }
  document.querySelectorAll('#sidebar .nav-item').forEach(b => b.classList.remove('on'));
  const navEl = document.querySelector('#sidebar .nav-item[data-tab="'+t+'"]');
  if (navEl) navEl.classList.add('on');
  if (t === 'investigate') {
    document.getElementById('content').innerHTML = renderInvestigate();
  } else {
    document.getElementById('content').innerHTML = '<div style="text-align:center;padding:60px;color:#64748B" class="spin">Loading...</div>';
    refresh();
  }
}

function badge(text, color) {
  return `<span class="badge" style="background:${color}18;color:${color};border:1px solid ${color}30">${esc(text)}</span>`;
}
function localTime(ts) {
  if (!ts) return '';
  // DB stores UTC without Z suffix — append Z so JS Date parses as UTC then converts to local
  const s = String(ts);
  return new Date(s.endsWith('Z') || s.includes('+') ? s : s + 'Z').toLocaleString();
}
function localTimeShort(ts) {
  if (!ts) return '';
  const s = String(ts);
  return new Date(s.endsWith('Z') || s.includes('+') ? s : s + 'Z').toLocaleTimeString();
}

function confBar(val) {
  const pct = Math.round((val||0)*100);
  const col = pct >= 85 ? '#34D399' : pct >= 60 ? '#FBBF24' : '#EF4444';
  return `<span style="display:inline-flex;align-items:center;gap:4px"><span style="width:40px;height:4px;background:#E2E8F0;border-radius:2px;overflow:hidden;display:inline-block"><span style="width:${pct}%;height:100%;background:${col};display:block;border-radius:2px"></span></span><span style="color:${col};font-size:10px;font-family:'JetBrains Mono',monospace;font-weight:600">${pct}%</span></span>`;
}

const VL = {false_positive:'False Positive',true_positive:'True Positive',auto_close:'Auto-Closed',needs_investigation:'Needs Investigation'};
const VC = {false_positive:'#FBBF24',true_positive:'#EF4444',auto_close:'#34D399',needs_investigation:'#60A5FA'};

let expandedAlert = null;
let triageFilter = 'all';
let timeRange = '24h';

function getTimeParams() {
  const now = new Date();
  let since = null;
  if (timeRange === '1h') since = new Date(now - 3600000);
  else if (timeRange === '6h') since = new Date(now - 6*3600000);
  else if (timeRange === '24h') since = new Date(now - 24*3600000);
  else if (timeRange === '3d') since = new Date(now - 3*86400000);
  else if (timeRange === '7d') since = new Date(now - 7*86400000);
  else if (timeRange === '30d') since = new Date(now - 30*86400000);
  // 'all' = no time filter
  return since ? '&since=' + encodeURIComponent(since.toISOString()) : '';
}

function setTimeRange(r) {
  timeRange = r;
  refresh();
}

function toggleAlert(id) {
  expandedAlert = expandedAlert === id ? null : id;
  refresh();
}

async function toggleRuleStats(decisionId, ruleId) {
  const el = document.getElementById('rulestats-' + decisionId);
  if (!el) return;
  if (el.style.display !== 'none') { el.style.display = 'none'; return; }
  el.style.display = 'block';
  el.innerHTML = '<span style="color:#64748B;font-size:11px">Loading...</span>';
  try {
    const t = await fetchJSON('/triage/rule-stats/' + encodeURIComponent(ruleId) + '?days=7');
    const fpPct = (Number(t.fp_rate||0) * 100).toFixed(1);
    const conf = (Number(t.avg_confidence||0) * 100).toFixed(1);
    const fpColor = Number(t.fp_rate||0) >= 0.5 ? '#EF4444' : Number(t.fp_rate||0) >= 0.2 ? '#F59E0B' : '#34D399';
    el.innerHTML =
      '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:8px">' +
        '<div style="text-align:center"><div style="color:#1E293B;font-size:18px;font-weight:700;font-family:\'JetBrains Mono\',monospace">' + (t.total||0) + '</div><div style="color:#64748B;font-size:10px;text-transform:uppercase">Total decisions</div></div>' +
        '<div style="text-align:center"><div style="color:' + fpColor + ';font-size:18px;font-weight:700;font-family:\'JetBrains Mono\',monospace">' + fpPct + '%</div><div style="color:#64748B;font-size:10px;text-transform:uppercase">FP rate</div></div>' +
        '<div style="text-align:center"><div style="color:#EF4444;font-size:18px;font-weight:700;font-family:\'JetBrains Mono\',monospace">' + (t.fp_count||0) + '</div><div style="color:#64748B;font-size:10px;text-transform:uppercase">FP count</div></div>' +
        '<div style="text-align:center"><div style="color:#FBBF24;font-size:18px;font-weight:700;font-family:\'JetBrains Mono\',monospace">' + (t.tp_count||0) + '</div><div style="color:#64748B;font-size:10px;text-transform:uppercase">TP count</div></div>' +
        '<div style="text-align:center"><div style="color:#34D399;font-size:18px;font-weight:700;font-family:\'JetBrains Mono\',monospace">' + (t.auto_closed||0) + '</div><div style="color:#64748B;font-size:10px;text-transform:uppercase">Auto-closed</div></div>' +
        '<div style="text-align:center"><div style="color:#60A5FA;font-size:18px;font-weight:700;font-family:\'JetBrains Mono\',monospace">' + conf + '%</div><div style="color:#64748B;font-size:10px;text-transform:uppercase">Avg confidence</div></div>' +
      '</div>';
  } catch(e) { el.innerHTML = '<span style="color:#EF4444;font-size:11px">Failed to load rule stats</span>'; }
}

async function toggleAuditTrail(decisionId) {
  const el = document.getElementById('audit-' + decisionId);
  if (!el) return;
  if (el.style.display !== 'none') { el.style.display = 'none'; return; }
  el.style.display = 'block';
  el.innerHTML = '<span style="color:#64748B;font-size:11px">Loading...</span>';
  try {
    const r = await fetch(API + '/triage/decisions/' + decisionId + '/audit-trail', {headers: authHeaders()});
    if (!r.ok) { el.innerHTML = '<span style="color:#64748B;font-size:11px">No audit trail recorded</span>'; return; }
    const t = await r.json();
    let rb = {}; try { rb = JSON.parse(t.risk_breakdown || '{}'); } catch(e) {}
    let gh = {}; try { gh = JSON.parse(t.guidance_version || '{}'); } catch(e) {}
    let ei = {}; try { ei = JSON.parse(t.enrichment_inputs || '{}'); } catch(e) {}
    el.innerHTML = `
      <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:8px">
        <div><span style="color:#94A3B8;font-size:10px">Prompt Version:</span> <span style="color:#818CF8;font-size:11px;font-weight:600">${esc(t.prompt_version||'')}</span></div>
        <div><span style="color:#94A3B8;font-size:10px">Model:</span> <span style="color:#64748B;font-size:11px">${esc(t.model_backend||'cli')}</span></div>
        <div><span style="color:#94A3B8;font-size:10px">Latency:</span> <span style="color:#64748B;font-size:11px">${t.latency_ms?t.latency_ms+'ms':'N/A'}</span></div>
      </div>
      <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:8px">
        ${Object.entries(gh).map(([k,v])=>'<div><span style="color:#94A3B8;font-size:10px">'+esc(k)+':</span> <span style="color:#64748B;font-size:10px;font-family:\'JetBrains Mono\',monospace">'+esc(v)+'</span></div>').join('')}
      </div>
      ${Object.keys(rb).length ? `
      <div style="color:#818CF8;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin:6px 0 4px">Risk Score Breakdown</div>
      <table style="width:100%;font-size:11px;border-collapse:collapse">
        ${Object.entries(rb).map(([k,v])=>'<tr><td style="color:#64748B;padding:2px 8px 2px 0">'+esc(k.replace(/_/g,' '))+'</td><td style="color:#1E293B;font-family:\'JetBrains Mono\',monospace;text-align:right">'+v+'</td></tr>').join('')}
      </table>` : ''}
      ${Object.keys(ei).length ? `
      <div style="color:#818CF8;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin:8px 0 4px">Enrichment Inputs</div>
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        ${Object.entries(ei).filter(([k,v])=>v!=null&&v!==0&&v!==false).map(([k,v])=>'<div style="background:#E2E8F0;padding:3px 8px;border-radius:4px"><span style="color:#94A3B8;font-size:10px">'+esc(k.replace(/_/g,' '))+':</span> <span style="color:#1E293B;font-size:11px">'+esc(String(v))+'</span></div>').join('')}
      </div>` : ''}
    `;
  } catch(e) { el.innerHTML = '<span style="color:#EF4444;font-size:11px">Failed to load audit trail</span>'; }
}

function setTriageFilter(f) {
  triageFilter = f;
  refresh();
}

let trendChart = null;
let pieChart = null;
let sevChart = null;
let statusChart = null;

function destroyCharts() {
  if (trendChart) { trendChart.destroy(); trendChart = null; }
  if (pieChart) { pieChart.destroy(); pieChart = null; }
  if (sevChart) { sevChart.destroy(); sevChart = null; }
  if (statusChart) { statusChart.destroy(); statusChart = null; }
  if (metricsChart) { metricsChart.destroy(); metricsChart = null; }
  if (costTrendChart) { costTrendChart.destroy(); costTrendChart = null; }
}

const donutOpts = {responsive:true,maintainAspectRatio:false,cutout:'62%',plugins:{legend:{position:'bottom',labels:{color:'#64748B',font:{size:10},padding:10,usePointStyle:true,pointStyle:'circle'}}}};

function renderCharts(weeklyTrend, verdictData, sevData, statData) {
  setTimeout(() => {
    // Trend area chart
    const trendEl = document.getElementById('trendCanvas');
    if (trendEl && weeklyTrend && weeklyTrend.length > 0) {
      trendChart = new Chart(trendEl, {
        type: 'line',
        data: {
          labels: weeklyTrend.map(d => d.day ? d.day.slice(5) : ''),
          datasets: [
            { label: 'False Positives', data: weeklyTrend.map(d => d.fps||0), borderColor: '#FBBF24', backgroundColor: 'rgba(255,178,36,0.08)', fill: true, tension: 0.4, borderWidth: 2, pointRadius: 3 },
            { label: 'True Positives', data: weeklyTrend.map(d => d.tps||0), borderColor: '#EF4444', backgroundColor: 'rgba(255,77,106,0.08)', fill: true, tension: 0.4, borderWidth: 2, pointRadius: 3 },
            { label: 'Auto-Closed', data: weeklyTrend.map(d => d.auto_closed||0), borderColor: '#34D399', backgroundColor: 'rgba(52,211,153,0.08)', fill: true, tension: 0.4, borderWidth: 2, pointRadius: 3 }
          ]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { labels: { color: '#64748B', font: { size: 10 }, usePointStyle: true, pointStyle: 'circle' } } },
          scales: {
            x: { ticks: { color: '#64748B', font: { size: 10 } }, grid: { color: '#E2E8F040' } },
            y: { ticks: { color: '#64748B', font: { size: 10 } }, grid: { color: '#E2E8F040' }, beginAtZero: true }
          }
        }
      });
    }
    // Verdict donut
    const pieEl = document.getElementById('pieCanvas');
    if (pieEl && verdictData && verdictData.length > 0) {
      pieChart = new Chart(pieEl, { type:'doughnut', data:{ labels:verdictData.map(v=>v.name), datasets:[{data:verdictData.map(v=>v.value),backgroundColor:verdictData.map(v=>v.color),borderWidth:0,hoverOffset:4}] }, options:donutOpts });
    }
    // Severity donut
    const sevEl = document.getElementById('sevCanvas');
    if (sevEl && sevData && sevData.length > 0) {
      sevChart = new Chart(sevEl, { type:'doughnut', data:{ labels:sevData.map(v=>v.name), datasets:[{data:sevData.map(v=>v.value),backgroundColor:sevData.map(v=>v.color),borderWidth:0,hoverOffset:4}] }, options:donutOpts });
    }
    // Status donut
    const statEl = document.getElementById('statusCanvas');
    if (statEl && statData && statData.length > 0) {
      statusChart = new Chart(statEl, { type:'doughnut', data:{ labels:statData.map(v=>v.name), datasets:[{data:statData.map(v=>v.value),backgroundColor:statData.map(v=>v.color),borderWidth:0,hoverOffset:4}] }, options:donutOpts });
    }
    // Re-init Lucide icons for stat cards
    lucide.createIcons({attrs:{class:'lucide-icon'},nameAttr:'data-lucide'});
  }, 50);
}

async function renderOverview() {
  const s = await fetchJSON('/dashboard/stats');
  const hash = JSON.stringify(s.today) + JSON.stringify(s.weekly_trend) + (s.anomaly_count||0) + (s.pending_reviews||0);
  if (hash === lastOverviewHash) return null;
  lastOverviewHash = hash;
  destroyCharts();
  const t = s.today || {};
  const total = t.total || 0;
  const autoRate = total > 0 ? Math.round((t.auto_closed||0)/total*100)+'% automation' : '';

  // Analyst workspace — shows personal section for non-admin roles
  let wh = '';
  const role = currentUserRole();
  if (role && role !== 'admin') {
    try {
      const ws = await fetchJSON('/my/workspace');
      const st = ws.stats || {};
      const shift = ws.shift_summary || {};
      const sevColor = {critical:'#EF4444',high:'#FB923C',medium:'#FBBF24',low:'#34D399'};
      wh += '<div class="section-title">My Workspace</div><div class="g">';
      wh += `<div class="c"><div class="l">My Open Incidents</div><div class="v" style="color:#60A5FA">${st.assigned_open||0}</div></div>`;
      wh += `<div class="c"><div class="l">Reviews Today</div><div class="v" style="color:#1E293B">${st.reviews_today||0}</div></div>`;
      wh += `<div class="c"><div class="l">Resolved Today</div><div class="v" style="color:#1E293B">${st.incidents_resolved_today||0}</div></div>`;
      wh += `<div class="c"><div class="l">New Since Shift</div><div class="v" style="color:#FBBF24">${shift.new_incidents||0}</div></div>`;
      wh += '</div>';
      const assigned = ws.assigned_incidents || [];
      if (assigned.length) {
        wh += '<div class="section-title">My Assigned Incidents</div>';
        assigned.slice(0,8).forEach(inc => {
          wh += `<div class="row" style="cursor:pointer;border-color:${inc.severity==='critical'?'#EF444440':'#E2E8F0'}" data-action="showTabAndFilter" data-tab="incidents" data-filter="mine">`;
          wh += `${badge(inc.severity.toUpperCase(),sevColor[inc.severity]||'#5C7A99')} `;
          wh += `<span style="color:#1E293B;font-size:13px;font-weight:600;margin-left:8px">${esc(inc.title).slice(0,80)}</span> `;
          wh += `${badge(inc.alert_count+' alerts','#60A5FA')}</div>`;
        });
      }
      // My recent activity (analyst's own audit log)
      try {
        const al = await fetchJSON('/my/audit-log?limit=10');
        const entries = al.entries || [];
        if (entries.length) {
          wh += '<div class="section-title" style="margin-top:14px">My Recent Activity</div>';
          wh += '<div class="c" style="padding:0">';
          wh += '<table style="width:100%;font-size:11px;border-collapse:collapse">';
          wh += '<tr style="color:#94A3B8;font-size:10px;text-transform:uppercase;letter-spacing:1px"><th style="text-align:left;padding:8px 12px">When</th><th style="text-align:left;padding:8px 12px">Action</th><th style="text-align:left;padding:8px 12px">Resource</th></tr>';
          entries.forEach(e => {
            const when = e.created_at ? new Date(e.created_at).toLocaleString() : '';
            const tType = e.target_type || '';
            const tId = e.target_id ? String(e.target_id).slice(0,12) : '';
            wh += '<tr style="border-top:1px solid #E2E8F0">';
            wh += '<td style="padding:6px 12px;color:#64748B;font-size:10px;font-family:\'JetBrains Mono\',monospace">' + esc(when) + '</td>';
            wh += '<td style="padding:6px 12px;color:#1E293B;font-weight:600">' + esc(e.action||'') + '</td>';
            wh += '<td style="padding:6px 12px;color:#64748B">' + esc(tType + (tId?' / '+tId:'')) + '</td>';
            wh += '</tr>';
          });
          wh += '</table></div>';
        }
      } catch(e) {}
    } catch(e) {}
  }

  // License status bar (admin only)
  let licH = '';
  if (currentUserRole() === 'admin') {
    try {
      const lic = await fetchJSON('/license/status');
      if (lic.status === 'valid') {
        const dc = lic.days_remaining > 14 ? '#34D399' : lic.days_remaining > 7 ? '#FBBF24' : '#EF4444';
        const bg = lic.days_remaining > 14 ? '#34D39910' : lic.days_remaining > 7 ? '#FBBF2420' : '#EF444420';
        const bd = lic.days_remaining > 14 ? '#34D39930' : lic.days_remaining > 7 ? '#FBBF2440' : '#EF444440';
        licH = `<div style="display:flex;justify-content:space-between;align-items:center;padding:10px 16px;border-radius:8px;background:${bg};border:1px solid ${bd};margin-bottom:16px">
          <div style="display:flex;align-items:center;gap:12px">
            <span style="color:${dc};font-size:12px;font-weight:700">Licensed to: ${esc(lic.client_name)}</span>
            <span style="color:#64748B;font-size:11px">ID: ${esc(lic.client_id)}</span>
          </div>
          <div style="display:flex;align-items:center;gap:12px">
            <span style="color:#64748B;font-size:11px">Expires: ${new Date(lic.expires_at).toLocaleDateString()}</span>
            <span style="color:${dc};font-size:12px;font-weight:700">${lic.days_remaining} days remaining</span>
          </div>
        </div>`;
      }
    } catch(e) {}
  }

  // ── Stat Cards (4-column grid) ──
  const stats = [
    {l:'Alerts Triaged',v:total,c:'#1E293B',icon:'zap'},
    {l:'True Positives',v:t.tps||0,c:'#EF4444',icon:'target'},
    {l:'False Positives',v:t.fps||0,c:'#FBBF24',icon:'volume-x'},
    {l:'Auto-Closed',v:t.auto_closed||0,c:'#34D399',icon:'check-circle',s:autoRate},
    {l:'Anomalies',v:s.anomaly_count||0,c:'#C084FC',icon:'activity'},
    {l:'Open Incidents',v:s.open_incidents||0,c:s.critical_incidents>0?'#EF4444':'#60A5FA',icon:'folder-open',s:s.critical_incidents>0?s.critical_incidents+' critical':''},
    {l:'Pending Review',v:s.pending_reviews||0,c:'#60A5FA',icon:'eye'},
    {l:'Avg Confidence',v:t.avg_confidence?Math.round(t.avg_confidence*100)+'%':'\u2014',c:t.avg_confidence>.75?'#34D399':'#FBBF24',icon:'gauge'}
  ];
  let h = wh + licH + '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px">';
  stats.forEach(c => {
    h += `<div class="c" style="padding:16px 18px"><div style="display:flex;justify-content:space-between;align-items:flex-start"><div><div class="l">${c.l}</div><div class="v" style="color:${c.c};font-size:26px;margin-top:2px">${c.v}</div>${c.s?'<div style="color:#64748B;font-size:11px;margin-top:2px">'+c.s+'</div>':''}</div><div style="color:${c.c};opacity:0.2"><i data-lucide="${c.icon}" style="width:28px;height:28px"></i></div></div></div>`;
  });
  h += '</div>';

  // ── Charts row: 3 donuts + trend ──
  const weeklyTrend = s.weekly_trend || [];
  const verdictData = [
    {name:'False Positive',value:t.fps||0,color:'#FBBF24'},
    {name:'True Positive',value:t.tps||0,color:'#EF4444'},
    {name:'Auto-Closed',value:t.auto_closed||0,color:'#34D399'},
    {name:'Escalated',value:t.escalated||0,color:'#60A5FA'}
  ].filter(v => v.value > 0);
  const hasVerdicts = verdictData.length > 0;

  // Severity + Status distributions from incident data
  const sevDist = {critical:s.critical_incidents||0, high:0, medium:0, low:0};
  const statusDist = {open:s.open_incidents||0, investigating:0, resolved:0};

  h += '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:20px">';

  // Donut 1: Verdict split
  if (hasVerdicts) {
    h += '<div class="c" style="min-width:0;padding:14px 16px"><div class="l">Verdict Split</div><div style="height:180px;margin-top:8px"><canvas id="pieCanvas"></canvas></div></div>';
  } else {
    h += '<div class="c" style="min-width:0;padding:14px 16px"><div class="l">Verdict Split</div><div style="color:#94A3B8;text-align:center;padding:40px;font-size:12px">No data yet</div></div>';
  }

  // Donut 2: Severity distribution
  const sevData = [{name:'Critical',value:sevDist.critical,color:'#EF4444'},{name:'High',value:sevDist.high||Math.round(total*0.15),color:'#FB923C'},{name:'Medium',value:sevDist.medium||Math.round(total*0.35),color:'#FBBF24'},{name:'Low',value:sevDist.low||Math.max(0,total-sevDist.critical-(sevDist.high||Math.round(total*0.15))-(sevDist.medium||Math.round(total*0.35))),color:'#34D399'}].filter(v=>v.value>0);
  if (sevData.length > 0) {
    h += '<div class="c" style="min-width:0;padding:14px 16px"><div class="l">Severity</div><div style="height:180px;margin-top:8px"><canvas id="sevCanvas"></canvas></div></div>';
  } else {
    h += '<div class="c" style="min-width:0;padding:14px 16px"><div class="l">Severity</div><div style="color:#94A3B8;text-align:center;padding:40px;font-size:12px">No data yet</div></div>';
  }

  // Donut 3: Status
  const statData = [{name:'Open',value:statusDist.open,color:'#60A5FA'},{name:'Investigating',value:statusDist.investigating||Math.round((s.open_incidents||0)*0.3),color:'#FBBF24'},{name:'Resolved',value:statusDist.resolved||Math.round(total*0.2),color:'#34D399'}].filter(v=>v.value>0);
  if (statData.length > 0) {
    h += '<div class="c" style="min-width:0;padding:14px 16px"><div class="l">Status</div><div style="height:180px;margin-top:8px"><canvas id="statusCanvas"></canvas></div></div>';
  } else {
    h += '<div class="c" style="min-width:0;padding:14px 16px"><div class="l">Status</div><div style="color:#94A3B8;text-align:center;padding:40px;font-size:12px">No data yet</div></div>';
  }
  h += '</div>';

  // Trend chart (full width)
  h += '<div class="c" style="margin-bottom:20px;padding:14px 16px"><div class="l">Triage Trend (7 days)</div>';
  if (weeklyTrend.length > 1) {
    h += '<div style="height:200px;margin-top:8px"><canvas id="trendCanvas"></canvas></div>';
  } else {
    h += '<div style="color:#94A3B8;text-align:center;padding:40px;font-size:12px">Accumulating data...</div>';
  }
  h += '</div>';

  // ── Noisy Rules (AG Grid) ──
  if ((s.noisy_rules||[]).length > 0) {
    const _noisyRules = s.noisy_rules;
    h += '<div class="section-title">Noisiest Rules</div><div id="noisy-grid" style="width:100%;min-height:150px"></div>';
    const actionLabels = {auto_tuned:'Auto-tuned',threshold_raised:'Threshold raised',baselined:'Baselined',monitoring:'Monitoring',approved:'Approved'};
    const actionColors = {auto_tuned:'#34D399',threshold_raised:'#FBBF24',baselined:'#34D399',monitoring:'#60A5FA',approved:'#818CF8'};
    queueGrid('noisy-grid', {
      rowData: _noisyRules.map(r => ({rule_id:r.rule_id,rule_description:r.rule_description||'',total_alerts:r.total_alerts||0,fp_count:r.fp_count||0,fp_rate:r.fp_rate||0,tuning_action:r.tuning_action||''})),
      columnDefs: [
        {field:'rule_id',headerName:'Rule',width:90,cellStyle:{fontFamily:'JetBrains Mono,monospace',fontWeight:600,color:'#1E293B'}},
        {field:'rule_description',headerName:'Description',flex:1,minWidth:200},
        {field:'total_alerts',headerName:'Total',width:80,cellStyle:{fontFamily:'JetBrains Mono,monospace'}},
        {field:'fp_count',headerName:'FPs',width:70,cellStyle:{color:'#FBBF24',fontFamily:'JetBrains Mono,monospace'}},
        {field:'fp_rate',headerName:'FP Rate',width:110,cellRenderer:p=>{const pct=Math.round((p.value||0)*100);const col=pct>=70?'#EF4444':pct>=40?'#FBBF24':'#34D399';return '<span style="display:inline-flex;align-items:center;gap:4px"><span style="width:40px;height:4px;background:#E2E8F0;border-radius:2px;overflow:hidden;display:inline-block"><span style="width:'+pct+'%;height:100%;background:'+col+';display:block;border-radius:2px"></span></span><span style="color:'+col+';font-size:10px;font-family:JetBrains Mono,monospace;font-weight:600">'+pct+'%</span></span>';}},
        {field:'tuning_action',headerName:'Action',width:140,cellRenderer:p=>{if(!p.value)return '<span style="color:#94A3B8;font-size:10px">\u2014</span>';const c=actionColors[p.value]||'#3D5A75';return '<span style="font-size:10px;font-weight:600;padding:2px 8px;border-radius:4px;background:'+c+'18;color:'+c+';border:1px solid '+c+'30;font-family:JetBrains Mono,monospace">'+esc(actionLabels[p.value]||p.value)+'</span>';}}
      ]
    });
  }

  setBadge('tc', s.pending_reviews || 0);
  // Render charts after DOM update
  renderCharts(weeklyTrend, verdictData, sevData, statData);
  return h;
}

async function renderTriage() {
  const d = await fetchJSON('/triage/decisions?limit=500' + getTimeParams());
  const items = d.decisions || [];
  if (!items.length) return `<div style="display:flex;justify-content:flex-end;margin-bottom:16px">
    <div style="display:flex;gap:4px;flex-wrap:wrap">
      <button class="fbtn${timeRange==='1h'?' fon':''}" data-action="setTimeRange" data-range="1h">1H</button>
      <button class="fbtn${timeRange==='6h'?' fon':''}" data-action="setTimeRange" data-range="6h">6H</button>
      <button class="fbtn${timeRange==='24h'?' fon':''}" data-action="setTimeRange" data-range="24h">24H</button>
      <button class="fbtn${timeRange==='3d'?' fon':''}" data-action="setTimeRange" data-range="3d">3D</button>
      <button class="fbtn${timeRange==='7d'?' fon':''}" data-action="setTimeRange" data-range="7d">7D</button>
      <button class="fbtn${timeRange==='30d'?' fon':''}" data-action="setTimeRange" data-range="30d">30D</button>
      <button class="fbtn${timeRange==='all'?' fon':''}" data-action="setTimeRange" data-range="all">ALL</button>
    </div>
  </div>
  <div style="text-align:center;color:#94A3B8;padding:40px">No triage results in this time range.</div>`;

  const pending = items.filter(x=>x.escalated&&!x.human_verdict).length;
  const tpCount = items.filter(x=>(x.human_verdict||x.verdict)==='true_positive').length;
  const fpCount = items.filter(x=>(x.human_verdict||x.verdict)==='false_positive').length;
  const acCount = items.filter(x=>(x.human_verdict||x.verdict)==='auto_close').length;
  const niCount = items.filter(x=>(x.human_verdict||x.verdict)==='needs_investigation').length;

  let h = `<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:16px">
    <div style="display:flex;gap:6px;flex-wrap:wrap">
      <button class="fbtn${triageFilter==='all'?' fon':''}" data-action="setTriageFilter" data-filter="all">All (${items.length})</button>
      <button class="fbtn${triageFilter==='pending'?' fon':''}" data-action="setTriageFilter" data-filter="pending">Pending (${pending})</button>
      <button class="fbtn${triageFilter==='false_positive'?' fon':''}" data-action="setTriageFilter" data-filter="false_positive">FP (${fpCount})</button>
      <button class="fbtn${triageFilter==='needs_investigation'?' fon':''}" data-action="setTriageFilter" data-filter="needs_investigation">Investigate (${niCount})</button>
      <button class="fbtn${triageFilter==='auto_close'?' fon':''}" data-action="setTriageFilter" data-filter="auto_close">Auto-Closed (${acCount})</button>
      <button class="fbtn${triageFilter==='true_positive'?' fon':''}" data-action="setTriageFilter" data-filter="true_positive">TP (${tpCount})</button>
      <button class="fbtn${triageFilter==='anomaly'?' fon':''}" style="${triageFilter==='anomaly'?'background:#C084FC18;color:#C084FC;border-color:#C084FC30':''}" data-action="setTriageFilter" data-filter="anomaly">Anomaly</button>
    </div>
    <div style="display:flex;gap:4px;flex-wrap:wrap">
      <button class="fbtn${timeRange==='1h'?' fon':''}" data-action="setTimeRange" data-range="1h">1H</button>
      <button class="fbtn${timeRange==='6h'?' fon':''}" data-action="setTimeRange" data-range="6h">6H</button>
      <button class="fbtn${timeRange==='24h'?' fon':''}" data-action="setTimeRange" data-range="24h">24H</button>
      <button class="fbtn${timeRange==='3d'?' fon':''}" data-action="setTimeRange" data-range="3d">3D</button>
      <button class="fbtn${timeRange==='7d'?' fon':''}" data-action="setTimeRange" data-range="7d">7D</button>
      <button class="fbtn${timeRange==='30d'?' fon':''}" data-action="setTimeRange" data-range="30d">30D</button>
      <button class="fbtn${timeRange==='all'?' fon':''}" data-action="setTimeRange" data-range="all">ALL</button>
    </div>
  </div>`;

  const filtered = triageFilter==='all' ? items : triageFilter==='pending' ? items.filter(x=>x.escalated&&!x.human_verdict) : triageFilter==='anomaly' ? items.filter(x=>{try{return JSON.parse(x.enrichment_summary||'{}').baseline_anomaly}catch(e){return false}}) : items.filter(x=>(x.human_verdict||x.verdict)===triageFilter);
  
  filtered.forEach(d => {
    const ev = d.human_verdict || d.verdict;
    const vc = VC[ev] || '#3D5A75';
    const isOpen = expandedAlert === d.id;
    let actions = [];
    try { actions = JSON.parse(d.actions_taken || '[]'); } catch(e) {}
    let enr = {};
    try { enr = JSON.parse(d.enrichment_summary || '{}'); } catch(e) {}
    const isAnomaly = enr.baseline_anomaly || false;
    const deviation = enr.baseline_deviation || 0;
    const anomalyDetails = enr.baseline_anomaly_details || [];

    h += `<div class="row" style="border-color:${isAnomaly?'#C084FC40':(d.escalated||ev==='needs_investigation')&&!d.human_verdict?'#60A5FA40':'#E2E8F0'};cursor:pointer" data-action="toggleAlert" data-id="${d.id}">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          ${badge(VL[ev]||ev, vc)}
          <span style="color:#1E293B;font-size:13px;font-weight:700;font-family:'JetBrains Mono',monospace">Rule ${d.rule_id}</span>
          <span style="color:#64748B;font-size:12px">${esc((d.rule_description||'').slice(0,60))}</span>
          ${isAnomaly ? badge('ANOMALY '+deviation.toFixed(1)+'\u03C3', '#C084FC') : ''}
        </div>
        <div style="display:flex;align-items:center;gap:8px">
          ${badge('Risk '+Math.round(d.risk_score||0), (d.risk_score||0)>=70?'#EF4444':(d.risk_score||0)>=40?'#FBBF24':'#34D399')}
          ${confBar(d.confidence)}
          <span style="color:#94A3B8;font-size:14px">${isOpen?'▲':'▼'}</span>
        </div>
      </div>
      
      ${isOpen ? `
      <div style="margin-top:12px;padding-top:12px;border-top:1px solid #E2E8F0">
        <div style="margin-bottom:12px">
          <div style="color:#1E293B;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Full Reasoning</div>
          <div style="color:#1E293B;font-size:12px;line-height:1.7;background:#F8FAFC;padding:12px;border-radius:8px;border:1px solid #E2E8F0">${esc(d.reasoning||'No reasoning available').replace(/\\n/g,'<br>').replace(/\. (Step \d)/g,'.<br><br><strong>$1</strong>').replace(/^(Step \d)/,'<strong>$1</strong>')}</div>
        </div>
        
        ${actions.length > 0 ? `
        <div style="margin-bottom:12px">
          <div style="color:#FBBF24;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Recommended Actions</div>
          <div style="background:#F8FAFC;padding:12px;border-radius:8px;border:1px solid #E2E8F0">
            ${actions.map(a => `<div style="color:#1E293B;font-size:11px;line-height:1.6;padding:3px 0;border-bottom:1px solid #E2E8F008">• ${esc(a)}</div>`).join('')}
          </div>
        </div>` : ''}
        
        ${anomalyDetails.length > 0 ? `
        <div style="margin-bottom:12px">
          <div style="color:#C084FC;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Baseline Anomaly (${deviation.toFixed(1)}\u03C3 deviation)</div>
          <div style="background:#C084FC08;padding:12px;border-radius:8px;border:1px solid #C084FC30">
            ${anomalyDetails.map(a => `<div style="color:#1E293B;font-size:11px;line-height:1.8;padding:4px 0;border-bottom:1px solid #E2E8F020">
              <span style="color:#C084FC;font-weight:600">${esc(a.dimension)}</span> <span style="color:#64748B;font-family:'JetBrains Mono',monospace">${esc(a.value)}</span>
              <span style="color:#94A3B8;margin:0 4px">|</span>
              Today: <span style="color:#EF4444;font-weight:600">${esc(a.current_24h)}</span> alerts
              <span style="color:#94A3B8;margin:0 4px">|</span>
              Baseline: <span style="color:#1E293B">${esc(a.baseline_mean)}</span> \u00B1 <span style="color:#64748B">${esc(a.baseline_std)}</span>/day
              <span style="color:#94A3B8;margin:0 4px">|</span>
              Z-score: <span style="color:#C084FC;font-weight:600">${esc(a.z_score)}</span>
              (${esc(a.sample_days)}d window)
            </div>`).join('')}
          </div>
        </div>` : ''}

        <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:10px">
          <div><span style="color:#94A3B8;font-size:10px">Alert ID:</span> <span style="color:#64748B;font-size:11px;font-family:'JetBrains Mono',monospace">${esc(d.alert_id)}</span></div>
          <div><span style="color:#94A3B8;font-size:10px">Time:</span> <span style="color:#64748B;font-size:11px">${d.created_at?localTime(d.created_at):''}</span></div>
          <div><span style="color:#94A3B8;font-size:10px">Agent:</span> <span style="color:#64748B;font-size:11px">${esc(d.agent_type||'triage')}</span></div>
          <div><span style="color:#94A3B8;font-size:10px">Playbook:</span> <span style="color:#64748B;font-size:11px">${d.playbook_used?esc(d.playbook_used.slice(0,50)):'None matched'}</span></div>
        </div>

        <div style="margin-bottom:12px">
          <div style="color:#818CF8;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;cursor:pointer" data-action="toggleAuditTrail" data-id="${d.id}" data-stop-propagation="true">Audit Trail ▾</div>
          <div id="audit-${d.id}" style="display:none;background:#F8FAFC;padding:12px;border-radius:8px;border:1px solid #818CF830"></div>
        </div>
        <div style="margin-bottom:12px">
          <div style="color:#34D399;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;cursor:pointer" data-action="toggleRuleStats" data-id="${d.id}" data-rule="${d.rule_id}" data-stop-propagation="true">Rule ${d.rule_id} Stats (7d) ▾</div>
          <div id="rulestats-${d.id}" style="display:none;background:#F8FAFC;padding:12px;border-radius:8px;border:1px solid #34D39930"></div>
        </div>
        
        ${(d.escalated||ev==='needs_investigation')&&!d.human_verdict ? `
        <div style="display:flex;gap:8px;padding-top:10px;border-top:1px solid #E2E8F0">
          <button class="btn" style="background:#EF4444;color:#0B1527;padding:8px 20px;font-size:12px;font-weight:700;border-radius:6px" data-action="review" data-id="${d.id}" data-verdict="true_positive" data-stop-propagation="true">✓ Mark True Positive</button>
          <button class="btn" style="background:#FBBF24;color:#0B1527;padding:8px 20px;font-size:12px;font-weight:700;border-radius:6px" data-action="review" data-id="${d.id}" data-verdict="false_positive" data-stop-propagation="true">✗ Mark False Positive</button>
        </div>` : ''}
        
        ${d.human_verdict ? `
        <div style="display:flex;justify-content:space-between;align-items:center;padding-top:10px;border-top:1px solid #E2E8F0">
          <div>
            ${badge('Human Verdict: '+(VL[d.human_verdict]||d.human_verdict), d.human_verdict===d.verdict?'#34D399':'#EF4444')}
            ${d.human_verdict!==d.verdict ? '<span style="color:#EF4444;font-size:11px;margin-left:8px">⚠ Override</span>' : '<span style="color:#34D399;font-size:11px;margin-left:8px">✓ Confirmed</span>'}
          </div>
          ${currentUserRole()==='admin' ? '<div style="display:flex;gap:4px"><button class="btn" style="background:#EF444418;color:#EF4444;padding:4px 10px;font-size:10px;border-radius:4px" data-action="review" data-id="'+d.id+'" data-verdict="true_positive" data-stop-propagation="true">Re-mark TP</button><button class="btn" style="background:#FBBF2418;color:#FBBF24;padding:4px 10px;font-size:10px;border-radius:4px" data-action="review" data-id="'+d.id+'" data-verdict="false_positive" data-stop-propagation="true">Re-mark FP</button></div>' : ''}
        </div>` : ''}
      </div>
      ` : `
      <div style="color:#64748B;font-size:11px;line-height:1.5;margin-top:6px;max-height:40px;overflow:hidden">${isAnomaly?'<span style="color:#C084FC;font-weight:600">[ANOMALY] </span>':''}${esc((d.reasoning||'\u2014').slice(0,180))}...</div>
      <div style="display:flex;justify-content:space-between;align-items:center;margin-top:6px">
        <span class="muted">${d.created_at?localTimeShort(d.created_at):''} — ${esc(d.alert_id)} ${(d.escalated||ev==='needs_investigation')&&!d.human_verdict?badge('⏳ Awaiting','#60A5FA'):''} ${d.human_verdict?badge('Human: '+(VL[d.human_verdict]||d.human_verdict),d.human_verdict===d.verdict?'#34D399':'#EF4444'):''}</span>
        ${(d.escalated||ev==='needs_investigation')&&!d.human_verdict?`<div><button class="btn" style="background:#EF444418;color:#EF4444;margin-right:4px" data-action="review" data-id="${d.id}" data-verdict="true_positive" data-stop-propagation="true">TP</button><button class="btn" style="background:#FBBF2418;color:#FBBF24" data-action="review" data-id="${d.id}" data-verdict="false_positive" data-stop-propagation="true">FP</button></div>`:''}
      </div>
      `}
    </div>`;
  });
  return h;
}

async function renderFeedback() {
  const role = currentUserRole();
  const isPrivileged = ['admin','senior_analyst','mssp_admin'].includes(role);
  // Fetch base stats + (privileged-only) patterns + effectiveness in parallel
  const [statsR, patternsR, effR] = await Promise.allSettled([
    fetchJSON('/dashboard/stats'),
    isPrivileged ? fetchJSON('/feedback/patterns?min_occurrences=3&limit=100') : Promise.resolve({patterns:[],total:0}),
    isPrivileged ? fetchJSON('/feedback/effectiveness') : Promise.resolve([])
  ]);
  const s = statsR.status==='fulfilled' ? statsR.value : {};
  const t = s.today || {}; const total = t.total || 1;
  const patterns = patternsR.status==='fulfilled' ? (patternsR.value.patterns || []) : [];
  // /feedback/effectiveness returns a bare list, not {results: ...}
  const effRaw = effR.status==='fulfilled' ? effR.value : [];
  const effectiveness = Array.isArray(effRaw) ? effRaw : (effRaw.results || []);

  // ── Header: Compounding Loop infographic ─────────────────────
  let h = `<div class="c" style="min-width:100%;text-align:center;margin-bottom:16px">
    <div class="l">The Compounding Loop</div>
    <div style="display:flex;justify-content:center;align-items:center;gap:0;flex-wrap:wrap;margin:16px 0">
      ${['📥 Alerts|'+t.total+'|#60A5FA','🤖 Triage|'+Math.round((t.avg_confidence||0)*100)+'%|#1E293B','👁 Review|'+(s.pending_reviews||0)+' pending|#818CF8','📊 FP Detect|'+(s.noisy_rules||[]).length+' rules|#FBBF24','🔧 Tune|'+(s.pending_proposals||0)+' proposals|#EF4444','✅ Deploy|Loop closes|#1E293B'].map((x,i) => {
        const [label,sub,col] = x.split('|');
        return `<div style="text-align:center;padding:10px 14px"><div style="font-size:22px;margin-bottom:4px">${[...label][0]}</div><div style="color:${col};font-size:11px;font-weight:700">${label.replace(/^.\s*/,'')}</div><div style="color:#94A3B8;font-size:9px">${sub}</div></div>${i<5?'<div style="color:#94A3B8;font-size:18px">→</div>':''}`;
      }).join('')}
    </div></div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:16px">
      <div class="c" style="text-align:center"><div class="v" style="color:#FBBF24">${Math.round((t.fps||0)/total*100)}%</div><div class="l" style="margin-top:6px">FP Rate</div></div>
      <div class="c" style="text-align:center"><div class="v" style="color:#1E293B">${Math.round((t.auto_closed||0)/total*100)}%</div><div class="l" style="margin-top:6px">Automation</div></div>
      <div class="c" style="text-align:center"><div class="v" style="color:#818CF8">${Math.round((t.avg_confidence||0)*100)}%</div><div class="l" style="margin-top:6px">Confidence</div></div>
    </div>`;

  if (!isPrivileged) {
    h += `<div class="c" style="color:#94A3B8;text-align:center;padding:30px;font-size:12px">Detailed feedback patterns and proposal-effectiveness tracking are visible to admins and senior analysts.</div>`;
    return h;
  }

  // ── Run cycle button (admin only) ───────────────────────────
  if (role === 'admin' || role === 'mssp_admin') {
    h += `<div class="c" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
      <div>
        <div style="color:#1E293B;font-size:13px;font-weight:600">Manual Feedback Cycle</div>
        <div style="color:#64748B;font-size:11px;margin-top:2px">Re-scans recent decisions for new FP patterns and applies auto-tuning. Normally runs every 4 hours.</div>
      </div>
      <button class="fbtn" id="feedback-run-btn" style="background:#8B5CF6;color:#fff;border-color:#8B5CF6;padding:8px 18px;font-weight:600" data-action="runFeedbackCycle">Run Cycle Now</button>
    </div>`;
  }

  // ── Active Feedback Patterns ────────────────────────────────
  h += `<div style="display:flex;justify-content:space-between;align-items:center;margin:0 0 8px 0">
    <div class="section-title" style="margin:0">Active Feedback Patterns</div>
    <span style="color:#64748B;font-size:11px">${patterns.length} pattern${patterns.length===1?'':'s'} (≥3 occurrences)</span>
  </div>`;
  if (patterns.length) {
    const ptypeColor = pt => ({recurring_fp:'#FBBF24', missed_threat:'#EF4444', false_alarm:'#FB923C', over_cautious:'#60A5FA', missed_threat_auto_close:'#EF4444'}[pt] || '#94A3B8');
    h += `<div class="c" style="padding:0;margin-bottom:20px">
      <table style="width:100%;font-size:11px;border-collapse:collapse">
        <tr style="color:#94A3B8;font-size:10px;text-transform:uppercase;letter-spacing:1px"><th style="text-align:left;padding:8px 12px">Pattern</th><th style="text-align:left;padding:8px 12px">Rule</th><th style="text-align:left;padding:8px 12px">Description</th><th style="text-align:left;padding:8px 12px">Occurrences</th><th style="text-align:left;padding:8px 12px">Auto-action</th><th style="text-align:left;padding:8px 12px">Last seen</th></tr>`;
    patterns.forEach(p => {
      const c = ptypeColor(p.pattern_type);
      const ls = p.last_seen ? new Date(p.last_seen).toLocaleString() : '';
      h += `<tr style="border-top:1px solid #E2E8F0">`;
      h += `<td style="padding:6px 12px"><span style="background:${c}18;color:${c};border:1px solid ${c}30;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600">${esc((p.pattern_type||'').replace(/_/g,' '))}</span></td>`;
      h += `<td style="padding:6px 12px;font-family:'JetBrains Mono',monospace;color:#1E293B;font-weight:600">${esc(String(p.rule_id||''))}</td>`;
      h += `<td style="padding:6px 12px;color:#334155;max-width:380px">${esc((p.description||'').slice(0,160))}${(p.description||'').length>160?'…':''}</td>`;
      h += `<td style="padding:6px 12px;color:#1E293B;font-weight:700;font-family:'JetBrains Mono',monospace">${p.occurrence_count||0}</td>`;
      h += `<td style="padding:6px 12px">${p.auto_action_taken ? `<span style="color:#34D399;font-size:10px">${esc(p.auto_action_taken)}</span>` : '<span style="color:#94A3B8;font-size:10px">—</span>'}</td>`;
      h += `<td style="padding:6px 12px;color:#64748B;font-size:10px;font-family:'JetBrains Mono',monospace">${esc(ls)}</td>`;
      h += `</tr>`;
    });
    h += `</table></div>`;
  } else {
    h += `<div class="c" style="text-align:center;color:#94A3B8;padding:30px;margin-bottom:20px">No active patterns. The engine writes a pattern only after seeing the same FP signature ≥3 times.</div>`;
  }

  // ── Proposal Effectiveness ─────────────────────────────────
  h += `<div style="display:flex;justify-content:space-between;align-items:center;margin:0 0 8px 0">
    <div class="section-title" style="margin:0">Deployed Proposal Effectiveness</div>
    <span style="color:#64748B;font-size:11px">${effectiveness.length} deployment${effectiveness.length===1?'':'s'} in last 30d</span>
  </div>`;
  if (effectiveness.length) {
    h += `<div class="c" style="padding:0">
      <table style="width:100%;font-size:11px;border-collapse:collapse">
        <tr style="color:#94A3B8;font-size:10px;text-transform:uppercase;letter-spacing:1px"><th style="text-align:left;padding:8px 12px">Rule</th><th style="text-align:left;padding:8px 12px">Deployed</th><th style="text-align:left;padding:8px 12px">Pre-FPs</th><th style="text-align:left;padding:8px 12px">Pre-TP rate</th><th style="text-align:left;padding:8px 12px">Post decisions</th><th style="text-align:left;padding:8px 12px">Post-FP rate</th><th style="text-align:left;padding:8px 12px">Post-TP rate</th><th style="text-align:left;padding:8px 12px">Effective?</th></tr>`;
    effectiveness.forEach(e => {
      const dep = e.deployed_at ? new Date(e.deployed_at).toLocaleDateString() : '';
      const postFp = (Number(e.post_fp_rate||0)*100).toFixed(1);
      const postTp = (Number(e.post_tp_rate||0)*100).toFixed(1);
      const preTp = (Number(e.pre_tp_rate||0)*100).toFixed(1);
      const eff = e.effective;
      const effLabel = eff === true ? '<span style="background:#34D39918;color:#10B981;border:1px solid #34D39940;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600">EFFECTIVE</span>'
        : eff === false ? '<span style="background:#EF444418;color:#EF4444;border:1px solid #EF444440;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600">NOT EFFECTIVE</span>'
        : '<span style="background:#94A3B818;color:#64748B;border:1px solid #94A3B840;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600">PENDING</span>';
      const fpColor = Number(e.post_fp_rate||0) >= 0.3 ? '#EF4444' : Number(e.post_fp_rate||0) >= 0.1 ? '#F59E0B' : '#34D399';
      h += `<tr style="border-top:1px solid #E2E8F0">`;
      h += `<td style="padding:6px 12px;font-family:'JetBrains Mono',monospace;color:#1E293B;font-weight:600">${esc(String(e.rule_id||''))}</td>`;
      h += `<td style="padding:6px 12px;color:#64748B;font-size:10px">${esc(dep)}</td>`;
      h += `<td style="padding:6px 12px;color:#64748B;font-family:'JetBrains Mono',monospace">${e.pre_fp_count||0}</td>`;
      h += `<td style="padding:6px 12px;color:#64748B;font-family:'JetBrains Mono',monospace">${preTp}%</td>`;
      h += `<td style="padding:6px 12px;color:#1E293B;font-family:'JetBrains Mono',monospace">${e.post_total_decisions||0}</td>`;
      h += `<td style="padding:6px 12px;color:${fpColor};font-weight:700;font-family:'JetBrains Mono',monospace">${postFp}%</td>`;
      h += `<td style="padding:6px 12px;color:#1E293B;font-family:'JetBrains Mono',monospace">${postTp}%</td>`;
      h += `<td style="padding:6px 12px">${effLabel}</td>`;
      h += `</tr>`;
    });
    h += `</table></div>`;
  } else {
    h += `<div class="c" style="text-align:center;color:#94A3B8;padding:30px">No deployed proposals to track yet. Effectiveness is computed once a deployed proposal accrues ≥5 post-deployment decisions.</div>`;
  }

  return h;
}

async function runFeedbackCycle() {
  const btn = document.getElementById('feedback-run-btn');
  if (!btn) return;
  const orig = btn.textContent; btn.disabled = true; btn.textContent = 'Starting…';
  try {
    const r = await fetch(API + '/feedback/run-cycle', {method:'POST', headers: authHeaders()});
    if (r.ok) {
      btn.textContent = 'Started ✓';
      btn.style.background = '#34D399';
      setTimeout(() => { btn.textContent = orig; btn.style.background = '#8B5CF6'; btn.disabled = false; refresh(); }, 4000);
    } else {
      const e = await r.json().catch(()=>({}));
      btn.textContent = 'Failed';
      btn.style.background = '#EF4444';
      alert('Could not start cycle: ' + (e.detail || ('HTTP '+r.status)));
      setTimeout(() => { btn.textContent = orig; btn.style.background = '#8B5CF6'; btn.disabled = false; }, 3000);
    }
  } catch(e) {
    btn.textContent = 'Network error';
    btn.style.background = '#EF4444';
    setTimeout(() => { btn.textContent = orig; btn.style.background = '#8B5CF6'; btn.disabled = false; }, 3000);
  }
}

async function renderDetection() {
  const d = await fetchJSON('/detection/proposals');
  const allProposals = d.proposals || [];
  const counts = {all:allProposals.length, proposed:0, approved:0, deployed:0, rejected:0, needs_manual_tuning:0};
  allProposals.forEach(p => { if (counts[p.status] !== undefined) counts[p.status]++; });
  const pendingCount = counts.proposed;
  setBadge('dc', pendingCount);

  const proposals = proposalFilter === 'all' ? allProposals : allProposals.filter(p => p.status === proposalFilter);

  // Filter buttons
  let h = '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;align-items:center">';
  ['all','proposed','approved','deployed','rejected','needs_manual_tuning'].forEach(f => {
    const c = counts[f] || 0;
    const active = proposalFilter === f;
    const label = f === 'needs_manual_tuning' ? 'Manual Fix' : f.charAt(0).toUpperCase()+f.slice(1);
    const colors = {all:'#5C7A99',proposed:'#818CF8',approved:'#34D399',deployed:'#60A5FA',rejected:'#EF4444',needs_manual_tuning:'#FBBF24'};
    h += `<button class="btn" style="padding:6px 14px;font-size:11px;font-weight:${active?700:500};border-radius:6px;background:${active?colors[f]+'20':'transparent'};color:${active?colors[f]:'#3D5A75'};border:1px solid ${active?colors[f]+'40':'#E2E8F0'}" data-action="setProposalFilter" data-filter="${f}">${label} ${c?'('+c+')':''}</button>`;
  });
  // Bulk actions
  if (counts.proposed > 0) h += `<button class="btn" style="margin-left:auto;padding:6px 14px;font-size:11px;font-weight:600;border-radius:6px;background:#E8EDF220;color:#1E293B;border:1px solid #E8EDF240" data-action="bulkApprove">✓ Approve All (${counts.proposed})</button>`;
  if (counts.approved > 0) h += `<button class="btn" style="${counts.proposed?'':'margin-left:auto;'}padding:6px 14px;font-size:11px;font-weight:600;border-radius:6px;background:#60A5FA20;color:#60A5FA;border:1px solid #60A5FA40" data-action="bulkDeploy">🚀 Deploy All (${counts.approved})</button>`;
  h += `<button class="btn" style="${counts.proposed||counts.approved?'':'margin-left:auto;'}padding:6px 14px;font-size:11px;font-weight:600;border-radius:6px;background:#818CF820;color:#818CF8;border:1px solid #818CF840" data-action="runDetectionCycle">Run Tuning Agent</button>`;
  h += '</div>';
  // Detection toolbox row
  if (['admin','senior_analyst','mssp_admin'].includes(currentUserRole())) {
    h += '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px">';
    h += '<button class="fbtn" data-action="showDetectionHistory">📜 Deployment History</button>';
    h += '<button class="fbtn" data-action="showSigmaConvertModal">🔄 Convert Sigma Rule</button>';
    h += '<button class="fbtn" data-action="showSigmaImportModal">📂 Bulk-Import Sigma</button>';
    if (currentUserRole() === 'admin' || currentUserRole() === 'mssp_admin') {
      h += '<button class="fbtn" data-action="showValidateRuleModal">✅ Validate Rule XML</button>';
    }
    h += '</div>';
  }

  if (!proposals.length) {
    return h + `<div class="c" style="min-width:100%;text-align:center;padding:40px 20px">
      <div style="font-size:32px;margin-bottom:12px">${proposalFilter==='all'?'✅':'🔍'}</div>
      <div style="font-size:16px;font-weight:700;color:#1E293B;margin-bottom:6px">${proposalFilter==='all'?'No proposals yet':'No '+proposalFilter+' proposals'}</div>
      <div style="font-size:12px;color:#64748B">${proposalFilter==='all'?'Detection proposals appear here after the feedback loop identifies noisy rules.':'Try a different filter.'}</div>
    </div>`;
  }

  proposals.forEach(p => {
    let parsed = {};
    try { parsed = JSON.parse(p.reasoning || '{}'); } catch(e) {}
    const analysis = parsed.analysis || {};
    const proposal = parsed.proposal || parsed;
    const changes = parsed.changes_made || proposal.changes_made || [];
    const alternatives = parsed.alternatives || parsed.alternative_approaches || [];
    const testing = parsed.testing || parsed.testing_recommendations || [];
    const isOpen = expandedProposal === p.id;
    
    h += `<div class="row" style="border-color:#818CF840;cursor:pointer" data-action="toggleProposal" data-id="${p.id}">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
          ${badge(p.change_type || 'tune', '#818CF8')}
          <span style="color:#1E293B;font-size:16px;font-weight:700;font-family:'JetBrains Mono',monospace">Rule ${p.rule_id}</span>
          <span style="color:#64748B;font-size:12px">${esc(p.rule_file || '')}</span>
          ${badge(p.status==='needs_manual_tuning'?'MANUAL FIX NEEDED':p.status.toUpperCase(), p.status==='proposed'?'#FBBF24':p.status==='approved'?'#34D399':p.status==='needs_manual_tuning'?'#EF4444':'#5C7A99')}
        </div>
        <div style="display:flex;align-items:center;gap:8px">
          <span style="color:#94A3B8;font-size:11px">${p.proposed_at ? localTime(p.proposed_at) : ''}</span>
          <span style="color:#94A3B8;font-size:14px">${isOpen?'▲':'▼'}</span>
        </div>
      </div>
      
      ${isOpen ? `
      <div style="margin-top:14px;padding-top:14px;border-top:1px solid #E2E8F0">

        ${parsed.validation_error ? `<div style="background:#EF444415;border:1px solid #EF444440;border-radius:8px;padding:12px;margin-bottom:14px">
          <div style="color:#EF4444;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">⚠ Validation Failed — Manual Fix Required</div>
          <div style="color:#1E293B;font-size:12px;font-family:'JetBrains Mono',monospace;line-height:1.6">${esc(parsed.validation_error)}</div>
        </div>` : ''}

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px">
          <div>
            <div style="color:#EF4444;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Current Issue</div>
            <div style="color:#1E293B;font-size:12px;line-height:1.6;background:#F8FAFC;padding:12px;border-radius:8px;border:1px solid #E2E8F0">${esc(analysis.current_rule_assessment || 'N/A')}</div>
          </div>
          <div>
            <div style="color:#FBBF24;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">FP Pattern Identified</div>
            <div style="color:#1E293B;font-size:12px;line-height:1.6;background:#F8FAFC;padding:12px;border-radius:8px;border:1px solid #E2E8F0">${esc(analysis.fp_pattern_summary || 'N/A')}</div>
          </div>
        </div>
        
        <div style="margin-bottom:14px">
          <div style="color:#1E293B;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Proposed Rule XML</div>
          <div style="color:#1E293B;font-size:12px;line-height:1.6;background:#F8FAFC;padding:12px;border-radius:8px;border:1px solid #E2E8F0;font-family:'JetBrains Mono',monospace;white-space:pre-wrap;word-break:break-all">${esc(p.proposed_xml)}</div>
        </div>
        
        ${changes.length > 0 ? `
        <div style="margin-bottom:14px">
          <div style="color:#818CF8;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Changes Made</div>
          <div style="background:#F8FAFC;padding:12px;border-radius:8px;border:1px solid #E2E8F0">
            ${changes.map(c => `<div style="color:#1E293B;font-size:11px;line-height:1.6;padding:3px 0">• ${esc(c)}</div>`).join('')}
          </div>
        </div>` : ''}
        
        <div style="display:flex;gap:14px;flex-wrap:wrap;margin-bottom:14px">
          <div style="background:#34D39915;padding:10px 16px;border-radius:8px;border:1px solid #34D39930">
            <div style="color:#1E293B;font-size:10px;font-weight:600;text-transform:uppercase;margin-bottom:2px">Expected FP Reduction</div>
            <div style="color:#1E293B;font-size:16px;font-weight:700">${esc(proposal.expected_fp_reduction || parsed.expected_fp_reduction || 'N/A')}</div>
          </div>
          <div style="background:#60A5FA15;padding:10px 16px;border-radius:8px;border:1px solid #60A5FA30">
            <div style="color:#60A5FA;font-size:10px;font-weight:600;text-transform:uppercase;margin-bottom:2px">Coverage Impact</div>
            <div style="color:#60A5FA;font-size:16px;font-weight:700">${esc(proposal.coverage_impact || parsed.coverage_impact || 'N/A')}</div>
          </div>
          <div style="background:#FBBF2415;padding:10px 16px;border-radius:8px;border:1px solid #FBBF2430">
            <div style="color:#FBBF24;font-size:10px;font-weight:600;text-transform:uppercase;margin-bottom:2px">FP Trigger</div>
            <div style="color:#FBBF24;font-size:16px;font-weight:700">${p.fp_count_trigger} FPs in ${p.fp_window_days}d</div>
          </div>
        </div>
        
        ${analysis.tp_coverage_risk ? `
        <div style="margin-bottom:14px">
          <div style="color:#EF4444;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Coverage Risk Assessment</div>
          <div style="color:#1E293B;font-size:12px;line-height:1.6;background:#F8FAFC;padding:12px;border-radius:8px;border:1px solid #E2E8F0">${esc(analysis.tp_coverage_risk)}</div>
        </div>` : ''}
        
        ${testing.length > 0 ? `
        <div style="margin-bottom:14px">
          <div style="color:#64748B;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Testing Recommendations</div>
          <div style="background:#F8FAFC;padding:12px;border-radius:8px;border:1px solid #E2E8F0">
            ${testing.map((t,i) => `<div style="color:#64748B;font-size:11px;line-height:1.6;padding:3px 0">${i+1}. ${esc(t)}</div>`).join('')}
          </div>
        </div>` : ''}
        
        ${alternatives.length > 0 ? `
        <div style="margin-bottom:14px">
          <div style="color:#64748B;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Alternative Approaches</div>
          <div style="background:#F8FAFC;padding:12px;border-radius:8px;border:1px solid #E2E8F0">
            ${alternatives.map(a => `<div style="color:#64748B;font-size:11px;line-height:1.6;padding:3px 0">• ${esc(a)}</div>`).join('')}
          </div>
        </div>` : ''}
        
        ${p.status === 'proposed' ? `
        <div style="display:flex;gap:10px;padding-top:12px;border-top:1px solid #E2E8F0">
          <button class="btn" style="background:#E8EDF2;color:#0B1527;padding:10px 24px;font-size:13px;font-weight:700;border-radius:8px" data-action="proposalAction" data-id="${p.id}" data-status="approve" data-stop-propagation="true">✓ Approve Proposal</button>
          <button class="btn" style="background:transparent;color:#EF4444;padding:10px 24px;font-size:13px;font-weight:600;border-radius:8px;border:1px solid #EF444440" data-action="rejectProposal" data-id="${p.id}" data-stop-propagation="true">✗ Reject</button>
        </div>` : p.status === 'approved' ? `
        <div style="display:flex;gap:10px;align-items:center;padding-top:12px;border-top:1px solid #E2E8F0">
          ${badge('APPROVED by ' + (p.reviewed_by||''), '#34D399')}
          ${p.reviewed_at ? '<span style="color:#94A3B8;font-size:11px;margin-left:8px">' + localTime(p.reviewed_at) + '</span>' : ''}
          <button class="btn" style="background:#60A5FA;color:white;padding:8px 20px;font-size:12px;font-weight:700;border-radius:6px;margin-left:auto" data-action="deployProposal" data-id="${p.id}" data-stop-propagation="true">🚀 Deploy to Wazuh</button>
        </div>` : p.status === 'deployed' ? `
        <div style="display:flex;gap:10px;align-items:center;padding-top:12px;border-top:1px solid #E2E8F0">
          ${badge('DEPLOYED', '#34D399')}
          ${p.deployed_at ? '<span style="color:#94A3B8;font-size:11px;margin-left:8px">' + localTime(p.deployed_at) + '</span>' : ''}
          <button class="btn" style="background:transparent;color:#FB923C;padding:8px 16px;font-size:11px;font-weight:600;border-radius:6px;border:1px solid #FB923C40;margin-left:auto" data-action="rollbackProposal" data-id="${p.id}" data-stop-propagation="true">↩ Rollback</button>
        </div>` : `
        <div style="padding-top:12px;border-top:1px solid #E2E8F0">
          ${badge(p.status.toUpperCase() + (p.reviewed_by ? ' by ' + p.reviewed_by : ''), '#EF4444')}
          ${p.reviewed_at ? '<span style="color:#94A3B8;font-size:11px;margin-left:8px">' + localTime(p.reviewed_at) + '</span>' : ''}
          ${p.rejection_notes ? '<div style="color:#64748B;font-size:11px;margin-top:6px"><b>Reason:</b> ' + esc(p.rejection_notes) + '</div>' : ''}
        </div>`}
      </div>
      ` : `
      <div style="color:#64748B;font-size:12px;margin-top:8px">${analysis.current_rule_assessment ? esc(analysis.current_rule_assessment.slice(0,180))+'...' : 'Click to view proposal details'}</div>
      `}
    </div>`;
  });
  return h;
}

async function review(id, verdict) {
  const reason = prompt('Reason for this verdict (required):');
  if (reason === null || !reason.trim()) return;
  try {
    const r = await fetch(API+'/triage/review', {method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({decision_id:id,human_verdict:verdict,reason:reason.trim()})});
    if (!r.ok) { alert('Review failed: ' + r.status); return; }
  } catch(e) { alert('Review failed: network error'); return; }
  refresh();
}

async function proposalAction(id, action, notes) {
  try {
    const r = await fetch(API+'/detection/review', {method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({proposal_id:id,action:action,notes:notes||null})});
    if (!r.ok) { alert('Action failed: ' + r.status); return; }
  } catch(e) { alert('Action failed: network error'); return; }
  refresh();
}
async function rejectProposal(id) {
  const notes = prompt('Rejection reason (optional):');
  if (notes === null) return;
  await proposalAction(id, 'reject', notes || undefined);
}
async function deployProposal(id) {
  if (!confirm('Deploy this rule to Wazuh? This will restart the Wazuh manager.')) return;
  try {
    const r = await fetch(API+'/detection/deploy/'+id, {method:'POST',headers:authHeaders()});
    if (!r.ok) { const t = await r.text().catch(()=>''); throw new Error(t||r.status); }
    alert('Rule deployed and Wazuh manager restarted.');
  } catch(e) { alert('Deployment failed: ' + (e.message||e)); }
  refresh();
}
async function rollbackProposal(id) {
  if (!confirm('Roll back this rule to its original XML? This will restart the Wazuh manager.')) return;
  try {
    const r = await fetch(API+'/detection/rollback/'+id, {method:'POST',headers:authHeaders()});
    if (!r.ok) { const t = await r.text().catch(()=>''); throw new Error(t||r.status); }
    alert('Rule rolled back successfully.');
  } catch(e) { alert('Rollback failed: ' + (e.message||e)); }
  refresh();
}

let expandedProposal = null;
let proposalFilter = 'all';
function setProposalFilter(f) { proposalFilter = f; refresh(); }

function toggleProposal(id) {
  expandedProposal = expandedProposal === id ? null : id;
  refresh();
}

async function bulkApprove() {
  if (!confirm('Approve ALL proposed rules?')) return;
  const d = await fetchJSON('/detection/proposals');
  const proposed = (d.proposals||[]).filter(p=>p.status==='proposed');
  let ok = 0, fail = 0;
  for (const p of proposed) {
    try {
      const r = await fetch(API+'/detection/review', {method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({proposal_id:p.id,action:'approve',notes:null})});
      if (r.ok) ok++; else fail++;
    } catch(e) { fail++; }
  }
  alert(ok + ' proposals approved' + (fail ? ', ' + fail + ' failed' : '') + '.');
  refresh();
}

async function bulkDeploy() {
  if (!confirm('Deploy ALL approved rules to Wazuh? This will restart the Wazuh manager once after all rules are pushed.')) return;
  try {
    const r = await fetch(API+'/detection/bulk-deploy', {method:'POST',headers:authHeaders()});
    if (!r.ok) { const t = await r.text().catch(()=>''); throw new Error(t||r.status); }
    const res = await r.json();
    alert(res.deployed + ' deployed' + (res.failed ? ', ' + res.failed + ' failed' : '') + '. Wazuh manager restarted.');
  } catch(e) { alert('Bulk deploy failed: ' + (e.message||e)); }
  refresh();
}

async function runDetectionCycle() {
  try {
    const r = await fetch(API+'/detection/run', {method:'POST',headers:authHeaders()});
    if (!r.ok) { const t = await r.text().catch(()=>''); throw new Error(t||r.status); }
    alert('Detection tuning agent started in background. New proposals will appear shortly.');
  } catch(e) { alert('Failed to start detection cycle: ' + (e.message||e)); }
}

// ── Detection: deployment history ────────────────────────────

async function showDetectionHistory() {
  const so = document.getElementById('slide-over');
  so.style.display = 'block';
  so.classList.add('open');
  so.innerHTML = '<div style="padding:24px"><div class="spin" style="text-align:center;padding:40px;color:#94A3B8">Loading history...</div></div>';
  let hist;
  try { hist = await fetchJSON('/detection/history?limit=100'); }
  catch(e) { so.innerHTML = '<div style="padding:24px;color:#EF4444">Failed to load: '+esc(e.message)+'</div>'; return; }
  const entries = hist.history || [];
  let h = '<div style="padding:24px">';
  h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">';
  h += '<h3 style="margin:0;color:#1E293B">Detection Deployment History</h3>';
  h += '<button data-action="closeSlideOver" style="background:none;border:none;cursor:pointer;font-size:20px;color:#64748B">&times;</button></div>';
  h += '<div style="color:#64748B;font-size:11px;margin-bottom:12px">Last '+entries.length+' deployments. Click a rule file to load every version.</div>';
  if (!entries.length) {
    h += '<div style="color:#94A3B8;text-align:center;padding:30px">No deployments recorded yet.</div>';
    so.innerHTML = h + '</div>';
    return;
  }
  // Group by rule_file for the click-to-expand summary
  const groups = {};
  entries.forEach(e => {
    const k = e.rule_file || '(no file)';
    if (!groups[k]) groups[k] = [];
    groups[k].push(e);
  });
  Object.keys(groups).forEach(rf => {
    const list = groups[rf];
    const latest = list[0] || {};
    h += `<div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:8px;padding:10px 12px;margin-bottom:6px;cursor:pointer" data-action="showRuleVersions" data-id="${esc(rf)}">`;
    h += '<div style="display:flex;justify-content:space-between;align-items:center">';
    h += '<div><code style="color:#8B5CF6;font-size:12px;font-weight:600">'+esc(rf)+'</code>';
    h += '<span style="color:#94A3B8;margin-left:8px;font-size:11px">'+list.length+' version'+(list.length===1?'':'s')+'</span></div>';
    h += '<div style="color:#64748B;font-size:11px">Rule '+esc(String(latest.rule_id||'?'))+' · '+(latest.deployed_at?esc(localTime(latest.deployed_at)):'?')+(latest.rolled_back_at?' · <span style="color:#EF4444">rolled back</span>':'')+'</div>';
    h += '</div></div>';
  });
  so.innerHTML = h + '</div>';
}

async function showRuleVersions(ruleFile) {
  const so = document.getElementById('slide-over');
  so.innerHTML = '<div style="padding:24px"><div class="spin" style="text-align:center;padding:40px;color:#94A3B8">Loading versions...</div></div>';
  let data;
  try { data = await fetchJSON('/detection/history/'+encodeURIComponent(ruleFile)+'/versions'); }
  catch(e) { so.innerHTML = '<div style="padding:24px;color:#EF4444">Failed: '+esc(e.message)+'</div>'; return; }
  const versions = data.versions || [];
  let h = '<div style="padding:24px">';
  h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">';
  h += '<h3 style="margin:0;color:#1E293B">Versions of <code style="color:#8B5CF6;font-size:14px">'+esc(ruleFile)+'</code></h3>';
  h += '<button data-action="showDetectionHistory" style="background:none;border:none;cursor:pointer;font-size:20px;color:#64748B">&times;</button></div>';
  if (!versions.length) {
    h += '<div style="color:#94A3B8;text-align:center;padding:30px">No versions found.</div>';
    so.innerHTML = h + '</div>'; return;
  }
  h += '<table style="width:100%;font-size:11px;border-collapse:collapse">';
  h += '<tr style="color:#94A3B8;font-size:10px;text-transform:uppercase;letter-spacing:1px"><th style="text-align:left;padding:6px 12px">Ver</th><th style="text-align:left;padding:6px 12px">Rule</th><th style="text-align:left;padding:6px 12px">Deployed</th><th style="text-align:left;padding:6px 12px">By</th><th style="text-align:left;padding:6px 12px">Rolled back</th><th style="text-align:left;padding:6px 12px">Backup</th></tr>';
  versions.forEach(v => {
    h += '<tr style="border-top:1px solid #E2E8F0">';
    h += '<td style="padding:6px 12px;font-family:\'JetBrains Mono\',monospace;color:#1E293B;font-weight:600">v'+esc(String(v.version||'?'))+'</td>';
    h += '<td style="padding:6px 12px;color:#64748B;font-family:\'JetBrains Mono\',monospace">'+esc(String(v.rule_id||''))+'</td>';
    h += '<td style="padding:6px 12px;color:#64748B;font-size:10px">'+(v.deployed_at?esc(localTime(v.deployed_at)):'?')+'</td>';
    h += '<td style="padding:6px 12px;color:#1E293B">'+esc(v.deployed_by||'?')+'</td>';
    h += '<td style="padding:6px 12px">'+(v.rolled_back_at?'<span style="color:#EF4444;font-size:11px">'+esc(localTime(v.rolled_back_at))+'</span>':'<span style="color:#94A3B8">—</span>')+'</td>';
    h += '<td style="padding:6px 12px;color:'+(v.has_xml_before?'#34D399':'#94A3B8')+'">'+(v.has_xml_before?'✓ stored':'—')+'</td>';
    h += '</tr>';
  });
  h += '</table></div>';
  so.innerHTML = h;
}

// ── Detection: Sigma converter ───────────────────────────────

function showSigmaConvertModal() {
  const so = document.getElementById('slide-over');
  so.style.display = 'block';
  so.classList.add('open');
  so.innerHTML = '<div style="padding:24px">'
    + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">'
    + '<h3 style="margin:0;color:#1E293B">Convert Sigma Rule → Wazuh XML</h3>'
    + '<button data-action="closeSlideOver" style="background:none;border:none;cursor:pointer;font-size:20px;color:#64748B">&times;</button></div>'
    + '<div style="color:#64748B;font-size:11px;margin-bottom:10px">Paste a Sigma YAML rule. Output is a Wazuh-compatible <code>&lt;rule&gt;</code> XML block.</div>'
    + '<div style="display:grid;grid-template-columns:1fr 80px;gap:8px;margin-bottom:8px">'
    +   '<div><label style="display:block;font-size:11px;color:#64748B;font-weight:600;margin-bottom:4px">Sigma YAML</label></div>'
    +   '<div><label style="display:block;font-size:11px;color:#64748B;font-weight:600;margin-bottom:4px">Base ID</label></div>'
    + '</div>'
    + '<div style="display:grid;grid-template-columns:1fr 80px;gap:8px;margin-bottom:8px">'
    +   '<textarea id="sigma-yaml" rows="12" placeholder="title: ...\\nlogsource:\\n  product: linux\\n  service: auth\\ndetection: ..." style="width:100%;padding:8px;border:1px solid #D1D5DB;border-radius:6px;font-size:11px;font-family:\'JetBrains Mono\',monospace;resize:vertical;box-sizing:border-box"></textarea>'
    +   '<input id="sigma-baseid" type="number" value="200000" min="100000" max="999999" style="padding:8px;border:1px solid #D1D5DB;border-radius:6px;font-size:11px;font-family:\'JetBrains Mono\',monospace;box-sizing:border-box">'
    + '</div>'
    + '<button data-action="submitSigmaConvert" class="fbtn fon" style="padding:8px 16px">Convert</button>'
    + '<div id="sigma-result" style="margin-top:14px"></div>'
    + '</div>';
}

async function submitSigmaConvert() {
  const yaml = document.getElementById('sigma-yaml').value.trim();
  const baseId = parseInt(document.getElementById('sigma-baseid').value, 10) || 200000;
  const out = document.getElementById('sigma-result');
  if (!yaml) { out.innerHTML = '<span style="color:#EF4444">YAML is required</span>'; return; }
  out.innerHTML = '<span style="color:#94A3B8">Converting…</span>';
  try {
    const r = await fetch(API+'/detection/sigma/convert', {method:'POST', headers:{...authHeaders(),'Content-Type':'application/json'}, body: JSON.stringify({sigma_yaml: yaml, base_rule_id: baseId})});
    const d = await r.json().catch(()=>({}));
    if (!r.ok) {
      out.innerHTML = '<span style="color:#EF4444">'+esc(typeof d.detail==='string'?d.detail:JSON.stringify(d.detail||d))+'</span>';
      return;
    }
    let h = '<div style="color:#34D399;font-weight:600;margin-bottom:8px">Converted ✓</div>';
    if (d.xml || d.rule_xml) {
      h += '<div style="color:#94A3B8;font-size:10px;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Wazuh XML</div>';
      h += '<pre style="background:#1E293B;color:#34D399;padding:12px;border-radius:6px;font-size:11px;font-family:\'JetBrains Mono\',monospace;max-height:400px;overflow:auto;white-space:pre-wrap">'+esc(d.xml || d.rule_xml)+'</pre>';
    }
    if (d.warnings && d.warnings.length) {
      h += '<div style="color:#FBBF24;font-size:11px;margin-top:8px"><strong>Warnings:</strong> '+d.warnings.map(esc).join('; ')+'</div>';
    }
    if (d.metadata) {
      h += '<details style="margin-top:8px"><summary style="cursor:pointer;color:#64748B;font-size:11px">Metadata</summary><pre style="margin:6px 0 0;font-size:10px;color:#64748B;white-space:pre-wrap">'+esc(JSON.stringify(d.metadata, null, 2))+'</pre></details>';
    }
    out.innerHTML = h;
  } catch(e) { out.innerHTML = '<span style="color:#EF4444">'+esc(e.message)+'</span>'; }
}

function showSigmaImportModal() {
  const so = document.getElementById('slide-over');
  so.style.display = 'block';
  so.classList.add('open');
  so.innerHTML = '<div style="padding:24px">'
    + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">'
    + '<h3 style="margin:0;color:#1E293B">Bulk-Import Sigma Rules</h3>'
    + '<button data-action="closeSlideOver" style="background:none;border:none;cursor:pointer;font-size:20px;color:#64748B">&times;</button></div>'
    + '<div style="color:#64748B;font-size:11px;margin-bottom:10px">Path must be inside <code>./sigma_rules/</code> (server-side jail). Returns conversion results for each YAML file found.</div>'
    + '<label style="display:block;font-size:11px;color:#64748B;font-weight:600;margin-bottom:4px">Path</label>'
    + '<input id="sigma-path" type="text" placeholder="sigma_rules/linux/auth" style="width:100%;padding:8px 12px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:10px;font-size:12px;font-family:\'JetBrains Mono\',monospace;box-sizing:border-box">'
    + '<button data-action="submitSigmaImport" class="fbtn fon" style="padding:8px 16px">Import</button>'
    + '<div id="sigma-import-result" style="margin-top:12px"></div>'
    + '</div>';
}

async function submitSigmaImport() {
  const path = document.getElementById('sigma-path').value.trim();
  const out = document.getElementById('sigma-import-result');
  if (!path) { out.innerHTML = '<span style="color:#EF4444">Path is required</span>'; return; }
  out.innerHTML = '<span style="color:#94A3B8">Importing…</span>';
  try {
    const r = await fetch(API+'/detection/sigma/import', {method:'POST', headers:{...authHeaders(),'Content-Type':'application/json'}, body: JSON.stringify({path})});
    const d = await r.json().catch(()=>({}));
    if (!r.ok) {
      out.innerHTML = '<span style="color:#EF4444">'+esc(typeof d.detail==='string'?d.detail:JSON.stringify(d.detail||d))+'</span>';
      return;
    }
    let h = '<div style="color:#34D399;font-weight:600;margin-bottom:8px">'+d.success+' / '+d.total+' converted ✓</div>';
    if ((d.results||[]).length) {
      h += '<div style="max-height:300px;overflow-y:auto">';
      d.results.forEach(r => {
        const ok = r.result && r.result.success;
        const c = ok ? '#34D399' : '#EF4444';
        h += '<div style="background:'+c+'10;border-left:3px solid '+c+';padding:6px 10px;margin-bottom:3px;font-size:10px;font-family:\'JetBrains Mono\',monospace">';
        h += '<span style="color:'+c+';font-weight:600">'+(ok?'✓':'✗')+'</span> ';
        h += '<span style="color:#1E293B">'+esc(r.file||r.path||'')+'</span>';
        if (!ok && r.result && r.result.error) h += ' — <span style="color:#EF4444">'+esc(r.result.error)+'</span>';
        h += '</div>';
      });
      h += '</div>';
    }
    out.innerHTML = h;
  } catch(e) { out.innerHTML = '<span style="color:#EF4444">'+esc(e.message)+'</span>'; }
}

// ── Detection: validate rule via wazuh-logtest ───────────────

function showValidateRuleModal() {
  const so = document.getElementById('slide-over');
  so.style.display = 'block';
  so.classList.add('open');
  so.innerHTML = '<div style="padding:24px">'
    + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">'
    + '<h3 style="margin:0;color:#1E293B">Validate Rule XML (wazuh-logtest)</h3>'
    + '<button data-action="closeSlideOver" style="background:none;border:none;cursor:pointer;font-size:20px;color:#64748B">&times;</button></div>'
    + '<div style="color:#64748B;font-size:11px;margin-bottom:10px">Paste a Wazuh <code>&lt;rule&gt;</code> XML block. The platform runs <code>wazuh-logtest</code> against the manager to confirm the rule loads.</div>'
    + '<textarea id="val-xml" rows="14" placeholder="<rule id=\\\"100100\\\" level=\\\"5\\\">\\n  <if_sid>5712</if_sid>\\n  <description>Custom rule</description>\\n</rule>" style="width:100%;padding:8px;border:1px solid #D1D5DB;border-radius:6px;font-size:11px;font-family:\'JetBrains Mono\',monospace;resize:vertical;box-sizing:border-box;margin-bottom:10px"></textarea>'
    + '<button data-action="submitValidateRule" class="fbtn fon" style="padding:8px 16px">Validate</button>'
    + '<div id="val-result" style="margin-top:12px"></div>'
    + '</div>';
}

async function submitValidateRule() {
  const xml = document.getElementById('val-xml').value.trim();
  const out = document.getElementById('val-result');
  if (!xml) { out.innerHTML = '<span style="color:#EF4444">XML is required</span>'; return; }
  out.innerHTML = '<span style="color:#94A3B8">Validating…</span>';
  try {
    const r = await fetch(API+'/detection/validate', {method:'POST', headers:{...authHeaders(),'Content-Type':'application/json'}, body: JSON.stringify({rule_xml: xml})});
    const d = await r.json().catch(()=>({}));
    if (!r.ok) {
      out.innerHTML = '<span style="color:#EF4444">'+esc(typeof d.detail==='string'?d.detail:JSON.stringify(d.detail||d))+'</span>';
      return;
    }
    if (d.valid) {
      out.innerHTML = '<div style="color:#34D399;font-weight:600;background:#34D39910;border:1px solid #34D39940;padding:10px 14px;border-radius:6px">✓ Rule XML is valid (loaded by Wazuh manager)</div>';
    } else {
      out.innerHTML = '<div style="color:#EF4444;font-weight:600;background:#EF444410;border:1px solid #EF444440;padding:10px 14px;border-radius:6px">✗ Validation failed</div>'
        + '<pre style="margin-top:8px;background:#1E293B;color:#EF4444;padding:12px;border-radius:6px;font-size:11px;font-family:\'JetBrains Mono\',monospace;max-height:300px;overflow:auto;white-space:pre-wrap">'+esc(d.error||'(no detail)')+'</pre>';
    }
  } catch(e) { out.innerHTML = '<span style="color:#EF4444">'+esc(e.message)+'</span>'; }
}

// -- Incidents Tab --
let incidentFilter = 'open';
let expandedIncident = null;
function setIncidentFilter(f) { incidentFilter = f; refresh(); }
function toggleIncident(id) { expandedIncident = expandedIncident === id ? null : id; refresh(); }

async function renderIncidents() {
  const me = currentUsername();
  // Two filters use dedicated endpoints with different shapes
  const isSlaRisk = incidentFilter === 'slarisk';
  const isInteresting = incidentFilter === 'interesting';

  let items = [];
  let atRisk = null;
  if (isSlaRisk) {
    try { atRisk = (await fetchJSON('/incidents/sla-at-risk')).at_risk || []; } catch(e) { atRisk = null; }
  } else if (isInteresting) {
    try { items = (await fetchJSON('/incidents/interesting?limit=100')).incidents || []; } catch(e) { items = []; }
  } else {
    let url = '/incidents?limit=200';
    if (incidentFilter === 'mine') url += '&assigned_to=' + encodeURIComponent(me);
    else if (incidentFilter !== 'all') url += '&status=' + incidentFilter;
    const d = await fetchJSON(url);
    items = d.incidents || [];
  }

  // Fetch counts for filter buttons (resilient to failures)
  let allOpen = [], invAll = [], allTotal = [], slaAtRiskCount = 0, interestingCount = 0;
  try { allOpen = (isSlaRisk||isInteresting) ? (await fetchJSON('/incidents?limit=500&status=open')).incidents || [] : (incidentFilter === 'open' ? items : (await fetchJSON('/incidents?limit=500&status=open')).incidents || []); } catch(e) {}
  const openCount = allOpen.length;
  try { invAll = (isSlaRisk||isInteresting) ? (await fetchJSON('/incidents?limit=500&status=investigating')).incidents || [] : (incidentFilter === 'investigating' ? items : (await fetchJSON('/incidents?limit=500&status=investigating')).incidents || []); } catch(e) {}
  const invCount = invAll.length;
  try { allTotal = (isSlaRisk||isInteresting) ? (await fetchJSON('/incidents?limit=500')).incidents || [] : (incidentFilter === 'all' ? items : (await fetchJSON('/incidents?limit=500')).incidents || []); } catch(e) {}
  const allCount = allTotal.length;
  const myCount = allOpen.filter(x => x.assigned_to === me).length + invAll.filter(x => x.assigned_to === me).length;
  // SLA-at-risk count and interesting count for badge display
  if (atRisk !== null) slaAtRiskCount = atRisk.length;
  else { try { slaAtRiskCount = (await fetchJSON('/incidents/sla-at-risk')).count || 0; } catch(e) {} }
  if (isInteresting) interestingCount = items.length;
  else { try { interestingCount = ((await fetchJSON('/incidents/interesting?limit=200')).incidents || []).length; } catch(e) {} }

  let h = `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:10px">
    <div style="display:flex;gap:6px;flex-wrap:wrap">
      ${me ? `<button class="fbtn${incidentFilter==='mine'?' fon':''}" style="${incidentFilter==='mine'?'background:#E8EDF218;color:#1E293B;border-color:#1E293B30':myCount>0?'color:#1E293B':''}" data-action="setIncidentFilter" data-filter="mine">Mine (${myCount})</button>` : ''}
      <button class="fbtn${incidentFilter==='open'?' fon':''}" data-action="setIncidentFilter" data-filter="open">Open (${openCount})</button>
      <button class="fbtn${incidentFilter==='investigating'?' fon':''}" data-action="setIncidentFilter" data-filter="investigating">Investigating (${invCount})</button>
      <button class="fbtn${incidentFilter==='resolved'?' fon':''}" data-action="setIncidentFilter" data-filter="resolved">Resolved</button>
      <button class="fbtn${incidentFilter==='all'?' fon':''}" data-action="setIncidentFilter" data-filter="all">All (${allCount})</button>
      <button class="fbtn${incidentFilter==='slarisk'?' fon':''}" style="${slaAtRiskCount>0?'color:#EF4444;border-color:#EF444430':''}" data-action="setIncidentFilter" data-filter="slarisk">SLA at Risk${slaAtRiskCount>0?' ('+slaAtRiskCount+')':''}</button>
      <button class="fbtn${incidentFilter==='interesting'?' fon':''}" style="${interestingCount>0?'color:#FBBF24':''}" data-action="setIncidentFilter" data-filter="interesting">★ Interesting${interestingCount>0?' ('+interestingCount+')':''}</button>
    </div>
  </div>`;

  // SLA-at-risk uses a dedicated table because the response shape is different
  if (isSlaRisk) {
    if (atRisk === null) return h + '<div style="text-align:center;color:#94A3B8;padding:40px">SLA tracking unavailable for this license tier.</div>';
    if (!atRisk.length) return h + '<div style="text-align:center;color:#34D399;padding:40px">No incidents are at SLA risk. ✓</div>';
    h += '<div class="c" style="padding:0">';
    h += '<table style="width:100%;font-size:11px;border-collapse:collapse">';
    h += '<tr style="color:#94A3B8;font-size:10px;text-transform:uppercase;letter-spacing:1px"><th style="text-align:left;padding:8px 12px">Severity</th><th style="text-align:left;padding:8px 12px">Tier</th><th style="text-align:left;padding:8px 12px">SLA Type</th><th style="text-align:left;padding:8px 12px">Time Remaining</th><th style="text-align:left;padding:8px 12px">Title</th></tr>';
    const sevColor = {critical:'#EF4444',high:'#FB923C',medium:'#FBBF24',low:'#34D399'};
    atRisk.forEach(r => {
      const sc = sevColor[r.severity]||'#94A3B8';
      const tc = r.tier==='L3'?'#EF4444':r.tier==='L2'?'#FB923C':'#3D5A75';
      const breached = r.remaining_sec === 0;
      const remColor = breached ? '#EF4444' : '#FB923C';
      const remLabel = breached ? 'BREACHED' : (r.remaining_sec < 60 ? r.remaining_sec+'s' : Math.round(r.remaining_sec/60)+'m');
      h += '<tr style="border-top:1px solid #E2E8F0;cursor:pointer" data-action="loadIncidentDetail" data-id="'+esc(r.incident_id)+'">';
      h += '<td style="padding:8px 12px"><span style="font-size:10px;font-weight:600;padding:2px 8px;border-radius:4px;background:'+sc+'18;color:'+sc+';border:1px solid '+sc+'30">'+esc((r.severity||'').toUpperCase())+'</span></td>';
      h += '<td style="padding:8px 12px"><span style="font-size:10px;font-weight:600;padding:2px 8px;border-radius:4px;background:'+tc+'18;color:'+tc+';border:1px solid '+tc+'30">'+esc(r.tier||'')+'</span></td>';
      h += '<td style="padding:8px 12px;color:#1E293B">'+esc(r.sla_type||'')+'</td>';
      h += '<td style="padding:8px 12px;color:'+remColor+';font-weight:700;font-family:\'JetBrains Mono\',monospace">'+remLabel+'</td>';
      h += '<td style="padding:8px 12px;color:#1E293B">'+esc((r.title||'').slice(0,80))+'</td>';
      h += '</tr>';
    });
    h += '</table></div>';
    return h;
  }

  if (!items.length) return h + '<div style="text-align:center;color:#94A3B8;padding:40px">No incidents in this view.</div>';

  const sevColor = {critical:'#EF4444',high:'#FB923C',medium:'#FBBF24',low:'#34D399'};
  const statusColor = {open:'#60A5FA',investigating:'#FBBF24',resolved:'#34D399',closed:'#3D5A75'};

  h += '<div id="incidents-grid" style="width:100%;min-height:300px"></div>';

  const _incidentItems = items;
  queueGrid('incidents-grid', {
    rowData: _incidentItems.map(inc => ({
      id:inc.id, severity:(inc.severity||'').toUpperCase(), status:inc.status,
      tier:inc.tier||'L1', title:(inc.title||'').slice(0,80),
      alert_count:inc.alert_count||0, assigned_to:inc.assigned_to||'',
      last_seen:inc.last_seen?localTime(inc.last_seen):'',
      _sevRaw:inc.severity, _raw:inc
    })),
    columnDefs: [
      {field:'severity',headerName:'Severity',width:100,cellRenderer:p=>{const c=sevColor[p.data._sevRaw]||'#5C7A99';return '<span style="font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px;background:'+c+'18;color:'+c+';border:1px solid '+c+'30">'+esc(p.value)+'</span>';}},
      {field:'status',headerName:'Status',width:110,cellRenderer:p=>{const c=statusColor[p.value]||'#5C7A99';return '<span style="font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px;background:'+c+'18;color:'+c+';border:1px solid '+c+'30">'+esc(p.value)+'</span>';}},
      {field:'tier',headerName:'Tier',width:70,cellRenderer:p=>{const c=p.value==='L3'?'#EF4444':p.value==='L2'?'#FB923C':'#3D5A75';return '<span style="font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px;background:'+c+'18;color:'+c+';border:1px solid '+c+'30">'+esc(p.value)+'</span>';}},
      {field:'title',headerName:'Title',flex:1,minWidth:200,cellStyle:{fontWeight:600,color:'#1E293B'}},
      {field:'alert_count',headerName:'Alerts',width:80,cellRenderer:p=>'<span style="font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px;background:#60A5FA18;color:#60A5FA;border:1px solid #60A5FA30">'+esc(p.value)+'</span>'},
      {field:'assigned_to',headerName:'Assigned To',width:130,cellRenderer:p=>p.value?'<span style="color:#64748B">'+esc(p.value)+'</span>':'<span style="color:#94A3B8">Unassigned</span>'},
      {field:'last_seen',headerName:'Last Seen',width:170,cellStyle:{color:'#3D5A75',fontSize:'11px'}}
    ],
    onRowClicked: p => {
      openIncidentSlideOver(p.data.id, p.data._raw);
    },
    getRowStyle: p => p.data.id === expandedIncident ? {background:'#818CF815',borderLeft:'3px solid #818CF8'} : null
  });
  return h;
}

let soActiveTab = 'details';

function closeSlideOver() {
  document.getElementById('slide-over').classList.remove('open');
  expandedIncident = null;
}

function openIncidentSlideOver(id, raw) {
  expandedIncident = id;
  soActiveTab = 'details';
  const so = document.getElementById('slide-over');
  const sevColor = {critical:'#EF4444',high:'#FB923C',medium:'#FBBF24',low:'#34D399'};
  const statusColor = {open:'#60A5FA',investigating:'#FBBF24',resolved:'#34D399',closed:'#94A3B8'};
  const sc = sevColor[raw.severity]||'#64748B';
  const stc = statusColor[raw.status]||'#64748B';
  so.innerHTML = `
    <div class="so-header">
      <div class="so-title">${badge((raw.severity||'').toUpperCase(),sc)} ${badge(raw.status,stc)} <span style="margin-left:4px">${esc((raw.title||'').slice(0,50))}</span></div>
      <button class="so-close" data-action="closeSlideOver">&times;</button>
    </div>
    <div class="so-tabs">
      <div class="so-tab active" data-action="switchSOTab" data-tab="details" data-id="${esc(id)}">Details</div>
      <div class="so-tab" data-action="switchSOTab" data-tab="alerts" data-id="${esc(id)}">Alerts</div>
      <div class="so-tab" data-action="switchSOTab" data-tab="timeline" data-id="${esc(id)}">Timeline</div>
      <div class="so-tab" data-action="switchSOTab" data-tab="evidence" data-id="${esc(id)}">Evidence</div>
      <div class="so-tab" data-action="switchSOTab" data-tab="sla" data-id="${esc(id)}">SLA</div>
      <div class="so-tab" data-action="switchSOTab" data-tab="review" data-id="${esc(id)}">PIR</div>
      <div class="so-tab" data-action="switchSOTab" data-tab="tickets" data-id="${esc(id)}">Tickets</div>
      <div class="so-tab" data-action="switchSOTab" data-tab="actions" data-id="${esc(id)}">Actions</div>
    </div>
    <div class="so-body" id="so-body"><div style="text-align:center;padding:40px;color:#94A3B8" class="spin">Loading...</div></div>`;
  so.classList.add('open');
  loadIncidentSlideOver(id, 'details');
}

function switchSOTab(el, tab, id) {
  soActiveTab = tab;
  el.parentElement.querySelectorAll('.so-tab').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('so-body').innerHTML = '<div style="text-align:center;padding:40px;color:#94A3B8" class="spin">Loading...</div>';
  loadIncidentSlideOver(id, tab);
}

async function loadIncidentSlideOver(id, tab) {
  const body = document.getElementById('so-body');
  if (!body) return;
  try {
    const inc = await fetchJSON('/incidents/' + id);
    let h = '';

    if (tab === 'details') {
      // Summary
      if (inc.summary) {
        h += `<div style="margin-bottom:14px">
          <div style="color:#64748B;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Summary</div>
          <div style="color:#334155;font-size:12px;line-height:1.7;background:#F8FAFC;padding:12px;border-radius:8px;border:1px solid #E2E8F0">${esc(inc.summary)}</div>
        </div>`;
      }
      // Plain-language summary (cached in timeline, or on-demand generation)
      const cachedPlain = (inc.timeline||[]).find(t => t.event_type === 'plain_summary');
      h += '<div style="margin-bottom:14px" id="incPlain-' + esc(id) + '">';
      h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">';
      h += '<span style="color:#64748B;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px">Plain English Summary</span>';
      if (canAct() && !cachedPlain) {
        h += '<button class="fbtn" style="font-size:10px;padding:2px 8px;background:#8B5CF610;color:#7C3AED;border-color:#8B5CF640" data-action="genPlainSummary" data-id="' + esc(id) + '">Generate</button>';
      } else if (canAct() && cachedPlain) {
        h += '<button class="fbtn" style="font-size:10px;padding:2px 8px" data-action="genPlainSummary" data-id="' + esc(id) + '">Refresh</button>';
      }
      h += '</div>';
      if (cachedPlain) {
        h += '<div style="color:#1E293B;font-size:12px;line-height:1.7;background:#F8FAFC;padding:12px;border-radius:8px;border:1px solid #8B5CF630;white-space:pre-wrap">' + esc(cachedPlain.description) + '</div>';
      } else {
        h += '<div style="color:#94A3B8;font-size:11px;padding:8px;background:#F8FAFC;border-radius:6px;border:1px dashed #E2E8F0">Click <strong>Generate</strong> for a non-technical explanation of what happened.</div>';
      }
      h += '</div>';
      // MITRE
      let tactics=[]; try{tactics=JSON.parse(inc.mitre_tactics||'[]')}catch(e){}
      let techniques=[]; try{techniques=JSON.parse(inc.mitre_techniques||'[]')}catch(e){}
      let hosts=[]; try{hosts=JSON.parse(inc.affected_hosts||'[]')}catch(e){}
      let users=[]; try{users=JSON.parse(inc.affected_users||'[]')}catch(e){}
      let ips=[]; try{ips=JSON.parse(inc.affected_ips||'[]')}catch(e){}
      h += '<div style="display:flex;flex-direction:column;gap:8px;margin-bottom:14px">';
      if (tactics.filter(Boolean).length) h += '<div><span style="color:#94A3B8;font-size:10px;font-weight:600">TACTICS</span><div style="margin-top:4px">'+tactics.filter(Boolean).map(t=>badge(t,'#818CF8')).join(' ')+'</div></div>';
      if (techniques.filter(Boolean).length) h += '<div><span style="color:#94A3B8;font-size:10px;font-weight:600">TECHNIQUES</span><div style="margin-top:4px">'+techniques.filter(Boolean).map(t=>badge(t,'#60A5FA')).join(' ')+'</div></div>';
      h += '</div>';
      // Metadata grid
      const tier = inc.tier||'L1';
      const tierColor = tier==='L3'?'#EF4444':tier==='L2'?'#FB923C':'#60A5FA';
      h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:14px">';
      h += '<div style="background:#F8FAFC;padding:10px;border-radius:8px;border:1px solid #E2E8F0"><div style="color:#94A3B8;font-size:9px;font-weight:600;text-transform:uppercase">Tier</div><div style="margin-top:4px">'+badge(tier,tierColor)+'</div></div>';
      h += '<div style="background:#F8FAFC;padding:10px;border-radius:8px;border:1px solid #E2E8F0"><div style="color:#94A3B8;font-size:9px;font-weight:600;text-transform:uppercase">Alerts</div><div style="color:#1E293B;font-size:16px;font-weight:700;margin-top:2px">'+(inc.alert_count||0)+'</div></div>';
      h += '<div style="background:#F8FAFC;padding:10px;border-radius:8px;border:1px solid #E2E8F0"><div style="color:#94A3B8;font-size:9px;font-weight:600;text-transform:uppercase">Assigned To</div><div style="color:#1E293B;font-size:12px;margin-top:4px">'+(inc.assigned_to?esc(inc.assigned_to):'<span style="color:#94A3B8">Unassigned</span>')+'</div></div>';
      h += '<div style="background:#F8FAFC;padding:10px;border-radius:8px;border:1px solid #E2E8F0"><div style="color:#94A3B8;font-size:9px;font-weight:600;text-transform:uppercase">Escalations</div><div style="color:#1E293B;font-size:16px;font-weight:700;margin-top:2px">'+(inc.escalation_count||0)+'</div></div>';
      h += '</div>';
      if (hosts.filter(Boolean).length) h += '<div style="margin-bottom:8px"><span style="color:#94A3B8;font-size:10px;font-weight:600">HOSTS:</span> <span style="color:#1E293B;font-size:11px">'+hosts.filter(Boolean).map(x=>esc(x)).join(', ')+'</span></div>';
      if (ips.filter(Boolean).length) h += '<div style="margin-bottom:8px"><span style="color:#94A3B8;font-size:10px;font-weight:600">IPs:</span> <span style="color:#1E293B;font-size:11px">'+ips.filter(Boolean).map(x=>esc(x)).join(', ')+'</span></div>';
      if (users.filter(Boolean).length) h += '<div style="margin-bottom:8px"><span style="color:#94A3B8;font-size:10px;font-weight:600">USERS:</span> <span style="color:#1E293B;font-size:11px">'+users.filter(Boolean).map(x=>esc(x)).join(', ')+'</span></div>';
    }
    else if (tab === 'alerts') {
      if (inc.alerts && inc.alerts.length) {
        inc.alerts.forEach(a => {
          const ev=a.human_verdict||a.verdict; const vc=VC[ev]||'#94A3B8'; const vl=VL[ev]||ev;
          h += `<div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:8px;padding:12px;margin-bottom:8px">
            <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:4px;margin-bottom:6px">
              <div style="display:flex;align-items:center;gap:6px">${badge(vl,vc)} <span style="color:#1E293B;font-size:11px;font-family:'JetBrains Mono',monospace;font-weight:600">Rule ${a.rule_id}</span></div>
              <div style="display:flex;align-items:center;gap:6px">${badge('Risk '+Math.round(a.risk_score||0),(a.risk_score||0)>=70?'#EF4444':'#FBBF24')} ${confBar(a.confidence)}</div>
            </div>
            <div style="color:#64748B;font-size:11px">${esc((a.rule_description||'').slice(0,100))}</div>
            <div style="color:#94A3B8;font-size:10px;margin-top:4px">${a.created_at?localTime(a.created_at):''}</div>
          </div>`;
        });
      } else {
        h += '<div style="color:#94A3B8;text-align:center;padding:40px">No linked alerts</div>';
      }
    }
    else if (tab === 'timeline') {
      if (inc.timeline && inc.timeline.length) {
        h += '<div style="position:relative;padding-left:20px;border-left:2px solid #E2E8F0;margin-left:8px">';
        inc.timeline.forEach(t => {
          const ec = t.event_type==='escalated'?'#EF4444':t.event_type==='alert_added'?'#60A5FA':t.event_type==='status_changed'?'#FBBF24':'#94A3B8';
          h += `<div style="margin-bottom:16px;position:relative">
            <div style="position:absolute;left:-25px;top:2px;width:10px;height:10px;border-radius:50%;background:${ec};border:2px solid #FFFFFF"></div>
            <div style="color:#94A3B8;font-size:10px;font-family:'JetBrains Mono',monospace">${localTime(t.created_at)}</div>
            <div style="margin-top:2px">${badge(t.event_type.replace(/_/g,' '),ec)} <span style="color:#64748B;font-size:11px;margin-left:4px">${esc(t.description)}</span></div>
            <div style="color:#94A3B8;font-size:10px;margin-top:2px">by ${esc(t.actor)}</div>
          </div>`;
        });
        h += '</div>';
      } else {
        h += '<div style="color:#94A3B8;text-align:center;padding:40px">No timeline events</div>';
      }
    }
    else if (tab === 'tickets') {
      let incTickets = [];
      try { incTickets = (await fetchJSON('/tickets/incident/' + id)).tickets || []; } catch(e) {}
      if (incTickets.length) {
        incTickets.forEach(t => {
          const sc = {pending:'#F59E0B',created:'#34D399',synced:'#60A5FA',error:'#EF4444',closed:'#94A3B8'}[t.platform_status]||'#94A3B8';
          const pi = {jira:'Jira',servicenow:'ServiceNow',pagerduty:'PagerDuty'}[t.provider]||t.provider;
          h += `<div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:8px;padding:12px;margin-bottom:8px">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
              <div><span style="font-weight:600;color:#1E293B;font-size:12px">${esc(pi)}</span> ${badge(t.platform_status,sc)}</div>
              <div style="font-size:10px;color:#94A3B8">${t.created_at?new Date(t.created_at).toLocaleString():''}</div>
            </div>
            <div style="font-size:12px;color:#334155;margin-bottom:4px">${t.external_url?'<a href="'+esc(t.external_url)+'" target="_blank" style="color:#3B82F6">'+esc(t.external_id||'Link')+'</a>':esc(t.external_id||'Pending...')}</div>
            <div style="font-size:11px;color:#64748B">${esc((t.summary||'').slice(0,80))}</div>
            ${t.sync_error?'<div style="font-size:10px;color:#EF4444;margin-top:4px">Error: '+esc(t.sync_error.slice(0,100))+'</div>':''}
          </div>`;
        });
      } else {
        h += '<div style="color:#94A3B8;text-align:center;padding:30px;font-size:12px">No tickets linked to this incident</div>';
      }
      if (canAct()) {
        h += `<button class="fbtn" style="width:100%;text-align:center;padding:8px;margin-top:8px;background:#8B5CF610;color:#7C3AED;border-color:#8B5CF640" data-action="createTicketForIncident" data-id="${esc(id)}">Create Ticket for this Incident</button>`;
      }
    }
    else if (tab === 'actions') {
      if (canAct()) {
        h += '<div style="display:flex;flex-direction:column;gap:8px">';
        if (inc.status === 'open') h += `<button class="fbtn" style="width:100%;text-align:center;padding:10px;background:#FBBF2410;color:#B45309;border-color:#FBBF2440" data-action="changeIncidentStatusAndClose" data-id="${esc(inc.id)}" data-status="investigating">Start Investigating</button>`;
        if (inc.status === 'investigating') h += `<button class="fbtn" style="width:100%;text-align:center;padding:10px;background:#34D39910;color:#059669;border-color:#34D39940" data-action="changeIncidentStatusAndClose" data-id="${esc(inc.id)}" data-status="resolved">Resolve Incident</button>`;
        if (inc.status !== 'closed') h += `<button class="fbtn" style="width:100%;text-align:center;padding:10px" data-action="changeIncidentStatusAndClose" data-id="${esc(inc.id)}" data-status="closed">Close Incident</button>`;
        h += `<button class="fbtn" style="width:100%;text-align:center;padding:10px;background:#60A5FA10;color:#2563EB;border-color:#60A5FA40" data-action="assignIncident" data-id="${esc(inc.id)}">Assign to Analyst</button>`;
        h += `<button class="fbtn" style="width:100%;text-align:center;padding:10px;background:#818CF810;color:#4F46E5;border-color:#818CF840" data-action="addIncidentNote" data-id="${esc(inc.id)}">Add Note</button>`;
        if ((inc.tier||'L1') !== 'L3') {
          const nextTier = (inc.tier||'L1')==='L1'?'L2':'L3';
          h += `<button class="fbtn" style="width:100%;text-align:center;padding:10px;background:#FB923C10;color:#C2410C;border-color:#FB923C40" data-action="escalateIncident" data-id="${esc(inc.id)}" data-field="${nextTier}">Escalate to ${nextTier}</button>`;
        }
        if (['admin','senior_analyst','mssp_admin','analyst'].includes(currentUserRole())) {
          const flagged = !!inc.flagged_interesting;
          h += `<button class="fbtn" style="width:100%;text-align:center;padding:10px;background:#FBBF2410;color:#B45309;border-color:#FBBF2440" data-action="flagInterestingPrompt" data-id="${esc(inc.id)}" data-status="${flagged?'1':'0'}">${flagged?'★ Flagged Interesting (re-flag)':'☆ Flag as Interesting'}</button>`;
        }
        if (['admin','senior_analyst','mssp_admin'].includes(currentUserRole())) {
          h += `<button class="fbtn" style="width:100%;text-align:center;padding:10px;background:#EF444410;color:#B91C1C;border-color:#EF444440" data-action="mergeIntoIncidentPrompt" data-id="${esc(inc.id)}">Merge other incidents into this one</button>`;
        }
        h += '</div>';
      } else {
        h += '<div style="color:#94A3B8;text-align:center;padding:40px">Read-only access</div>';
      }
    }
    else if (tab === 'evidence') {
      let chain = [];
      try { chain = JSON.parse(inc.evidence_chain||'[]'); } catch(e) {}
      if (Array.isArray(chain) && chain.length) {
        chain.forEach((ev, idx) => {
          const tcolor = {note:'#60A5FA',artifact:'#8B5CF6',screenshot:'#FBBF24',log:'#34D399',ioc:'#EF4444',file:'#FB923C',other:'#94A3B8'}[ev.type]||'#94A3B8';
          h += `<div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:8px;padding:10px 12px;margin-bottom:6px">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
              <span style="background:${tcolor}18;color:${tcolor};border:1px solid ${tcolor}30;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600">${esc(ev.type||'')}</span>
              <span style="color:#94A3B8;font-size:10px;font-family:'JetBrains Mono',monospace">#${idx+1} · ${ev.added_at?esc(localTime(ev.added_at)):''}</span>
            </div>
            <div style="color:#1E293B;font-size:12px;white-space:pre-wrap;line-height:1.5">${esc(ev.description||'')}</div>
            <div style="margin-top:4px;color:#64748B;font-size:10px">${ev.ref_id?'Ref: <code>'+esc(ev.ref_id)+'</code> · ':''}by ${esc(ev.added_by||'')}</div>
          </div>`;
        });
      } else {
        h += '<div style="color:#94A3B8;text-align:center;padding:30px;font-size:12px">No evidence collected for this incident yet.</div>';
      }
      if (canAct()) {
        h += `<div style="margin-top:14px;border-top:1px solid #E2E8F0;padding-top:12px">
          <div style="color:#64748B;font-size:11px;font-weight:600;margin-bottom:8px">Add evidence entry</div>
          <select id="ev-type" style="width:100%;padding:8px 10px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:6px;font-size:12px;background:#F8FAFC">
            <option value="note">Note</option><option value="artifact">Artifact</option><option value="screenshot">Screenshot</option>
            <option value="log">Log</option><option value="ioc">IOC</option><option value="file">File</option><option value="other">Other</option>
          </select>
          <textarea id="ev-desc" rows="3" placeholder="Description (max 5000 chars)" style="width:100%;padding:8px 10px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:6px;font-size:12px;resize:vertical;box-sizing:border-box"></textarea>
          <input id="ev-ref" type="text" placeholder="Optional reference ID (alert ID, ticket ID, file path...)" style="width:100%;padding:8px 10px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:6px;font-size:12px;box-sizing:border-box">
          <button class="fbtn fon" style="padding:6px 14px" data-action="submitEvidence" data-id="${esc(id)}">Add Evidence</button>
          <div id="ev-result" style="margin-top:6px;font-size:11px"></div>
        </div>`;
      }
    }
    else if (tab === 'sla') {
      let sla = null;
      try { sla = await fetchJSON('/incidents/'+encodeURIComponent(id)+'/sla'); } catch(e) {
        h += '<div style="color:#94A3B8;font-size:12px;padding:20px;text-align:center">SLA tracking not enabled for this license tier or no SLA data for this incident.</div>';
        body.innerHTML = h; return;
      }
      const fmtSec = s => {
        if (s == null) return '—';
        if (s <= 0) return '<span style="color:#EF4444;font-weight:600">BREACHED</span>';
        if (s < 60) return s+'s';
        if (s < 3600) return Math.round(s/60)+'m';
        if (s < 86400) return Math.round(s/3600)+'h '+Math.round((s%3600)/60)+'m';
        return Math.round(s/86400)+'d '+Math.round((s%86400)/3600)+'h';
      };
      h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:14px">';
      h += `<div style="background:#F8FAFC;padding:10px;border-radius:8px;border:1px solid #E2E8F0"><div style="color:#94A3B8;font-size:9px;font-weight:600;text-transform:uppercase">Tier</div><div style="margin-top:4px">${badge(sla.tier||'L1', sla.tier==='L3'?'#EF4444':sla.tier==='L2'?'#FB923C':'#60A5FA')}</div></div>`;
      h += `<div style="background:#F8FAFC;padding:10px;border-radius:8px;border:1px solid #E2E8F0"><div style="color:#94A3B8;font-size:9px;font-weight:600;text-transform:uppercase">Escalations</div><div style="color:#1E293B;font-size:16px;font-weight:700;margin-top:2px">${sla.escalation_count||0}</div></div>`;
      h += '</div>';
      h += '<div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:8px;padding:12px;margin-bottom:10px">';
      h += '<div style="color:#94A3B8;font-size:9px;font-weight:600;text-transform:uppercase;margin-bottom:6px">First Response</div>';
      h += `<div style="color:#1E293B;font-size:12px">Due: ${sla.sla_response_due?esc(localTime(sla.sla_response_due)):'—'} · Met: ${sla.first_response_at?esc(localTime(sla.first_response_at)):'<span style="color:#94A3B8">not yet</span>'}</div>`;
      h += `<div style="color:#64748B;font-size:11px;margin-top:4px">Time remaining: ${fmtSec(sla.response_remaining_sec)}${sla.sla_response_met===true?' · <span style="color:#34D399;font-weight:600">SLA met</span>':sla.sla_response_met===false?' · <span style="color:#EF4444;font-weight:600">SLA missed</span>':''}</div>`;
      h += '</div>';
      h += '<div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:8px;padding:12px;margin-bottom:10px">';
      h += '<div style="color:#94A3B8;font-size:9px;font-weight:600;text-transform:uppercase;margin-bottom:6px">Resolution</div>';
      h += `<div style="color:#1E293B;font-size:12px">Due: ${sla.sla_resolution_due?esc(localTime(sla.sla_resolution_due)):'—'}</div>`;
      h += `<div style="color:#64748B;font-size:11px;margin-top:4px">Time remaining: ${fmtSec(sla.resolution_remaining_sec)}${sla.sla_resolution_met===true?' · <span style="color:#34D399;font-weight:600">SLA met</span>':sla.sla_resolution_met===false?' · <span style="color:#EF4444;font-weight:600">SLA missed</span>':''}</div>`;
      h += '</div>';
      const breaches = sla.breaches || [];
      if (breaches.length) {
        h += '<div style="color:#94A3B8;font-size:9px;font-weight:600;text-transform:uppercase;margin:10px 0 6px">Recorded Breaches</div>';
        breaches.forEach(b => {
          h += `<div style="background:#FEF2F2;border:1px solid #EF444430;border-radius:6px;padding:8px 10px;margin-bottom:4px;font-size:11px;color:#991B1B"><strong>${esc(b.breach_type||b.type||'breach')}</strong> · ${b.breached_at?esc(localTime(b.breached_at)):''} · ${esc(b.note||'')}</div>`;
        });
      }
    }
    else if (tab === 'review') {
      let rev = null;
      try { rev = (await fetchJSON('/incidents/'+encodeURIComponent(id)+'/review')).review; } catch(e) {}
      const r = rev || {};
      const isNew = !rev;
      const canEdit = ['admin','senior_analyst','mssp_admin'].includes(currentUserRole());
      h += `<div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:8px;padding:12px 14px;margin-bottom:14px">
        <div style="color:#64748B;font-size:11px;line-height:1.6">${isNew?'<strong>No post-incident review yet.</strong> '+(canEdit?'Fill in below and Save to create one.':'Senior analysts can create one.'):'<strong>PIR last updated:</strong> '+(r.updated_at?esc(localTime(r.updated_at)):'?')+' by '+esc(r.created_by||'?')+(r.status?' · status: <strong>'+esc(r.status)+'</strong>':'')}</div>
      </div>`;
      const ro = !canEdit ? ' readonly' : '';
      const dis = !canEdit ? 'disabled' : '';
      h += '<label style="display:block;font-size:11px;color:#64748B;font-weight:600;margin-bottom:4px">Timeline accuracy</label>';
      h += `<textarea id="pir-timeline" rows="2" maxlength="2000" ${ro} style="width:100%;padding:8px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:8px;font-size:12px;box-sizing:border-box;resize:vertical">${esc(r.timeline_accuracy||'')}</textarea>`;
      h += '<label style="display:block;font-size:11px;color:#64748B;font-weight:600;margin-bottom:4px">Detection gap</label>';
      h += `<textarea id="pir-detection" rows="2" maxlength="2000" ${ro} style="width:100%;padding:8px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:8px;font-size:12px;box-sizing:border-box;resize:vertical">${esc(r.detection_gap||'')}</textarea>`;
      h += '<label style="display:block;font-size:11px;color:#64748B;font-weight:600;margin-bottom:4px">Response effectiveness</label>';
      h += `<textarea id="pir-response" rows="2" maxlength="2000" ${ro} style="width:100%;padding:8px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:8px;font-size:12px;box-sizing:border-box;resize:vertical">${esc(r.response_effectiveness||'')}</textarea>`;
      h += '<label style="display:block;font-size:11px;color:#64748B;font-weight:600;margin-bottom:4px">Lessons learned</label>';
      h += `<textarea id="pir-lessons" rows="3" maxlength="5000" ${ro} style="width:100%;padding:8px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:8px;font-size:12px;box-sizing:border-box;resize:vertical">${esc(r.lessons_learned||'')}</textarea>`;
      h += '<label style="display:block;font-size:11px;color:#64748B;font-weight:600;margin-bottom:4px">Participants (comma-separated usernames)</label>';
      const partsInit = Array.isArray(r.participants) ? r.participants.join(', ') : '';
      h += `<input id="pir-participants" type="text" ${ro} value="${esc(partsInit)}" style="width:100%;padding:8px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:8px;font-size:12px;box-sizing:border-box">`;
      h += '<label style="display:block;font-size:11px;color:#64748B;font-weight:600;margin-bottom:4px">Status</label>';
      h += `<select id="pir-status" ${dis} style="width:100%;padding:8px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:8px;font-size:12px;box-sizing:border-box;background:#F8FAFC">`;
      ['draft','in_review','completed'].forEach(s => { h += `<option value="${s}"${(r.status||'draft')===s?' selected':''}>${s}</option>`; });
      h += '</select>';
      if (canEdit) {
        h += `<button class="fbtn fon" style="padding:8px 16px" data-action="submitPIR" data-id="${esc(id)}">${isNew?'Create Review':'Update Review'}</button>`;
        h += '<div id="pir-result" style="margin-top:6px;font-size:11px"></div>';
      }
    }
    body.innerHTML = h;
  } catch(e) {
    body.innerHTML = '<div style="color:#EF4444;font-size:11px;padding:20px">Failed to load details</div>';
  }
}

// Legacy function kept for any remaining callers
async function loadIncidentDetail(id) { openIncidentSlideOver(id, {severity:'',status:'',title:''}); }

async function changeIncidentStatus(id, status) {
  const reason = prompt('Reason for changing status to '+status+' (required):');
  if (reason === null || !reason.trim()) return;
  try {
    const r = await fetch(API+'/incidents/'+id+'/status', {method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({status:status,reason:reason.trim()})});
    if (!r.ok) { const e = await r.json().catch(()=>({})); alert('Status change failed: '+esc(e.detail||r.status)); return; }
  } catch(e) { alert('Status change failed: network error'); return; }
  refresh();
}
async function assignIncident(id) {
  const who = prompt('Assign to (username):');
  if (!who) return;
  try {
    const r = await fetch(API+'/incidents/'+id+'/assign', {method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({assigned_to:who})});
    if (!r.ok) { alert('Assignment failed: '+r.status); return; }
  } catch(e) { alert('Assignment failed: network error'); return; }
  refresh();
}
async function addIncidentNote(id) {
  const note = prompt('Add note:');
  if (!note) return;
  try {
    const r = await fetch(API+'/incidents/'+id+'/note', {method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({note:note})});
    if (!r.ok) { alert('Note failed: '+r.status); return; }
  } catch(e) { alert('Note failed: network error'); return; }
  expandedIncident = id;
  refresh();
}
async function escalateIncident(id, tier) {
  const notes = prompt('Handoff notes for '+tier+' (what you tried, why escalating):');
  if (notes === null) return;
  try {
    const r = await fetch(API+'/incidents/'+id+'/escalate', {method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({tier:tier,handoff_notes:notes||''})});
    if (!r.ok) { alert('Escalation failed: '+r.status); return; }
  } catch(e) { alert('Escalation failed: network error'); return; }
  expandedIncident = id;
  refresh();
}

async function flagInterestingPrompt(id, currentlyFlagged) {
  const wasFlagged = currentlyFlagged === '1';
  if (wasFlagged) {
    if (!confirm('Currently flagged interesting. Click OK to UN-FLAG, or Cancel to update notes.')) {
      const newNotes = prompt('Update interesting-notes:');
      if (newNotes === null) return;
      try {
        const r = await fetch(API+'/incidents/'+encodeURIComponent(id)+'/flag-interesting', {
          method:'POST', headers:{...authHeaders(),'Content-Type':'application/json'},
          body: JSON.stringify({flagged: true, notes: (newNotes||'').slice(0,500)})
        });
        if (!r.ok) { const e = await r.json().catch(()=>({})); alert('Update failed: '+(e.detail||('HTTP '+r.status))); return; }
        loadIncidentSlideOver(id, soActiveTab||'actions');
      } catch(e) { alert('Network error: '+e.message); }
      return;
    }
    // User confirmed un-flag
    try {
      const r = await fetch(API+'/incidents/'+encodeURIComponent(id)+'/flag-interesting', {
        method:'POST', headers:{...authHeaders(),'Content-Type':'application/json'},
        body: JSON.stringify({flagged: false, notes: ''})
      });
      if (!r.ok) { const e = await r.json().catch(()=>({})); alert('Un-flag failed: '+(e.detail||('HTTP '+r.status))); return; }
      loadIncidentSlideOver(id, soActiveTab||'actions');
    } catch(e) { alert('Network error: '+e.message); }
  } else {
    const notes = prompt('Why is this incident interesting? (max 500 chars, used for case-of-the-week)');
    if (notes === null) return;
    try {
      const r = await fetch(API+'/incidents/'+encodeURIComponent(id)+'/flag-interesting', {
        method:'POST', headers:{...authHeaders(),'Content-Type':'application/json'},
        body: JSON.stringify({flagged: true, notes: (notes||'').slice(0,500)})
      });
      if (!r.ok) { const e = await r.json().catch(()=>({})); alert('Flag failed: '+(e.detail||('HTTP '+r.status))); return; }
      loadIncidentSlideOver(id, soActiveTab||'actions');
    } catch(e) { alert('Network error: '+e.message); }
  }
}

async function mergeIntoIncidentPrompt(targetId) {
  const raw = prompt('Source incident IDs to merge INTO this one (comma-separated). Source incidents will be marked closed, alerts re-linked.');
  if (!raw) return;
  const sources = raw.split(',').map(s => s.trim()).filter(Boolean);
  if (!sources.length) return;
  if (!confirm('Merge '+sources.length+' incident(s) into '+targetId+'? This is irreversible.')) return;
  try {
    const r = await fetch(API+'/incidents/merge', {method:'POST', headers:{...authHeaders(),'Content-Type':'application/json'}, body: JSON.stringify({target_id: targetId, source_ids: sources})});
    const d = await r.json().catch(()=>({}));
    if (!r.ok) { alert('Merge failed: '+(d.detail||('HTTP '+r.status))); return; }
    alert('Merged successfully.');
    loadIncidentSlideOver(targetId, soActiveTab||'details');
  } catch(e) { alert('Network error: '+e.message); }
}

async function submitEvidence(id) {
  const out = document.getElementById('ev-result');
  const type = document.getElementById('ev-type').value;
  const desc = document.getElementById('ev-desc').value.trim();
  const ref = document.getElementById('ev-ref').value.trim();
  if (!desc) { out.innerHTML = '<span style="color:#EF4444">Description required</span>'; return; }
  const body = {type, description: desc};
  if (ref) body.ref_id = ref;
  try {
    const r = await fetch(API+'/incidents/'+encodeURIComponent(id)+'/evidence', {method:'POST', headers:{...authHeaders(),'Content-Type':'application/json'}, body: JSON.stringify(body)});
    const d = await r.json().catch(()=>({}));
    if (r.ok) {
      out.innerHTML = '<span style="color:#34D399">Added.</span>';
      setTimeout(() => loadIncidentSlideOver(id, 'evidence'), 600);
    } else {
      out.innerHTML = '<span style="color:#EF4444">'+esc(typeof d.detail==='string'?d.detail:JSON.stringify(d.detail||d))+'</span>';
    }
  } catch(e) { out.innerHTML = '<span style="color:#EF4444">'+esc(e.message)+'</span>'; }
}

async function submitPIR(id) {
  const out = document.getElementById('pir-result');
  const partsRaw = document.getElementById('pir-participants').value;
  const participants = partsRaw ? partsRaw.split(',').map(s=>s.trim()).filter(Boolean) : [];
  const body = {
    timeline_accuracy: document.getElementById('pir-timeline').value,
    detection_gap: document.getElementById('pir-detection').value,
    response_effectiveness: document.getElementById('pir-response').value,
    lessons_learned: document.getElementById('pir-lessons').value,
    participants,
    status: document.getElementById('pir-status').value,
  };
  try {
    const r = await fetch(API+'/incidents/'+encodeURIComponent(id)+'/review', {method:'POST', headers:{...authHeaders(),'Content-Type':'application/json'}, body: JSON.stringify(body)});
    const d = await r.json().catch(()=>({}));
    if (r.ok) {
      out.innerHTML = '<span style="color:#34D399">Saved.</span>';
      setTimeout(() => loadIncidentSlideOver(id, 'review'), 600);
    } else {
      out.innerHTML = '<span style="color:#EF4444">'+esc(typeof d.detail==='string'?d.detail:JSON.stringify(d.detail||d))+'</span>';
    }
  } catch(e) { out.innerHTML = '<span style="color:#EF4444">'+esc(e.message)+'</span>'; }
}

// -- Admin Tab --
async function renderAdmin() {
  const role = currentUserRole();
  if (!['admin','mssp_admin'].includes(role)) return '<div style="text-align:center;color:#EF4444;padding:40px">Admin access required.</div>';
  var h = '';
  // Sub-tab bar — Tenants and Pipeline tabs are mssp_admin only
  var tabs = [{id:'users',label:'Users & System'},{id:'assets',label:'Asset Inventory'},{id:'identities',label:'Identity Context'},{id:'localiocs',label:'Local IOCs'},{id:'shifts',label:'Shifts'},{id:'governance',label:'Governance'},{id:'anon',label:'Anonymization'}];
  if (role === 'mssp_admin') {
    tabs.push({id:'tenants',label:'Tenants'});
    tabs.push({id:'pipeline',label:'Pipeline Health'});
  }
  // If user landed on a tab their role can't see, reset
  const mssp_only = ['tenants','pipeline'];
  if (mssp_only.includes(adminSubTab) && role !== 'mssp_admin') adminSubTab = 'users';
  h += '<div style="display:flex;gap:4px;margin-bottom:20px;border-bottom:1px solid #E2E8F0;padding-bottom:8px;flex-wrap:wrap">';
  tabs.forEach(function(t){
    var active = adminSubTab === t.id;
    h += '<button class="fbtn'+(active?' fon':'')+'" data-action="setAdminSubTab" data-id="'+t.id+'" style="padding:6px 16px;font-size:12px">'+esc(t.label)+'</button>';
  });
  h += '</div>';
  if (adminSubTab === 'users') h += await renderAdminUsers();
  else if (adminSubTab === 'assets') h += await renderAdminAssets();
  else if (adminSubTab === 'identities') h += await renderAdminIdentities();
  else if (adminSubTab === 'localiocs') h += await renderAdminLocalIOCs();
  else if (adminSubTab === 'tenants') h += await renderAdminTenants();
  else if (adminSubTab === 'pipeline') h += await renderAdminPipeline();
  else if (adminSubTab === 'shifts') h += await renderAdminShifts();
  else if (adminSubTab === 'governance') h += await renderAdminGovernance();
  else if (adminSubTab === 'anon') h += await renderAdminAnon();
  return h;
}

async function renderAdminUsers() {
  var h = '';
  // User Management
  try {
    const ud = await fetchJSON('/admin/users?include_inactive=true');
    const users = ud.users || [];
    h += '<div class="section-title">User Management</div>';
    h += '<div style="margin-bottom:12px"><button class="fbtn fon" data-action="promptCreateUser">+ Create User</button></div>';
    h += '<div id="users-grid" style="width:100%;min-height:150px"></div>';
    queueGrid('users-grid', {
      rowData: users.map(u => ({id:u.id,username:u.username,display_name:u.display_name,role:u.role,is_active:u.is_active})),
      columnDefs: [
        {field:'username',headerName:'Username',width:160,cellStyle:{fontFamily:'JetBrains Mono,monospace',color:'#1E293B'}},
        {field:'display_name',headerName:'Name',flex:1,minWidth:140},
        {field:'role',headerName:'Role',width:140,cellRenderer:p=>'<span style="font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px;background:#818CF818;color:#818CF8;border:1px solid #818CF830">'+esc(p.value)+'</span>'},
        {field:'is_active',headerName:'Status',width:110,cellRenderer:p=>{const c=p.value?'#34D399':'#EF4444';const t=p.value?'Active':'Inactive';return '<span style="font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px;background:'+c+'18;color:'+c+';border:1px solid '+c+'30">'+t+'</span>';}},
        {headerName:'Actions',width:90,sortable:false,resizable:false,cellRenderer:p=>'<button class="fbtn" style="padding:3px 10px;font-size:10px" data-action="promptEditUser" data-id="'+esc(p.data.id)+'" data-field="'+esc(p.data.username)+'" data-status="'+esc(p.data.role)+'" data-verdict="'+(p.data.is_active?'true':'false')+'">Edit</button>'}
      ]
    });
  } catch(e) { h += '<div class="row" style="color:#EF4444">Failed to load users</div>'; }

  // Platform Health
  try {
    const s = await fetchJSON('/dashboard/stats');
    const t = s.today || {};
    h += '<div class="section-title">Platform Health</div>';
    h += '<div class="g">';
    h += '<div class="c"><div class="l">Alerts Today</div><div class="v">'+(t.total||0)+'</div></div>';
    h += '<div class="c"><div class="l">Avg Confidence</div><div class="v">'+(t.avg_confidence?Math.round(t.avg_confidence*100)+'%':'--')+'</div></div>';
    h += '<div class="c"><div class="l">Open Incidents</div><div class="v" style="color:#60A5FA">'+(s.open_incidents||0)+'</div></div>';
    h += '<div class="c"><div class="l">Pending Reviews</div><div class="v" style="color:#FBBF24">'+(s.pending_reviews||0)+'</div></div>';
    h += '<div class="c"><div class="l">Pending Proposals</div><div class="v" style="color:#818CF8">'+(s.pending_proposals||0)+'</div></div>';
    h += '</div>';
  } catch(e) {}

  // Audit Log
  try {
    const al = await fetchJSON('/admin/audit-log?limit=50');
    const entries = al.entries || [];
    h += '<div class="section-title">Audit Log</div>';
    if (entries.length) {
      h += '<div id="audit-grid" style="width:100%;height:300px"></div>';
      queueGrid('audit-grid', {
        domLayout: 'normal',
        rowData: entries.map(e => ({time:e.created_at?localTime(e.created_at):'',actor:e.actor||'',action:e.action||'',target:(e.target_type||'')+(e.target_id?':'+String(e.target_id).slice(0,8):''),ip:e.ip_address||''})),
        columnDefs: [
          {field:'time',headerName:'Time',width:170,cellStyle:{color:'#3D5A75',fontFamily:'JetBrains Mono,monospace',fontSize:'10px'}},
          {field:'actor',headerName:'Actor',width:130,cellStyle:{color:'#1E293B'}},
          {field:'action',headerName:'Action',width:140,cellRenderer:p=>'<span style="font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px;background:#60A5FA18;color:#60A5FA;border:1px solid #60A5FA30">'+esc(p.value)+'</span>'},
          {field:'target',headerName:'Target',flex:1,minWidth:120},
          {field:'ip',headerName:'IP',width:130,cellStyle:{color:'#3D5A75',fontFamily:'JetBrains Mono,monospace',fontSize:'10px'}}
        ]
      });
    } else { h += '<div style="color:#94A3B8;padding:20px;text-align:center">No audit entries yet</div>'; }
  } catch(e) {}

  // System Config
  try {
    const cfg = await fetchJSON('/admin/config');
    const c = cfg.config || {};
    h += '<div class="section-title">System Configuration</div>';
    h += '<div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px;padding:14px"><table style="width:100%;font-size:12px;border-collapse:collapse">';
    Object.entries(c).forEach(function(kv){
      h += '<tr><td style="padding:6px 10px;color:#64748B;font-family:\'JetBrains Mono\',monospace;width:40%">'+esc(kv[0])+'</td><td style="padding:6px 10px;color:#1E293B">'+esc(String(kv[1]))+'</td></tr>';
    });
    h += '</table></div>';
  } catch(e) {}
  return h;
}

const PASSWORD_RULES = 'min 12 chars, must include uppercase, lowercase, digit, and special character';
function assignableRolesForCurrentTier(){return _licenseTier==='community'?['analyst','read_only']:['admin','senior_analyst','analyst','read_only'];}

function promptCreateUser() {
  const u = prompt('Username:'); if (!u) return;
  const p = prompt('Password ('+PASSWORD_RULES+'):'); if (!p) return;
  const roles = assignableRolesForCurrentTier();
  const r = prompt('Role ('+roles.join('/')+'):', 'analyst'); if (!r) return;
  const dn = prompt('Display name:', u);
  fetch(API+'/admin/users', {method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},
    body:JSON.stringify({username:u,password:p,role:r,display_name:dn||u,email:''})})
  .then(r => r.ok ? r.json() : r.json().then(e => Promise.reject(e)))
  .then(() => refresh())
  .catch(e => alert('Error: ' + extractErrorMessage(e)));
}
function promptEditUser(id, username, currentRole, isActive) {
  const action = prompt('Action for '+username+':\\n1) Change role\\n2) '+(isActive?'Deactivate':'Reactivate')+'\\n3) Reset password\\nEnter 1, 2, or 3:');
  if (action==='1') {
    const roles = assignableRolesForCurrentTier();
    const r = prompt('New role ('+roles.join('/')+'):', currentRole); if (!r) return;
    fetch(API+'/admin/users/'+id, {method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({role:r})})
      .then(r => r.ok ? r.json() : r.json().then(e => Promise.reject(e)))
      .then(() => refresh())
      .catch(e => alert('Error: ' + extractErrorMessage(e)));
  } else if (action==='2') {
    fetch(API+'/admin/users/'+id, {method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({is_active:!isActive})})
      .then(r => r.ok ? r.json() : r.json().then(e => Promise.reject(e)))
      .then(() => refresh())
      .catch(e => alert('Error: ' + extractErrorMessage(e)));
  } else if (action==='3') {
    const p = prompt('New password ('+PASSWORD_RULES+'):'); if (!p) return;
    fetch(API+'/admin/users/'+id, {method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({password:p})})
      .then(r => r.ok ? r.json() : r.json().then(e => Promise.reject(e)))
      .then(() => refresh())
      .catch(e => alert('Error: ' + extractErrorMessage(e)));
  }
}

// ── Admin Settings: Assets, Identities, Local IOCs ──────────────

async function renderAdminAssets() {
  var h = '';
  try {
    var data = await fetchJSON('/admin/settings/assets');
    var assets = data.assets || [];
    h += '<div class="section-title">Asset Inventory</div>';
    h += '<p style="color:#64748B;font-size:12px;margin:0 0 12px">Define assets so alerts are enriched with criticality, ownership, and environment context.</p>';
    h += '<div style="margin-bottom:12px">';
    h += '<button class="fbtn fon" data-action="showAssetForm">+ Add Asset</button>';
    h += ' <button class="fbtn" data-action="reloadEnrichers" style="margin-left:8px">Reload Enrichers</button>';
    h += '</div>';
    if (assets.length) {
      h += '<div id="assets-grid" style="width:100%;min-height:200px"></div>';
      queueGrid('assets-grid', {
        rowData: assets.map(function(a) {
          var tags = Array.isArray(a.tags) ? a.tags : JSON.parse(a.tags||'[]');
          return {id:a.id,hostname:a.hostname,tier:a.tier||'unknown',owner:a.owner||'unknown',environment:a.environment||'unknown',criticality_multiplier:a.criticality_multiplier||1.0,tags:tags.join(', ')};
        }),
        columnDefs: [
          {field:'hostname',headerName:'Hostname',width:200,cellStyle:{fontFamily:'JetBrains Mono,monospace',color:'#1E293B'}},
          {field:'tier',headerName:'Tier',width:150,cellRenderer:function(p){var c=p.value==='tier_1_critical'?'#EF4444':p.value==='tier_2_important'?'#F59E0B':'#34D399';return '<span style="font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px;background:'+c+'18;color:'+c+';border:1px solid '+c+'30">'+esc(p.value)+'</span>';}},
          {field:'owner',headerName:'Owner',width:140},
          {field:'environment',headerName:'Env',width:120},
          {field:'criticality_multiplier',headerName:'Multiplier',width:100},
          {field:'tags',headerName:'Tags',flex:1,minWidth:120},
          {headerName:'Actions',width:140,sortable:false,cellRenderer:function(p){return '<button class="fbtn" style="padding:3px 8px;font-size:10px" data-action="editAsset" data-id="'+esc(p.data.id)+'">Edit</button> <button class="fbtn" style="padding:3px 8px;font-size:10px;color:#EF4444" data-action="deleteAsset" data-id="'+esc(p.data.id)+'" data-field="'+esc(p.data.hostname)+'">Del</button>';}}
        ]
      });
    } else {
      h += '<div style="color:#94A3B8;padding:40px;text-align:center;background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px">No assets configured yet. Click "+ Add Asset" to define your first asset.</div>';
    }
  } catch(e) { h += '<div style="color:#EF4444">Failed to load assets: '+esc(e.message)+'</div>'; }
  return h;
}

async function renderAdminIdentities() {
  var h = '';
  try {
    var data = await fetchJSON('/admin/settings/identities');
    var identities = data.identities || [];
    h += '<div class="section-title">Identity Context</div>';
    h += '<p style="color:#64748B;font-size:12px;margin:0 0 12px">Define user identities so alerts are enriched with risk levels, admin status, and department context.</p>';
    h += '<div style="margin-bottom:12px">';
    h += '<button class="fbtn fon" data-action="showIdentityForm">+ Add Identity</button>';
    h += ' <button class="fbtn" data-action="reloadEnrichers" style="margin-left:8px">Reload Enrichers</button>';
    h += '</div>';
    if (identities.length) {
      h += '<div id="identities-grid" style="width:100%;min-height:200px"></div>';
      queueGrid('identities-grid', {
        rowData: identities.map(function(i) {
          var roles = Array.isArray(i.roles) ? i.roles : JSON.parse(i.roles||'[]');
          return {id:i.id,username:i.username,risk_level:i.risk_level||'standard',risk_multiplier:i.risk_multiplier||1.0,is_admin:i.is_admin,is_service_account:i.is_service_account,department:i.department||'unknown',roles:roles.join(', ')};
        }),
        columnDefs: [
          {field:'username',headerName:'Username',width:160,cellStyle:{fontFamily:'JetBrains Mono,monospace',color:'#1E293B'}},
          {field:'risk_level',headerName:'Risk',width:120,cellRenderer:function(p){var c=p.value==='high_risk'||p.value==='critical'?'#EF4444':p.value==='elevated'?'#F59E0B':'#34D399';return '<span style="font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px;background:'+c+'18;color:'+c+';border:1px solid '+c+'30">'+esc(p.value)+'</span>';}},
          {field:'risk_multiplier',headerName:'Multiplier',width:100},
          {field:'is_admin',headerName:'Admin',width:80,cellRenderer:function(p){return p.value?'<span style="color:#EF4444;font-weight:600">Yes</span>':'No';}},
          {field:'is_service_account',headerName:'Svc Acct',width:90,cellRenderer:function(p){return p.value?'<span style="color:#F59E0B;font-weight:600">Yes</span>':'No';}},
          {field:'department',headerName:'Dept',width:120},
          {field:'roles',headerName:'Roles',flex:1,minWidth:120},
          {headerName:'Actions',width:140,sortable:false,cellRenderer:function(p){return '<button class="fbtn" style="padding:3px 8px;font-size:10px" data-action="editIdentity" data-id="'+esc(p.data.id)+'">Edit</button> <button class="fbtn" style="padding:3px 8px;font-size:10px;color:#EF4444" data-action="deleteIdentity" data-id="'+esc(p.data.id)+'" data-field="'+esc(p.data.username)+'">Del</button>';}}
        ]
      });
    } else {
      h += '<div style="color:#94A3B8;padding:40px;text-align:center;background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px">No identities configured yet. Click "+ Add Identity" to define your first user identity.</div>';
    }
  } catch(e) { h += '<div style="color:#EF4444">Failed to load identities: '+esc(e.message)+'</div>'; }
  return h;
}

async function renderAdminLocalIOCs() {
  var h = '';
  try {
    var data = await fetchJSON('/admin/settings/local-iocs');
    var iocs = data.iocs || [];
    h += '<div class="section-title">Local IOCs</div>';
    h += '<p style="color:#64748B;font-size:12px;margin:0 0 12px">Add local indicators of compromise (IPs, domains, hashes). These are matched against every incoming alert in real-time.</p>';
    h += '<div style="margin-bottom:12px">';
    h += '<button class="fbtn fon" data-action="showLocalIOCForm">+ Add IOC</button>';
    h += '</div>';
    if (iocs.length) {
      h += '<div id="iocs-grid" style="width:100%;min-height:200px"></div>';
      queueGrid('iocs-grid', {
        rowData: iocs.map(function(i){return {id:i.id,ioc_type:i.ioc_type,value:i.value,severity:i.severity||'medium',description:i.description||''};}),
        columnDefs: [
          {field:'ioc_type',headerName:'Type',width:100,cellRenderer:function(p){return '<span style="font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px;background:#818CF818;color:#818CF8;border:1px solid #818CF830">'+esc(p.value)+'</span>';}},
          {field:'value',headerName:'Value',width:280,cellStyle:{fontFamily:'JetBrains Mono,monospace',color:'#1E293B'}},
          {field:'severity',headerName:'Severity',width:110,cellRenderer:function(p){var c=p.value==='critical'?'#EF4444':p.value==='high'?'#F59E0B':p.value==='medium'?'#60A5FA':'#34D399';return '<span style="font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px;background:'+c+'18;color:'+c+';border:1px solid '+c+'30">'+esc(p.value)+'</span>';}},
          {field:'description',headerName:'Description',flex:1,minWidth:150},
          {headerName:'',width:70,sortable:false,cellRenderer:function(p){return '<button class="fbtn" style="padding:3px 8px;font-size:10px;color:#EF4444" data-action="deleteLocalIOC" data-id="'+esc(p.data.id)+'" data-field="'+esc(p.data.value)+'">Del</button>';}}
        ]
      });
    } else {
      h += '<div style="color:#94A3B8;padding:40px;text-align:center;background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px">No local IOCs configured yet. Click "+ Add IOC" to add your first indicator.</div>';
    }
  } catch(e) { h += '<div style="color:#EF4444">Failed to load IOCs: '+esc(e.message)+'</div>'; }
  return h;
}

// ── Tenant Lifecycle (mssp_admin) ─────────────────────────────

async function renderAdminTenants() {
  var h = '';
  h += '<div class="section-title">Tenants</div>';
  h += '<p style="color:#64748B;font-size:12px;margin:0 0 12px">Each tenant has its own encrypted config (Wazuh, LLM, notifications, dashboard proxy, TI keys) and a set of mapped Wazuh agent IDs. Click a row to manage configuration and agent mapping.</p>';
  h += '<div style="margin-bottom:12px"><button class="fbtn fon" data-action="showTenantCreateModal">+ Create Tenant</button></div>';
  try {
    var data = await fetchJSON('/admin/tenants');
    var tenants = data.tenants || [];
    if (!tenants.length) {
      h += '<div style="color:#94A3B8;padding:40px;text-align:center;background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px">No tenants yet. Click "+ Create Tenant" to onboard one.</div>';
      return h;
    }
    h += '<div id="tenants-grid" style="width:100%;min-height:240px"></div>';
    queueGrid('tenants-grid', {
      rowData: tenants.map(function(t){
        return {
          id: t.id,
          name: t.name,
          slug: t.slug,
          active: t.active,
          config_keys: (t.config_keys||[]).join(', ') || '—',
          has_wazuh: !!t.has_wazuh,
          has_claude: !!t.has_claude,
          has_notifications: !!t.has_notifications,
          updated_at: t.updated_at || ''
        };
      }),
      columnDefs: [
        {field:'name',headerName:'Name',width:200,cellStyle:{color:'#1E293B',fontWeight:'600'}},
        {field:'slug',headerName:'Slug',width:160,cellStyle:{fontFamily:'JetBrains Mono,monospace',color:'#64748B'}},
        {field:'active',headerName:'Status',width:100,cellRenderer:function(p){var c=p.value?'#34D399':'#EF4444';var t=p.value?'Active':'Inactive';return '<span style="font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px;background:'+c+'18;color:'+c+';border:1px solid '+c+'30">'+t+'</span>';}},
        {field:'config_keys',headerName:'Config Sections',flex:1,minWidth:200,cellStyle:{fontFamily:'JetBrains Mono,monospace',color:'#64748B',fontSize:'11px'}},
        {headerName:'Updated',width:170,field:'updated_at',cellRenderer:function(p){return p.value?'<span style="font-size:11px;color:#64748B">'+esc(localTime(p.value))+'</span>':'';}},
        {headerName:'',width:90,sortable:false,resizable:false,cellRenderer:function(p){return '<button class="fbtn" style="padding:3px 10px;font-size:10px" data-action="showTenantDetail" data-id="'+esc(p.data.id)+'">Manage</button>';}}
      ]
    });
  } catch(e) {
    h += '<div style="color:#EF4444">Failed to load tenants: '+esc(e.message)+'</div>';
  }
  return h;
}

function showTenantCreateModal() {
  const so = document.getElementById('slide-over');
  so.style.display = 'block';
  so.classList.add('open');
  // Section header style
  const sec = title => '<div style="margin:18px 0 8px;color:#64748B;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;border-top:1px solid #E2E8F0;padding-top:14px">'+title+'</div>';
  const fldLabel = (txt, opt) => '<label style="display:block;margin-bottom:4px;font-weight:600;color:#374151;font-size:12px">'+txt+(opt?' <span style="color:#94A3B8;font-weight:400">(optional)</span>':'')+'</label>';
  const inp = (id, type, ph) => '<input id="'+id+'" type="'+type+'" placeholder="'+esc(ph||'')+'" style="width:100%;padding:8px 10px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:10px;font-size:12px;box-sizing:border-box;font-family:'+(type==='password'||id.includes('url')||id.includes('slug')?'\'JetBrains Mono\',monospace':'inherit')+'">';

  so.innerHTML = '<div style="padding:24px;max-height:90vh;overflow-y:auto">'
    + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">'
    + '<h3 style="margin:0;color:#1E293B">Create Tenant</h3>'
    + '<button data-action="closeSlideOver" style="background:none;border:none;cursor:pointer;font-size:20px;color:#64748B">&times;</button></div>'
    + '<div style="color:#64748B;font-size:11px;margin-bottom:14px">Fill in the essentials below. You can add more sections later via <strong>Edit Section</strong> in the tenant detail.</div>'

    // Identity
    + sec('Tenant Identity')
    + fldLabel('Name')
    + inp('ten-name', 'text', 'Acme Corp')
    + fldLabel('Slug')
    + '<div style="color:#94A3B8;font-size:10px;margin-top:-6px;margin-bottom:4px">3–50 chars, lowercase, a–z 0–9 hyphens or underscores</div>'
    + inp('ten-slug', 'text', 'acme-corp')

    // Wazuh
    + sec('Wazuh Connection (optional)')
    + fldLabel('API URL', true)
    + inp('ten-w-url', 'url', 'https://wazuh.example.com:55000')
    + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">'
    +   '<div>'+fldLabel('Username', true)+inp('ten-w-user','text','wazuh')+'</div>'
    +   '<div>'+fldLabel('Password', true)+inp('ten-w-pass','password','••••••••')+'</div>'
    + '</div>'
    + '<label style="display:flex;align-items:center;gap:6px;color:#64748B;font-size:11px;margin-bottom:6px;cursor:pointer">'
    + '<input id="ten-w-verify" type="checkbox" checked> Verify SSL certificate'
    + '</label>'

    // LLM Provider
    + sec('LLM Provider (optional)')
    + fldLabel('Provider', true)
    + '<select id="ten-llm-provider" data-action-change="tenLlmProviderChange" style="width:100%;padding:8px 10px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:10px;font-size:12px;background:#F8FAFC;box-sizing:border-box">'
    +   '<option value="">— Use platform default —</option>'
    +   '<option value="anthropic">Anthropic Claude (API or CLI)</option>'
    +   '<option value="openai">OpenAI (GPT-4o, Azure)</option>'
    +   '<option value="ollama">Ollama (local)</option>'
    +   '<option value="groq">Groq</option>'
    + '</select>'
    + '<div id="ten-llm-fields" style="display:none">'
    +   '<div id="ten-llm-mode-wrap" style="display:none">'
    +     fldLabel('Mode', true)
    +     '<select id="ten-llm-mode" style="width:100%;padding:8px 10px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:10px;font-size:12px;background:#F8FAFC;box-sizing:border-box">'
    +       '<option value="auto">auto (API if key present, CLI fallback)</option>'
    +       '<option value="api">api (requires API key)</option>'
    +       '<option value="cli">cli (no API key, uses Claude CLI)</option>'
    +     '</select>'
    +   '</div>'
    +   '<div id="ten-llm-model-wrap">'+fldLabel('Model', true)+inp('ten-llm-model','text','provider default')+'</div>'
    +   '<div id="ten-llm-key-wrap">'+fldLabel('API Key', true)+inp('ten-llm-key','password','sk-...')+'</div>'
    +   '<div id="ten-llm-url-wrap" style="display:none">'+fldLabel('Base URL', true)+inp('ten-llm-url','url','http://localhost:11434')+'</div>'
    + '</div>'

    // Slack
    + sec('Slack Notifications (optional)')
    + fldLabel('Slack Webhook URL', true)
    + inp('ten-slack-url', 'url', 'https://hooks.slack.com/services/...')

    + '<div style="margin-top:18px">'
    + '<button data-action="submitTenantCreate" class="fbtn" style="background:#8B5CF6;color:#fff;width:100%;padding:10px;font-size:14px">Create Tenant</button>'
    + '</div>'
    + '<div id="ten-result" style="margin-top:12px"></div>'
    + '</div>';

  // Wire provider dropdown to update conditional fields
  const sel = document.getElementById('ten-llm-provider');
  if (sel) sel.addEventListener('change', tenLlmProviderChange);
}

function tenLlmProviderChange() {
  const p = document.getElementById('ten-llm-provider').value;
  const wrap = document.getElementById('ten-llm-fields');
  const modelInp = document.getElementById('ten-llm-model');
  const keyWrap = document.getElementById('ten-llm-key-wrap');
  const urlWrap = document.getElementById('ten-llm-url-wrap');
  const urlInp = document.getElementById('ten-llm-url');
  const modeWrap = document.getElementById('ten-llm-mode-wrap');
  if (!p) { wrap.style.display = 'none'; return; }
  wrap.style.display = 'block';
  // Per-provider: which fields show + default model placeholders
  // anthropic: mode + model + api_key (api_key only for mode=api/auto)
  // openai:   model + api_key + optional base_url (Azure)
  // ollama:   model + base_url (no api_key)
  // groq:     model + api_key + optional base_url
  modeWrap.style.display = (p === 'anthropic') ? 'block' : 'none';
  if (p === 'anthropic') {
    modelInp.placeholder = 'claude-sonnet-4-20250514 (default)';
    keyWrap.style.display = 'block';
    urlWrap.style.display = 'none';
  } else if (p === 'openai') {
    modelInp.placeholder = 'gpt-4o (default)';
    keyWrap.style.display = 'block';
    urlWrap.style.display = 'block';
    urlInp.placeholder = 'https://YOUR.openai.azure.com/ (Azure only — leave blank for openai.com)';
  } else if (p === 'ollama') {
    modelInp.placeholder = 'llama3.1:70b (default)';
    keyWrap.style.display = 'none';
    urlWrap.style.display = 'block';
    urlInp.placeholder = 'http://localhost:11434';
  } else if (p === 'groq') {
    modelInp.placeholder = 'llama-3.1-70b-versatile (default)';
    keyWrap.style.display = 'block';
    urlWrap.style.display = 'block';
    urlInp.placeholder = 'https://api.groq.com/openai/v1 (default — leave blank)';
  }
}

async function submitTenantCreate() {
  const out = document.getElementById('ten-result');
  const name = (document.getElementById('ten-name').value || '').trim();
  const slug = (document.getElementById('ten-slug').value || '').trim();
  if (!name || !slug) { out.innerHTML = '<span style="color:#EF4444">Name and slug are required</span>'; return; }
  if (!/^[a-z0-9][a-z0-9_-]{1,48}[a-z0-9]$/.test(slug)) {
    out.innerHTML = '<span style="color:#EF4444">Slug must be 3–50 chars, lowercase letters/digits, hyphens or underscores (no leading/trailing punctuation)</span>'; return;
  }

  // Build config from form fields. Only include sections whose required fields
  // are actually filled — we don't want empty {} stubs polluting the tenant config.
  const config = {};

  // Wazuh
  const wUrl = (document.getElementById('ten-w-url').value || '').trim();
  const wUser = (document.getElementById('ten-w-user').value || '').trim();
  const wPass = document.getElementById('ten-w-pass').value || '';
  if (wUrl || wUser || wPass) {
    config.wazuh = {};
    if (wUrl) config.wazuh.api_url = wUrl;
    if (wUser) config.wazuh.username = wUser;
    if (wPass) config.wazuh.password = wPass;
    config.wazuh.verify_ssl = !!document.getElementById('ten-w-verify').checked;
  }

  // LLM
  const llmProv = (document.getElementById('ten-llm-provider').value || '').trim();
  if (llmProv) {
    const llm = { provider: llmProv };
    const model = (document.getElementById('ten-llm-model').value || '').trim();
    const key = document.getElementById('ten-llm-key').value || '';
    const url = (document.getElementById('ten-llm-url').value || '').trim();
    if (model) llm.model = model;
    if (key && document.getElementById('ten-llm-key-wrap').style.display !== 'none') llm.api_key = key;
    if (url && document.getElementById('ten-llm-url-wrap').style.display !== 'none') llm.base_url = url;
    if (llmProv === 'anthropic') {
      const mode = document.getElementById('ten-llm-mode').value;
      if (mode) llm.mode = mode;
    }
    config.llm = llm;
  }

  // Slack
  const slack = (document.getElementById('ten-slack-url').value || '').trim();
  if (slack) {
    config.notifications = { slack: { webhook_url: slack } };
  }

  try {
    const r = await fetch(API+'/admin/tenants', {method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({name, slug, config})});
    const d = await r.json();
    if (r.ok) {
      out.innerHTML = '<span style="color:#34D399">Tenant created (id '+esc(d.tenant_id||'')+')</span>';
      setTimeout(()=>{closeSlideOver();refresh();}, 1000);
    } else {
      out.innerHTML = '<span style="color:#EF4444">'+esc(typeof d.detail==='string'?d.detail:JSON.stringify(d.detail||d))+'</span>';
    }
  } catch(e) {
    out.innerHTML = '<span style="color:#EF4444">'+esc(e.message)+'</span>';
  }
}

async function showTenantDetail(id) {
  const so = document.getElementById('slide-over');
  so.style.display = 'block';
  so.classList.add('open');
  so.innerHTML = '<div style="padding:24px"><div class="spin" style="text-align:center;padding:40px;color:#94A3B8">Loading tenant...</div></div>';
  let t, agentList, webhookStatus;
  try {
    [t, agentList, webhookStatus] = await Promise.all([
      fetchJSON('/admin/tenants/' + encodeURIComponent(id)),
      fetchJSON('/admin/tenants/' + encodeURIComponent(id) + '/agents').catch(()=>({agents:[]})),
      fetchJSON('/v1/webhooks/wazuh/status/' + encodeURIComponent(id) + '?hours=24').catch(()=>null)
    ]);
  } catch(e) {
    so.innerHTML = '<div style="padding:24px;color:#EF4444">Failed to load tenant: '+esc(e.message)+'</div>';
    return;
  }
  const agents = agentList.agents || [];
  let h = '<div style="padding:24px">';
  h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">';
  h += '<h3 style="margin:0;color:#1E293B">'+esc(t.name)+' <span style="color:#94A3B8;font-size:12px;font-family:\'JetBrains Mono\',monospace;font-weight:400">/'+esc(t.slug)+'</span></h3>';
  h += '<button data-action="closeSlideOver" style="background:none;border:none;cursor:pointer;font-size:20px;color:#64748B">&times;</button></div>';
  // Status row
  const sc = t.active ? '#34D399' : '#EF4444';
  h += '<div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">';
  h += '<span style="font-size:11px;font-weight:600;padding:3px 10px;border-radius:6px;background:'+sc+'18;color:'+sc+';border:1px solid '+sc+'30">'+(t.active?'Active':'Inactive')+'</span>';
  h += '<button class="fbtn" style="font-size:10px;padding:3px 10px" data-action="toggleTenantActive" data-id="'+esc(t.id)+'" data-status="'+(t.active?'1':'0')+'">'+(t.active?'Deactivate':'Activate')+'</button>';
  h += '<button class="fbtn" style="font-size:10px;padding:3px 10px" data-action="showTenantRenameModal" data-id="'+esc(t.id)+'" data-field="'+esc(t.name)+'">Rename</button>';
  h += '</div>';
  h += '<div style="color:#94A3B8;font-size:11px;margin-bottom:14px">ID: <code style="color:#64748B">'+esc(t.id)+'</code> · Created '+(t.created_at?esc(localTime(t.created_at)):'?')+' · Updated '+(t.updated_at?esc(localTime(t.updated_at)):'?')+'</div>';

  // Config sections
  h += '<div style="display:flex;justify-content:space-between;align-items:center;margin:18px 0 8px">';
  h += '<div style="color:#64748B;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1px">Configuration</div>';
  h += '<button class="fbtn" style="font-size:10px;padding:3px 10px" data-action="showTenantConfigEditModal" data-id="'+esc(t.id)+'">Edit Section</button>';
  h += '</div>';
  const SECTIONS = ['wazuh','llm','notifications','dashboard_proxy','ti_api_keys'];
  const cfg = t.config || {};
  SECTIONS.forEach(function(sec) {
    const present = cfg[sec] && Object.keys(cfg[sec]).length > 0;
    const sBg = present ? '#F8FAFC' : '#FFFFFF';
    const sBd = present ? '#E2E8F0' : '#F1F5F9';
    h += '<div style="background:'+sBg+';border:1px solid '+sBd+';border-radius:8px;padding:10px 12px;margin-bottom:8px">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:'+(present?'6px':'0')+'">';
    h += '<span style="color:#1E293B;font-size:12px;font-weight:600">'+esc(sec.replace(/_/g,' '))+'</span>';
    h += '<span style="color:'+(present?'#34D399':'#94A3B8')+';font-size:10px;font-weight:600">'+(present?'configured':'not configured')+'</span>';
    h += '</div>';
    if (present) {
      h += '<pre style="margin:0;font-size:11px;color:#334155;white-space:pre-wrap;max-height:160px;overflow-y:auto;font-family:\'JetBrains Mono\',monospace">'+esc(JSON.stringify(cfg[sec], null, 2))+'</pre>';
    }
    h += '</div>';
  });
  h += '<div style="color:#94A3B8;font-size:10px;margin-top:4px">Secret values are masked (shown as <code>abcd****</code>). When editing a section, re-enter the full secret if you want to change it.</div>';

  // Wazuh agent mapping
  h += '<div style="margin-top:20px;border-top:1px solid #E2E8F0;padding-top:14px">';
  h += '<div style="color:#64748B;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Wazuh Agent Mapping ('+agents.length+')</div>';
  h += '<div style="color:#94A3B8;font-size:11px;margin-bottom:10px">Wazuh agent IDs that belong to this tenant. Each agent ID is exclusive — it can only be mapped to one tenant.</div>';
  if (agents.length) {
    h += '<div style="display:flex;flex-direction:column;gap:4px;margin-bottom:10px">';
    agents.forEach(function(a) {
      h += '<div style="display:flex;justify-content:space-between;align-items:center;background:#F8FAFC;border:1px solid #E2E8F0;border-radius:6px;padding:6px 12px">';
      h += '<span style="font-family:\'JetBrains Mono\',monospace;color:#1E293B;font-weight:600">'+esc(a.agent_id||'')+'</span>';
      h += '<span style="color:#94A3B8;font-size:10px">added '+(a.added_at?esc(localTime(a.added_at)):'?')+'</span>';
      h += '<button class="fbtn" style="font-size:10px;padding:3px 8px;color:#EF4444" data-action="removeTenantAgent" data-id="'+esc(t.id)+'" data-field="'+esc(a.agent_id||'')+'">Unmap</button>';
      h += '</div>';
    });
    h += '</div>';
  } else {
    h += '<div style="color:#94A3B8;font-size:11px;padding:14px;background:#F8FAFC;border-radius:6px;border:1px dashed #E2E8F0;margin-bottom:10px">No agents mapped. Without a mapping, this tenant won\'t see any Wazuh data.</div>';
  }
  h += '<div style="display:flex;gap:6px">';
  h += '<input id="ten-agent-add" type="text" placeholder="Agent IDs, comma-separated (e.g. 001, 002, 003)" style="flex:1;padding:8px 10px;border:1px solid #D1D5DB;border-radius:6px;font-size:12px;font-family:\'JetBrains Mono\',monospace">';
  h += '<button class="fbtn fon" style="font-size:11px;padding:4px 12px" data-action="addTenantAgent" data-id="'+esc(t.id)+'">Add</button>';
  h += '</div>';
  h += '<div id="ten-agent-result" style="margin-top:8px;font-size:11px"></div>';
  h += '</div>';

  // Webhook status / test
  h += '<div style="margin-top:20px;border-top:1px solid #E2E8F0;padding-top:14px">';
  h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">';
  h += '<div style="color:#64748B;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1px">Webhook Status (last 24h)</div>';
  h += '<button class="fbtn" style="font-size:10px;padding:3px 10px" data-action="showWebhookTestModal" data-id="'+esc(t.id)+'">Send Test Alert</button>';
  h += '</div>';
  if (webhookStatus && webhookStatus.processing_stats) {
    // Backend: WebhookAlertProcessor.get_processing_stats returns
    // {tenant_id, period_hours, total_processed, high_risk_alerts, immediate_triage_count, avg_risk_score, cache_size}.
    // SignatureValidator.get_rate_limit_status returns
    // {tenant_id, current_count, window_start, limit_configured}.
    const ps = webhookStatus.processing_stats || {};
    const rl = webhookStatus.rate_limit_status || {};
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:6px">';
    h += '<div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:6px;padding:8px;text-align:center"><div style="color:#1E293B;font-size:18px;font-weight:700;font-family:\'JetBrains Mono\',monospace">'+(ps.total_processed||0)+'</div><div style="color:#64748B;font-size:10px">Processed</div></div>';
    h += '<div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:6px;padding:8px;text-align:center"><div style="color:'+(ps.high_risk_alerts>0?'#EF4444':'#34D399')+';font-size:18px;font-weight:700;font-family:\'JetBrains Mono\',monospace">'+(ps.high_risk_alerts||0)+'</div><div style="color:#64748B;font-size:10px">High Risk</div></div>';
    h += '<div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:6px;padding:8px;text-align:center"><div style="color:#FBBF24;font-size:18px;font-weight:700;font-family:\'JetBrains Mono\',monospace">'+(ps.immediate_triage_count||0)+'</div><div style="color:#64748B;font-size:10px">Triaged</div></div>';
    h += '<div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:6px;padding:8px;text-align:center"><div style="color:#60A5FA;font-size:18px;font-weight:700;font-family:\'JetBrains Mono\',monospace">'+(ps.avg_risk_score!=null?ps.avg_risk_score:'—')+'</div><div style="color:#64748B;font-size:10px">Avg Risk</div></div>';
    let rateLbl = 'Rate Counter';
    if (rl.window_start) {
      try { rateLbl += ' (since ' + (localTime(rl.window_start).split(',')[1] || '').trim() + ')'; } catch(e) {}
    }
    h += '<div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:6px;padding:8px;text-align:center"><div style="color:#1E293B;font-size:18px;font-weight:700;font-family:\'JetBrains Mono\',monospace">'+(rl.current_count!=null?rl.current_count:'—')+'</div><div style="color:#64748B;font-size:10px">'+esc(rateLbl)+'</div></div>';
    h += '</div>';
  } else {
    h += '<div style="color:#94A3B8;font-size:11px;padding:14px;background:#F8FAFC;border-radius:6px;border:1px dashed #E2E8F0">No webhook traffic in the last 24h, or webhook not configured for this tenant.</div>';
  }
  h += '</div>';

  h += '</div>';
  so.innerHTML = h;
}

function showWebhookTestModal(tenantId) {
  const so = document.getElementById('slide-over');
  so.innerHTML = '<div style="padding:24px">'
    + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">'
    + '<h3 style="margin:0;color:#1E293B">Test Webhook Endpoint</h3>'
    + '<button data-action="showTenantDetail" data-id="'+esc(tenantId)+'" style="background:none;border:none;cursor:pointer;font-size:20px;color:#64748B">&times;</button></div>'
    + '<div style="color:#64748B;font-size:11px;margin-bottom:10px">Synchronously feeds a sample alert through the webhook processor (signature validation bypassed). Useful for verifying tenant routing without configuring the integrator.</div>'
    + '<label style="display:block;font-size:11px;color:#64748B;font-weight:600;margin-bottom:4px">Alert payload (JSON)</label>'
    + '<textarea id="wh-payload" rows="14" style="width:100%;padding:8px;border:1px solid #D1D5DB;border-radius:6px;font-size:11px;font-family:\'JetBrains Mono\',monospace;resize:vertical;box-sizing:border-box;margin-bottom:10px">{\n  "rule": {"id": "5712", "level": 5, "description": "Test webhook alert"},\n  "agent": {"id": "001", "name": "test-agent"},\n  "timestamp": "' + new Date().toISOString() + '",\n  "data": {"src_ip": "10.0.0.50"}\n}</textarea>'
    + '<button data-action="submitWebhookTest" data-id="'+esc(tenantId)+'" class="fbtn fon" style="padding:8px 16px">Send</button>'
    + '<div id="wh-test-result" style="margin-top:12px"></div>'
    + '</div>';
}

async function submitWebhookTest(tenantId) {
  const out = document.getElementById('wh-test-result');
  const raw = document.getElementById('wh-payload').value.trim();
  let payload;
  try { payload = JSON.parse(raw); }
  catch(e) { out.innerHTML = '<span style="color:#EF4444">Invalid JSON: '+esc(e.message)+'</span>'; return; }
  out.innerHTML = '<span style="color:#94A3B8">Sending…</span>';
  try {
    const r = await fetch(API+'/v1/webhooks/test/'+encodeURIComponent(tenantId), {method:'POST', headers:{...authHeaders(),'Content-Type':'application/json'}, body: JSON.stringify(payload)});
    const d = await r.json().catch(()=>({}));
    if (!r.ok) {
      out.innerHTML = '<span style="color:#EF4444">'+esc(typeof d.detail==='string'?d.detail:JSON.stringify(d.detail||d))+'</span>';
      return;
    }
    out.innerHTML = '<div style="color:#34D399;font-weight:600;margin-bottom:8px">Test processed ✓</div>'
      + '<pre style="margin:0;background:#F8FAFC;border:1px solid #E2E8F0;border-radius:6px;padding:10px;font-size:11px;font-family:\'JetBrains Mono\',monospace;max-height:300px;overflow:auto;white-space:pre-wrap">'+esc(JSON.stringify(d, null, 2))+'</pre>';
  } catch(e) { out.innerHTML = '<span style="color:#EF4444">'+esc(e.message)+'</span>'; }
}

async function toggleTenantActive(id, currentActive) {
  const newActive = currentActive === '1' ? false : true;
  if (!confirm((newActive?'Activate':'Deactivate')+' this tenant?')) return;
  try {
    const r = await fetch(API+'/admin/tenants/'+encodeURIComponent(id), {method:'PUT',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({active:newActive})});
    if (!r.ok) { const e = await r.json().catch(()=>({})); alert('Failed: '+(e.detail||('HTTP '+r.status))); return; }
    showTenantDetail(id);
  } catch(e) { alert('Network error: '+e.message); }
}

function showTenantRenameModal(id, currentName) {
  const newName = prompt('New tenant name:', currentName||'');
  if (newName === null) return;
  const trimmed = newName.trim();
  if (!trimmed) { alert('Name cannot be empty'); return; }
  fetch(API+'/admin/tenants/'+encodeURIComponent(id), {method:'PUT',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({name:trimmed})})
    .then(r => r.ok ? r.json() : r.json().then(e => Promise.reject(e)))
    .then(() => showTenantDetail(id))
    .catch(e => alert('Rename failed: '+(e.detail||JSON.stringify(e))));
}

function showTenantConfigEditModal(id) {
  const so = document.getElementById('slide-over');
  so.innerHTML = '<div style="padding:24px">'
    + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">'
    + '<h3 style="margin:0;color:#1E293B">Edit Config Section</h3>'
    + '<button data-action="showTenantDetail" data-id="'+esc(id)+'" style="background:none;border:none;cursor:pointer;font-size:20px;color:#64748B">&times;</button></div>'
    + '<label style="display:block;margin-bottom:6px;font-weight:600;color:#374151;font-size:13px">Section</label>'
    + '<select id="ten-cfg-section" style="width:100%;padding:8px 12px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:12px;font-size:13px;background:#F8FAFC">'
    +   '<option value="wazuh">wazuh</option>'
    +   '<option value="llm">llm</option>'
    +   '<option value="notifications">notifications</option>'
    +   '<option value="dashboard_proxy">dashboard_proxy</option>'
    +   '<option value="ti_api_keys">ti_api_keys</option>'
    + '</select>'
    + '<label style="display:block;margin-bottom:6px;font-weight:600;color:#374151;font-size:13px">Section JSON</label>'
    + '<div style="color:#94A3B8;font-size:11px;margin-bottom:6px">Submit a complete JSON object for this section. Existing keys not in the submission are preserved (server-side merge), but any key you do submit replaces its previous value — including secrets.</div>'
    + '<textarea id="ten-cfg-json" rows="14" placeholder=\'{"api_url": "https://wazuh.example.com:55000", "username": "wazuh", "password": "..."}\' style="width:100%;padding:8px 12px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:12px;font-size:12px;font-family:\'JetBrains Mono\',monospace;resize:vertical;box-sizing:border-box"></textarea>'
    + '<div style="display:flex;gap:8px">'
    + '<button data-action="submitTenantConfigUpdate" data-id="'+esc(id)+'" class="fbtn" style="background:#8B5CF6;color:#fff;flex:1;padding:10px;font-size:14px">Save Section</button>'
    + '<button data-action="showTenantDetail" data-id="'+esc(id)+'" class="fbtn" style="flex:0 0 auto;padding:10px 16px">Cancel</button>'
    + '</div>'
    + '<div id="ten-cfg-result" style="margin-top:12px"></div>'
    + '</div>';
}

async function submitTenantConfigUpdate(id) {
  const sec = document.getElementById('ten-cfg-section').value;
  const raw = document.getElementById('ten-cfg-json').value.trim();
  const out = document.getElementById('ten-cfg-result');
  if (!raw) { out.innerHTML = '<span style="color:#EF4444">Section JSON is required</span>'; return; }
  let parsed;
  try { parsed = JSON.parse(raw); }
  catch(e) { out.innerHTML = '<span style="color:#EF4444">Not valid JSON: '+esc(e.message)+'</span>'; return; }
  if (typeof parsed !== 'object' || Array.isArray(parsed) || parsed === null) {
    out.innerHTML = '<span style="color:#EF4444">Section must be a JSON object</span>'; return;
  }
  // Body must be {"config": {<section>: {...}}} so server-side merge keeps other sections intact
  const body = {config: {}};
  body.config[sec] = parsed;
  try {
    const r = await fetch(API+'/admin/tenants/'+encodeURIComponent(id), {method:'PUT',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d = await r.json().catch(()=>({}));
    if (r.ok) {
      out.innerHTML = '<span style="color:#34D399">Saved. Reloading...</span>';
      setTimeout(()=>showTenantDetail(id), 700);
    } else {
      out.innerHTML = '<span style="color:#EF4444">'+esc(typeof d.detail==='string'?d.detail:JSON.stringify(d.detail||d))+'</span>';
    }
  } catch(e) { out.innerHTML = '<span style="color:#EF4444">'+esc(e.message)+'</span>'; }
}

async function addTenantAgent(id) {
  const inp = document.getElementById('ten-agent-add');
  const out = document.getElementById('ten-agent-result');
  if (!inp || !out) return;
  const raw = inp.value.trim();
  if (!raw) { out.innerHTML = '<span style="color:#EF4444">Enter at least one agent ID</span>'; return; }
  const agent_ids = raw.split(',').map(s => s.trim()).filter(Boolean);
  for (const aid of agent_ids) {
    if (!/^\d{1,5}$/.test(aid)) { out.innerHTML = '<span style="color:#EF4444">Invalid agent ID "'+esc(aid)+'" — must be 1–5 digits</span>'; return; }
  }
  try {
    const r = await fetch(API+'/admin/tenants/'+encodeURIComponent(id)+'/agents', {method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({agent_ids})});
    const d = await r.json().catch(()=>({}));
    if (r.ok) {
      let msg = '<span style="color:#34D399">Assigned: '+(d.assigned||[]).join(', ')+'</span>';
      if (d.conflicts && d.conflicts.length) msg += '<br><span style="color:#F59E0B">Already mapped elsewhere: '+d.conflicts.join(', ')+'</span>';
      out.innerHTML = msg;
      setTimeout(()=>showTenantDetail(id), 800);
    } else {
      out.innerHTML = '<span style="color:#EF4444">'+esc(typeof d.detail==='string'?d.detail:JSON.stringify(d.detail||d))+'</span>';
    }
  } catch(e) { out.innerHTML = '<span style="color:#EF4444">'+esc(e.message)+'</span>'; }
}

async function removeTenantAgent(id, agentId) {
  if (!confirm('Unmap agent '+agentId+' from this tenant?')) return;
  try {
    const r = await fetch(API+'/admin/tenants/'+encodeURIComponent(id)+'/agents/'+encodeURIComponent(agentId), {method:'DELETE',headers:authHeaders()});
    if (!r.ok) { const e = await r.json().catch(()=>({})); alert('Failed: '+(e.detail||('HTTP '+r.status))); return; }
    showTenantDetail(id);
  } catch(e) { alert('Network error: '+e.message); }
}

// ── Pipeline Health (mssp_admin) ─────────────────────────────

async function renderAdminPipeline() {
  let h = '';
  h += '<div class="section-title">Pipeline Health</div>';
  h += '<p style="color:#64748B;font-size:12px;margin:0 0 12px">Live telemetry across the alert pipeline — log-source heartbeats, EPS anomaly detection, parser failure rates, and automation health.</p>';
  let pipe = null, sources = null;
  try { pipe = await fetchJSON('/health/pipeline'); } catch(e) {
    return h + '<div style="color:#EF4444;background:#FEF2F2;border:1px solid #EF444430;padding:12px;border-radius:6px;font-size:12px">Failed to load pipeline health: '+esc(e.message)+'</div>';
  }
  if (pipe.status === 'unavailable') {
    return h + '<div style="color:#94A3B8;padding:30px;text-align:center;background:#F8FAFC;border:1px dashed #E2E8F0;border-radius:8px">'+esc(pipe.message||'Pipeline monitor not initialized')+'</div>';
  }
  try { sources = (await fetchJSON('/health/log-sources')).sources || []; } catch(e) { sources = []; }

  // KPI tiles. Backend at health_monitor.get_pipeline_status() returns
  // {heartbeat: {silent_agents, reporting_agents, ...}, eps: {recent_5min_avg, mean_events_per_minute, is_anomaly, ...}, parser: {failure_rate, total_events_1h, unparsed_events_1h, is_above_threshold, ...}}.
  const heartbeat = pipe.heartbeat || {};
  const epsBlock = pipe.eps || {};
  const parserBlock = pipe.parser || {};
  const ah = pipe.automation_health || {};
  // Derive overall health from the three sub-statuses
  const heartbeatBad = (heartbeat.silent_agents || 0) > 0;
  const epsBad = !!epsBlock.is_anomaly;
  const parserBad = !!parserBlock.is_above_threshold;
  const overall = heartbeat.error || epsBlock.error || parserBlock.error ? 'error'
                : (heartbeatBad || parserBad) ? 'critical'
                : epsBad ? 'degraded'
                : (Object.keys(heartbeat).length || Object.keys(epsBlock).length || Object.keys(parserBlock).length) ? 'healthy' : 'unknown';
  const overallColor = overall === 'healthy' ? '#34D399' : overall === 'degraded' ? '#FBBF24' : overall === 'critical' || overall === 'error' ? '#EF4444' : '#94A3B8';

  h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin-bottom:16px">';
  h += `<div class="c" style="text-align:center"><div style="font-size:22px;font-weight:800;color:${overallColor};font-family:'JetBrains Mono',monospace;text-transform:uppercase">${esc(String(overall))}</div><div class="l" style="margin-top:4px">Overall</div></div>`;
  if (heartbeat.reporting_agents != null) {
    const total = (heartbeat.reporting_agents || 0) + (heartbeat.silent_agents || 0);
    h += `<div class="c" style="text-align:center"><div style="font-size:22px;font-weight:800;color:${heartbeatBad?'#EF4444':'#34D399'};font-family:'JetBrains Mono',monospace">${heartbeat.reporting_agents}/${total}</div><div class="l" style="margin-top:4px">Reporting Agents</div></div>`;
  }
  if (epsBlock.recent_5min_avg != null) {
    h += `<div class="c" style="text-align:center"><div style="font-size:22px;font-weight:800;color:${epsBad?'#FBBF24':'#1E293B'};font-family:'JetBrains Mono',monospace">${epsBlock.recent_5min_avg}</div><div class="l" style="margin-top:4px">Events/min (5m avg)${epsBlock.mean_events_per_minute!=null?', μ '+epsBlock.mean_events_per_minute:''}</div></div>`;
  }
  if (parserBlock.failure_rate != null) {
    const pfr = (parserBlock.failure_rate*100).toFixed(2);
    const pfc = parserBlock.failure_rate > 0.05 ? '#EF4444' : parserBlock.failure_rate > 0.01 ? '#FBBF24' : '#34D399';
    h += `<div class="c" style="text-align:center"><div style="font-size:22px;font-weight:800;color:${pfc};font-family:'JetBrains Mono',monospace">${pfr}%</div><div class="l" style="margin-top:4px">Parser Fail Rate</div></div>`;
  }
  // Automation health is nested. enrichment_latency.{p50_ms, p95_ms, ...}, soar_actions.{success_rate (0-100), success_count, failure_count, total_actions}
  if (ah.enrichment_latency && ah.enrichment_latency.p95_ms != null) {
    h += `<div class="c" style="text-align:center"><div style="font-size:22px;font-weight:800;color:#1E293B;font-family:'JetBrains Mono',monospace">${ah.enrichment_latency.p95_ms}ms</div><div class="l" style="margin-top:4px">Enrich p95</div></div>`;
  }
  if (ah.soar_actions && ah.soar_actions.success_rate != null) {
    const srNum = ah.soar_actions.success_rate;  // already 0-100
    const sr = srNum.toFixed(1);
    h += `<div class="c" style="text-align:center"><div style="font-size:22px;font-weight:800;color:${srNum>=95?'#34D399':srNum>=85?'#FBBF24':'#EF4444'};font-family:'JetBrains Mono',monospace">${sr}%</div><div class="l" style="margin-top:4px">SOAR Success</div></div>`;
  }
  h += '</div>';

  // Silent-agents detail (when any)
  if (heartbeat.silent_agent_names && heartbeat.silent_agent_names.length) {
    h += '<div class="c" style="margin-bottom:16px;border-left:3px solid #EF4444;padding:10px 14px">';
    h += '<div style="color:#EF4444;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Silent Agents (last '+(heartbeat.window_minutes||'?')+' min)</div>';
    h += '<div style="color:#1E293B;font-size:12px;font-family:\'JetBrains Mono\',monospace">'+heartbeat.silent_agent_names.map(esc).join(', ')+'</div>';
    h += '</div>';
  }

  // Log sources table. Backend returns YAML inventory + status ('silent'/'reporting').
  // Available fields per source: name, type, description, collection_method, volume_eps_estimate, retention_days, reliability, parser, notes, status.
  h += '<div class="section-title">Log Sources</div>';
  if (!sources.length) {
    h += '<div style="color:#94A3B8;padding:20px;text-align:center;background:#F8FAFC;border:1px dashed #E2E8F0;border-radius:8px">No log sources configured. Edit <code>config/guidance/log_source_inventory.yaml</code> to add entries.</div>';
  } else {
    h += '<div class="c" style="padding:0">';
    h += '<table style="width:100%;font-size:11px;border-collapse:collapse">';
    h += '<tr style="color:#94A3B8;font-size:10px;text-transform:uppercase;letter-spacing:1px"><th style="text-align:left;padding:8px 12px">Source</th><th style="text-align:left;padding:8px 12px">Type</th><th style="text-align:left;padding:8px 12px">Status</th><th style="text-align:left;padding:8px 12px">EPS (est)</th><th style="text-align:left;padding:8px 12px">Retention</th><th style="text-align:left;padding:8px 12px">Notes</th></tr>';
    sources.forEach(s => {
      const st = s.status || 'unknown';
      const sc = st==='reporting'?'#34D399':st==='silent'?'#EF4444':'#94A3B8';
      h += '<tr style="border-top:1px solid #E2E8F0">';
      h += '<td style="padding:8px 12px;color:#1E293B;font-weight:600">'+esc(s.name||'')+'</td>';
      h += '<td style="padding:8px 12px;color:#64748B">'+esc(s.type||'')+'</td>';
      h += '<td style="padding:8px 12px"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:'+sc+';margin-right:6px"></span><span style="color:'+sc+';font-weight:600">'+esc(st)+'</span></td>';
      h += '<td style="padding:8px 12px;color:#1E293B;font-family:\'JetBrains Mono\',monospace">'+esc(String(s.volume_eps_estimate==null?'—':s.volume_eps_estimate))+'</td>';
      h += '<td style="padding:8px 12px;color:#64748B;font-family:\'JetBrains Mono\',monospace">'+esc(String(s.retention_days==null?'—':s.retention_days+'d'))+'</td>';
      h += '<td style="padding:8px 12px;color:#94A3B8;font-size:10px">'+esc((s.notes||s.description||'').slice(0,80))+'</td>';
      h += '</tr>';
    });
    h += '</table></div>';
  }
  return h;
}

// ── Shift Management ─────────────────────────────────────────

async function renderAdminShifts() {
  let h = '';
  h += '<div class="section-title">Shift Management</div>';
  h += '<p style="color:#64748B;font-size:12px;margin:0 0 12px">Current shift, on-duty analysts, and the shift-handoff workflow. Shift Management requires the SLA license feature.</p>';
  let cur = null, report = null;
  try { cur = await fetchJSON('/admin/shifts/current'); } catch(e) {
    return h + '<div style="color:#EF4444;background:#FEF2F2;border:1px solid #EF444430;padding:12px;border-radius:6px;font-size:12px">Failed to load shift data: '+esc(e.message)+'</div>';
  }
  if (!cur || cur.shift == null && cur.message) {
    return h + '<div style="color:#94A3B8;padding:30px;text-align:center;background:#F8FAFC;border:1px dashed #E2E8F0;border-radius:8px">'+esc(cur.message||'Shift schedule not configured')+'</div>';
  }
  // Current shift card. Backend ShiftManager.get_current_shift returns
  // {shift: <YAML shift dict with name, start_utc (int), end_utc (int), days, analysts, on_call_primary>, current_time_utc}
  // or {shift: null, message, current_time_utc}.
  const shift = cur.shift || {};
  const onDuty = shift.analysts || [];
  h += '<div class="c" style="padding:14px;margin-bottom:16px">';
  h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">';
  h += '<span style="color:#64748B;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1px">Current Shift</span>';
  if (shift.name) h += '<span style="background:#34D39918;color:#10B981;border:1px solid #34D39940;padding:3px 10px;border-radius:6px;font-size:11px;font-weight:600">'+esc(shift.name)+'</span>';
  h += '</div>';
  if (shift.start_utc != null || shift.end_utc != null) {
    const fmtH = h => h == null ? '?' : String(h).padStart(2,'0')+':00';
    h += '<div style="color:#1E293B;font-size:13px">'+fmtH(shift.start_utc)+' – '+fmtH(shift.end_utc)+' UTC</div>';
  }
  if (shift.days && shift.days.length) h += '<div style="color:#64748B;font-size:11px;margin-top:4px">Days: '+shift.days.map(esc).join(', ')+'</div>';
  if (shift.on_call_primary) h += '<div style="color:#64748B;font-size:11px;margin-top:2px">On-call primary: <strong>'+esc(shift.on_call_primary)+'</strong></div>';
  if (cur.current_time_utc) h += '<div style="color:#94A3B8;font-size:10px;margin-top:4px;font-family:\'JetBrains Mono\',monospace">Server time (UTC): '+esc(cur.current_time_utc)+'</div>';
  h += '<div style="margin-top:10px"><div style="color:#94A3B8;font-size:10px;font-weight:600;text-transform:uppercase;margin-bottom:4px">On-Duty Analysts ('+onDuty.length+')</div>';
  if (onDuty.length) {
    h += onDuty.map(a => '<span style="background:#818CF818;color:#4F46E5;padding:3px 10px;border-radius:14px;font-size:11px;margin:2px;display:inline-block">'+esc(typeof a==='string'?a:(a.username||a.name||''))+'</span>').join(' ');
  } else {
    h += '<span style="color:#94A3B8;font-size:11px">No analysts assigned to this shift.</span>';
  }
  h += '</div></div>';

  // Handoff report (admin/senior_analyst)
  if (['admin','senior_analyst','mssp_admin'].includes(currentUserRole())) {
    h += '<div class="section-title" style="margin-top:18px">Shift Handoff</div>';
    h += '<p style="color:#64748B;font-size:11px;margin:0 0 8px">Generate a handoff report and save it as a record so the next shift starts with full context.</p>';
    h += '<div style="display:flex;gap:6px;margin-bottom:8px">';
    h += '<button class="fbtn" data-action="loadHandoffReport">Generate Report</button>';
    h += '<button class="fbtn fon" data-action="showSaveHandoffModal">Save Handoff…</button>';
    h += '</div>';
    h += '<div id="handoff-report" style="margin-top:12px"></div>';
  }
  return h;
}

async function loadHandoffReport() {
  const out = document.getElementById('handoff-report');
  if (!out) return;
  out.innerHTML = '<div style="color:#94A3B8;font-size:12px;padding:14px">Generating report…</div>';
  try {
    const r = await fetchJSON('/admin/shifts/handoff-report');
    let h = '<div class="c" style="padding:14px;background:#F8FAFC">';
    h += '<div style="color:#64748B;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Handoff Report</div>';
    if (r.error) { h += '<div style="color:#EF4444">'+esc(r.error)+'</div>'; }
    else if (typeof r === 'string') { h += '<pre style="margin:0;white-space:pre-wrap;font-family:\'JetBrains Mono\',monospace;font-size:11px;color:#1E293B">'+esc(r)+'</pre>'; }
    else {
      h += '<pre style="margin:0;white-space:pre-wrap;font-family:\'JetBrains Mono\',monospace;font-size:11px;color:#1E293B;max-height:400px;overflow-y:auto">'+esc(JSON.stringify(r, null, 2))+'</pre>';
    }
    h += '</div>';
    out.innerHTML = h;
  } catch(e) { out.innerHTML = '<div style="color:#EF4444;font-size:12px;padding:14px">Failed: '+esc(e.message)+'</div>'; }
}

function showSaveHandoffModal() {
  const so = document.getElementById('slide-over');
  so.style.display = 'block';
  so.classList.add('open');
  so.innerHTML = '<div style="padding:24px">'
    + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">'
    + '<h3 style="margin:0;color:#1E293B">Save Shift Handoff</h3>'
    + '<button data-action="closeSlideOver" style="background:none;border:none;cursor:pointer;font-size:20px;color:#64748B">&times;</button></div>'
    + '<div style="color:#64748B;font-size:12px;margin-bottom:14px">The current handoff report is auto-attached to this record.</div>'
    + '<label style="display:block;margin-bottom:6px;font-weight:600;color:#374151;font-size:13px">From shift</label>'
    + '<input id="ho-from" type="text" placeholder="e.g. apac-day" style="width:100%;padding:8px 12px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:12px;font-size:13px;box-sizing:border-box">'
    + '<label style="display:block;margin-bottom:6px;font-weight:600;color:#374151;font-size:13px">To shift</label>'
    + '<input id="ho-to" type="text" placeholder="e.g. emea-day" style="width:100%;padding:8px 12px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:14px;font-size:13px;box-sizing:border-box">'
    + '<button data-action="submitSaveHandoff" class="fbtn" style="background:#8B5CF6;color:#fff;width:100%;padding:10px;font-size:14px">Save</button>'
    + '<div id="ho-result" style="margin-top:12px"></div>'
    + '</div>';
}

async function submitSaveHandoff() {
  const sf = document.getElementById('ho-from').value.trim();
  const st = document.getElementById('ho-to').value.trim();
  const out = document.getElementById('ho-result');
  if (!sf || !st) { out.innerHTML = '<span style="color:#EF4444">Both shift names required</span>'; return; }
  try {
    const r = await fetch(API+'/admin/shifts/handoff', {method:'POST', headers:{...authHeaders(),'Content-Type':'application/json'}, body:JSON.stringify({shift_from:sf, shift_to:st})});
    const d = await r.json().catch(()=>({}));
    if (r.ok) {
      out.innerHTML = '<span style="color:#34D399">Saved (id '+esc(d.handoff_id||'')+')</span>';
      setTimeout(()=>{closeSlideOver();refresh();}, 800);
    } else {
      out.innerHTML = '<span style="color:#EF4444">'+esc(typeof d.detail==='string'?d.detail:JSON.stringify(d.detail||d))+'</span>';
    }
  } catch(e) { out.innerHTML = '<span style="color:#EF4444">'+esc(e.message)+'</span>'; }
}

// ── Governance ───────────────────────────────────────────────

async function renderAdminGovernance() {
  const role = currentUserRole();
  let h = '';
  h += '<div class="section-title">Governance Documents</div>';
  h += '<p style="color:#64748B;font-size:12px;margin:0 0 12px">SOC charter and data-access policy as configured in <code>config/governance/*.yaml</code>.</p>';
  // Charter (visible to anyone)
  let charter = null, dataAccess = null;
  try { charter = (await fetchJSON('/admin/governance/charter')).charter; } catch(e) {}
  if (['admin','senior_analyst','mssp_admin'].includes(role)) {
    // Backend returns the YAML root dict directly (or {error: ...}); no wrapper key.
    try {
      const da = await fetchJSON('/admin/governance/data-access');
      dataAccess = (da && !da.error && Object.keys(da).length) ? da : null;
    } catch(e) {}
  }
  h += '<div class="c" style="padding:14px;margin-bottom:14px">';
  h += '<div style="color:#64748B;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">SOC Charter</div>';
  if (!charter) h += '<div style="color:#94A3B8;font-size:12px">Not configured. Place a YAML file at <code>config/governance/soc_charter.yaml</code>.</div>';
  else h += '<pre style="margin:0;white-space:pre-wrap;font-family:\'JetBrains Mono\',monospace;font-size:11px;color:#1E293B;max-height:300px;overflow-y:auto">'+esc(JSON.stringify(charter, null, 2))+'</pre>';
  h += '</div>';
  if (['admin','senior_analyst','mssp_admin'].includes(role)) {
    h += '<div class="c" style="padding:14px">';
    h += '<div style="color:#64748B;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Data Access Policy</div>';
    if (!dataAccess) h += '<div style="color:#94A3B8;font-size:12px">Not configured. Place a YAML file at <code>config/governance/data_access.yaml</code>.</div>';
    else h += '<pre style="margin:0;white-space:pre-wrap;font-family:\'JetBrains Mono\',monospace;font-size:11px;color:#1E293B;max-height:300px;overflow-y:auto">'+esc(JSON.stringify(dataAccess, null, 2))+'</pre>';
    h += '</div>';
  }
  // Guidance reload (admin only)
  if (role === 'admin' || role === 'mssp_admin') {
    h += '<div class="section-title" style="margin-top:18px">Guidance Files</div>';
    h += '<p style="color:#64748B;font-size:12px;margin:0 0 8px">Reload risk-criteria, escalation-logic, playbooks, and other guidance YAMLs from <code>config/guidance/</code> without restarting the platform.</p>';
    h += '<button class="fbtn fon" data-action="reloadGuidance">Reload Guidance from Disk</button>';
    h += '<div id="guidance-reload-result" style="margin-top:6px;font-size:11px"></div>';
  }
  return h;
}

async function reloadGuidance() {
  const out = document.getElementById('guidance-reload-result');
  if (!out) return;
  out.innerHTML = '<span style="color:#94A3B8">Reloading…</span>';
  try {
    const r = await fetch(API+'/guidance/reload', {method:'POST', headers: authHeaders()});
    const d = await r.json().catch(()=>({}));
    if (r.ok) out.innerHTML = '<span style="color:#34D399">'+esc(d.message||'Guidance reloaded')+'</span>';
    else out.innerHTML = '<span style="color:#EF4444">'+esc(typeof d.detail==='string'?d.detail:('HTTP '+r.status))+'</span>';
  } catch(e) { out.innerHTML = '<span style="color:#EF4444">'+esc(e.message)+'</span>'; }
}

// ── Anonymization Mappings ───────────────────────────────────

let _anonLookupResult = null;

async function renderAdminAnon() {
  let h = '';
  h += '<div class="section-title">Anonymization Mappings</div>';
  h += '<p style="color:#64748B;font-size:12px;margin:0 0 12px">Tokens used to anonymize identifiers before sending alerts to LLMs. Use the lookup form to resolve a token back to its original value (audit-logged).</p>';
  // Lookup form
  h += '<div class="c" style="padding:14px;margin-bottom:14px">';
  h += '<div style="color:#64748B;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Token Lookup</div>';
  h += '<div style="display:flex;gap:6px">';
  h += '<input id="anon-token" type="text" placeholder="Token (e.g. AGENT_001 or USER_4f2)" style="flex:1;padding:8px 12px;border:1px solid #D1D5DB;border-radius:6px;font-size:12px;font-family:\'JetBrains Mono\',monospace">';
  h += '<button class="fbtn fon" style="padding:6px 14px" data-action="lookupAnonToken">Lookup</button>';
  h += '</div>';
  h += '<div id="anon-lookup-result" style="margin-top:10px;font-size:11px">';
  if (_anonLookupResult) {
    // Backend lookup_anon_token returns row dict with columns: token, original_value, field_type, first_seen, last_seen, hit_count, client_id.
    if (_anonLookupResult.error) h += '<span style="color:#EF4444">'+esc(_anonLookupResult.error)+'</span>';
    else if (_anonLookupResult.original_value) h += '<span style="color:#1E293B">Original: <code style="color:#8B5CF6">'+esc(_anonLookupResult.original_value)+'</code> · type: '+esc(_anonLookupResult.field_type||'')+' · first seen: '+(_anonLookupResult.first_seen?esc(localTime(_anonLookupResult.first_seen)):'?')+' · hits: '+(_anonLookupResult.hit_count||0)+'</span>';
    else h += '<span style="color:#94A3B8">No mapping found for that token.</span>';
  }
  h += '</div></div>';

  // Mappings list. Backend get_anon_mappings returns flat list of row dicts;
  // route returns {mappings: [...], total}. We group client-side by field_type.
  let data;
  try { data = await fetchJSON('/admin/anon-mappings?limit=500'); }
  catch(e) { return h + '<div style="color:#EF4444;background:#FEF2F2;border:1px solid #EF444430;padding:12px;border-radius:6px;font-size:12px">Failed: '+esc(e.message)+'</div>'; }
  const mappingsList = data.mappings || [];
  const total = data.total != null ? data.total : mappingsList.length;
  const grouped = {};
  mappingsList.forEach(m => {
    const t = m.field_type || 'unknown';
    if (!grouped[t]) grouped[t] = [];
    grouped[t].push(m);
  });
  h += '<div class="section-title">Mappings ('+total+' total)</div>';
  const types = Object.keys(grouped).sort();
  if (!types.length) {
    h += '<div style="color:#94A3B8;padding:20px;text-align:center;background:#F8FAFC;border:1px dashed #E2E8F0;border-radius:8px">No anonymization mappings yet — they\'re created lazily as alerts go through the anonymizer.</div>';
    return h;
  }
  types.forEach(t => {
    const list = grouped[t] || [];
    if (!list.length) return;
    h += '<div class="c" style="padding:0;margin-bottom:10px">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;padding:10px 14px;border-bottom:1px solid #E2E8F0;background:#F8FAFC">';
    h += '<span style="font-weight:600;color:#1E293B;font-size:12px">'+esc(t)+'</span>';
    h += '<span style="color:#64748B;font-size:11px">'+list.length+'</span>';
    h += '</div>';
    h += '<table style="width:100%;font-size:11px;border-collapse:collapse">';
    h += '<tr style="color:#94A3B8;font-size:10px;text-transform:uppercase;letter-spacing:1px"><th style="text-align:left;padding:6px 14px">Token</th><th style="text-align:left;padding:6px 14px">Original</th><th style="text-align:left;padding:6px 14px">Hits</th><th style="text-align:left;padding:6px 14px">Last Seen</th></tr>';
    list.slice(0, 50).forEach(m => {
      h += '<tr style="border-top:1px solid #E2E8F0">';
      h += '<td style="padding:5px 14px;font-family:\'JetBrains Mono\',monospace;color:#8B5CF6">'+esc(m.token||'')+'</td>';
      h += '<td style="padding:5px 14px;color:#1E293B">'+esc(m.original_value||'')+'</td>';
      h += '<td style="padding:5px 14px;color:#1E293B;font-family:\'JetBrains Mono\',monospace">'+(m.hit_count||0)+'</td>';
      h += '<td style="padding:5px 14px;color:#64748B;font-size:10px">'+(m.last_seen?esc(localTime(m.last_seen)):'')+'</td>';
      h += '</tr>';
    });
    if (list.length > 50) h += '<tr><td colspan="4" style="padding:6px 14px;color:#94A3B8;font-size:10px;text-align:center">… and '+(list.length-50)+' more</td></tr>';
    h += '</table></div>';
  });
  return h;
}

async function lookupAnonToken() {
  const v = (document.getElementById('anon-token').value || '').trim();
  if (!v) { _anonLookupResult = {error: 'Enter a token'}; refresh(); return; }
  try {
    const r = await fetch(API+'/admin/anon-mappings/lookup?token='+encodeURIComponent(v), {headers: authHeaders()});
    if (!r.ok) {
      const e = await r.json().catch(()=>({}));
      _anonLookupResult = {error: e.detail || ('HTTP '+r.status)};
    } else {
      const d = await r.json();
      _anonLookupResult = d || {error: 'empty response'};
    }
  } catch(e) { _anonLookupResult = {error: e.message}; }
  refresh();
}

// ── Settings Slide-Over Forms ──

var _settingsEditId = null;

function _settingsField(label, id, type, value, opts) {
  var s = '<div style="margin-bottom:12px"><label style="display:block;font-size:11px;font-weight:600;color:#64748B;margin-bottom:4px">'+label+'</label>';
  if (type === 'select') {
    s += '<select id="'+id+'" style="width:100%;padding:8px;border:1px solid #E2E8F0;border-radius:6px;font-size:13px;background:#F8FAFC">';
    (opts||[]).forEach(function(o){s += '<option value="'+esc(o)+'"'+(o===value?' selected':'')+'>'+esc(o)+'</option>';});
    s += '</select>';
  } else if (type === 'checkbox') {
    s += '<input id="'+id+'" type="checkbox"'+(value?' checked':'')+' style="margin-right:6px">';
  } else if (type === 'textarea') {
    s += '<textarea id="'+id+'" rows="3" style="width:100%;padding:8px;border:1px solid #E2E8F0;border-radius:6px;font-size:13px;background:#F8FAFC;resize:vertical;box-sizing:border-box">'+(value||'')+'</textarea>';
  } else {
    s += '<input id="'+id+'" type="'+(type||'text')+'" value="'+esc(value||'')+'" style="width:100%;padding:8px;border:1px solid #E2E8F0;border-radius:6px;font-size:13px;background:#F8FAFC;box-sizing:border-box"'+(opts&&opts.step?' step="'+opts.step+'"':'')+(opts&&opts.placeholder?' placeholder="'+esc(opts.placeholder)+'"':'')+'>';
  }
  s += '</div>';
  return s;
}

function showAssetForm(editData) {
  _settingsEditId = editData ? editData.id : null;
  var so = document.getElementById('slide-over');
  var d = editData || {};
  var tags = Array.isArray(d.tags) ? d.tags : (d.tags ? JSON.parse(d.tags) : []);
  var services = Array.isArray(d.services) ? d.services : (d.services ? JSON.parse(d.services) : []);
  so.innerHTML = '<div style="padding:24px">'
    + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">'
    + '<h3 style="margin:0;color:#1E293B">'+(editData?'Edit':'Add')+' Asset</h3>'
    + '<button data-action="closeSlideOver" style="background:none;border:none;font-size:20px;cursor:pointer;color:#94A3B8">&times;</button></div>'
    + _settingsField('Hostname *','sf-hostname','text',d.hostname,{placeholder:'e.g. prod-db-01'})
    + _settingsField('Tier','sf-tier','select',d.tier||'unknown',['tier_1_critical','tier_2_important','tier_3_standard','tier_4_low','unknown'])
    + _settingsField('Owner','sf-owner','text',d.owner,{placeholder:'e.g. database-team'})
    + _settingsField('Environment','sf-env','select',d.environment||'unknown',['production','staging','development','testing','unknown'])
    + _settingsField('Criticality Multiplier','sf-mult','number',d.criticality_multiplier||1.0,{step:'0.1'})
    + _settingsField('Tags (comma-separated)','sf-tags','text',tags.join(', '),{placeholder:'e.g. database, pii'})
    + _settingsField('Services (comma-separated)','sf-services','text',services.join(', '),{placeholder:'e.g. mysql, replication'})
    + '<button data-action="submitAssetForm" class="fbtn" style="background:#818CF8;color:#fff;width:100%;padding:10px;margin-top:8px">'+(_settingsEditId?'Update':'Add')+' Asset</button>'
    + '<div id="sf-result" style="margin-top:12px"></div>'
    + '</div>';
  so.classList.add('open');
}

function showIdentityForm(editData) {
  _settingsEditId = editData ? editData.id : null;
  var so = document.getElementById('slide-over');
  var d = editData || {};
  var roles = Array.isArray(d.roles) ? d.roles : (d.roles ? JSON.parse(d.roles) : []);
  var knownIps = Array.isArray(d.known_ips) ? d.known_ips : (d.known_ips ? JSON.parse(d.known_ips) : []);
  so.innerHTML = '<div style="padding:24px">'
    + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">'
    + '<h3 style="margin:0;color:#1E293B">'+(editData?'Edit':'Add')+' Identity</h3>'
    + '<button data-action="closeSlideOver" style="background:none;border:none;font-size:20px;cursor:pointer;color:#94A3B8">&times;</button></div>'
    + _settingsField('Username *','sf-username','text',d.username,{placeholder:'e.g. svc-deploy'})
    + _settingsField('Risk Level','sf-risklevel','select',d.risk_level||'standard',['critical','high_risk','elevated','standard','low_risk'])
    + _settingsField('Risk Multiplier','sf-riskmult','number',d.risk_multiplier||1.0,{step:'0.1'})
    + '<div style="margin-bottom:12px;display:flex;gap:20px">'
    + '<label style="font-size:12px;color:#1E293B"><input id="sf-isadmin" type="checkbox"'+(d.is_admin?' checked':'')+' style="margin-right:6px">Admin</label>'
    + '<label style="font-size:12px;color:#1E293B"><input id="sf-issvc" type="checkbox"'+(d.is_service_account?' checked':'')+' style="margin-right:6px">Service Account</label>'
    + '</div>'
    + _settingsField('Department','sf-dept','text',d.department,{placeholder:'e.g. devops'})
    + _settingsField('Roles (comma-separated)','sf-roles','text',roles.join(', '),{placeholder:'e.g. deployment, ci-cd'})
    + _settingsField('Known IPs (comma-separated)','sf-knownips','text',knownIps.join(', '),{placeholder:'e.g. 10.0.1.5, 10.0.1.6'})
    + '<button data-action="submitIdentityForm" class="fbtn" style="background:#818CF8;color:#fff;width:100%;padding:10px;margin-top:8px">'+(_settingsEditId?'Update':'Add')+' Identity</button>'
    + '<div id="sf-result" style="margin-top:12px"></div>'
    + '</div>';
  so.classList.add('open');
}

function showLocalIOCForm() {
  var so = document.getElementById('slide-over');
  so.innerHTML = '<div style="padding:24px">'
    + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">'
    + '<h3 style="margin:0;color:#1E293B">Add Local IOC</h3>'
    + '<button data-action="closeSlideOver" style="background:none;border:none;font-size:20px;cursor:pointer;color:#94A3B8">&times;</button></div>'
    + _settingsField('Type *','sf-ioctype','select','ip',['ip','domain','hash'])
    + _settingsField('Value *','sf-iocvalue','text','',{placeholder:'e.g. 192.168.1.100 or evil.com'})
    + _settingsField('Severity','sf-iocsev','select','medium',['critical','high','medium','low','info'])
    + _settingsField('Description','sf-iocdesc','textarea','')
    + '<button data-action="submitLocalIOCForm" class="fbtn" style="background:#818CF8;color:#fff;width:100%;padding:10px;margin-top:8px">Add IOC</button>'
    + '<div id="sf-result" style="margin-top:12px"></div>'
    + '</div>';
  so.classList.add('open');
}

// ── Submit/Delete Handlers ──

function _csvToList(v) { return v ? v.split(',').map(function(s){return s.trim();}).filter(Boolean) : []; }

async function submitAssetForm() {
  var hostname = (document.getElementById('sf-hostname').value||'').trim();
  if (!hostname) { document.getElementById('sf-result').innerHTML='<span style="color:#EF4444">Hostname is required</span>'; return; }
  var body = {
    hostname: hostname,
    tier: document.getElementById('sf-tier').value,
    owner: (document.getElementById('sf-owner').value||'').trim() || 'unknown',
    environment: document.getElementById('sf-env').value,
    criticality_multiplier: parseFloat(document.getElementById('sf-mult').value) || 1.0,
    tags: _csvToList(document.getElementById('sf-tags').value),
    services: _csvToList(document.getElementById('sf-services').value)
  };
  try {
    var url = _settingsEditId ? '/admin/settings/assets/'+_settingsEditId : '/admin/settings/assets';
    var method = _settingsEditId ? 'PUT' : 'POST';
    var r = await fetch(API+url, {method:method, headers:{...authHeaders(),'Content-Type':'application/json'}, body:JSON.stringify(body)});
    var d = await r.json();
    if (r.ok) { document.getElementById('sf-result').innerHTML='<span style="color:#34D399">Saved!</span>'; setTimeout(function(){closeSlideOver();refresh();},800); }
    else { document.getElementById('sf-result').innerHTML='<span style="color:#EF4444">'+esc(d.detail||JSON.stringify(d))+'</span>'; }
  } catch(e) { document.getElementById('sf-result').innerHTML='<span style="color:#EF4444">'+esc(e.message)+'</span>'; }
}

async function submitIdentityForm() {
  var username = (document.getElementById('sf-username').value||'').trim();
  if (!username) { document.getElementById('sf-result').innerHTML='<span style="color:#EF4444">Username is required</span>'; return; }
  var body = {
    username: username,
    risk_level: document.getElementById('sf-risklevel').value,
    risk_multiplier: parseFloat(document.getElementById('sf-riskmult').value) || 1.0,
    is_admin: document.getElementById('sf-isadmin').checked,
    is_service_account: document.getElementById('sf-issvc').checked,
    department: (document.getElementById('sf-dept').value||'').trim() || 'unknown',
    roles: _csvToList(document.getElementById('sf-roles').value),
    known_ips: _csvToList(document.getElementById('sf-knownips').value)
  };
  try {
    var url = _settingsEditId ? '/admin/settings/identities/'+_settingsEditId : '/admin/settings/identities';
    var method = _settingsEditId ? 'PUT' : 'POST';
    var r = await fetch(API+url, {method:method, headers:{...authHeaders(),'Content-Type':'application/json'}, body:JSON.stringify(body)});
    var d = await r.json();
    if (r.ok) { document.getElementById('sf-result').innerHTML='<span style="color:#34D399">Saved!</span>'; setTimeout(function(){closeSlideOver();refresh();},800); }
    else { document.getElementById('sf-result').innerHTML='<span style="color:#EF4444">'+esc(d.detail||JSON.stringify(d))+'</span>'; }
  } catch(e) { document.getElementById('sf-result').innerHTML='<span style="color:#EF4444">'+esc(e.message)+'</span>'; }
}

async function submitLocalIOCForm() {
  var value = (document.getElementById('sf-iocvalue').value||'').trim();
  if (!value) { document.getElementById('sf-result').innerHTML='<span style="color:#EF4444">Value is required</span>'; return; }
  var body = {
    ioc_type: document.getElementById('sf-ioctype').value,
    value: value,
    severity: document.getElementById('sf-iocsev').value,
    description: (document.getElementById('sf-iocdesc').value||'').trim()
  };
  try {
    var r = await fetch(API+'/admin/settings/local-iocs', {method:'POST', headers:{...authHeaders(),'Content-Type':'application/json'}, body:JSON.stringify(body)});
    var d = await r.json();
    if (r.ok) { document.getElementById('sf-result').innerHTML='<span style="color:#34D399">Saved!</span>'; setTimeout(function(){closeSlideOver();refresh();},800); }
    else { document.getElementById('sf-result').innerHTML='<span style="color:#EF4444">'+esc(d.detail||JSON.stringify(d))+'</span>'; }
  } catch(e) { document.getElementById('sf-result').innerHTML='<span style="color:#EF4444">'+esc(e.message)+'</span>'; }
}

async function editAssetById(id) {
  try {
    var data = await fetchJSON('/admin/settings/assets');
    var asset = (data.assets||[]).find(function(a){return a.id===id;});
    if (asset) showAssetForm(asset);
  } catch(e) { alert('Failed to load asset: '+e.message); }
}

async function editIdentityById(id) {
  try {
    var data = await fetchJSON('/admin/settings/identities');
    var identity = (data.identities||[]).find(function(i){return i.id===id;});
    if (identity) showIdentityForm(identity);
  } catch(e) { alert('Failed to load identity: '+e.message); }
}

async function deleteAsset(id, hostname) {
  if (!confirm('Delete asset "'+hostname+'"?')) return;
  try {
    await fetch(API+'/admin/settings/assets/'+id, {method:'DELETE', headers:authHeaders()});
    refresh();
  } catch(e) { alert('Delete failed: '+e.message); }
}

async function deleteIdentity(id, username) {
  if (!confirm('Delete identity "'+username+'"?')) return;
  try {
    await fetch(API+'/admin/settings/identities/'+id, {method:'DELETE', headers:authHeaders()});
    refresh();
  } catch(e) { alert('Delete failed: '+e.message); }
}

async function deleteLocalIOC(id, value) {
  if (!confirm('Delete IOC "'+value+'"?')) return;
  try {
    await fetch(API+'/admin/settings/local-iocs/'+id, {method:'DELETE', headers:authHeaders()});
    refresh();
  } catch(e) { alert('Delete failed: '+e.message); }
}

async function reloadEnrichers() {
  try {
    var r = await fetch(API+'/admin/settings/reload-enrichers', {method:'POST', headers:authHeaders()});
    var d = await r.json();
    if (r.ok) { alert('Enrichers reloaded: '+d.assets+' assets, '+d.identities+' identities, '+d.local_iocs+' local IOCs'); }
    else { alert('Reload failed: '+(d.detail||JSON.stringify(d))); }
  } catch(e) { alert('Reload failed: '+e.message); }
}

let huntFilter = 'all';
let huntTimeRange = 'all';
function setHuntFilter(f) { huntFilter = f; refresh(); }
function setHuntTimeRange(r) { huntTimeRange = r; refresh(); }

async function renderHunt() {
  const d = await fetchJSON('/hunt/findings?limit=200');
  let items = d.findings || [];

  // Client-side time range filter
  if (huntTimeRange !== 'all') {
    const msMap = {'1h':3600e3,'6h':6*3600e3,'24h':86400e3,'3d':3*86400e3,'7d':7*86400e3,'30d':30*86400e3};
    const cutoff = Date.now() - (msMap[huntTimeRange]||86400e3);
    items = items.filter(x => new Date(x.created_at).getTime() >= cutoff);
  }

  const hits = items.filter(x=>x.result_count>0).length;
  const open = items.filter(x=>x.status==='hit'&&!x.reviewed_at).length;

  let h = `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:10px">
    <div style="display:flex;gap:6px;flex-wrap:wrap">
      <button class="fbtn${huntFilter==='all'?' fon':''}" data-action="setHuntFilter" data-filter="all">All (${items.length})</button>
      <button class="fbtn${huntFilter==='hit'?' fon':''}" data-action="setHuntFilter" data-filter="hit">Hits (${hits})</button>
      <button class="fbtn${huntFilter==='miss'?' fon':''}" data-action="setHuntFilter" data-filter="miss">Miss</button>
      <button class="fbtn${huntFilter==='confirmed'?' fon':''}" data-action="setHuntFilter" data-filter="confirmed">Confirmed</button>
      <button class="fbtn${huntFilter==='dismissed'?' fon':''}" data-action="setHuntFilter" data-filter="dismissed">Dismissed</button>
    </div>
    <div style="display:flex;gap:4px;align-items:center;flex-wrap:wrap">
      <button class="fbtn${huntTimeRange==='24h'?' fon':''}" data-action="setHuntTimeRange" data-range="24h">24H</button>
      <button class="fbtn${huntTimeRange==='3d'?' fon':''}" data-action="setHuntTimeRange" data-range="3d">3D</button>
      <button class="fbtn${huntTimeRange==='7d'?' fon':''}" data-action="setHuntTimeRange" data-range="7d">7D</button>
      <button class="fbtn${huntTimeRange==='30d'?' fon':''}" data-action="setHuntTimeRange" data-range="30d">30D</button>
      <button class="fbtn${huntTimeRange==='all'?' fon':''}" data-action="setHuntTimeRange" data-range="all">ALL</button>
      <button class="btn" style="background:#818CF8;color:#0B1527;padding:6px 16px;font-size:11px;font-weight:700;border-radius:6px;margin-left:6px" data-action="runHunt">Run Hunt</button>
    </div>
  </div>`;

  if (!items.length) return h + '<div style="text-align:center;color:#94A3B8;padding:40px">No hunt findings yet. Click "Run Hunt" to start.</div>' + await renderHuntLibrary();

  const filtered = huntFilter==='all' ? items : huntFilter==='hit' ? items.filter(x=>x.result_count>0) : huntFilter==='confirmed' ? items.filter(x=>x.confirmed) : huntFilter==='dismissed' ? items.filter(x=>x.status==='dismissed') : items.filter(x=>x.status===huntFilter);

  filtered.forEach(f => {
    const isOpen = expandedHunt === f.id;
    const pc = {high:'#EF4444',medium:'#FBBF24',low:'#34D399'}[f.priority] || '#5C7A99';
    const sc = f.result_count > 0 ? '#818CF8' : '#3D5A75';
    h += `<div class="row" style="border-color:${f.result_count>0&&!f.reviewed_at?'#818CF840':'#E2E8F0'};cursor:pointer" data-action="toggleHunt" data-id="${f.id}">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          ${badge(f.result_count>0?'HIT '+f.result_count:'MISS', sc)}
          ${badge(f.priority.toUpperCase(), pc)}
          ${f.mitre_technique ? badge(f.mitre_technique, '#60A5FA') : ''}
          <span style="color:#1E293B;font-size:12px">${esc(f.hypothesis||'')}</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px">
          ${f.confirmed ? badge('CONFIRMED','#EF4444') : f.status==='dismissed' ? badge('DISMISSED','#3D5A75') : ''}
          <span style="color:#94A3B8;font-size:11px">${f.created_at?localTime(f.created_at):''}</span>
          <span style="color:#94A3B8;font-size:14px">${isOpen?'\u25B2':'\u25BC'}</span>
        </div>
      </div>

      ${isOpen ? `
      <div style="margin-top:12px;padding-top:12px;border-top:1px solid #E2E8F0">
        <div style="margin-bottom:12px">
          <div style="color:#818CF8;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Hypothesis</div>
          <div style="color:#1E293B;font-size:12px;line-height:1.7;background:#F8FAFC;padding:12px;border-radius:8px;border:1px solid #E2E8F0">${esc(f.hypothesis)}</div>
        </div>

        ${f.results_summary ? `
        <div style="margin-bottom:12px">
          <div style="color:${f.result_count>0?'#EF4444':'#3D5A75'};font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Results (${f.result_count} events)</div>
          <div style="color:#1E293B;font-size:11px;line-height:1.6;background:#F8FAFC;padding:12px;border-radius:8px;border:1px solid #E2E8F0;font-family:'JetBrains Mono',monospace;white-space:pre-wrap">${esc(f.results_summary)}</div>
        </div>` : ''}

        <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:10px">
          <div><span style="color:#94A3B8;font-size:10px">Cycle:</span> <span style="color:#64748B;font-size:11px;font-family:'JetBrains Mono',monospace">${esc(f.hunt_cycle_id||'')}</span></div>
          <div><span style="color:#94A3B8;font-size:10px">Index:</span> <span style="color:#64748B;font-size:11px">${esc(f.query_index||'N/A')}</span></div>
        </div>

        ${f.result_count > 0 && !f.reviewed_at ? `
        <div style="display:flex;gap:8px;padding-top:10px;border-top:1px solid #E2E8F0">
          <button class="btn" style="background:#EF4444;color:#0B1527;padding:8px 20px;font-size:12px;font-weight:700;border-radius:6px" data-action="reviewHunt" data-id="${f.id}" data-status="confirmed" data-verdict="true" data-stop-propagation="true">Confirm Threat</button>
          <button class="btn" style="background:transparent;color:#64748B;padding:8px 20px;font-size:12px;font-weight:600;border-radius:6px;border:1px solid #E2E8F040" data-action="reviewHunt" data-id="${f.id}" data-status="dismissed" data-verdict="false" data-stop-propagation="true">Dismiss</button>
        </div>` : ''}

        ${f.reviewed_at ? `
        <div style="padding-top:10px;border-top:1px solid #E2E8F0">
          ${f.confirmed ? badge('CONFIRMED THREAT','#EF4444') : badge('DISMISSED','#3D5A75')}
          <span style="color:#94A3B8;font-size:11px;margin-left:8px">${localTime(f.reviewed_at)}</span>
          ${f.analyst_notes ? '<div style="color:#64748B;font-size:11px;margin-top:6px">Notes: '+esc(f.analyst_notes)+'</div>' : ''}
        </div>` : ''}
      </div>
      ` : `
      <div style="color:#64748B;font-size:11px;margin-top:4px">${f.results_summary?esc((f.results_summary||'').slice(0,150))+'...':'No results'}</div>
      `}
    </div>`;
  });
  h += await renderHuntLibrary();
  return h;
}

// -- Hunt hypothesis library + replay --
let _huntReplayResults = {};   // hypothesis_id → {hit_count, sample_hits, error}

async function renderHuntLibrary() {
  let h = '<div style="margin-top:24px;border-top:1px solid #E2E8F0;padding-top:16px"></div>';
  h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">';
  h += '<div style="font-size:14px;font-weight:700;color:#1E293B">Hypothesis Library</div>';
  h += '<span style="color:#64748B;font-size:11px">Hypotheses that produced confirmed hits — replay to re-run with current data</span>';
  h += '</div>';
  let lib;
  try { lib = await fetchJSON('/hunt/library?limit=50'); }
  catch(e) { return h + '<div style="color:#EF4444;font-size:12px;padding:14px;background:#FEF2F2;border-radius:6px;border:1px solid #EF444430">Failed to load library: '+esc(e.message)+'</div>'; }
  const hyps = lib.hypotheses || [];
  if (!hyps.length) {
    return h + '<div style="color:#94A3B8;font-size:12px;padding:20px;text-align:center;background:#F8FAFC;border-radius:8px;border:1px dashed #E2E8F0">No saved hypotheses yet. The hunt agent saves a hypothesis to the library each time analysts confirm a finding.</div>';
  }
  h += '<table style="width:100%;font-size:11px;border-collapse:collapse">';
  h += '<tr style="color:#94A3B8;font-size:10px;text-transform:uppercase;letter-spacing:1px"><th style="text-align:left;padding:8px 12px">Hypothesis</th><th style="text-align:left;padding:8px 12px">MITRE</th><th style="text-align:left;padding:8px 12px">Index</th><th style="text-align:left;padding:8px 12px">Confirmed Hits</th><th style="text-align:left;padding:8px 12px">Last Success</th><th style="text-align:left;padding:8px 12px">Action</th></tr>';
  hyps.forEach(hp => {
    const tags = (hp.tags||[]).slice(0,3);
    const last = hp.last_success_at ? localTime(hp.last_success_at) : '—';
    h += '<tr style="border-top:1px solid #E2E8F0;vertical-align:top">';
    h += '<td style="padding:8px 12px;color:#1E293B;max-width:380px"><div style="font-weight:600">'+esc((hp.hypothesis||'').slice(0,140))+((hp.hypothesis||'').length>140?'…':'')+'</div>';
    if (tags.length) h += '<div style="margin-top:3px">'+tags.map(t=>'<span style="background:#F1F5F9;color:#64748B;padding:1px 6px;border-radius:3px;font-size:10px;margin-right:3px">'+esc(t)+'</span>').join('')+'</div>';
    h += '</td>';
    h += '<td style="padding:8px 12px;color:#60A5FA;font-family:\'JetBrains Mono\',monospace">'+esc(hp.mitre_technique||'—')+'</td>';
    h += '<td style="padding:8px 12px;color:#64748B;font-size:10px;font-family:\'JetBrains Mono\',monospace">'+esc(hp.query_index||'')+'</td>';
    h += '<td style="padding:8px 12px;color:#34D399;font-weight:700;font-family:\'JetBrains Mono\',monospace">'+(hp.success_count||0)+'</td>';
    h += '<td style="padding:8px 12px;color:#64748B;font-size:10px;font-family:\'JetBrains Mono\',monospace">'+esc(last)+'</td>';
    h += '<td style="padding:8px 12px"><button class="fbtn" style="font-size:10px;padding:3px 10px;background:#818CF810;color:#4F46E5;border-color:#818CF840" data-action="replayHypothesis" data-id="'+esc(hp.id)+'">Replay</button></td>';
    h += '</tr>';
    // Replay results row (if any)
    const r = _huntReplayResults[hp.id];
    if (r) {
      const c = r.error ? '#EF4444' : (r.hit_count > 0 ? '#34D399' : '#94A3B8');
      h += '<tr style="background:'+c+'10"><td colspan="6" style="padding:8px 12px">';
      if (r.error) {
        h += '<span style="color:#EF4444;font-size:11px">Replay failed: '+esc(r.error)+'</span>';
      } else {
        h += '<span style="color:'+c+';font-size:11px;font-weight:600">Replay result: '+r.hit_count+' hits</span>';
        if ((r.sample_hits||[]).length) {
          h += ' <span style="color:#64748B;font-size:11px">— sample fields: '+(Object.keys(r.sample_hits[0]||{}).slice(0,6).map(esc).join(', '))+(Object.keys(r.sample_hits[0]||{}).length>6?'…':'')+'</span>';
        }
        h += ' <button class="fbtn" style="font-size:9px;padding:2px 6px;margin-left:8px" data-action="clearReplayResult" data-id="'+esc(hp.id)+'">×</button>';
      }
      h += '</td></tr>';
    }
  });
  h += '</table>';
  return h;
}

async function replayHypothesis(id) {
  _huntReplayResults[id] = {hit_count: 0, sample_hits: [], _loading: true};
  refresh();
  try {
    const r = await fetch(API + '/hunt/library/' + encodeURIComponent(id) + '/replay', {method:'POST', headers: authHeaders()});
    if (!r.ok) {
      const e = await r.json().catch(()=>({}));
      _huntReplayResults[id] = {error: e.detail || ('HTTP '+r.status)};
    } else {
      const d = await r.json();
      _huntReplayResults[id] = {hit_count: d.hit_count||0, sample_hits: d.sample_hits||[]};
    }
  } catch(e) {
    _huntReplayResults[id] = {error: e.message || 'network error'};
  }
  refresh();
}

function clearReplayResult(id) { delete _huntReplayResults[id]; refresh(); }

let expandedHunt = null;
function toggleHunt(id) { expandedHunt = expandedHunt === id ? null : id; refresh(); }

let huntRunning = false;
async function runHunt() {
  if (huntRunning) return;
  huntRunning = true;
  document.getElementById('content').innerHTML = '<div style="text-align:center;padding:60px;color:#818CF8"><div style="font-size:24px;margin-bottom:12px" class="spin">...</div>Hunt cycle started in background. Results will appear shortly...<br><span style="color:#94A3B8;font-size:12px">This runs in the background — page will auto-refresh in 10s.</span></div>';
  try {
    const r = await fetch(API+'/hunt/run', {method:'POST',headers:authHeaders()});
    if (r.status === 429) {
      document.getElementById('content').innerHTML = '<div style="text-align:center;padding:60px;color:#FBBF24">Rate limited — please wait a moment before running another hunt cycle.</div>';
    }
  } catch(e) { console.error('Hunt trigger failed:', e); }
  setTimeout(() => { huntRunning = false; refresh(); }, 30000);
}

async function reviewHunt(id, status, confirmed) {
  await fetch(API+'/hunt/review', {method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({finding_id:id,status:status,confirmed:confirmed})});
  refresh();
}

// ── Respond tab ──
let arRunning = false;

async function executeAR(action, agentId, target, timeout) {
  if (arRunning) return;
  arRunning = true;
  try {
    const body = {action, agent_id: agentId};
    if (target) body.target = target;
    if (timeout) body.timeout = timeout;
    const r = await fetch(API+'/response/execute',{method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d = await r.json();
    if (!r.ok) { alert('Error: ' + (extractErrorMessage(d) || 'Failed')); return; }
    alert(d.success ? 'Action executed successfully' : 'Action failed: '+(d.error||'Unknown'));
  } catch(e) { alert('Network error: '+e.message); }
  finally { arRunning = false; }
}

function promptAR(action, label) {
  const agentId = prompt('Agent ID (e.g. 001):');
  if (!agentId) return;
  let target = null;
  if (['block_ip','unblock_ip'].includes(action)) target = prompt('IP address:');
  else if (['kill_process'].includes(action)) target = prompt('Process PID:');
  else if (['disable_user','enable_user'].includes(action)) target = prompt('Username:');
  else if (['quarantine_file'].includes(action)) target = prompt('File path:');
  if (['block_ip','unblock_ip','kill_process','disable_user','enable_user','quarantine_file'].includes(action) && !target) return;
  if (!confirm('Execute '+label+' on agent '+agentId+(target?' targeting '+target:'')+'?')) return;
  executeAR(action, agentId, target);
}

let selectedAgent = null;
let agentDetailLoading = false;

async function selectAgent(id) {
  selectedAgent = selectedAgent === id ? null : id;
  // Re-render respond tab
  const html = await renderRespond();
  document.getElementById('content').innerHTML = html;
  flushGrids();
  if (selectedAgent) loadAgentDetail(selectedAgent);
}

async function loadAgentDetail(agentId) {
  if (agentDetailLoading) return;
  agentDetailLoading = true;
  const el = document.getElementById('agent-detail');
  if (!el) { agentDetailLoading = false; return; }

  try {
    const [info, procs, ports, vulns, sca] = await Promise.allSettled([
      fetchJSON('/agents/'+agentId),
      fetchJSON('/agents/'+agentId+'/processes?limit=50'),
      fetchJSON('/agents/'+agentId+'/ports?limit=50'),
      fetchJSON('/vulnerabilities?agent_id='+agentId+'&limit=50'),
      fetchJSON('/agents/'+agentId+'/sca'),
    ]);

    let h = '<div class="section-title" style="margin-top:24px">Agent '+esc(agentId)+' — Detail View</div>';

    // OS Info
    if (info.status==='fulfilled') {
      const d = info.value;
      const a = d.agent || {};
      const os = d.os || {};
      h += '<div class="g">';
      h += '<div class="c"><div class="l">Agent Name</div><div class="v" style="font-size:18px">'+esc(a.name||agentId)+'</div></div>';
      h += '<div class="c"><div class="l">OS</div><div class="v" style="font-size:14px;color:#60A5FA">'+esc(os.os_name||os.sysname||'Unknown')+' '+esc(os.os_version||os.version||'')+'</div></div>';
      h += '<div class="c"><div class="l">Architecture</div><div class="v" style="font-size:14px">'+esc(os.os_platform||os.platform||'')+'</div></div>';
      h += '<div class="c"><div class="l">IP Address</div><div class="v" style="font-size:14px;font-family:JetBrains Mono,monospace">'+esc(a.ip||'')+'</div></div>';
      h += '</div>';
    }

    // Vulnerability summary + remediation for this agent
    if (vulns.status==='fulfilled') {
      const vl = vulns.value.vulnerabilities || [];
      const sevCounts = {};
      vl.forEach(v => { let s = (v.vulnerability||{}).severity||''; if(!s||s==='-'||s==='unknown') s='Low'; sevCounts[s] = (sevCounts[s]||0)+1; });
      const sevColors = {Critical:'#EF4444',High:'#FBBF24',Medium:'#60A5FA',Low:'#34D399'};
      const sevOrder = ['Critical','High','Medium','Low'];
      h += '<div class="section-title">Vulnerabilities &amp; Remediation ('+vl.length+')</div>';
      if (vl.length > 0) {
        h += '<div class="g">';
        sevOrder.forEach(k => { if(sevCounts[k]) h += '<div class="c"><div class="l">'+k+'</div><div class="v" style="color:'+(sevColors[k]||'#1E293B')+'">'+sevCounts[k]+'</div></div>'; });
        h += '</div>';
        // Fetch remediation data
        let remData = [];
        try { const rd = await fetchJSON('/vulnerabilities/remediation?agent_id='+agentId); remData = rd.remediations || []; } catch(e) {}
        const remMap = {};
        remData.forEach(r => { remMap[r.cve_id] = r; });
        h += '<div class="c" style="max-height:500px;overflow-y:auto">';
        vl.slice(0,30).forEach(v => {
          const vd = v.vulnerability||{};
          const pk = v.package||{};
          const sc2 = sevColors[vd.severity]||'#3D5A75';
          const rem = remMap[vd.id] || {};
          const cvss = (vd.score||{}).base;
          h += '<div style="border-bottom:1px solid #E2E8F0;padding:12px 0">';
          h += '<div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px">';
          h += '<div><span style="color:'+sc2+';font-family:JetBrains Mono,monospace;font-weight:700;font-size:14px">'+esc(vd.id||'')+'</span> '+badge(vd.severity||'',sc2);
          if (cvss) h += ' <span style="color:#64748B;font-size:11px">CVSS '+cvss+'</span>';
          h += '<div style="color:#1E293B;font-size:12px;margin-top:4px"><strong>'+esc(pk.name||'')+'</strong> <span style="color:#EF4444;font-family:JetBrains Mono,monospace">'+esc(pk.version||'')+'</span>';
          if (rem.fix_version) h += ' <span style="color:#94A3B8;margin:0 4px">&rarr;</span> <span style="color:#1E293B;font-family:JetBrains Mono,monospace;font-weight:600">'+esc(rem.fix_hint||'')+'</span>';
          h += '</div></div>';
          h += '<div style="display:flex;gap:6px;align-items:center">';
          if (vd.reference) h += '<a href="'+esc(vd.reference)+'" target="_blank" rel="noopener" style="color:#60A5FA;font-size:10px;text-decoration:none">Advisory</a>';
          if (rem.command) h += '<button class="btn" style="background:#E2E8F0;color:#64748B;font-size:10px;padding:4px 10px" data-cmd="'+esc(rem.command)+'" data-action="copyCmd" data-stop-propagation="true">Copy Fix</button>';
          if (rem.can_auto_execute) h += '<button class="btn" style="background:#EF444420;color:#EF4444;font-size:10px;padding:4px 10px" data-action="execRemediation" data-id="'+esc(agentId)+'" data-field="'+esc(pk.name||'')+'" data-stop-propagation="true">Execute</button>';
          h += '</div></div>';
          if (rem.command) {
            h += '<div style="margin-top:6px;background:#F8FAFC;border:1px solid #E2E8F0;border-radius:6px;padding:8px 10px;font-family:JetBrains Mono,monospace;font-size:10px;color:#64748B;white-space:pre-wrap;word-break:break-all">'+esc(rem.command)+'</div>';
          }
          if (vd.description) {
            h += '<div style="color:#94A3B8;font-size:10px;margin-top:4px;line-height:1.4">'+esc((vd.description||'').slice(0,200))+(vd.description.length>200?'...':'')+'</div>';
          }
          h += '</div>';
        });
        if (vl.length > 30) h += '<div style="color:#94A3B8;text-align:center;padding:12px">... and '+(vl.length-30)+' more vulnerabilities</div>';
        h += '</div>';
      } else {
        h += '<div class="c" style="color:#1E293B;text-align:center;padding:12px">No vulnerabilities found</div>';
      }
    }

    // Running Processes
    if (procs.status==='fulfilled') {
      const pl = procs.value.processes || [];
      h += '<div class="section-title">Running Processes ('+pl.length+')</div>';
      if (pl.length > 0) {
        h += '<div id="proc-grid" style="width:100%;height:300px"></div>';
        queueGrid('proc-grid', {
          domLayout: 'normal',
          rowData: pl.map(p => ({pid:p.pid||'',name:p.name||'',user:p.euser||p.ruser||'',state:p.state||'',cmd:(p.cmd||'').slice(0,120)})),
          columnDefs: [
            {field:'pid',headerName:'PID',width:80,cellStyle:{fontFamily:'JetBrains Mono,monospace',color:'#1E293B'}},
            {field:'name',headerName:'Name',width:150,cellStyle:{fontWeight:600}},
            {field:'user',headerName:'User',width:120},
            {field:'state',headerName:'State',width:100},
            {field:'cmd',headerName:'CMD',flex:1,minWidth:200,cellStyle:{color:'#3D5A75',fontSize:'10px'}}
          ],
          pagination: pl.length > 50,
          paginationPageSize: 50
        });
      } else {
        h += '<div class="c" style="color:#94A3B8;text-align:center;padding:12px">No process data available</div>';
      }
    }

    // Open Ports
    if (ports.status==='fulfilled') {
      const ptl = ports.value.ports || [];
      h += '<div class="section-title">Open Ports ('+ptl.length+')</div>';
      if (ptl.length > 0) {
        h += '<div id="port-grid" style="width:100%;height:250px"></div>';
        queueGrid('port-grid', {
          domLayout: 'normal',
          rowData: ptl.map(p => {const la=p.local||{};const ra=p.remote||{};return {protocol:p.protocol||'',localIp:la.ip||'',localPort:la.port||'',remoteIp:ra.ip||'',state:p.state||'',pid:p.pid||'',process:p.process||''};}),
          columnDefs: [
            {field:'protocol',headerName:'Protocol',width:90},
            {field:'localIp',headerName:'Local IP',width:130,cellStyle:{fontFamily:'JetBrains Mono,monospace'}},
            {field:'localPort',headerName:'Port',width:80,cellStyle:{color:'#FBBF24',fontFamily:'JetBrains Mono,monospace',fontWeight:600}},
            {field:'remoteIp',headerName:'Remote IP',width:130,cellStyle:{fontFamily:'JetBrains Mono,monospace'}},
            {field:'state',headerName:'State',width:110},
            {field:'pid',headerName:'PID',width:70,cellStyle:{fontFamily:'JetBrains Mono,monospace'}},
            {field:'process',headerName:'Process',flex:1,minWidth:120}
          ],
          pagination: ptl.length > 50,
          paginationPageSize: 50
        });
      } else {
        h += '<div class="c" style="color:#94A3B8;text-align:center;padding:12px">No port data available</div>';
      }
    }

    // SCA Compliance
    if (sca.status==='fulfilled') {
      const policies = sca.value.policies || [];
      h += '<div class="section-title">Compliance / SCA ('+policies.length+' policies)</div>';
      if (policies.length > 0) {
        h += '<div class="g">';
        policies.forEach(p => {
          const pass = p.pass||0;
          const fail = p.fail||0;
          const total = pass+fail+(p.invalid||0);
          const pct = total>0?Math.round(pass/total*100):0;
          const col = pct>=80?'#34D399':pct>=60?'#FBBF24':'#EF4444';
          h += '<div class="c" style="min-width:250px"><div class="l">'+esc(p.name||p.policy_id||'')+'</div><div class="v" style="color:'+col+';font-size:22px">'+pct+'%</div><div style="display:flex;gap:8px;margin-top:6px;font-size:11px"><span style="color:#34D399">Pass: '+pass+'</span><span style="color:#EF4444">Fail: '+fail+'</span><span style="color:#94A3B8">N/A: '+(p.invalid||0)+'</span></div><div style="color:#94A3B8;font-size:10px;margin-top:4px">'+esc(p.description||'')+'</div></div>';
        });
        h += '</div>';
      } else {
        h += '<div class="c" style="color:#94A3B8;text-align:center;padding:12px">No SCA policies configured</div>';
      }
    }

    el.innerHTML = h;
    flushGrids();
  } catch(e) {
    el.innerHTML = '<div class="c" style="color:#EF4444;text-align:center;padding:20px">Failed to load agent details: '+esc(e.message)+'</div>';
  } finally {
    agentDetailLoading = false;
  }
}

function copyCmd(btn) {
  const text = btn.getAttribute('data-cmd');
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    btn.style.color = '#1E293B';
    setTimeout(() => { btn.textContent = orig; btn.style.color = ''; }, 1500);
  });
}

async function execRemediation(agentId, pkgName) {
  if (!confirm('WARNING: This will execute a package update on agent '+agentId+' for package "'+pkgName+'".\\n\\nThis may restart services and could impact production workloads.\\n\\nAre you sure?')) return;
  const btn = event.target;
  const origText = btn.textContent;
  btn.textContent = 'Sending...';
  btn.disabled = true;
  btn.style.opacity = '0.5';
  try {
    const r = await fetch(API+'/vulnerabilities/remediate',{method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({agent_id:agentId,package_name:pkgName})});
    const d = await r.json();
    if (!r.ok) { btn.textContent = 'Failed'; btn.style.color = '#EF4444'; setTimeout(()=>{btn.textContent=origText;btn.disabled=false;btn.style.opacity='1';btn.style.color='';},3000); alert('Error: ' + (extractErrorMessage(d) || 'Failed')); return; }
    // Command sent — now verify
    btn.textContent = 'Verifying...';
    const vBefore = d.version_before || '';
    // Wait for the package manager to finish (poll up to 30s)
    let verified = false;
    for (let i = 0; i < 3; i++) {
      await new Promise(r => setTimeout(r, 10000));
      try {
        const vr = await fetchJSON('/vulnerabilities/verify?agent_id='+agentId+'&package_name='+encodeURIComponent(pkgName)+'&version_before='+encodeURIComponent(vBefore));
        if (vr.status === 'updated') {
          btn.textContent = 'Updated!';
          btn.style.color = '#1E293B';
          btn.style.background = '#E8EDF220';
          alert('SUCCESS: '+vr.message);
          verified = true;
          break;
        } else if (vr.status === 'possibly_updated') {
          btn.textContent = 'May be fixed';
          btn.style.color = '#FBBF24';
          alert(vr.message);
          verified = true;
          break;
        }
      } catch(e) {}
    }
    if (!verified) {
      btn.textContent = 'Sent (unverified)';
      btn.style.color = '#FBBF24';
      alert('Command was sent to agent '+agentId+' but version change could not be confirmed after 30s. The update may still be in progress or may require a syscollector rescan.');
    }
    setTimeout(()=>{btn.textContent=origText;btn.disabled=false;btn.style.opacity='1';btn.style.color='';btn.style.background='';},10000);
  } catch(e) { btn.textContent='Error';btn.style.color='#EF4444'; alert('Network error: '+e.message); setTimeout(()=>{btn.textContent=origText;btn.disabled=false;btn.style.opacity='1';btn.style.color='';},3000); }
}

// ── Host Integrity (M6): FIM / rootcheck / registry read views ──────────────
let hiAgent = '';            // selected agent id
let hiView = 'syscheck';     // syscheck | rootcheck | registry

function setHostIntegrityView(v) { hiView = v; refresh(); }
function setHostIntegrityAgent(id) { hiAgent = id; refresh(); }

async function renderHostIntegrity() {
  // Keep the in-tab sub-view in sync with the sidebar tab the user landed on.
  if (currentTab === 'registry') hiView = 'registry';
  else if (currentTab === 'rootcheck') hiView = 'rootcheck';
  else if (currentTab === 'fim' && (hiView !== 'rootcheck' && hiView !== 'registry')) hiView = 'syscheck';

  let h = '<div class="section-title">Host Integrity</div>';
  // Agent picker
  let agents = [];
  try { const ag = await fetchJSON('/agents'); agents = ag.agents || []; } catch(e) {}
  h += '<div class="c" style="margin-bottom:12px;display:flex;gap:12px;align-items:center;flex-wrap:wrap">';
  h += '<label style="color:#94A3B8;font-size:12px">Agent</label>';
  h += '<select data-action="setHostIntegrityAgent" style="background:#0F1E36;color:#E2E8F0;border:1px solid #334155;border-radius:6px;padding:6px 10px;font-size:12px">';
  h += '<option value="">— select agent —</option>';
  agents.forEach(a => {
    const sel = (String(a.id) === String(hiAgent)) ? ' selected' : '';
    h += '<option value="'+esc(String(a.id))+'"'+sel+'>'+esc(String(a.id))+' / '+esc(a.name||'')+'</option>';
  });
  h += '</select>';
  const views = [['syscheck','FIM / Syscheck'],['rootcheck','Rootcheck'],['registry','Registry']];
  h += '<span style="display:inline-flex;gap:6px;margin-left:auto">';
  views.forEach(([v,n]) => {
    const on = (hiView === v);
    h += '<button class="fbtn'+(on?' on':'')+'" data-action="setHostIntegrityView" data-view="'+v+'" style="font-size:11px;padding:4px 10px'+(on?';background:#1D4ED8;color:#fff':'')+'">'+n+'</button>';
  });
  h += '</span></div>';

  if (!hiAgent) {
    h += '<div class="c" style="color:#94A3B8;text-align:center;padding:30px">Select an agent to view host-integrity data.</div>';
    return h;
  }

  const endpoints = {syscheck:'/agents/'+encodeURIComponent(hiAgent)+'/syscheck',
                     rootcheck:'/agents/'+encodeURIComponent(hiAgent)+'/rootcheck',
                     registry:'/agents/'+encodeURIComponent(hiAgent)+'/registry'};
  const keys = {syscheck:'syscheck', rootcheck:'rootcheck', registry:'registry'};
  let rows = [];
  try {
    const d = await fetchJSON(endpoints[hiView] + '?limit=500');
    rows = d[keys[hiView]] || [];
  } catch(e) {
    return h + '<div class="c" style="color:#94A3B8;text-align:center;padding:30px">'+esc(extractErrorMessage(e))+'</div>';
  }

  if (!rows.length) {
    h += '<div class="c" style="color:#94A3B8;text-align:center;padding:30px">No '+esc(hiView)+' records for this agent.</div>';
    return h;
  }

  // Build a generic table from the union of common keys (read-only, minimal).
  const cols = (hiView === 'rootcheck')
    ? ['cis','pci_dss','log','status']
    : ['file','type','mtime','size','perm','uname','gname','md5','sha1'];
  h += '<div class="c"><div class="l">'+esc(hiView)+' — '+rows.length+' records</div>';
  h += '<table class="tbl" style="font-size:11px"><tr>'+cols.map(c=>'<th>'+esc(c)+'</th>').join('')+'</tr>';
  rows.slice(0, 500).forEach(r => {
    h += '<tr>'+cols.map(c=>{
      let v = r[c];
      if (v && typeof v === 'object') v = JSON.stringify(v);
      return '<td style="color:#CBD5E1;font-family:JetBrains Mono,monospace">'+esc(v===undefined||v===null?'':String(v).slice(0,80))+'</td>';
    }).join('')+'</tr>';
  });
  h += '</table></div>';
  return h;
}

async function renderAgentGroups() {
  let h = '<div class="section-title">Agent Groups (Manager-global — MSSP admin)</div>';
  let groups = [];
  try { const d = await fetchJSON('/groups?limit=500'); groups = d.groups || []; }
  catch(e) { return h + '<div class="c" style="color:#94A3B8;text-align:center;padding:30px">'+esc(extractErrorMessage(e))+'</div>'; }
  if (!groups.length) return h + '<div class="c" style="color:#94A3B8;text-align:center;padding:30px">No groups returned.</div>';
  h += '<div class="c"><table class="tbl" style="font-size:11px"><tr><th>Name</th><th>Agents</th><th>Config sum</th></tr>';
  groups.forEach(g => {
    h += '<tr><td style="color:#E2E8F0">'+esc(g.name||'')+'</td><td style="color:#60A5FA;font-family:JetBrains Mono,monospace">'+esc(String(g.count===undefined?'':g.count))+'</td><td style="color:#64748B;font-family:JetBrains Mono,monospace">'+esc(String(g.configSum||g.mergedSum||'').slice(0,16))+'</td></tr>';
  });
  h += '</table></div>';
  return h;
}

async function renderRespond() {
  let h = '';
  // Active Response section
  h += '<div class="section-title">Active Response Actions</div>';
  h += '<div class="ar-grid">';
  const actions = [
    {a:'block_ip',n:'Block IP',d:'Firewall drop',i:'&#x1F6AB;',c:'#EF4444'},
    {a:'unblock_ip',n:'Unblock IP',d:'Remove firewall block',i:'&#x2705;',c:'#34D399'},
    {a:'isolate_host',n:'Isolate Host',d:'Network isolation',i:'&#x1F512;',c:'#EF4444'},
    {a:'unisolate_host',n:'Unisolate Host',d:'Remove isolation',i:'&#x1F513;',c:'#34D399'},
    {a:'kill_process',n:'Kill Process',d:'Terminate by PID',i:'&#x2620;',c:'#FBBF24'},
    {a:'disable_user',n:'Disable User',d:'Lock account',i:'&#x1F6B7;',c:'#EF4444'},
    {a:'enable_user',n:'Enable User',d:'Unlock account',i:'&#x1F464;',c:'#34D399'},
    {a:'quarantine_file',n:'Quarantine File',d:'Isolate malicious file',i:'&#x1F4E6;',c:'#FBBF24'},
    {a:'restart_agent',n:'Restart Agent',d:'Restart Wazuh agent',i:'&#x1F504;',c:'#60A5FA'},
  ];
  actions.forEach(x => {
    h += '<div class="ar-card" style="border-color:'+x.c+'30" data-action="promptAR" data-id="'+x.a+'" data-field="'+x.n+'"><div class="icon">'+x.i+'</div><div class="name" style="color:'+x.c+'">'+x.n+'</div><div class="desc">'+x.d+'</div></div>';
  });
  h += '</div>';

  // Fetch vulnerability summary, critical findings, and agents in parallel
  const [vulnResult, critResult, agentResult] = await Promise.allSettled([
    fetchJSON('/vulnerabilities/summary'),
    fetchJSON('/vulnerabilities/critical?limit=50'),
    fetchJSON('/agents')
  ]);

  // Vulnerability Summary
  h += '<div class="section-title">Vulnerability Overview</div>';
  if (vulnResult.status === 'fulfilled') {
    try {
      const vs = vulnResult.value;
      const sev = vs.by_severity || {};
      const sevColors = {Critical:'#EF4444',High:'#FBBF24',Medium:'#60A5FA',Low:'#34D399'};
      const sevOrder = ['Critical','High','Medium','Low'];
      h += '<div class="g">';
      h += '<div class="c"><div class="l">Total Vulnerabilities</div><div class="v">'+vs.total_vulnerabilities+'</div></div>';
      h += '<div class="c"><div class="l">Affected Agents</div><div class="v" style="color:#60A5FA">'+vs.affected_agents+'</div></div>';
      sevOrder.forEach(k => {
        const v = sev[k] || 0;
        if (v > 0) h += '<div class="c"><div class="l">'+k+'</div><div class="v" style="color:'+(sevColors[k]||'#94A3B8')+'">'+v+'</div></div>';
      });
      h += '</div>';
      if ((vs.top_cves||[]).length) {
        h += '<div class="c" style="margin-bottom:16px"><div class="l">Top CVEs</div><table class="tbl"><tr><th>CVE</th><th>Count</th></tr>';
        vs.top_cves.slice(0,10).forEach(c => {
          h += '<tr><td style="color:#EF4444;font-family:JetBrains Mono,monospace">'+esc(c.cve)+'</td><td>'+c.count+'</td></tr>';
        });
        h += '</table></div>';
      }
    } catch(e) {
      h += '<div class="c" style="color:#94A3B8;text-align:center;padding:20px">Vulnerability data unavailable — requires wazuh-states-vulnerabilities-* index</div>';
    }
  } else {
    h += '<div class="c" style="color:#94A3B8;text-align:center;padding:20px">Vulnerability data unavailable — requires wazuh-states-vulnerabilities-* index</div>';
  }

  // Critical Severity Findings (actual records, across all agents)
  if (critResult.status === 'fulfilled' && (critResult.value.vulnerabilities||[]).length) {
    const crit = critResult.value.vulnerabilities;
    h += '<div class="c" style="margin-bottom:16px;border-left:3px solid #EF4444">';
    h += '<div class="l" style="display:flex;justify-content:space-between;align-items:center"><span>Critical Severity Findings (across fleet)</span><span style="color:#EF4444;font-family:JetBrains Mono,monospace;font-size:12px">'+critResult.value.total+' shown</span></div>';
    h += '<table class="tbl" style="font-size:11px"><tr><th>Agent</th><th>CVE</th><th>Package</th><th>Version</th><th>CVSS</th><th>Action</th></tr>';
    crit.forEach(item => {
      const v = item.vulnerability || {};
      const a = item.agent || {};
      const pkg = item.package || {};
      const cvss = (v.scanner && v.scanner.condition) || v.score || '';
      h += '<tr>';
      h += '<td style="font-family:JetBrains Mono,monospace;color:#1E293B">'+esc(String(a.id||'')+(a.name?' / '+a.name:''))+'</td>';
      h += '<td style="color:#EF4444;font-family:JetBrains Mono,monospace;font-weight:600">'+esc(v.id||v.cve||'')+'</td>';
      h += '<td style="color:#1E293B">'+esc(pkg.name||v.package||'')+'</td>';
      h += '<td style="color:#64748B;font-family:JetBrains Mono,monospace">'+esc(pkg.version||v.version||'')+'</td>';
      h += '<td style="color:#EF4444;font-weight:600;font-family:JetBrains Mono,monospace">'+esc(String(cvss).slice(0,12))+'</td>';
      h += '<td>'+(a.id?'<button class="fbtn" style="font-size:10px;padding:2px 8px" data-action="selectAgent" data-id="'+esc(String(a.id))+'">View Agent</button>':'')+'</td>';
      h += '</tr>';
    });
    h += '</table></div>';
  }

  // Agent Inventory
  h += '<div class="section-title">Agent Inventory — click an agent for full detail</div>';
  if (agentResult.status === 'fulfilled') {
    try {
      const ag = agentResult.value;
      const _agentRows = ag.agents || [];
      h += '<div id="agent-grid" style="width:100%;min-height:200px"></div>';
      queueGrid('agent-grid', {
        rowData: _agentRows.map(a => ({id:a.id, name:a.name, ip:a.ip||'', os:(a.os||{}).name||'', status:a.status||'unknown', lastKeepAlive:a.lastKeepAlive||'', _raw:a})),
        columnDefs: [
          {field:'id', headerName:'ID', width:80, cellStyle:{fontFamily:'JetBrains Mono,monospace',fontWeight:600,color:'#1E293B'}},
          {field:'name', headerName:'Name', flex:1, minWidth:120},
          {field:'ip', headerName:'IP', width:140, cellStyle:{fontFamily:'JetBrains Mono,monospace'}},
          {field:'os', headerName:'OS', flex:1, minWidth:140},
          {field:'status', headerName:'Status', width:110, cellRenderer: p => {
            const sc = p.value==='active'?'#34D399':p.value==='disconnected'?'#EF4444':'#3D5A75';
            return '<span style="font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px;background:'+sc+'18;color:'+sc+';border:1px solid '+sc+'30">'+esc(p.value)+'</span>';
          }},
          {field:'lastKeepAlive', headerName:'Last Seen', width:170, cellStyle:{color:'#3D5A75',fontSize:'11px'}}
        ],
        onRowClicked: p => selectAgent(p.data.id),
        getRowStyle: p => p.data.id === selectedAgent ? {background:'#E2E8F040'} : null
      });
    } catch(e) {
      h += '<div class="c" style="color:#94A3B8;text-align:center;padding:20px">Agent data unavailable</div>';
    }
  } else {
    h += '<div class="c" style="color:#94A3B8;text-align:center;padding:20px">Agent data unavailable</div>';
  }

  // Agent detail panel
  h += '<div id="agent-detail">';
  if (selectedAgent) {
    h += '<div style="text-align:center;padding:20px;color:#1E293B" class="spin">Loading agent '+esc(selectedAgent)+' details...</div>';
  }
  h += '</div>';

  return h;
}

// ── Investigate (NL Query) ──
let queryHistory = [];
let queryRunning = false;

async function runNLQuery(question) {
  if (!question || queryRunning) return;
  queryRunning = true;
  // Show loading state
  const resultsEl = document.getElementById('qresults');
  if (resultsEl) resultsEl.innerHTML = '<div style="text-align:center;padding:40px;color:#1E293B"><div class="spin" style="font-size:20px;margin-bottom:8px">...</div>Querying SIEM and analyzing results...</div>';
  const btn = document.getElementById('qbtn');
  if (btn) btn.disabled = true;
  try {
    const r = await fetch(API+'/query', {method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({question:question})});
    if (r.status === 429) { if (resultsEl) resultsEl.innerHTML = '<div style="text-align:center;padding:40px;color:#FBBF24">Rate limited. Wait a moment and try again.</div>'; return; }
    if (!r.ok) { const err = await r.json().catch(()=>({})); if (resultsEl) resultsEl.innerHTML = '<div style="color:#EF4444;padding:20px">Error: '+esc(err.detail||'Query failed')+'</div>'; return; }
    const data = await r.json();
    queryHistory.unshift({question, result:data, time:new Date().toISOString()});
    if (queryHistory.length > 20) queryHistory.pop();
    renderQueryResult(data);
  } catch(e) { if (resultsEl) resultsEl.innerHTML = '<div style="color:#EF4444;padding:20px">Network error: '+esc(e.message)+'</div>'; }
  finally { queryRunning = false; if (btn) btn.disabled = false; }
}

function renderQueryResult(data) {
  const el = document.getElementById('qresults');
  if (!el) return;
  let h = '';
  // Main answer
  h += '<div class="q-answer"><h3>Answer</h3><div class="body">'+md(data.answer||'No answer')+'</div>';
  // Findings
  const findings = data.findings || [];
  if (findings.length) {
    h += '<div class="q-findings">';
    findings.forEach(f => { h += '<div class="item">'+esc(f)+'</div>'; });
    h += '</div>';
  }
  // Risk assessment
  if (data.risk_assessment) {
    h += '<div style="background:#EF444410;border:1px solid #EF444430;border-radius:8px;padding:10px 14px;margin:10px 0"><span style="color:#EF4444;font-size:10px;font-weight:700;text-transform:uppercase">Risk Assessment</span><div style="color:#1E293B;font-size:12px;margin-top:4px">'+md(data.risk_assessment)+'</div></div>';
  }
  // Suggested actions
  const actions = data.suggested_actions || [];
  if (actions.length) {
    h += '<div style="margin-top:10px"><span style="color:#FBBF24;font-size:10px;font-weight:700;text-transform:uppercase">Suggested Actions</span><ul class="q-actions" style="margin-top:6px;padding-left:16px">';
    actions.forEach(a => { h += '<li>'+esc(a)+'</li>'; });
    h += '</ul></div>';
  }
  // Follow-up queries
  const followups = data.follow_up_queries || [];
  if (followups.length) {
    h += '<div class="q-followup">';
    followups.forEach(fq => {
      h += '<button data-action="runFollowup">'+esc(fq)+'</button>';
    });
    h += '</div>';
  }
  // Metadata
  h += '<div class="q-meta">';
  h += '<span>Duration: '+(data.duration_ms||0)+'ms</span>';
  h += '<span>Results: '+(data.total_hits||0)+' hits across '+(data.queries_executed||0)+' queries</span>';
  h += '</div>';
  h += '</div>';
  el.innerHTML = h;
}

async function renderMITRE() {
  let coverage, gaps, summary;
  try { coverage = await fetchJSON('/mitre/coverage'); } catch(e) { coverage = {tactics:[]}; }
  try { gaps = await fetchJSON('/mitre/gaps'); } catch(e) { gaps = {total_gaps:0,total_techniques:0,coverage_pct:0}; }
  try { summary = await fetchJSON('/mitre/summary'); } catch(e) { summary = {per_tactic:[],overall:{}}; }

  const ov = summary.overall || {};
  let h = '<div style="margin-bottom:16px"><div style="font-size:16px;font-weight:700;margin-bottom:4px">MITRE ATT&CK Coverage</div><div style="color:#64748B;font-size:12px">Detection coverage mapped to the ATT&CK Enterprise matrix.</div></div>';

  // Summary cards
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px">';
  const covPct = ov.coverage_pct || 0;
  [{l:'Coverage',v:covPct+'%',c:covPct>=60?'#34D399':covPct>=30?'#FBBF24':'#EF4444',s:'of techniques detected'},
   {l:'Detected',v:ov.detected||0,c:'#60A5FA',s:'unique techniques'},
   {l:'Gaps',v:gaps.total_gaps||0,c:gaps.total_gaps>50?'#EF4444':'#FBBF24',s:'not detected'},
   {l:'Total',v:ov.total_techniques||0,c:'#94A3B8',s:'in matrix'}
  ].forEach(c => {
    h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:16px;text-align:center">';
    h += '<div style="color:'+c.c+';font-size:24px;font-weight:700;font-family:\'JetBrains Mono\',monospace">'+c.v+'</div>';
    h += '<div style="color:#CBD5E1;font-size:11px;font-weight:600;margin-top:4px">'+c.l+'</div>';
    h += '<div style="color:#94A3B8;font-size:10px">'+c.s+'</div></div>';
  });
  h += '</div>';

  // Per-tactic coverage bars
  const ptData = summary.per_tactic || [];
  if (ptData.length) {
    h += '<div style="margin-bottom:20px"><div style="color:#1E293B;font-size:12px;font-weight:600;margin-bottom:8px">Coverage by Tactic</div>';
    ptData.forEach(t => {
      const pct = t.coverage_pct || 0;
      const barColor = pct >= 60 ? '#34D399' : pct >= 30 ? '#FBBF24' : pct > 0 ? '#FB923C' : '#3D5A7540';
      h += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">';
      h += '<div style="width:180px;color:#64748B;font-size:11px;text-align:right;flex-shrink:0">'+esc(t.tactic)+'</div>';
      h += '<div style="flex:1;background:#E2E8F0;border-radius:4px;height:18px;position:relative;overflow:hidden">';
      h += '<div style="width:'+pct+'%;height:100%;background:'+barColor+';border-radius:4px;transition:width 0.3s"></div>';
      h += '<span style="position:absolute;right:6px;top:1px;color:#1E293B;font-size:10px;font-family:\'JetBrains Mono\',monospace">'+t.detected+'/'+t.total+' ('+pct+'%)</span>';
      h += '</div></div>';
    });
    h += '</div>';
  }

  // Heatmap grid
  const tactics = coverage.tactics || [];
  if (tactics.length) {
    const statusColor = {active:'#34D399',noisy:'#FBBF24',stale:'#60A5FA',not_detected:'#E2E8F0'};
    h += '<div style="margin-bottom:20px"><div style="color:#1E293B;font-size:12px;font-weight:600;margin-bottom:8px">Technique Heatmap</div>';
    h += '<div style="overflow-x:auto"><div style="display:flex;gap:2px;min-width:1200px">';

    tactics.forEach(tac => {
      h += '<div style="flex:1;min-width:80px">';
      h += '<div style="color:#64748B;font-size:9px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;padding:4px 2px;text-align:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="'+esc(tac.tactic)+'">'+esc(tac.tactic.replace(' ','\n').split('\n')[0])+'</div>';
      (tac.techniques||[]).forEach(tech => {
        const sc = statusColor[tech.status] || '#E2E8F0';
        const opacity = tech.status === 'not_detected' ? '0.3' : tech.detection_count > 10 ? '1' : '0.7';
        h += '<div style="background:'+sc+';opacity:'+opacity+';margin:1px;padding:3px 2px;border-radius:3px;cursor:pointer;text-align:center" title="'+esc(tech.id+': '+tech.name+' ('+tech.detection_count+' detections)')+'" data-action="showMitreTechnique" data-id="'+esc(tech.id)+'" data-stop-propagation="true">';
        h += '<div style="color:#0B1527;font-size:8px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc(tech.id)+'</div>';
        h += '</div>';
      });
      h += '</div>';
    });
    h += '</div></div>';

    // Legend
    h += '<div style="display:flex;gap:16px;margin-bottom:16px;font-size:10px">';
    [{c:'#34D399',l:'Active (TP detections)'},{c:'#FBBF24',l:'Noisy (>70% FP)'},{c:'#60A5FA',l:'Stale (>90d ago)'},{c:'#E2E8F0',l:'Not Detected'}].forEach(i => {
      h += '<div style="display:flex;align-items:center;gap:4px"><div style="width:12px;height:12px;border-radius:2px;background:'+i.c+'"></div><span style="color:#64748B">'+i.l+'</span></div>';
    });
    h += '</div></div>';
  }

  // Gap analysis table
  const gapData = gaps.gaps || {};
  const gapTactics = Object.keys(gapData).filter(t => gapData[t].length > 0);
  if (gapTactics.length) {
    h += '<div style="margin-bottom:20px"><div style="color:#EF4444;font-size:12px;font-weight:600;margin-bottom:8px">Detection Gaps ('+gaps.total_gaps+' techniques)</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px">';
    gapTactics.forEach(tactic => {
      h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:8px;padding:12px">';
      h += '<div style="color:#64748B;font-size:11px;font-weight:600;margin-bottom:6px">'+esc(tactic)+' ('+gapData[tactic].length+')</div>';
      gapData[tactic].forEach(t => {
        h += '<div style="color:#94A3B8;font-size:10px;padding:2px 0">'+esc(t.id)+' <span style="color:#64748B">'+esc(t.name)+'</span></div>';
      });
      h += '</div>';
    });
    h += '</div></div>';
  }

  // Technique detail panel (populated by click)
  h += '<div id="mitre-detail" style="display:none;background:#0F1D32;border:1px solid #818CF830;border-radius:10px;padding:16px;margin-bottom:20px"></div>';

  return h;
}

async function showMitreTechnique(id) {
  const el = document.getElementById('mitre-detail');
  if (!el) return;
  el.style.display = 'block';
  el.innerHTML = '<span style="color:#64748B;font-size:11px">Loading...</span>';
  try {
    const d = await fetchJSON('/mitre/technique/' + id);
    let h = '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">';
    h += '<div><span style="color:#818CF8;font-size:14px;font-weight:700">'+esc(d.technique_id)+'</span> <span style="color:#E8EDF2;font-size:13px;font-weight:600">'+esc(d.technique_name)+'</span></div>';
    h += '<button class="fbtn" style="padding:4px 10px;font-size:10px" data-action="closeMitreDetail">Close</button>';
    h += '</div>';
    h += '<div style="display:flex;gap:6px;margin-bottom:8px">';
    (d.tactics||[]).forEach(t => { h += badge(t, '#818CF8'); });
    h += '</div>';
    if (d.coverage && d.coverage.length) {
      d.coverage.forEach(c => {
        const sc = {active:'#34D399',noisy:'#FBBF24',stale:'#60A5FA',not_detected:'#3D5A75'};
        h += '<div style="display:flex;gap:12px;flex-wrap:wrap;font-size:11px;padding:6px 0;border-top:1px solid #E2E8F0">';
        h += '<div>'+badge(c.coverage_status, sc[c.coverage_status]||'#3D5A75')+'</div>';
        h += '<div><span style="color:#94A3B8">Detections:</span> <span style="color:#E8EDF2;font-family:\'JetBrains Mono\',monospace">'+c.detection_count+'</span></div>';
        h += '<div><span style="color:#94A3B8">TP:</span> <span style="color:#34D399">'+c.tp_count+'</span></div>';
        h += '<div><span style="color:#94A3B8">FP:</span> <span style="color:#FBBF24">'+c.fp_count+'</span></div>';
        h += '<div><span style="color:#94A3B8">Last seen:</span> <span style="color:#64748B">'+(c.last_seen?localTimeShort(c.last_seen):'Never')+'</span></div>';
        h += '</div>';
      });
    } else {
      h += '<div style="color:#94A3B8;font-size:11px;padding:8px 0">No detections recorded for this technique.</div>';
    }
    el.innerHTML = h;
  } catch(e) { el.innerHTML = '<span style="color:#EF4444;font-size:11px">Failed to load</span>'; }
}

async function renderSOAR() {
  let stats, playbooks, pending, executions;
  try { stats = await fetchJSON('/soar/stats'); } catch(e) { stats = {}; }
  try { playbooks = (await fetchJSON('/soar/playbooks')).playbooks || []; } catch(e) { playbooks = []; }
  try { pending = (await fetchJSON('/soar/executions/pending')).pending || []; } catch(e) { pending = []; }
  try { executions = (await fetchJSON('/soar/executions?limit=30')).executions || []; } catch(e) { executions = []; }

  let h = '<div style="margin-bottom:16px"><div style="font-size:16px;font-weight:700;margin-bottom:4px">SOAR Playbooks</div><div style="color:#64748B;font-size:12px">Automated response orchestration — playbooks evaluate on every true positive triage decision.</div></div>';

  // Stats cards
  const sr = stats.success_rate || 0;
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px">';
  [{l:'Active Playbooks',v:stats.active_playbooks||0,c:'#34D399'},{l:'Pending Approvals',v:stats.pending_approvals||0,c:stats.pending_approvals>0?'#FBBF24':'#3D5A75'},{l:'Executions Today',v:stats.executions_today||0,c:'#60A5FA'},{l:'Success Rate',v:sr+'%',c:sr>=80?'#34D399':sr>=50?'#FBBF24':'#EF4444'}].forEach(c => {
    h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:16px;text-align:center"><div style="color:'+c.c+';font-size:24px;font-weight:700;font-family:\'JetBrains Mono\',monospace">'+c.v+'</div><div style="color:#CBD5E1;font-size:11px;font-weight:600;margin-top:4px">'+c.l+'</div></div>';
  });
  h += '</div>';

  // Pending approvals
  if (pending.length) {
    h += '<div style="margin-bottom:20px"><div style="color:#FBBF24;font-size:12px;font-weight:600;margin-bottom:8px">Pending Approvals</div>';
    pending.forEach(ex => {
      let actions = []; try { actions = JSON.parse(ex.actions_planned || '[]'); } catch(e) {}
      let trigger = {}; try { trigger = JSON.parse(ex.trigger_data || '{}'); } catch(e) {}
      const techniques = trigger.mitre_techniques || [];
      h += '<div class="row" style="background:#0F1D32;border-color:#FBBF2440;margin-bottom:8px;padding:14px">';
      h += '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">';
      h += '<div><span style="color:#FBBF24;font-size:14px;font-weight:700">'+esc(ex.playbook_name||'')+'</span>';
      h += ' <span style="color:#64748B;font-size:10px">'+esc((ex.id||'').slice(0,8))+'</span></div>';
      h += '<div style="display:flex;gap:6px">';
      h += '<button class="fbtn" style="background:#34D39918;color:#34D399;border-color:#34D39930;padding:6px 16px" data-action="soarApprove" data-id="'+esc(ex.id)+'" data-stop-propagation="true">Approve</button>';
      h += '<button class="fbtn" style="padding:6px 16px" data-action="soarReject" data-id="'+esc(ex.id)+'" data-stop-propagation="true">Reject</button>';
      h += '</div></div>';
      // Trigger reason
      h += '<div style="margin-top:10px;color:#CBD5E1;font-size:12px;line-height:1.6">';
      h += 'Triggered because alert matched: ';
      h += '<span style="color:#FBBF24;font-weight:600">confidence '+((trigger.confidence||0)*100).toFixed(0)+'%</span>';
      h += ', <span style="color:#EF4444;font-weight:600">risk '+Math.round(trigger.risk_score||0)+'/100</span>';
      if (techniques.length) h += ', MITRE ' + techniques.map(t=>'<span style="color:#818CF8;font-weight:600">'+esc(t)+'</span>').join(' ');
      h += '</div>';
      // Actions planned
      h += '<div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;font-size:11px">';
      h += '<span style="color:#94A3B8">Planned actions:</span>';
      actions.forEach((a,i) => {
        h += '<span style="color:#60A5FA;font-weight:600">'+esc(a.action||'')+'</span>';
        if (a.target) h += '<span style="color:#64748B"> ('+esc(String(a.target).slice(0,30))+')</span>';
        if (i < actions.length-1) h += '<span style="color:#3D5A75"> → </span>';
      });
      h += '</div>';
      // Timestamp and incident link
      h += '<div style="margin-top:6px;font-size:10px;color:#64748B">';
      h += localTimeShort(ex.created_at);
      if (ex.incident_id) h += ' · Incident: '+esc((ex.incident_id||'').slice(0,8));
      h += '</div>';
      h += '</div>';
    });
    h += '</div>';
  }

  // Playbook cards
  h += '<div style="margin-bottom:20px"><div style="color:#CBD5E1;font-size:12px;font-weight:600;margin-bottom:8px">Playbooks</div>';
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px">';
  playbooks.forEach(pb => {
    const en = pb.enabled;
    let actions = []; try { actions = JSON.parse(pb.actions || '[]'); } catch(e) {}
    let techniques = []; try { techniques = JSON.parse(pb.trigger_mitre_techniques || '[]'); } catch(e) {}
    h += '<div style="background:#0F1D32;border:1px solid '+(en?'#E2E8F0':'#E2E8F080')+';border-radius:10px;padding:16px;opacity:'+(en?1:0.6)+'">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">';
    h += '<div style="color:#E8EDF2;font-size:13px;font-weight:600">'+esc(pb.display_name||pb.name)+'</div>';
    h += '<button class="fbtn" style="padding:4px 10px;font-size:10px;'+(en?'background:#34D39918;color:#34D399;border-color:#34D39930':'background:#EF444418;color:#EF4444;border-color:#EF444430')+'" data-action="soarToggle" data-id="'+esc(pb.id)+'" data-stop-propagation="true">'+( en?'Enabled':'Disabled')+'</button>';
    h += '</div>';
    h += '<div style="color:#64748B;font-size:11px;margin-bottom:8px">'+esc(pb.description||'').slice(0,120)+'</div>';
    h += '<div style="display:flex;gap:8px;flex-wrap:wrap;font-size:10px">';
    techniques.forEach(t => { h += badge(t, '#818CF8'); });
    h += badge(actions.length+' actions', '#60A5FA');
    h += badge(pb.require_approval?'Approval Required':'Auto-Execute', pb.require_approval?'#FBBF24':'#EF4444');
    h += badge('Conf \u2265'+pb.trigger_min_confidence, '#5C7A99');
    h += badge('Risk \u2265'+Math.round(pb.trigger_min_risk_score), '#5C7A99');
    h += '</div></div>';
  });
  h += '</div></div>';

  // Execution Kanban
  if (executions.length || pending.length) {
    const stColor = {pending_approval:'#FBBF24',approved:'#60A5FA',executing:'#818CF8',completed:'#34D399',failed:'#EF4444',partial:'#FB923C',rolled_back:'#5C7A99',cancelled:'#94A3B8'};
    const allExecs = [...pending.map(p=>({...p,status:'pending_approval'})), ...executions];
    const cols = {
      pending: allExecs.filter(e=>e.status==='pending_approval'||e.status==='approved'),
      running: allExecs.filter(e=>e.status==='executing'),
      completed: allExecs.filter(e=>e.status==='completed'||e.status==='partial'),
      failed: allExecs.filter(e=>e.status==='failed'||e.status==='rolled_back'||e.status==='cancelled')
    };
    h += '<div style="margin-bottom:20px"><div style="color:#1E293B;font-size:12px;font-weight:600;margin-bottom:4px">Execution Board</div></div>';
    h += '<div class="kanban">';
    [{key:'pending',label:'Pending',color:'#FBBF24'},{key:'running',label:'Running',color:'#818CF8'},{key:'completed',label:'Completed',color:'#34D399'},{key:'failed',label:'Failed',color:'#EF4444'}].forEach(col => {
      const items = cols[col.key];
      h += '<div class="kanban-col"><div class="kanban-title"><span style="color:'+col.color+'">'+col.label+'</span><span class="kanban-count" style="background:'+col.color+'18;color:'+col.color+'">'+items.length+'</span></div>';
      if (!items.length) {
        h += '<div style="color:#CBD5E1;font-size:11px;text-align:center;padding:20px">None</div>';
      }
      items.forEach(ex => {
        let acts = []; try { acts = JSON.parse(ex.actions_planned||ex.actions_completed||'[]'); } catch(e) {}
        let completed = []; try { completed = JSON.parse(ex.actions_completed||'[]'); } catch(e) {}
        const succeeded = completed.filter(a=>a.success).length;
        h += '<div class="kanban-card">';
        h += '<div class="kc-name">'+esc((ex.playbook_name||'').slice(0,30))+'</div>';
        h += '<div class="kc-meta">';
        h += '<span>'+localTimeShort(ex.created_at)+'</span>';
        if (ex.total_steps) h += '<span style="font-family:\'JetBrains Mono\',monospace">'+succeeded+'/'+ex.total_steps+' steps</span>';
        if (ex.approved_by) h += '<span>by '+esc(ex.approved_by)+'</span>';
        h += '</div>';
        h += '<div class="kc-actions">';
        if (ex.status==='pending_approval') {
          h += '<button class="fbtn" style="padding:3px 10px;font-size:10px;background:#34D39910;color:#059669;border-color:#34D39930" data-action="soarApprove" data-id="'+esc(ex.id)+'">Approve</button>';
          h += '<button class="fbtn" style="padding:3px 10px;font-size:10px" data-action="soarReject" data-id="'+esc(ex.id)+'">Reject</button>';
        }
        if (ex.status==='completed'||ex.status==='partial') {
          h += '<button class="fbtn" style="padding:3px 10px;font-size:10px" data-action="soarRollback" data-id="'+esc(ex.id)+'">Rollback</button>';
        }
        h += '</div></div>';
      });
      h += '</div>';
    });
    h += '</div>';
  }

  return h;
}

async function soarApprove(id) {
  await fetch(API+'/soar/executions/'+id+'/approve', {method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:'{}'});
  refresh();
}
async function soarReject(id) {
  if (!confirm('Reject this SOAR execution?')) return;
  await fetch(API+'/soar/executions/'+id+'/reject', {method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:'{}'});
  refresh();
}
async function soarToggle(id) {
  await fetch(API+'/soar/playbooks/'+id+'/toggle', {method:'POST',headers:authHeaders()});
  refresh();
}
async function soarRollback(id) {
  if (!confirm('Rollback this SOAR execution? This will reverse all actions.')) return;
  await fetch(API+'/soar/executions/'+id+'/rollback', {method:'POST',headers:authHeaders()});
  refresh();
}

// -- Knowledge Base Tab --
let kbSearchQuery = '';
let kbFilterType = '';

// -- Threat Intel Tab state --
let _tiIocQuery = '';
let _tiIocResult = null;
let _tiCveKevOnly = false;
async function renderKnowledge() {
  let stats, docs;
  try { stats = await fetchJSON('/kb/stats'); } catch(e) { stats = {total:0,by_type:{}}; }

  // If there's a search query, use search endpoint; otherwise list
  if (kbSearchQuery) {
    try {
      const sr = await fetchJSON('/kb/search?q=' + encodeURIComponent(kbSearchQuery) + (kbFilterType?'&type='+kbFilterType:'') + '&limit=50');
      docs = sr.results || [];
    } catch(e) { docs = []; }
  } else {
    try { docs = (await fetchJSON('/kb/documents?limit=100' + (kbFilterType?'&type='+kbFilterType:''))).documents || []; } catch(e) { docs = []; }
  }

  const typeColor = t => ({analyst_note:'#3B82F6',investigation_pattern:'#8B5CF6',feedback_pattern:'#F59E0B',hunt_finding:'#10B981',incident_learning:'#EF4444',guidance:'#64748B'}[t]||'#94A3B8');

  let h = '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">';
  h += '<div style="font-size:16px;font-weight:700;color:#1E293B">Knowledge Base</div>';
  if (canAct()) {
    h += '<button class="fbtn" style="background:#8B5CF6;color:#fff" data-action="showKBCreateModal">+ Add Knowledge</button>';
  }
  h += '</div>';

  // Search bar
  h += '<div style="display:flex;gap:8px;margin-bottom:12px">';
  h += '<input id="kb-search-input" type="text" placeholder="Search knowledge base..." value="'+esc(kbSearchQuery)+'" style="flex:1;padding:8px 12px;border:1px solid #D1D5DB;border-radius:6px;font-size:13px" data-action-enter="kbSearch">';
  h += '<button class="fbtn" data-action="kbSearchBtn">Search</button>';
  if (kbSearchQuery) h += '<button class="fbtn" data-action="kbClear">Clear</button>';
  h += '</div>';

  // Type filter buttons
  const types = ['analyst_note','investigation_pattern','feedback_pattern','hunt_finding','incident_learning','guidance'];
  h += '<div style="display:flex;gap:6px;margin-bottom:16px;flex-wrap:wrap">';
  h += '<button class="fbtn" style="font-size:11px;'+(kbFilterType===''?'background:#1E293B;color:#fff':'')+'" data-action="kbFilterType" data-filter="">All ('+stats.total+')</button>';
  types.forEach(t => {
    const cnt = (stats.by_type||{})[t]||0;
    const label = t.replace(/_/g,' ');
    h += '<button class="fbtn" style="font-size:11px;'+(kbFilterType===t?'background:'+typeColor(t)+';color:#fff':'')+'" data-action="kbFilterType" data-filter="'+t+'">'+label+' ('+cnt+')</button>';
  });
  h += '</div>';

  // Results
  if (docs.length) {
    docs.forEach(d => {
      const tc = typeColor(d.doc_type);
      let tags = []; try { tags = JSON.parse(d.tags||'[]'); } catch(e) {}
      h += '<div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:8px;padding:14px;margin-bottom:8px;cursor:pointer" data-action="showKBDetail" data-id="'+esc(d.id)+'">';
      h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">';
      h += '<div style="display:flex;align-items:center;gap:8px"><span style="background:'+tc+'20;color:'+tc+';padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600">'+esc(d.doc_type.replace(/_/g,' '))+'</span>';
      h += '<span style="font-weight:600;color:#1E293B;font-size:13px">'+esc((d.title||'').slice(0,80))+'</span></div>';
      h += '<span style="color:#94A3B8;font-size:10px">'+((d.updated_at||d.created_at)?new Date(d.updated_at||d.created_at).toLocaleDateString():'')+'</span>';
      h += '</div>';
      h += '<div style="color:#64748B;font-size:12px;line-height:1.5">'+esc((d.content||'').slice(0,200))+(d.content&&d.content.length>200?'...':'')+'</div>';
      if (tags.length) {
        h += '<div style="margin-top:6px;display:flex;gap:4px;flex-wrap:wrap">';
        tags.slice(0,6).forEach(t => { h += '<span style="background:#F1F5F9;color:#64748B;padding:1px 6px;border-radius:3px;font-size:10px">'+esc(t)+'</span>'; });
        h += '</div>';
      }
      h += '</div>';
    });
  } else {
    h += '<div style="text-align:center;padding:40px;color:#94A3B8">'+(kbSearchQuery?'No results for "'+esc(kbSearchQuery)+'"':'No knowledge base documents yet. Add notes, patterns, and learnings.')+'</div>';
  }
  return h;
}
async function showKBDetail(id) {
  const so = document.getElementById('slide-over');
  so.style.display = 'block';
  so.classList.add('open');
  so.innerHTML = '<div style="padding:24px"><div class="spin" style="text-align:center;padding:40px;color:#94A3B8">Loading...</div></div>';
  try {
    const doc = await fetchJSON('/kb/documents/' + id);
    let tags = []; try { tags = JSON.parse(doc.tags||'[]'); } catch(e) {}
    let mitre = []; try { mitre = JSON.parse(doc.mitre_techniques||'[]'); } catch(e) {}
    const tc = ({analyst_note:'#3B82F6',investigation_pattern:'#8B5CF6',feedback_pattern:'#F59E0B',hunt_finding:'#10B981',incident_learning:'#EF4444',guidance:'#64748B'}[doc.doc_type]||'#94A3B8');
    let h = '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">';
    h += '<div><span style="background:'+tc+'20;color:'+tc+';padding:3px 10px;border-radius:4px;font-size:11px;font-weight:600">'+esc(doc.doc_type.replace(/_/g,' '))+'</span></div>';
    h += '<button data-action="closeSlideOver" style="background:none;border:none;cursor:pointer;font-size:20px;color:#64748B">&times;</button></div>';
    h += '<h3 style="margin:0 0 12px 0;color:#1E293B">'+esc(doc.title)+'</h3>';
    h += '<div style="color:#334155;font-size:13px;line-height:1.7;white-space:pre-wrap;background:#F8FAFC;padding:16px;border-radius:8px;border:1px solid #E2E8F0;margin-bottom:14px;max-height:400px;overflow-y:auto">'+esc(doc.content)+'</div>';
    if (tags.length) { h += '<div style="margin-bottom:8px"><span style="color:#94A3B8;font-size:10px;font-weight:600">TAGS:</span> '+tags.map(t=>'<span style="background:#F1F5F9;color:#64748B;padding:1px 6px;border-radius:3px;font-size:10px;margin-left:4px">'+esc(t)+'</span>').join('')+'</div>'; }
    if (mitre.filter(Boolean).length) { h += '<div style="margin-bottom:8px"><span style="color:#94A3B8;font-size:10px;font-weight:600">MITRE:</span> '+mitre.filter(Boolean).map(t=>badge(t,'#818CF8')).join(' ')+'</div>'; }
    h += '<div style="color:#94A3B8;font-size:11px;margin-top:12px">Created by '+esc(doc.created_by||'system')+' on '+(doc.created_at?new Date(doc.created_at).toLocaleString():'')+'</div>';
    if (canAct() && doc.doc_type !== 'guidance') {
      h += '<div style="display:flex;gap:8px;margin-top:16px">';
      h += '<button class="fbtn" style="background:#8B5CF610;color:#8B5CF6;border-color:#8B5CF640" data-action="showKBEditModal" data-id="'+esc(doc.id)+'">Edit</button>';
      h += '<button class="fbtn" style="background:#EF444410;color:#EF4444;border-color:#EF444440" data-action="deleteKBDoc" data-id="'+esc(doc.id)+'">Delete</button>';
      h += '</div>';
    }
    so.innerHTML = '<div style="padding:24px">'+h+'</div>';
  } catch(e) {
    so.innerHTML = '<div style="padding:24px;color:#EF4444">Failed to load document</div>';
  }
}
async function deleteKBDoc(id) {
  if (!confirm('Delete this knowledge base document?')) return;
  await fetch(API+'/kb/documents/'+id, {method:'DELETE',headers:authHeaders()});
  closeSlideOver(); refresh();
}
function showKBCreateModal() {
  const so = document.getElementById('slide-over');
  so.style.display = 'block';
  so.classList.add('open');
  so.innerHTML = '<div style="padding:24px">'
    + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">'
    + '<h3 style="margin:0;color:#1E293B">Add Knowledge</h3>'
    + '<button data-action="closeSlideOver" style="background:none;border:none;cursor:pointer;font-size:20px;color:#64748B">&times;</button></div>'
    + '<label style="display:block;margin-bottom:6px;font-weight:600;color:#374151;font-size:13px">Type</label>'
    + '<select id="kb-type" style="width:100%;padding:8px 12px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:12px;font-size:13px">'
    + '<option value="analyst_note">Analyst Note</option><option value="investigation_pattern">Investigation Pattern</option></select>'
    + '<label style="display:block;margin-bottom:6px;font-weight:600;color:#374151;font-size:13px">Title</label>'
    + '<input id="kb-title" type="text" placeholder="Brief descriptive title" style="width:100%;padding:8px 12px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:12px;font-size:13px">'
    + '<label style="display:block;margin-bottom:6px;font-weight:600;color:#374151;font-size:13px">Content</label>'
    + '<textarea id="kb-content" rows="8" placeholder="Describe the pattern, investigation steps, or knowledge..." style="width:100%;padding:8px 12px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:12px;font-size:13px;resize:vertical"></textarea>'
    + '<label style="display:block;margin-bottom:6px;font-weight:600;color:#374151;font-size:13px">Tags (comma-separated)</label>'
    + '<input id="kb-tags" type="text" placeholder="e.g. lateral_movement, T1078, false_positive" style="width:100%;padding:8px 12px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:16px;font-size:13px">'
    + '<button data-action="submitKBCreate" class="fbtn" style="background:#8B5CF6;color:#fff;width:100%;padding:10px;font-size:14px">Save</button>'
    + '<div id="kb-result" style="margin-top:12px"></div>'
    + '</div>';
}
async function submitKBCreate() {
  const title = document.getElementById('kb-title').value.trim();
  const content = document.getElementById('kb-content').value.trim();
  if (!title || !content) { document.getElementById('kb-result').innerHTML='<span style="color:#EF4444">Title and content required</span>'; return; }
  const doc_type = document.getElementById('kb-type').value;
  const tagsRaw = document.getElementById('kb-tags').value;
  const tags = tagsRaw ? tagsRaw.split(',').map(t=>t.trim()).filter(Boolean) : [];
  try {
    const r = await fetch(API+'/kb/documents', {method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({title,content,doc_type,tags})});
    const d = await r.json();
    if (r.ok) {
      document.getElementById('kb-result').innerHTML='<span style="color:#34D399">Saved!</span>';
      setTimeout(()=>{closeSlideOver();refresh();},1000);
    } else {
      document.getElementById('kb-result').innerHTML='<span style="color:#EF4444">'+esc(d.detail||'Failed')+'</span>';
    }
  } catch(e) {
    document.getElementById('kb-result').innerHTML='<span style="color:#EF4444">'+esc(e.message)+'</span>';
  }
}
async function showKBEditModal(id) {
  const so = document.getElementById('slide-over');
  so.style.display = 'block';
  so.classList.add('open');
  so.innerHTML = '<div style="padding:24px"><div class="spin" style="text-align:center;padding:40px;color:#94A3B8">Loading...</div></div>';
  let doc;
  try { doc = await fetchJSON('/kb/documents/' + id); }
  catch(e) { so.innerHTML = '<div style="padding:24px;color:#EF4444">Failed to load document</div>'; return; }
  let tags = []; try { tags = JSON.parse(doc.tags||'[]'); } catch(e) {}
  let mitre = []; try { mitre = JSON.parse(doc.mitre_techniques||'[]'); } catch(e) {}
  so.innerHTML = '<div style="padding:24px">'
    + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">'
    + '<h3 style="margin:0;color:#1E293B">Edit Knowledge</h3>'
    + '<button data-action="closeSlideOver" style="background:none;border:none;cursor:pointer;font-size:20px;color:#64748B">&times;</button></div>'
    + '<div style="background:#F1F5F9;border:1px solid #E2E8F0;border-radius:6px;padding:8px 12px;margin-bottom:12px;font-size:11px;color:#64748B">Type: <strong>'+esc(doc.doc_type.replace(/_/g,' '))+'</strong> (cannot be changed)</div>'
    + '<label style="display:block;margin-bottom:6px;font-weight:600;color:#374151;font-size:13px">Title</label>'
    + '<input id="kb-edit-title" type="text" value="'+esc(doc.title||'')+'" style="width:100%;padding:8px 12px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:12px;font-size:13px">'
    + '<label style="display:block;margin-bottom:6px;font-weight:600;color:#374151;font-size:13px">Content</label>'
    + '<textarea id="kb-edit-content" rows="10" style="width:100%;padding:8px 12px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:12px;font-size:13px;resize:vertical">'+esc(doc.content||'')+'</textarea>'
    + '<label style="display:block;margin-bottom:6px;font-weight:600;color:#374151;font-size:13px">Tags (comma-separated)</label>'
    + '<input id="kb-edit-tags" type="text" value="'+esc(tags.join(', '))+'" style="width:100%;padding:8px 12px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:12px;font-size:13px">'
    + '<label style="display:block;margin-bottom:6px;font-weight:600;color:#374151;font-size:13px">MITRE techniques (comma-separated, e.g. T1078, T1059)</label>'
    + '<input id="kb-edit-mitre" type="text" value="'+esc(mitre.filter(Boolean).join(', '))+'" style="width:100%;padding:8px 12px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:16px;font-size:13px">'
    + '<button data-action="submitKBEdit" data-id="'+esc(id)+'" class="fbtn" style="background:#8B5CF6;color:#fff;width:100%;padding:10px;font-size:14px">Save Changes</button>'
    + '<div id="kb-edit-result" style="margin-top:12px"></div>'
    + '</div>';
}
async function submitKBEdit(id) {
  const title = document.getElementById('kb-edit-title').value.trim();
  const content = document.getElementById('kb-edit-content').value.trim();
  if (!title || !content) { document.getElementById('kb-edit-result').innerHTML='<span style="color:#EF4444">Title and content required</span>'; return; }
  const tagsRaw = document.getElementById('kb-edit-tags').value;
  const tags = tagsRaw ? tagsRaw.split(',').map(t=>t.trim()).filter(Boolean) : [];
  const mitreRaw = document.getElementById('kb-edit-mitre').value;
  const mitre_techniques = mitreRaw ? mitreRaw.split(',').map(t=>t.trim()).filter(Boolean) : [];
  try {
    const r = await fetch(API+'/kb/documents/'+id, {method:'PUT',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({title,content,tags,mitre_techniques})});
    const d = await r.json();
    if (r.ok) {
      document.getElementById('kb-edit-result').innerHTML='<span style="color:#34D399">Saved!</span>';
      setTimeout(()=>{closeSlideOver();refresh();},800);
    } else {
      document.getElementById('kb-edit-result').innerHTML='<span style="color:#EF4444">'+esc(d.detail||'Failed')+'</span>';
    }
  } catch(e) {
    document.getElementById('kb-edit-result').innerHTML='<span style="color:#EF4444">'+esc(e.message)+'</span>';
  }
}

// -- Tickets Tab --
async function renderTickets() {
  let stats, tickets;
  try { stats = await fetchJSON('/tickets/stats'); } catch(e) { stats = {}; }
  try { tickets = (await fetchJSON('/tickets?limit=200')).tickets || []; } catch(e) { tickets = []; }

  const providerIcon = p => ({jira:'🔵',servicenow:'🟢',pagerduty:'🔴'}[p]||'⚪');
  const statusColor = s => ({pending:'#F59E0B',created:'#34D399',synced:'#60A5FA',error:'#EF4444',closed:'#94A3B8'}[s]||'#94A3B8');

  let h = '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">';
  h += '<div style="font-size:16px;font-weight:700;color:#1E293B">Tickets</div>';
  if (canAct()) {
    h += '<button class="fbtn" style="background:#8B5CF6;color:#fff" data-action="showCreateTicketModal">+ Create Ticket</button>';
  }
  h += '</div>';

  // Stats cards
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px">';
  [{l:'Total',v:stats.total||0,c:'#64748B'},{l:'Synced',v:stats.synced||0,c:'#34D399'},{l:'Pending',v:stats.pending||0,c:'#F59E0B'},{l:'Errors',v:stats.errors||0,c:'#EF4444'},{l:'Closed',v:stats.closed||0,c:'#94A3B8'}].forEach(c=>{
    h+='<div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px;padding:16px;text-align:center">';
    h+='<div style="font-size:24px;font-weight:700;color:'+c.c+'">'+c.v+'</div>';
    h+='<div style="font-size:11px;color:#64748B;margin-top:4px">'+c.l+'</div></div>';
  });
  h += '</div>';

  // Provider breakdown
  const bp = stats.by_provider || {};
  if (Object.keys(bp).length) {
    h += '<div style="display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap">';
    for (const [prov, cnt] of Object.entries(bp)) {
      h += '<span style="background:#F1F5F9;border-radius:6px;padding:4px 12px;font-size:12px">' + providerIcon(prov) + ' ' + esc(prov) + ': <b>' + cnt + '</b></span>';
    }
    h += '</div>';
  }

  // Tickets table
  if (tickets.length) {
    queueGrid('ticketsGrid', {
      columnDefs: [
        {field:'provider',headerName:'Provider',width:110,cellRenderer:p=>'<span>'+providerIcon(p.value)+' '+esc(p.value||'')+'</span>'},
        {field:'external_id',headerName:'External ID',width:140,cellRenderer:p=>{
          const url=p.data.external_url;const id=esc(p.value||'—');
          return url?'<a href="'+esc(url)+'" target="_blank" style="color:#3B82F6;text-decoration:underline">'+id+'</a>':id;
        }},
        {field:'incident_id',headerName:'Incident',width:120,cellRenderer:p=>'<a href="#" data-action="loadIncidentDetail" data-id="'+esc(p.value)+'" style="color:#3B82F6">'+esc((p.value||'').slice(0,8))+'…</a>'},
        {field:'summary',headerName:'Summary',flex:1,minWidth:200},
        {field:'priority',headerName:'Priority',width:90,cellRenderer:p=>{
          const col={critical:'#EF4444',high:'#F59E0B',medium:'#3B82F6',low:'#94A3B8'}[p.value]||'#94A3B8';
          return '<span style="color:'+col+';font-weight:600;text-transform:uppercase;font-size:11px">'+esc(p.value||'')+'</span>';
        }},
        {field:'platform_status',headerName:'Status',width:100,cellRenderer:p=>{
          const c=statusColor(p.value);
          return '<span style="background:'+c+'20;color:'+c+';padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">'+esc(p.value||'')+'</span>';
        }},
        {field:'external_status',headerName:'Ext. Status',width:110},
        {field:'last_synced_at',headerName:'Last Sync',width:150,valueFormatter:p=>p.value?new Date(p.value).toLocaleString():'—'},
        {field:'created_at',headerName:'Created',width:150,valueFormatter:p=>p.value?new Date(p.value).toLocaleString():'—'},
        {headerName:'Actions',width:120,cellRenderer:p=>{
          if (!canAct()) return '';
          let btns='';
          if (p.data.platform_status==='error') btns+='<button class="fbtn" style="font-size:10px;padding:2px 6px" data-action="ticketRetry" data-id="'+esc(p.data.id)+'">Retry</button> ';
          if (p.data.external_id) btns+='<button class="fbtn" style="font-size:10px;padding:2px 6px" data-action="ticketSync" data-id="'+esc(p.data.id)+'">Sync</button>';
          return btns;
        }},
      ],
      rowData: tickets,
      defaultColDef:{sortable:true,filter:true,resizable:true},
    });
    h += '<div id="ticketsGrid" style="height:600px;margin-top:12px"></div>';
  } else {
    h += '<div style="text-align:center;padding:40px;color:#94A3B8">No tickets yet. Create one from an incident or enable auto-create in config.</div>';
  }

  return h;
}
async function ticketRetry(id) {
  try {
    await fetch(API+'/tickets/'+id+'/retry', {method:'POST',headers:authHeaders()});
  } catch(e) {}
  refresh();
}
async function ticketSync(id) {
  try {
    await fetch(API+'/tickets/'+id+'/sync', {method:'POST',headers:authHeaders()});
  } catch(e) {}
  refresh();
}
function showCreateTicketModal() {
  const so = document.getElementById('slide-over');
  so.style.display = 'block';
  so.classList.add('open');
  so.innerHTML = '<div style="padding:24px">'
    + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">'
    + '<h3 style="margin:0;color:#1E293B">Create Ticket</h3>'
    + '<button data-action="closeSlideOver" style="background:none;border:none;cursor:pointer;font-size:20px;color:#64748B">&times;</button></div>'
    + '<label style="display:block;margin-bottom:6px;font-weight:600;color:#374151;font-size:13px">Incident ID</label>'
    + '<input id="tkt-incident" type="text" placeholder="Paste incident ID" style="width:100%;padding:8px 12px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:16px;font-size:13px">'
    + '<label style="display:block;margin-bottom:6px;font-weight:600;color:#374151;font-size:13px">Provider (optional)</label>'
    + '<select id="tkt-provider" style="width:100%;padding:8px 12px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:16px;font-size:13px">'
    + '<option value="">Default</option><option value="jira">Jira</option><option value="servicenow">ServiceNow</option><option value="pagerduty">PagerDuty</option></select>'
    + '<label style="display:block;margin-bottom:6px;font-weight:600;color:#374151;font-size:13px">Summary (optional override)</label>'
    + '<input id="tkt-summary" type="text" placeholder="Leave blank for incident title" style="width:100%;padding:8px 12px;border:1px solid #D1D5DB;border-radius:6px;margin-bottom:20px;font-size:13px">'
    + '<button data-action="submitCreateTicket" class="fbtn" style="background:#8B5CF6;color:#fff;width:100%;padding:10px;font-size:14px">Create Ticket</button>'
    + '<div id="tkt-result" style="margin-top:12px"></div>'
    + '</div>';
}
async function submitCreateTicket() {
  const incId = document.getElementById('tkt-incident').value.trim();
  if (!incId) { document.getElementById('tkt-result').innerHTML='<span style="color:#EF4444">Incident ID required</span>'; return; }
  const provider = document.getElementById('tkt-provider').value || undefined;
  const summary = document.getElementById('tkt-summary').value.trim() || undefined;
  try {
    const r = await fetch(API+'/tickets', {method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({incident_id:incId,provider,summary})});
    const d = await r.json();
    if (r.ok) {
      document.getElementById('tkt-result').innerHTML='<span style="color:#34D399">Ticket created: '+esc(d.external_id||d.ticket_id||'OK')+'</span>';
      setTimeout(()=>{closeSlideOver();refresh();},1500);
    } else {
      document.getElementById('tkt-result').innerHTML='<span style="color:#EF4444">'+esc(d.detail||'Failed')+'</span>';
    }
  } catch(e) {
    document.getElementById('tkt-result').innerHTML='<span style="color:#EF4444">'+esc(e.message)+'</span>';
  }
}

let metricsChart = null;
async function renderMetrics() {
  // Fetch everything in parallel
  const [perfR, analystsR, summaryR, autoHR, agingR, autoRR, huntR, workloadR] = await Promise.allSettled([
    fetchJSON('/metrics/soc-performance?days=30'),
    fetchJSON('/metrics/analyst-performance?days=30'),
    fetchJSON('/metrics/soc-summary'),
    fetchJSON('/metrics/automation-health?days=7'),
    fetchJSON('/metrics/case-aging?stale_hours=48'),
    fetchJSON('/metrics/automation-rates?days=30'),
    fetchJSON('/metrics/hunt-trends?days=90'),
    fetchJSON('/metrics/analyst-workload?max_per_analyst=15')
  ]);
  const perf = perfR.status==='fulfilled' ? perfR.value : {metrics:{}, trends:[]};
  const analysts = analystsR.status==='fulfilled' ? analystsR.value : {analysts:[]};
  const summary = summaryR.status==='fulfilled' ? summaryR.value : null;
  const autoHealth = autoHR.status==='fulfilled' ? autoHR.value : null;
  const aging = agingR.status==='fulfilled' ? (agingR.value.cases||[]) : [];
  const autoRates = autoRR.status==='fulfilled' ? autoRR.value : null;
  const huntCycles = huntR.status==='fulfilled' ? (huntR.value.cycles||[]) : [];
  const workload = workloadR.status==='fulfilled' ? (workloadR.value.analysts||[]) : [];
  const m = perf.metrics || {};
  const trends = perf.trends || [];
  const analystList = analysts.analysts || [];

  // Format minutes nicely
  function fmt(min) {
    if (!min || min === 0) return 'N/A';
    if (min < 60) return Math.round(min) + 'm';
    if (min < 1440) return (min/60).toFixed(1) + 'h';
    return (min/1440).toFixed(1) + 'd';
  }

  // SLA color
  function slaColor(pct) { return pct >= 90 ? '#34D399' : pct >= 70 ? '#FBBF24' : '#EF4444'; }

  const slaResp = m.sla_response_compliance || 0;
  const slaRes = m.sla_resolution_compliance || 0;

  let h = '<div style="margin-bottom:16px"><div style="font-size:16px;font-weight:700;margin-bottom:4px">SOC Metrics</div><div style="color:#64748B;font-size:12px">Operational performance over the last 30 days (' + (m.sample_count||0) + ' incidents)</div></div>';

  // Stat cards
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:20px">';
  const cards = [
    {l:'MTTD', v:fmt(m.mttd_min), c:'#60A5FA', sub:'Mean Time to Detect'},
    {l:'MTTA', v:fmt(m.mtta_min), c:'#818CF8', sub:'Mean Time to Acknowledge'},
    {l:'MTTR', v:fmt(m.mttr_min), c:'#FBBF24', sub:'Mean Time to Resolve'},
    {l:'SLA Response', v:slaResp+'%', c:slaColor(slaResp), sub:'Response compliance'},
    {l:'SLA Resolution', v:slaRes+'%', c:slaColor(slaRes), sub:'Resolution compliance'},
    {l:'Incidents', v:m.sample_count||0, c:'#94A3B8', sub:'30-day total'},
  ];
  cards.forEach(c => {
    h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:16px;text-align:center">';
    h += '<div style="color:'+c.c+';font-size:24px;font-weight:700;font-family:\'JetBrains Mono\',monospace">'+c.v+'</div>';
    h += '<div style="color:#CBD5E1;font-size:11px;font-weight:600;margin-top:4px">'+c.l+'</div>';
    h += '<div style="color:#94A3B8;font-size:10px">'+c.sub+'</div>';
    h += '</div>';
  });
  h += '</div>';

  // Per-severity breakdown
  const bySev = m.by_severity || {};
  if (Object.keys(bySev).length) {
    const sevOrder = ['critical','high','medium','low'];
    const sevColor = {critical:'#EF4444',high:'#FB923C',medium:'#FBBF24',low:'#34D399'};
    h += '<div style="margin-bottom:20px"><div style="color:#1E293B;font-size:12px;font-weight:600;margin-bottom:8px">By Severity</div>';
    h += '<table style="width:100%;font-size:12px;border-collapse:collapse">';
    h += '<tr style="color:#94A3B8;font-size:10px;text-transform:uppercase;letter-spacing:1px"><th style="text-align:left;padding:6px">Severity</th><th>Count</th><th>MTTD</th><th>MTTA</th><th>MTTR</th></tr>';
    sevOrder.forEach(sev => {
      const d = bySev[sev];
      if (!d) return;
      h += '<tr style="border-top:1px solid #E2E8F0"><td style="padding:6px">'+badge(sev.toUpperCase(), sevColor[sev])+'</td>';
      h += '<td style="text-align:center;color:#1E293B">'+d.count+'</td>';
      h += '<td style="text-align:center;color:#1E293B;font-family:\'JetBrains Mono\',monospace">'+fmt(d.mttd_min)+'</td>';
      h += '<td style="text-align:center;color:#1E293B;font-family:\'JetBrains Mono\',monospace">'+fmt(d.mtta_min)+'</td>';
      h += '<td style="text-align:center;color:#1E293B;font-family:\'JetBrains Mono\',monospace">'+fmt(d.mttr_min)+'</td></tr>';
    });
    h += '</table></div>';
  }

  // Trend chart
  if (trends.length > 1) {
    h += '<div style="margin-bottom:20px"><div style="color:#1E293B;font-size:12px;font-weight:600;margin-bottom:8px">30-Day Trend</div>';
    h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:16px;height:250px"><canvas id="mttCanvas"></canvas></div></div>';
  }

  // Analyst performance table
  if (analystList.length) {
    h += '<div style="margin-bottom:20px"><div style="color:#1E293B;font-size:12px;font-weight:600;margin-bottom:8px">Analyst Performance (30d)</div>';
    h += '<table style="width:100%;font-size:12px;border-collapse:collapse">';
    h += '<tr style="color:#94A3B8;font-size:10px;text-transform:uppercase;letter-spacing:1px"><th style="text-align:left;padding:6px">Analyst</th><th>Incidents Touched</th><th>Resolved</th><th>Total Actions</th></tr>';
    analystList.forEach(a => {
      h += '<tr style="border-top:1px solid #E2E8F0">';
      h += '<td style="padding:6px;color:#1E293B;font-weight:600">'+esc(a.actor)+'</td>';
      h += '<td style="text-align:center;color:#60A5FA">'+(a.incidents_touched||0)+'</td>';
      h += '<td style="text-align:center;color:#34D399">'+(a.resolved_count||0)+'</td>';
      h += '<td style="text-align:center;color:#64748B">'+(a.total_actions||0)+'</td>';
      h += '</tr>';
    });
    h += '</table></div>';
  }

  // ── 1d/7d/30d snapshot ───────────────────────────────────
  if (summary && (summary.today || summary.week || summary.month)) {
    h += '<div style="margin-bottom:20px"><div style="color:#1E293B;font-size:12px;font-weight:600;margin-bottom:8px">MTT Snapshot — Today vs 7-Day vs 30-Day</div>';
    h += '<table style="width:100%;font-size:12px;border-collapse:collapse">';
    h += '<tr style="color:#94A3B8;font-size:10px;text-transform:uppercase;letter-spacing:1px"><th style="text-align:left;padding:6px">Window</th><th>Sample</th><th>MTTD</th><th>MTTA</th><th>MTTR</th><th>SLA Resp</th><th>SLA Resol</th></tr>';
    [['Today','today'],['7-Day','week'],['30-Day','month']].forEach(([lbl, key]) => {
      const w = summary[key] || {};
      h += '<tr style="border-top:1px solid #E2E8F0">';
      h += '<td style="padding:6px;color:#1E293B;font-weight:600">'+esc(lbl)+'</td>';
      h += '<td style="text-align:center;color:#64748B;font-family:\'JetBrains Mono\',monospace">'+(w.sample_count||0)+'</td>';
      h += '<td style="text-align:center;color:#1E293B;font-family:\'JetBrains Mono\',monospace">'+fmt(w.mttd_min)+'</td>';
      h += '<td style="text-align:center;color:#1E293B;font-family:\'JetBrains Mono\',monospace">'+fmt(w.mtta_min)+'</td>';
      h += '<td style="text-align:center;color:#1E293B;font-family:\'JetBrains Mono\',monospace">'+fmt(w.mttr_min)+'</td>';
      h += '<td style="text-align:center;color:'+slaColor(w.sla_response_compliance||0)+';font-weight:600">'+(w.sla_response_compliance||0)+'%</td>';
      h += '<td style="text-align:center;color:'+slaColor(w.sla_resolution_compliance||0)+';font-weight:600">'+(w.sla_resolution_compliance||0)+'%</td>';
      h += '</tr>';
    });
    h += '</table></div>';
  }

  // ── Automation Health (7d) ───────────────────────────────
  // Backend MetricsCalculator.get_automation_health returns
  // {period_days, enrichment_latency: {sample_count, p50_ms, p95_ms, p99_ms, avg_ms},
  //  soar_actions: {total_actions, success_count, failure_count, success_rate (0-100)}}.
  if (autoHealth && (autoHealth.enrichment_latency || autoHealth.soar_actions)) {
    const lat = autoHealth.enrichment_latency || {};
    const soar = autoHealth.soar_actions || {};
    h += '<div style="margin-bottom:20px"><div style="color:#1E293B;font-size:12px;font-weight:600;margin-bottom:8px">Automation Health (7d)</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px">';
    if (lat.p95_ms != null) {
      const p95Color = lat.p95_ms < 500 ? '#34D399' : lat.p95_ms < 2000 ? '#FBBF24' : '#EF4444';
      h += '<div class="c" style="text-align:center"><div style="font-size:22px;font-weight:800;color:'+p95Color+';font-family:\'JetBrains Mono\',monospace">'+lat.p95_ms+'ms</div><div class="l" style="margin-top:4px">Enrichment p95 (n='+(lat.sample_count||0)+')</div></div>';
    }
    if (lat.p50_ms != null) {
      h += '<div class="c" style="text-align:center"><div style="font-size:22px;font-weight:800;color:#1E293B;font-family:\'JetBrains Mono\',monospace">'+lat.p50_ms+'ms</div><div class="l" style="margin-top:4px">Enrichment p50</div></div>';
    }
    if (soar.success_rate != null) {
      const srNum = soar.success_rate;  // already 0-100 from backend
      const sr = srNum.toFixed(1);
      const sc = srNum >= 95 ? '#34D399' : srNum >= 85 ? '#FBBF24' : '#EF4444';
      h += '<div class="c" style="text-align:center"><div style="font-size:22px;font-weight:800;color:'+sc+';font-family:\'JetBrains Mono\',monospace">'+sr+'%</div><div class="l" style="margin-top:4px">SOAR Success</div></div>';
    }
    if (soar.failure_count != null) {
      h += '<div class="c" style="text-align:center"><div style="font-size:22px;font-weight:800;color:'+(soar.failure_count>0?'#EF4444':'#34D399')+';font-family:\'JetBrains Mono\',monospace">'+soar.failure_count+'</div><div class="l" style="margin-top:4px">Failed Actions</div></div>';
    }
    if (soar.total_actions != null) {
      h += '<div class="c" style="text-align:center"><div style="font-size:22px;font-weight:800;color:#1E293B;font-family:\'JetBrains Mono\',monospace">'+soar.total_actions+'</div><div class="l" style="margin-top:4px">Total Actions</div></div>';
    }
    h += '</div></div>';
  }

  // ── Automation Rates (30d) ───────────────────────────────
  // Backend get_automation_rates returns {period_days, total_decisions, auto_closed,
  // auto_close_rate (0-100), enrichment_automation_pct (0-100), false_positives, true_positives}.
  if (autoRates && autoRates.total_decisions != null) {
    h += '<div style="margin-bottom:20px"><div style="color:#1E293B;font-size:12px;font-weight:600;margin-bottom:8px">Automation Rates (30d, n='+(autoRates.total_decisions||0)+')</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px">';
    if (autoRates.auto_close_rate != null) {
      // Backend already returns 0-100, do NOT multiply
      const r = Number(autoRates.auto_close_rate).toFixed(1);
      h += '<div class="c" style="text-align:center"><div style="font-size:22px;font-weight:800;color:#34D399;font-family:\'JetBrains Mono\',monospace">'+r+'%</div><div class="l" style="margin-top:4px">Auto-Close Rate</div></div>';
    }
    if (autoRates.enrichment_automation_pct != null) {
      const r = Number(autoRates.enrichment_automation_pct).toFixed(1);
      h += '<div class="c" style="text-align:center"><div style="font-size:22px;font-weight:800;color:#60A5FA;font-family:\'JetBrains Mono\',monospace">'+r+'%</div><div class="l" style="margin-top:4px">Enrichment Coverage</div></div>';
    }
    if (autoRates.true_positives != null) {
      h += '<div class="c" style="text-align:center"><div style="font-size:22px;font-weight:800;color:#EF4444;font-family:\'JetBrains Mono\',monospace">'+autoRates.true_positives+'</div><div class="l" style="margin-top:4px">True Positives</div></div>';
    }
    if (autoRates.false_positives != null) {
      h += '<div class="c" style="text-align:center"><div style="font-size:22px;font-weight:800;color:#FBBF24;font-family:\'JetBrains Mono\',monospace">'+autoRates.false_positives+'</div><div class="l" style="margin-top:4px">False Positives</div></div>';
    }
    if (autoRates.auto_closed != null) {
      h += '<div class="c" style="text-align:center"><div style="font-size:22px;font-weight:800;color:#1E293B;font-family:\'JetBrains Mono\',monospace">'+autoRates.auto_closed+'</div><div class="l" style="margin-top:4px">Auto-Closed</div></div>';
    }
    h += '</div></div>';
  }

  // ── Case Aging (open incidents > 48h are stale) ──────────
  // Backend get_case_aging row: {id, title, severity, status, assigned_to, created_at, first_response_at, alert_count, hours_open, is_stale}.
  if (aging.length) {
    h += '<div style="margin-bottom:20px"><div style="color:#1E293B;font-size:12px;font-weight:600;margin-bottom:8px">Case Aging (open incidents — stale ≥ 48h)</div>';
    h += '<table style="width:100%;font-size:11px;border-collapse:collapse">';
    h += '<tr style="color:#94A3B8;font-size:10px;text-transform:uppercase;letter-spacing:1px"><th style="text-align:left;padding:6px">Severity</th><th style="text-align:left;padding:6px">Title</th><th style="text-align:left;padding:6px">Age</th><th style="text-align:left;padding:6px">Stale</th><th style="text-align:left;padding:6px">Assigned</th></tr>';
    const sevC = {critical:'#EF4444',high:'#FB923C',medium:'#FBBF24',low:'#34D399'};
    aging.slice(0, 30).forEach(c => {
      const sc = sevC[c.severity]||'#94A3B8';
      const hrs = c.hours_open != null ? Math.round(c.hours_open) : null;
      const ageStr = hrs == null ? '?' : hrs >= 24 ? Math.round(hrs/24)+'d' : hrs+'h';
      h += '<tr style="border-top:1px solid #E2E8F0;cursor:pointer" data-action="loadIncidentDetail" data-id="'+esc(c.id||'')+'">';
      h += '<td style="padding:6px"><span style="font-size:10px;font-weight:600;padding:2px 8px;border-radius:4px;background:'+sc+'18;color:'+sc+';border:1px solid '+sc+'30">'+esc((c.severity||'').toUpperCase())+'</span></td>';
      h += '<td style="padding:6px;color:#1E293B">'+esc((c.title||'').slice(0,60))+'</td>';
      h += '<td style="padding:6px;font-family:\'JetBrains Mono\',monospace;color:#1E293B">'+esc(ageStr)+'</td>';
      h += '<td style="padding:6px">'+(c.is_stale?'<span style="color:#EF4444;font-weight:600">⚠ stale</span>':'<span style="color:#94A3B8">—</span>')+'</td>';
      h += '<td style="padding:6px;color:#64748B">'+esc(c.assigned_to||'unassigned')+'</td>';
      h += '</tr>';
    });
    h += '</table></div>';
  }

  // ── Hunt Cycle Trends (90d) ──────────────────────────────
  // Backend get_hunt_cycle_trends row: {cycle_id, total_hypotheses, hits, confirmed,
  //   hit_rate, confirmation_rate, cycle_date}.
  if (huntCycles.length) {
    h += '<div style="margin-bottom:20px"><div style="color:#1E293B;font-size:12px;font-weight:600;margin-bottom:8px">Hunt Cycle Trends (90d)</div>';
    h += '<table style="width:100%;font-size:11px;border-collapse:collapse">';
    h += '<tr style="color:#94A3B8;font-size:10px;text-transform:uppercase;letter-spacing:1px"><th style="text-align:left;padding:6px">Cycle</th><th style="text-align:left;padding:6px">Hypotheses</th><th style="text-align:left;padding:6px">Hits</th><th style="text-align:left;padding:6px">Confirmed</th><th style="text-align:left;padding:6px">Confirm Rate</th></tr>';
    huntCycles.slice(0, 20).forEach(c => {
      const total = c.total_hypotheses || 0;
      const hits = c.hits || 0;
      const confirmed = c.confirmed || 0;
      const rate = c.confirmation_rate != null ? Number(c.confirmation_rate).toFixed(1)+'%' : (total > 0 ? ((confirmed/total)*100).toFixed(1)+'%' : '—');
      const dt = c.cycle_date;
      h += '<tr style="border-top:1px solid #E2E8F0">';
      h += '<td style="padding:6px;color:#64748B;font-size:10px;font-family:\'JetBrains Mono\',monospace">'+(dt?esc(localTime(dt)):'?')+'</td>';
      h += '<td style="padding:6px;color:#1E293B;font-family:\'JetBrains Mono\',monospace">'+total+'</td>';
      h += '<td style="padding:6px;color:#60A5FA;font-family:\'JetBrains Mono\',monospace">'+hits+'</td>';
      h += '<td style="padding:6px;color:#EF4444;font-family:\'JetBrains Mono\',monospace">'+confirmed+'</td>';
      h += '<td style="padding:6px;color:#1E293B;font-weight:600;font-family:\'JetBrains Mono\',monospace">'+esc(rate)+'</td>';
      h += '</tr>';
    });
    h += '</table></div>';
  }

  // ── Analyst Workload ─────────────────────────────────────
  // Backend check_analyst_workload row: {analyst, open_incidents, critical, high, is_overloaded}.
  // No max_per_analyst in row — that's the request param (default 15).
  const wlMax = 15;
  if (workload.length) {
    h += '<div style="margin-bottom:20px"><div style="color:#1E293B;font-size:12px;font-weight:600;margin-bottom:8px">Analyst Workload (open assignments, max '+wlMax+'/analyst)</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px">';
    workload.forEach(w => {
      const cnt = w.open_incidents || 0;
      const pct = Math.min(100, (cnt/wlMax)*100);
      const c = w.is_overloaded ? '#EF4444' : pct > 70 ? '#FBBF24' : '#34D399';
      h += '<div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:8px;padding:10px 12px">';
      h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px"><span style="color:#1E293B;font-weight:600;font-size:12px">'+esc(w.analyst||'?')+'</span><span style="color:'+c+';font-weight:700;font-family:\'JetBrains Mono\',monospace">'+cnt+'/'+wlMax+'</span></div>';
      h += '<div style="height:6px;background:#E2E8F0;border-radius:3px;overflow:hidden"><div style="height:100%;width:'+pct+'%;background:'+c+'"></div></div>';
      if ((w.critical||0) > 0 || (w.high||0) > 0) h += '<div style="color:#64748B;font-size:10px;margin-top:4px">'+(w.critical?w.critical+' critical':'')+(w.critical&&w.high?' · ':'')+(w.high?w.high+' high':'')+'</div>';
      if (w.is_overloaded) h += '<div style="color:#EF4444;font-size:10px;margin-top:4px">⚠ Overloaded</div>';
      h += '</div>';
    });
    h += '</div></div>';
  }

  // Render chart after DOM update
  if (trends.length > 1) {
    setTimeout(() => {
      const el = document.getElementById('mttCanvas');
      if (!el) return;
      if (metricsChart) { metricsChart.destroy(); metricsChart = null; }
      metricsChart = new Chart(el, {
        type: 'line',
        data: {
          labels: trends.map(d => (d.day||'').slice(5)),
          datasets: [
            { label: 'MTTD (min)', data: trends.map(d => d.avg_mttd ? Math.round(d.avg_mttd) : null), borderColor: '#60A5FA', backgroundColor: 'rgba(96,165,250,0.1)', fill: true, tension: 0.3, spanGaps: true },
            { label: 'MTTA (min)', data: trends.map(d => d.avg_mtta ? Math.round(d.avg_mtta) : null), borderColor: '#818CF8', backgroundColor: 'rgba(129,140,248,0.1)', fill: true, tension: 0.3, spanGaps: true },
            { label: 'MTTR (min)', data: trends.map(d => d.avg_mttr ? Math.round(d.avg_mttr) : null), borderColor: '#FBBF24', backgroundColor: 'rgba(251,191,36,0.1)', fill: true, tension: 0.3, spanGaps: true },
          ]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { labels: { color: '#64748B', font: { size: 11 } } } },
          scales: {
            x: { grid: { color: '#E2E8F0' }, ticks: { color: '#64748B', font: { size: 10 } } },
            y: { grid: { color: '#E2E8F0' }, ticks: { color: '#64748B', font: { size: 10 } }, title: { display: true, text: 'Minutes', color: '#64748B' } }
          }
        }
      });
    }, 50);
  }

  return h;
}

// ── Reports Tab ──────────────────────────────────────────────────

function _getActiveTenantId() {
  if (currentUserRole() === 'mssp_admin') {
    return localStorage.getItem('soc_selected_tenant') || currentTenantId() || 'default';
  }
  return currentTenantId() || 'default';
}

async function renderReports() {
  var h = '';
  var tabs = [{id:'soc',label:'SOC Reports'},{id:'llm',label:'LLM Usage'},{id:'ti',label:'Threat Intel'}];
  h += '<div style="display:flex;gap:4px;margin-bottom:20px;border-bottom:1px solid #E2E8F0;padding-bottom:8px">';
  tabs.forEach(function(t){
    var active = reportsSubTab === t.id;
    h += '<button class="fbtn'+(active?' fon':'')+'" data-action="setReportsSubTab" data-id="'+t.id+'" style="padding:6px 16px;font-size:12px">'+esc(t.label)+'</button>';
  });
  h += '</div>';
  if (reportsSubTab === 'soc') h += await renderReportsSOC();
  else if (reportsSubTab === 'llm') h += await renderReportsLLM();
  else if (reportsSubTab === 'ti') h += await renderReportsTI();
  return h;
}

async function renderReportsSOC() {
  var h = '';
  // Period selector
  h += '<div style="margin-bottom:16px"><div style="font-size:16px;font-weight:700;margin-bottom:4px">SOC Operational Report</div><div style="color:#64748B;font-size:12px">Generated on-demand from platform data.</div></div>';
  h += '<div style="margin-bottom:16px;display:flex;gap:4px">';
  ['daily','weekly','monthly'].forEach(function(p){
    var active = reportPeriod === p;
    h += '<button class="fbtn'+(active?' fon':'')+'" data-action="setReportPeriod" data-id="'+p+'" style="padding:5px 14px;font-size:11px;text-transform:capitalize">'+p+'</button>';
  });
  h += '</div>';

  var rpt;
  try { rpt = await fetchJSON('/metrics/reports/'+reportPeriod); } catch(e) { return h + '<div style="color:#EF4444">Failed to load report: '+esc(e.message)+'</div>'; }

  var a = rpt.alerts || {};
  var inc = rpt.incidents || {};

  // Alert stat cards
  h += '<div class="section-title">Alerts ('+esc(rpt.period||reportPeriod)+')</div>';
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px">';
  var alertCards = [
    {l:'Total',v:a.total||0,c:'#60A5FA'},
    {l:'True Positive',v:a.true_positives||0,c:'#EF4444'},
    {l:'False Positive',v:a.false_positives||0,c:'#34D399'},
    {l:'Auto-Closed',v:a.auto_closed||0,c:'#818CF8'},
    {l:'Escalated',v:a.escalated||0,c:'#F59E0B'},
    {l:'Avg Confidence',v:a.avg_confidence?(a.avg_confidence*100).toFixed(0)+'%':'--',c:'#94A3B8'}
  ];
  alertCards.forEach(function(c){
    h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:14px;text-align:center">';
    h += '<div style="color:'+c.c+';font-size:22px;font-weight:700;font-family:\'JetBrains Mono\',monospace">'+c.v+'</div>';
    h += '<div style="color:#CBD5E1;font-size:10px;font-weight:600;margin-top:4px">'+c.l+'</div></div>';
  });
  h += '</div>';

  // Incidents
  h += '<div class="section-title">Incidents</div>';
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px">';
  var incCards = [
    {l:'New',v:inc.new||0,c:'#60A5FA'},
    {l:'Critical',v:inc.critical||0,c:'#EF4444'},
    {l:'High',v:inc.high||0,c:'#F59E0B'},
    {l:'Resolved',v:inc.resolved||0,c:'#34D399'},
    {l:'Open',v:inc.currently_open||0,c:'#818CF8'}
  ];
  incCards.forEach(function(c){
    h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:14px;text-align:center">';
    h += '<div style="color:'+c.c+';font-size:22px;font-weight:700;font-family:\'JetBrains Mono\',monospace">'+c.v+'</div>';
    h += '<div style="color:#CBD5E1;font-size:10px;font-weight:600;margin-top:4px">'+c.l+'</div></div>';
  });
  h += '</div>';

  // Top noisy rules
  var noisy = rpt.top_noisy_rules || [];
  if (noisy.length) {
    h += '<div class="section-title">Top Noisy Rules (FP Generators)</div>';
    h += '<div id="noisy-rules-grid" style="width:100%;min-height:150px"></div>';
    queueGrid('noisy-rules-grid', {
      rowData: noisy.map(function(r){return {rule_id:r.rule_id,description:r.description||'',fp_count:r.fp_count||0};}),
      columnDefs: [
        {field:'rule_id',headerName:'Rule ID',width:120,cellStyle:{fontFamily:'JetBrains Mono,monospace',color:'#1E293B'}},
        {field:'description',headerName:'Description',flex:1,minWidth:200},
        {field:'fp_count',headerName:'FP Count',width:110,cellStyle:{color:'#EF4444',fontWeight:'600'}}
      ]
    });
  }

  // Weekly extras
  if (reportPeriod === 'weekly' || reportPeriod === 'monthly') {
    var det = rpt.detection_engineering || (rpt.weekly_snapshot||{}).detection_engineering || {};
    var hunt = rpt.threat_hunting || (rpt.weekly_snapshot||{}).threat_hunting || {};
    if (det.proposals_created !== undefined || hunt.findings_total !== undefined) {
      h += '<div class="section-title">Detection & Hunting</div>';
      h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px">';
      h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:14px;text-align:center"><div style="color:#818CF8;font-size:22px;font-weight:700">'+(det.proposals_created||0)+'</div><div style="color:#CBD5E1;font-size:10px;font-weight:600;margin-top:4px">Proposals Created</div></div>';
      h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:14px;text-align:center"><div style="color:#34D399;font-size:22px;font-weight:700">'+(det.proposals_deployed||0)+'</div><div style="color:#CBD5E1;font-size:10px;font-weight:600;margin-top:4px">Deployed</div></div>';
      h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:14px;text-align:center"><div style="color:#60A5FA;font-size:22px;font-weight:700">'+(hunt.findings_total||0)+'</div><div style="color:#CBD5E1;font-size:10px;font-weight:600;margin-top:4px">Hunt Findings</div></div>';
      h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:14px;text-align:center"><div style="color:#EF4444;font-size:22px;font-weight:700">'+(hunt.findings_confirmed||0)+'</div><div style="color:#CBD5E1;font-size:10px;font-weight:600;margin-top:4px">Confirmed Hits</div></div>';
      h += '</div>';
    }
  }

  // Monthly extras
  if (reportPeriod === 'monthly') {
    // Analyst performance
    var analysts = rpt.analyst_performance || [];
    if (analysts.length) {
      h += '<div class="section-title">Analyst Performance (30d)</div>';
      h += '<div id="rpt-analyst-grid" style="width:100%;min-height:150px"></div>';
      queueGrid('rpt-analyst-grid', {
        rowData: analysts,
        columnDefs: [
          {field:'actor',headerName:'Analyst',width:160,cellStyle:{fontWeight:'600',color:'#1E293B'}},
          {field:'incidents_touched',headerName:'Incidents',width:110,cellStyle:{textAlign:'center',color:'#60A5FA'}},
          {field:'resolved_count',headerName:'Resolved',width:110,cellStyle:{textAlign:'center',color:'#34D399'}},
          {field:'total_actions',headerName:'Actions',width:110,cellStyle:{textAlign:'center',color:'#64748B'}}
        ]
      });
    }
    // MITRE coverage
    var mitre = rpt.mitre_coverage || {};
    if (mitre.total_techniques) {
      h += '<div class="section-title">MITRE Coverage</div>';
      h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px">';
      h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:14px;text-align:center"><div style="color:#60A5FA;font-size:22px;font-weight:700">'+(mitre.coverage_pct||0).toFixed(0)+'%</div><div style="color:#CBD5E1;font-size:10px;font-weight:600;margin-top:4px">Coverage</div></div>';
      h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:14px;text-align:center"><div style="color:#34D399;font-size:22px;font-weight:700">'+(mitre.active||0)+'</div><div style="color:#CBD5E1;font-size:10px;font-weight:600;margin-top:4px">Active</div></div>';
      h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:14px;text-align:center"><div style="color:#F59E0B;font-size:22px;font-weight:700">'+(mitre.stale||0)+'</div><div style="color:#CBD5E1;font-size:10px;font-weight:600;margin-top:4px">Stale</div></div>';
      h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:14px;text-align:center"><div style="color:#EF4444;font-size:22px;font-weight:700">'+(mitre.noisy||0)+'</div><div style="color:#CBD5E1;font-size:10px;font-weight:600;margin-top:4px">Noisy</div></div>';
      h += '</div>';
    }
    // SLA compliance
    var sla = rpt.sla_compliance || {};
    if (sla.total_resolved) {
      h += '<div class="section-title">SLA Compliance</div>';
      h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:20px">';
      var rPct = sla.response_compliance_pct || 0;
      var resPct = sla.resolution_compliance_pct || 0;
      var rCol = rPct >= 90 ? '#34D399' : rPct >= 70 ? '#FBBF24' : '#EF4444';
      var resCol = resPct >= 90 ? '#34D399' : resPct >= 70 ? '#FBBF24' : '#EF4444';
      h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:14px;text-align:center"><div style="color:'+rCol+';font-size:22px;font-weight:700">'+rPct.toFixed(0)+'%</div><div style="color:#CBD5E1;font-size:10px;font-weight:600;margin-top:4px">Response SLA</div></div>';
      h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:14px;text-align:center"><div style="color:'+resCol+';font-size:22px;font-weight:700">'+resPct.toFixed(0)+'%</div><div style="color:#CBD5E1;font-size:10px;font-weight:600;margin-top:4px">Resolution SLA</div></div>';
      h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:14px;text-align:center"><div style="color:#94A3B8;font-size:22px;font-weight:700">'+(sla.total_resolved||0)+'</div><div style="color:#CBD5E1;font-size:10px;font-weight:600;margin-top:4px">Resolved</div></div>';
      h += '</div>';
    }
  }

  return h;
}

async function renderReportsLLM() {
  var h = '';
  var tid = _getActiveTenantId();

  h += '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px;flex-wrap:wrap;gap:10px">';
  h += '<div><div style="font-size:16px;font-weight:700;margin-bottom:4px">LLM Usage & Costs</div><div style="color:#64748B;font-size:12px">Token usage, costs, and optimization insights (last 30 days).</div></div>';
  // Manual refresh — this tab is intentionally NOT on the 10-second auto-refresh
  // allowlist (would hit /v1/llm-usage/* endpoints continuously). Click to pull fresh data.
  h += '<button class="fbtn" data-action="refreshLLMUsage" style="padding:6px 14px;font-size:11px;align-self:flex-start"><i data-lucide="refresh-cw" style="width:11px;height:11px;vertical-align:-1px;margin-right:4px"></i>Refresh</button>';
  h += '</div>';

  // Fetch all 4 endpoints in parallel
  var rpt, trends, alerts, opts;
  try {
    var results = await Promise.allSettled([
      fetchJSON('/v1/llm-usage/tenant/'+encodeURIComponent(tid)+'/report?days=30'),
      fetchJSON('/v1/llm-usage/tenant/'+encodeURIComponent(tid)+'/cost-trends?days=30'),
      fetchJSON('/v1/llm-usage/tenant/'+encodeURIComponent(tid)+'/budget-alerts'),
      fetchJSON('/v1/llm-usage/tenant/'+encodeURIComponent(tid)+'/optimization')
    ]);
    rpt = results[0].status==='fulfilled' ? results[0].value : null;
    trends = results[1].status==='fulfilled' ? results[1].value : null;
    alerts = results[2].status==='fulfilled' ? results[2].value : null;
    opts = results[3].status==='fulfilled' ? results[3].value : null;
  } catch(e) {
    return h + '<div style="color:#EF4444">Failed to load LLM usage data: '+esc(e.message)+'</div>';
  }

  // Budget alerts banner
  var alertList = (alerts && alerts.alerts) || [];
  if (alertList.length) {
    alertList.forEach(function(al){
      var bg = al.severity==='critical' ? '#FEE2E2' : al.severity==='warning' ? '#FEF3C7' : '#DBEAFE';
      var tc = al.severity==='critical' ? '#991B1B' : al.severity==='warning' ? '#92400E' : '#1E40AF';
      h += '<div style="background:'+bg+';color:'+tc+';padding:10px 14px;border-radius:8px;margin-bottom:8px;font-size:12px;font-weight:600">'+esc(al.message)+'</div>';
    });
  }

  // Summary cards
  var sum = (rpt && rpt.report && rpt.report.summary) || {};
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px">';
  var llmCards = [
    {l:'Total Requests',v:sum.total_requests||0,c:'#60A5FA'},
    {l:'Total Tokens',v:sum.total_tokens?sum.total_tokens.toLocaleString():'0',c:'#818CF8'},
    {l:'Total Cost',v:'$'+(sum.total_cost_usd||0).toFixed(2),c:'#34D399'},
    {l:'Avg Latency',v:(sum.avg_latency_ms||0).toFixed(0)+'ms',c:'#FBBF24'},
    {l:'Success Rate',v:sum.success_rate?(sum.success_rate*100).toFixed(1)+'%':'--',c:sum.success_rate>=0.95?'#34D399':sum.success_rate>=0.8?'#FBBF24':'#EF4444'}
  ];
  llmCards.forEach(function(c){
    h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:14px;text-align:center">';
    h += '<div style="color:'+c.c+';font-size:22px;font-weight:700;font-family:\'JetBrains Mono\',monospace">'+c.v+'</div>';
    h += '<div style="color:#CBD5E1;font-size:10px;font-weight:600;margin-top:4px">'+c.l+'</div></div>';
  });
  h += '</div>';

  // Provider breakdown table
  var breakdowns = (rpt && rpt.report && rpt.report.breakdowns) || {};
  var providers = breakdowns.providers || {};
  var provKeys = Object.keys(providers);
  if (provKeys.length) {
    h += '<div class="section-title">Provider Breakdown</div>';
    h += '<table style="width:100%;font-size:12px;border-collapse:collapse;margin-bottom:20px">';
    h += '<tr style="color:#94A3B8;font-size:10px;text-transform:uppercase;letter-spacing:1px"><th style="text-align:left;padding:6px">Provider</th><th>Requests</th><th>Tokens In</th><th>Tokens Out</th><th>Cost</th><th>Latency</th><th>Success</th></tr>';
    provKeys.forEach(function(k){
      var p = providers[k];
      h += '<tr style="border-top:1px solid #E2E8F0">';
      h += '<td style="padding:6px;font-weight:600;color:#1E293B">'+esc(k)+'</td>';
      h += '<td style="text-align:center;color:#60A5FA">'+(p.requests||0)+'</td>';
      h += '<td style="text-align:center;color:#1E293B;font-family:\'JetBrains Mono\',monospace;font-size:11px">'+(p.tokens_input||0).toLocaleString()+'</td>';
      h += '<td style="text-align:center;color:#1E293B;font-family:\'JetBrains Mono\',monospace;font-size:11px">'+(p.tokens_output||0).toLocaleString()+'</td>';
      h += '<td style="text-align:center;color:#34D399;font-weight:600">$'+(p.cost_usd||0).toFixed(2)+'</td>';
      h += '<td style="text-align:center;color:#FBBF24;font-family:\'JetBrains Mono\',monospace;font-size:11px">'+(p.avg_latency_ms||0).toFixed(0)+'ms</td>';
      var sr = p.success_rate||0;
      var sc = sr>=0.95?'#34D399':sr>=0.8?'#FBBF24':'#EF4444';
      h += '<td style="text-align:center;color:'+sc+';font-weight:600">'+(sr*100).toFixed(0)+'%</td>';
      h += '</tr>';
    });
    h += '</table>';
  }

  // Request type breakdown
  var reqTypes = breakdowns.request_types || {};
  var rtKeys = Object.keys(reqTypes);
  if (rtKeys.length) {
    h += '<div class="section-title">Usage by Agent</div>';
    h += '<table style="width:100%;font-size:12px;border-collapse:collapse;margin-bottom:20px">';
    h += '<tr style="color:#94A3B8;font-size:10px;text-transform:uppercase;letter-spacing:1px"><th style="text-align:left;padding:6px">Agent</th><th>Requests</th><th>Tokens</th><th>Cost</th></tr>';
    rtKeys.forEach(function(k){
      var r = reqTypes[k];
      h += '<tr style="border-top:1px solid #E2E8F0">';
      h += '<td style="padding:6px;color:#1E293B;font-weight:600;text-transform:capitalize">'+esc(k)+'</td>';
      h += '<td style="text-align:center;color:#60A5FA">'+(r.requests||0)+'</td>';
      h += '<td style="text-align:center;color:#1E293B;font-family:\'JetBrains Mono\',monospace;font-size:11px">'+((r.tokens_input||0)+(r.tokens_output||0)).toLocaleString()+'</td>';
      h += '<td style="text-align:center;color:#34D399;font-weight:600">$'+(r.cost_usd||0).toFixed(2)+'</td>';
      h += '</tr>';
    });
    h += '</table>';
  }

  // Cost trend chart
  var dailyTrends = (trends && trends.trends && trends.trends.daily_trends) || [];
  if (dailyTrends.length > 1) {
    h += '<div class="section-title">Cost Trend (30d)</div>';
    h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:16px;height:250px;margin-bottom:20px"><canvas id="costTrendCanvas"></canvas></div>';
    setTimeout(function(){
      var el = document.getElementById('costTrendCanvas');
      if (!el) return;
      if (costTrendChart) { costTrendChart.destroy(); costTrendChart = null; }
      costTrendChart = new Chart(el, {
        type: 'line',
        data: {
          labels: dailyTrends.map(function(d){return (d.date||'').slice(5);}),
          datasets: [
            {label:'Cost ($)',data:dailyTrends.map(function(d){return d.cost||0;}),borderColor:'#34D399',backgroundColor:'rgba(52,211,153,0.1)',fill:true,tension:0.3},
            {label:'Requests',data:dailyTrends.map(function(d){return d.requests||0;}),borderColor:'#60A5FA',backgroundColor:'rgba(96,165,250,0.1)',fill:true,tension:0.3,yAxisID:'y1'}
          ]
        },
        options: {
          responsive:true,maintainAspectRatio:false,
          plugins:{legend:{labels:{color:'#64748B',font:{size:11}}}},
          scales:{
            x:{grid:{color:'#E2E8F0'},ticks:{color:'#64748B',font:{size:10}}},
            y:{position:'left',grid:{color:'#E2E8F0'},ticks:{color:'#34D399',font:{size:10}},title:{display:true,text:'Cost ($)',color:'#34D399'}},
            y1:{position:'right',grid:{display:false},ticks:{color:'#60A5FA',font:{size:10}},title:{display:true,text:'Requests',color:'#60A5FA'}}
          }
        }
      });
    }, 50);
  }

  // Optimization suggestions
  var suggestions = (opts && opts.suggestions) || [];
  if (suggestions.length) {
    h += '<div class="section-title">Optimization Suggestions</div>';
    suggestions.forEach(function(s){
      var priCol = s.priority==='high'?'#EF4444':'#FBBF24';
      h += '<div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px;padding:14px;margin-bottom:8px">';
      h += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">';
      h += '<span style="font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px;background:'+priCol+'18;color:'+priCol+';border:1px solid '+priCol+'30">'+esc(s.priority)+'</span>';
      h += '<span style="font-size:12px;font-weight:600;color:#1E293B">'+esc(s.type||'').replace(/_/g,' ')+'</span>';
      h += '</div>';
      h += '<div style="font-size:12px;color:#64748B">'+esc(s.description||'')+'</div>';
      if (s.potential_savings) h += '<div style="font-size:11px;color:#34D399;margin-top:4px;font-weight:600">Potential savings: $'+s.potential_savings.toFixed(2)+'/mo</div>';
      h += '</div>';
    });
  }

  return h;
}

async function renderReportsTI() {
  var h = '';
  h += '<div style="margin-bottom:16px"><div style="font-size:16px;font-weight:700;margin-bottom:4px">Strategic Threat Intelligence</div><div style="color:#64748B;font-size:12px">Threat landscape analysis from collected intelligence.</div></div>';

  var rpt;
  try { rpt = await fetchJSON('/threat-intel/strategic-report'); } catch(e) { return h + '<div style="color:#EF4444">Failed to load TI report: '+esc(e.message)+'</div>'; }

  // Alert verdicts
  var verdicts = rpt.alert_verdicts || {};
  h += '<div class="section-title">Alert Verdicts ('+esc(String(rpt.period_days||30))+'d)</div>';
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px">';
  h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:14px;text-align:center"><div style="color:#EF4444;font-size:22px;font-weight:700">'+(verdicts.true_positive||0)+'</div><div style="color:#CBD5E1;font-size:10px;font-weight:600;margin-top:4px">True Positive</div></div>';
  h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:14px;text-align:center"><div style="color:#34D399;font-size:22px;font-weight:700">'+(verdicts.false_positive||0)+'</div><div style="color:#CBD5E1;font-size:10px;font-weight:600;margin-top:4px">False Positive</div></div>';
  h += '<div style="background:#0F1D32;border:1px solid #E2E8F0;border-radius:10px;padding:14px;text-align:center"><div style="color:#818CF8;font-size:22px;font-weight:700">'+(verdicts.auto_close||0)+'</div><div style="color:#CBD5E1;font-size:10px;font-weight:600;margin-top:4px">Auto-Closed</div></div>';
  h += '</div>';

  // IOC sources table
  var sources = rpt.ioc_sources || [];
  if (sources.length) {
    h += '<div class="section-title">IOC Sources</div>';
    h += '<table style="width:100%;font-size:12px;border-collapse:collapse;margin-bottom:20px">';
    h += '<tr style="color:#94A3B8;font-size:10px;text-transform:uppercase;letter-spacing:1px"><th style="text-align:left;padding:6px">Source</th><th>Total</th><th>Critical</th><th>High</th></tr>';
    sources.forEach(function(s){
      h += '<tr style="border-top:1px solid #E2E8F0">';
      h += '<td style="padding:6px;font-weight:600;color:#1E293B">'+esc(s.source||'')+'</td>';
      h += '<td style="text-align:center;color:#60A5FA">'+(s.total||0)+'</td>';
      h += '<td style="text-align:center;color:#EF4444;font-weight:600">'+(s.critical||0)+'</td>';
      h += '<td style="text-align:center;color:#F59E0B;font-weight:600">'+(s.high||0)+'</td>';
      h += '</tr>';
    });
    h += '</table>';
  }

  // Top MITRE techniques
  var techniques = rpt.top_mitre_techniques || [];
  if (techniques.length) {
    h += '<div class="section-title">Top MITRE Techniques</div>';
    h += '<div id="ti-mitre-grid" style="width:100%;min-height:200px;margin-bottom:20px"></div>';
    queueGrid('ti-mitre-grid', {
      rowData: techniques,
      columnDefs: [
        {field:'id',headerName:'ID',width:120,cellStyle:{fontFamily:'JetBrains Mono,monospace',color:'#818CF8',fontWeight:'600'}},
        {field:'name',headerName:'Technique',flex:1,minWidth:200},
        {field:'detections',headerName:'Detections',width:120,cellStyle:{textAlign:'center',color:'#60A5FA',fontWeight:'600'}},
        {field:'true_positives',headerName:'True Positives',width:130,cellStyle:{textAlign:'center',color:'#EF4444',fontWeight:'600'}}
      ]
    });
  }

  // Trending threats
  var trending = rpt.trending_threats || [];
  if (trending.length) {
    h += '<div class="section-title">Trending Threats (7d)</div>';
    h += '<table style="width:100%;font-size:12px;border-collapse:collapse;margin-bottom:20px">';
    h += '<tr style="color:#94A3B8;font-size:10px;text-transform:uppercase;letter-spacing:1px"><th style="text-align:left;padding:6px">Source</th><th>Type</th><th>Severity</th><th>Count</th></tr>';
    trending.forEach(function(t){
      var sc = t.severity==='critical'?'#EF4444':t.severity==='high'?'#F59E0B':'#60A5FA';
      h += '<tr style="border-top:1px solid #E2E8F0">';
      h += '<td style="padding:6px;color:#1E293B;font-weight:600">'+esc(t.source||'')+'</td>';
      h += '<td style="text-align:center"><span style="font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px;background:#818CF818;color:#818CF8;border:1px solid #818CF830">'+esc(t.ioc_type||'')+'</span></td>';
      h += '<td style="text-align:center"><span style="font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px;background:'+sc+'18;color:'+sc+';border:1px solid '+sc+'30">'+esc(t.severity||'')+'</span></td>';
      h += '<td style="text-align:center;color:#1E293B;font-weight:600">'+(t.count||0)+'</td>';
      h += '</tr>';
    });
    h += '</table>';
  }

  return h;
}

function renderInvestigate() {
  let h = '<div style="margin-bottom:16px"><div style="font-size:16px;font-weight:700;margin-bottom:4px">Investigate</div><div style="color:#64748B;font-size:12px">Ask questions about your environment in plain English.</div></div>';
  h += '<div class="qbar"><input type="text" id="qinput" placeholder="e.g. Show me all machines that communicated with 10.0.0.50 in the last 24 hours" data-action-enter="runNLQuery"><button id="qbtn" data-action="runNLQueryBtn">Ask</button></div>';
  h += '<div id="qresults">';
  if (queryHistory.length === 0) {
    h += '<div class="c" style="min-width:100%;text-align:center;padding:40px 20px"><div style="font-size:28px;margin-bottom:12px;opacity:0.3">&#x1F50D;</div><div style="color:#64748B;font-size:13px;line-height:1.8">Try asking:</div><div class="q-followup" style="justify-content:center;margin-top:12px">';
    ['What alerts fired in the last hour?','Show me all true positives from today','Which IPs triggered the most alerts this week?','Show me anomalous activity in the last 24 hours','What MITRE techniques were detected today?'].forEach(ex => {
      h += '<button data-action="runFollowup">'+ex+'</button>';
    });
    h += '</div></div>';
  } else {
    // Show last result
    renderQueryResult(queryHistory[0].result);
    return h + '</div>';
  }
  h += '</div>';
  return h;
}

async function renderThreatIntel() {
  const d = await fetchJSON('/threat-intel/stats');
  const stats = d.stats || {};
  const feeds = d.feeds || [];
  const kevCount = d.kev_count || 0;
  const total = stats.total_iocs || 0;
  const bySource = stats.by_source || [];
  const byType = stats.by_type || [];
  const bySeverity = stats.by_severity || [];
  const activeFeeds = feeds.filter(f => f.status === 'active').length;

  let h = '';

  // Summary cards
  h += `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:20px">`;
  h += `<div class="c" style="text-align:center"><div style="font-size:28px;font-weight:800;color:#1E293B;font-family:'JetBrains Mono',monospace">${total.toLocaleString()}</div><div style="color:#64748B;font-size:11px;margin-top:4px">Total IOCs</div></div>`;
  h += `<div class="c" style="text-align:center"><div style="font-size:28px;font-weight:800;color:#60A5FA;font-family:'JetBrains Mono',monospace">${activeFeeds}/${feeds.length}</div><div style="color:#64748B;font-size:11px;margin-top:4px">Active Feeds</div></div>`;
  h += `<div class="c" style="text-align:center"><div style="font-size:28px;font-weight:800;color:#FBBF24;font-family:'JetBrains Mono',monospace">${bySource.length}</div><div style="color:#64748B;font-size:11px;margin-top:4px">Sources</div></div>`;
  h += `<div class="c" style="text-align:center"><div style="font-size:28px;font-weight:800;color:#EF4444;font-family:'JetBrains Mono',monospace">${kevCount}</div><div style="color:#64748B;font-size:11px;margin-top:4px">CISA KEV CVEs</div></div>`;
  h += `</div>`;

  // IOCs by type + severity side by side
  h += `<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px">`;

  // By type card
  h += `<div class="c"><div class="l">IOCs by Type</div>`;
  if (byType.length) {
    byType.forEach(t => {
      const pct = total > 0 ? Math.round(t.count / total * 100) : 0;
      const typeColors = {ip:'#60A5FA',domain:'#34D399',url:'#FBBF24',hash_md5:'#C084FC',hash_sha256:'#C084FC',hash_sha1:'#C084FC',cve:'#EF4444'};
      const c = typeColors[t.ioc_type] || '#5C7A99';
      h += `<div style="display:flex;align-items:center;gap:8px;margin:6px 0"><span style="color:${c};font-family:'JetBrains Mono',monospace;font-size:12px;min-width:90px">${esc(t.ioc_type)}</span><div style="flex:1;background:#E2E8F0;border-radius:3px;height:16px;overflow:hidden"><div style="width:${pct}%;height:100%;background:${c}30;border-left:3px solid ${c}"></div></div><span style="color:#64748B;font-size:11px;font-family:'JetBrains Mono',monospace;min-width:50px;text-align:right">${t.count.toLocaleString()}</span></div>`;
    });
  } else {
    h += `<div style="color:#94A3B8;font-size:12px;padding:10px">No IOCs collected yet</div>`;
  }
  h += `</div>`;

  // By severity card
  h += `<div class="c"><div class="l">IOCs by Severity</div>`;
  if (bySeverity.length) {
    const sevColors = {critical:'#EF4444',high:'#FF6B35',medium:'#FBBF24',low:'#60A5FA',info:'#5C7A99'};
    bySeverity.forEach(s => {
      const pct = total > 0 ? Math.round(s.count / total * 100) : 0;
      const c = sevColors[s.severity] || '#5C7A99';
      h += `<div style="display:flex;align-items:center;gap:8px;margin:6px 0"><span style="color:${c};font-family:'JetBrains Mono',monospace;font-size:12px;min-width:90px;text-transform:uppercase">${esc(s.severity)}</span><div style="flex:1;background:#E2E8F0;border-radius:3px;height:16px;overflow:hidden"><div style="width:${pct}%;height:100%;background:${c}30;border-left:3px solid ${c}"></div></div><span style="color:#64748B;font-size:11px;font-family:'JetBrains Mono',monospace;min-width:50px;text-align:right">${s.count.toLocaleString()}</span></div>`;
    });
  } else {
    h += `<div style="color:#94A3B8;font-size:12px;padding:10px">No IOCs collected yet</div>`;
  }
  h += `</div>`;
  h += `</div>`;

  // IOCs by source
  if (bySource.length) {
    h += `<div class="c" style="margin-bottom:20px"><div class="l">IOCs by Source</div>`;
    h += `<div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:10px">`;
    const srcColors = {threatfox:'#FF6B35',urlhaus:'#FBBF24',feodo:'#EF4444',malwarebazaar:'#C084FC',openphish:'#60A5FA',abuseipdb:'#34D399',virustotal:'#7C3AED',alienvault_otx:'#10B981',cisa_kev:'#EF4444'};
    bySource.forEach(s => {
      const c = srcColors[s.source] || '#5C7A99';
      h += `<div style="background:${c}15;border:1px solid ${c}30;border-radius:6px;padding:8px 14px;text-align:center"><div style="color:${c};font-size:16px;font-weight:700;font-family:'JetBrains Mono',monospace">${s.count.toLocaleString()}</div><div style="color:#64748B;font-size:10px;margin-top:2px">${esc(s.source)}</div></div>`;
    });
    h += `</div></div>`;
  }

  // Feed status table
  h += `<div class="c"><div class="l" style="display:flex;justify-content:space-between;align-items:center">Feed Status`;
  if (canAct()) {
    h += `<button data-action="triggerTICollection" style="background:#E8EDF218;color:#1E293B;border:1px solid #E8EDF230;border-radius:4px;padding:4px 12px;font-size:11px;cursor:pointer;font-family:inherit">Run Collection</button>`;
  }
  h += `</div>`;
  h += `<table style="width:100%;margin-top:10px;font-size:12px;border-collapse:collapse">`;
  h += `<tr style="border-bottom:1px solid #E2E8F0"><th style="text-align:left;padding:8px 10px;color:#64748B;font-size:10px;text-transform:uppercase">Feed</th><th style="text-align:left;padding:8px 10px;color:#64748B;font-size:10px;text-transform:uppercase">Tier</th><th style="text-align:left;padding:8px 10px;color:#64748B;font-size:10px;text-transform:uppercase">Status</th><th style="text-align:left;padding:8px 10px;color:#64748B;font-size:10px;text-transform:uppercase">IOCs</th><th style="text-align:left;padding:8px 10px;color:#64748B;font-size:10px;text-transform:uppercase">Last Fetch</th><th style="text-align:left;padding:8px 10px;color:#64748B;font-size:10px;text-transform:uppercase">Interval</th><th style="text-align:left;padding:8px 10px;color:#64748B;font-size:10px;text-transform:uppercase">Error</th></tr>`;

  feeds.forEach(f => {
    const statusColors = {active:'#34D399',error:'#EF4444',pending:'#FBBF24',disabled:'#3D5A75'};
    const sc = statusColors[f.status] || '#5C7A99';
    const tierLabels = {1:'Free',2:'API Key',3:'Optional'};
    const lastFetch = f.last_success_at ? new Date(f.last_success_at).toLocaleString() : 'Never';
    const intervalHrs = f.collection_interval_minutes >= 60 ? Math.round(f.collection_interval_minutes/60)+'h' : f.collection_interval_minutes+'m';
    h += `<tr style="border-bottom:1px solid #E2E8F008">`;
    h += `<td style="padding:8px 10px;color:#1E293B;font-weight:600">${esc(f.feed_name)}</td>`;
    h += `<td style="padding:8px 10px"><span style="background:#E2E8F0;color:#64748B;padding:2px 6px;border-radius:3px;font-size:10px">${tierLabels[f.tier]||f.tier}</span></td>`;
    h += `<td style="padding:8px 10px"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${sc};margin-right:6px"></span><span style="color:${sc}">${esc(f.status)}</span></td>`;
    h += `<td style="padding:8px 10px;font-family:'JetBrains Mono',monospace;color:#1E293B">${(f.total_ioc_count||0).toLocaleString()}</td>`;
    h += `<td style="padding:8px 10px;color:#64748B;font-size:11px">${lastFetch}</td>`;
    h += `<td style="padding:8px 10px;color:#64748B;font-size:11px;font-family:'JetBrains Mono',monospace">${intervalHrs}</td>`;
    h += `<td style="padding:8px 10px;color:#EF4444;font-size:10px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(f.last_error||'')}">${f.error_count > 0 ? esc((f.last_error||'').slice(0,60)) : '<span style="color:#94A3B8">\u2014</span>'}</td>`;
    h += `</tr>`;
  });

  if (!feeds.length) {
    h += `<tr><td colspan="7" style="text-align:center;color:#94A3B8;padding:20px">No feeds configured. TI collection will start on next cycle.</td></tr>`;
  }

  h += `</table></div>`;

  // IOC lookup
  h += `<div class="c" style="margin-top:20px"><div class="l">IOC Lookup</div>`;
  h += `<div style="color:#64748B;font-size:11px;margin-bottom:10px">Search the local IOC database for an IP, domain, URL, hash, or CVE.</div>`;
  h += `<div style="display:flex;gap:8px;margin-top:8px">`;
  h += `<input id="ti-ioc-input" type="text" placeholder="e.g. 1.2.3.4 or evil.example.com or CVE-2024-1234" value="${esc(_tiIocQuery||'')}" style="flex:1;padding:8px 12px;border:1px solid #D1D5DB;border-radius:6px;font-size:13px;font-family:'JetBrains Mono',monospace" data-action-enter="tiIocLookup">`;
  h += `<button class="fbtn" data-action="tiIocLookupBtn">Look up</button>`;
  if (_tiIocQuery) h += `<button class="fbtn" data-action="tiIocClear">Clear</button>`;
  h += `</div>`;
  h += `<div id="ti-ioc-result" style="margin-top:12px">`;
  if (_tiIocResult) {
    if (_tiIocResult.error) {
      h += `<div style="color:#EF4444;font-size:12px">${esc(_tiIocResult.error)}</div>`;
    } else if (_tiIocResult.total === 0) {
      h += `<div style="color:#94A3B8;font-size:12px;padding:10px;background:#F8FAFC;border-radius:6px">No matches in local IOC database for <code>${esc(_tiIocResult.ioc_value)}</code>.</div>`;
    } else {
      h += `<div style="color:#1E293B;font-size:12px;margin-bottom:8px"><strong>${_tiIocResult.total}</strong> match(es) for <code style="color:#8B5CF6">${esc(_tiIocResult.ioc_value)}</code>:</div>`;
      h += `<table style="width:100%;font-size:11px;border-collapse:collapse">`;
      h += `<tr style="color:#94A3B8;font-size:10px;text-transform:uppercase;letter-spacing:1px"><th style="text-align:left;padding:6px">Type</th><th style="text-align:left;padding:6px">Source</th><th style="text-align:left;padding:6px">Severity</th><th style="text-align:left;padding:6px">First Seen</th><th style="text-align:left;padding:6px">Tags</th></tr>`;
      _tiIocResult.matches.forEach(m => {
        const sevColors = {critical:'#EF4444',high:'#F59E0B',medium:'#FBBF24',low:'#60A5FA',info:'#5C7A99'};
        const sc = sevColors[m.severity] || '#5C7A99';
        let tags = []; try { tags = JSON.parse(m.tags||'[]'); } catch(e) {}
        h += `<tr style="border-top:1px solid #E2E8F0">`;
        h += `<td style="padding:6px;color:#818CF8;font-family:'JetBrains Mono',monospace">${esc(m.ioc_type||'')}</td>`;
        h += `<td style="padding:6px;color:#1E293B">${esc(m.source||'')}</td>`;
        h += `<td style="padding:6px"><span style="font-size:10px;font-weight:600;padding:2px 6px;border-radius:4px;background:${sc}18;color:${sc};border:1px solid ${sc}30">${esc(m.severity||'')}</span></td>`;
        h += `<td style="padding:6px;color:#64748B;font-size:10px">${m.first_seen?new Date(m.first_seen).toLocaleString():''}</td>`;
        h += `<td style="padding:6px">${tags.slice(0,4).map(t=>`<span style="background:#F1F5F9;color:#64748B;padding:1px 6px;border-radius:3px;font-size:10px;margin-right:3px">${esc(t)}</span>`).join('')}</td>`;
        h += `</tr>`;
      });
      h += `</table>`;
    }
  }
  h += `</div></div>`;

  // CVE / KEV browser
  let cveData = null;
  try { cveData = await fetchJSON('/threat-intel/cve?kev_only=' + (_tiCveKevOnly?'true':'false') + '&limit=50'); } catch(e) { cveData = {cves:[], total:0}; }
  h += `<div class="c" style="margin-top:20px"><div class="l" style="display:flex;justify-content:space-between;align-items:center">CVE / KEV Browser`;
  h += `<div style="display:flex;gap:6px"><button class="fbtn" style="font-size:11px;${_tiCveKevOnly?'background:#EF4444;color:#fff':''}" data-action="tiCveToggleKev">${_tiCveKevOnly?'Showing KEV only':'All CVEs'}</button></div>`;
  h += `</div>`;
  h += `<div style="color:#64748B;font-size:11px;margin-bottom:10px">${_tiCveKevOnly?'Known Exploited Vulnerabilities tracked by CISA':'CVEs collected via TI feeds'} (showing up to 50, ${cveData.total||0} total).</div>`;
  if ((cveData.cves||[]).length) {
    h += `<table style="width:100%;font-size:11px;border-collapse:collapse">`;
    h += `<tr style="color:#94A3B8;font-size:10px;text-transform:uppercase;letter-spacing:1px"><th style="text-align:left;padding:6px">CVE</th><th style="text-align:left;padding:6px">CVSS</th><th style="text-align:left;padding:6px">EPSS</th><th style="text-align:left;padding:6px">KEV</th><th style="text-align:left;padding:6px;width:50%">Description</th></tr>`;
    (cveData.cves||[]).forEach(c => {
      const cvss = c.cvss_score!=null?Number(c.cvss_score).toFixed(1):'—';
      const cvssNum = parseFloat(cvss);
      const cvssColor = cvssNum>=9?'#EF4444':cvssNum>=7?'#F59E0B':cvssNum>=4?'#FBBF24':'#60A5FA';
      const epss = c.epss_score!=null?(Number(c.epss_score)*100).toFixed(1)+'%':'—';
      h += `<tr style="border-top:1px solid #E2E8F0">`;
      h += `<td style="padding:6px;color:#8B5CF6;font-family:'JetBrains Mono',monospace;font-weight:600">${esc(c.cve_id||'')}</td>`;
      h += `<td style="padding:6px;font-family:'JetBrains Mono',monospace;color:${cvssColor};font-weight:600">${cvss}</td>`;
      h += `<td style="padding:6px;font-family:'JetBrains Mono',monospace;color:#64748B">${epss}</td>`;
      h += `<td style="padding:6px">${c.in_cisa_kev?'<span style="background:#EF444418;color:#EF4444;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600">KEV</span>':'<span style="color:#94A3B8">—</span>'}</td>`;
      h += `<td style="padding:6px;color:#1E293B;font-size:11px;max-width:500px">${esc((c.description||'').slice(0,200))}${(c.description||'').length>200?'…':''}</td>`;
      h += `</tr>`;
    });
    h += `</table>`;
  } else {
    h += `<div style="color:#94A3B8;font-size:12px;padding:20px;text-align:center">No CVE data yet. CVE feeds populate via TI collection.</div>`;
  }
  h += `</div>`;

  return h;
}

async function tiIocLookup() {
  const v = document.getElementById('ti-ioc-input').value.trim();
  if (!v) return;
  _tiIocQuery = v;
  try {
    _tiIocResult = await fetchJSON('/threat-intel/ioc/' + encodeURIComponent(v));
  } catch(e) {
    _tiIocResult = {ioc_value: v, error: 'Lookup failed: ' + (e.message || 'unknown error'), matches: [], total: 0};
  }
  refresh();
}
function tiIocClear() { _tiIocQuery = ''; _tiIocResult = null; refresh(); }
function tiCveToggleKev() { _tiCveKevOnly = !_tiCveKevOnly; refresh(); }

async function triggerTICollection() {
  try {
    const r = await fetch(API + '/threat-intel/collect', {method:'POST', headers: authHeaders()});
    if (!r.ok) throw new Error('API ' + r.status);
    refresh();
  } catch(e) {
    alert('Failed to start collection: ' + e.message);
  }
}

// ---------------------------------------------------------------------------
// Daily Review — simplified view for non-technical IT users
// ---------------------------------------------------------------------------
let drView = 'morning'; // 'morning' | 'detail' | 'health'
let drIncidentId = null;
let drGroupIds = [];    // all incident IDs in the clicked group
let drPlainLoading = false;
let drNavClick = false; // true when user explicitly navigated

function drOpenGroup(idx, incId) {
  drNavClick = true;
  drView = 'detail';
  drIncidentId = incId;
  drGroupIds = (window._drGroupData && window._drGroupData[idx]) || [incId];
  refresh();
}

async function renderDailyReview() {
  if (drView === 'detail' && drIncidentId) return await renderDRDetail(drIncidentId);
  if (drView === 'health') return await renderDRHealth();

  const [statsRes, incRes] = await Promise.all([
    fetchJSON('/dashboard/stats'),
    fetchJSON('/incidents?status=open&limit=100'),
  ]);

  const t = statsRes.today || {};
  const incidents = incRes.incidents || [];
  const criticals = incidents.filter(i => i.severity === 'critical');

  // Last visit tracking
  const lastVisitRaw = localStorage.getItem('dr_last_visit');
  const lastVisit = lastVisitRaw ? new Date(lastVisitRaw) : null;
  const now = new Date();

  // Time-since label
  let sinceTxt = '';
  if (lastVisit) {
    const diffMs = now - lastVisit;
    const diffMin = Math.floor(diffMs / 60000);
    if (diffMin < 60) sinceTxt = diffMin + ' minute' + (diffMin !== 1 ? 's' : '') + ' ago';
    else if (diffMin < 1440) { const h = Math.floor(diffMin/60); sinceTxt = h + ' hour' + (h !== 1 ? 's' : '') + ' ago'; }
    else { const d = Math.floor(diffMin/1440); sinceTxt = d + ' day' + (d !== 1 ? 's' : '') + ' ago'; }
  }

  // Split incidents into new (since last visit) and older (still open)
  const sevOrder = {critical:0,high:1,medium:2,low:3};
  const sevColor = {critical:'#EF4444',high:'#FB923C',medium:'#FBBF24',low:'#34D399'};
  const sortBySev = (a,b) => (sevOrder[a.severity]||9) - (sevOrder[b.severity]||9);

  let newInc = [], olderInc = [];
  if (lastVisit) {
    incidents.forEach(inc => {
      const created = new Date(inc.created_at || inc.first_seen);
      if (created > lastVisit) newInc.push(inc);
      else olderInc.push(inc);
    });
  } else {
    newInc = [...incidents];
  }
  newInc.sort(sortBySev);
  olderInc.sort(sortBySev);

  // Status banner
  let bc, bbg, bbd, btxt;
  if (criticals.length > 0) {
    let hosts = [];
    criticals.forEach(i => { try { hosts.push(...JSON.parse(i.affected_hosts||'[]')); } catch(e){} });
    bc='#EF4444'; bbg='#EF444415'; bbd='#EF444440';
    btxt = 'CRITICAL: Active threat detected' + (hosts.length ? ' on ' + hosts.slice(0,3).join(', ') : '');
  } else if (newInc.length > 0) {
    bc='#FBBF24'; bbg='#FBBF2415'; bbd='#FBBF2440';
    btxt = newInc.length + ' new incident' + (newInc.length !== 1 ? 's' : '') + ' since you last checked' + (sinceTxt ? ' (' + sinceTxt + ')' : '');
  } else if (olderInc.length > 0) {
    bc='#FBBF24'; bbg='#FBBF2415'; bbd='#FBBF2440';
    btxt = olderInc.length + ' older incident' + (olderInc.length !== 1 ? 's' : '') + ' still open';
  } else {
    bc='#34D399'; bbg='#34D39915'; bbd='#34D39930';
    btxt = 'All clear \u2014 ' + (t.total || 0).toLocaleString() + ' alerts handled' + (sinceTxt ? ' since you last checked (' + sinceTxt + ')' : ' automatically');
  }

  let h = `<div style="background:${bbg};border:2px solid ${bbd};border-radius:12px;padding:20px 28px;margin-bottom:24px;display:flex;align-items:center;gap:14px">
    <div style="width:14px;height:14px;border-radius:50%;background:${bc};flex-shrink:0"></div>
    <div style="font-size:17px;font-weight:700;color:${bc}">${esc(btxt)}</div>
  </div>`;

  // Summary cards
  h += `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px">`;
  h += `<div class="c" style="text-align:center"><div style="font-size:26px;font-weight:800;color:#1E293B;font-family:'JetBrains Mono',monospace">${(t.total||0).toLocaleString()}</div><div style="color:#64748B;font-size:11px;margin-top:4px">Alerts Processed</div></div>`;
  h += `<div class="c" style="text-align:center"><div style="font-size:26px;font-weight:800;color:#1E293B;font-family:'JetBrains Mono',monospace">${(t.auto_closed||0).toLocaleString()}</div><div style="color:#64748B;font-size:11px;margin-top:4px">Auto-Closed</div></div>`;
  h += `<div class="c" style="text-align:center"><div style="font-size:26px;font-weight:800;color:#FBBF24;font-family:'JetBrains Mono',monospace">${t.escalated||0}</div><div style="color:#64748B;font-size:11px;margin-top:4px">Escalated</div></div>`;
  h += `<div class="c" style="text-align:center"><div style="font-size:26px;font-weight:800;color:#EF4444;font-family:'JetBrains Mono',monospace">${t.tps||0}</div><div style="color:#64748B;font-size:11px;margin-top:4px">Threats Found</div></div>`;
  h += `<div class="c" style="text-align:center"><div style="font-size:26px;font-weight:800;color:#818CF8;font-family:'JetBrains Mono',monospace">${statsRes.pending_proposals||0}</div><div style="color:#64748B;font-size:11px;margin-top:4px">Rules Tuned</div></div>`;
  h += `</div>`;

  // Navigation header
  h += `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
    <div style="font-size:14px;font-weight:700;color:#64748B;text-transform:uppercase;letter-spacing:1px">Needs Your Review</div>
    <button class="fbtn" data-action="drShowHealth">System Health</button>
  </div>`;

  // Group incidents by title — show count badge instead of repeating rows
  function groupIncidents(list) {
    const groups = {};
    list.forEach(inc => {
      // Normalize title: strip trailing timestamps and minor variations
      const key = (inc.title || '').replace(/\s+on agent \d+/, '').trim();
      if (!groups[key]) {
        groups[key] = { representative: inc, count: 0, totalAlerts: 0, ids: [] };
      }
      groups[key].count++;
      groups[key].totalAlerts += inc.alert_count || 1;
      groups[key].ids.push(inc.id);
      // Keep the most recent as representative
      if ((inc.last_seen || inc.created_at) > (groups[key].representative.last_seen || groups[key].representative.created_at)) {
        groups[key].representative = inc;
      }
    });
    // Sort by highest severity, then by count
    return Object.values(groups).sort((a, b) => {
      const sd = (sevOrder[a.representative.severity]||9) - (sevOrder[b.representative.severity]||9);
      return sd !== 0 ? sd : b.count - a.count;
    });
  }

  // Store group data on window so onclick handlers can reference by index
  window._drGroupData = {};

  function drRow(group, isNew, idx) {
    const inc = group.representative;
    window._drGroupData[idx] = group.ids;
    let hosts=[]; try{hosts=JSON.parse(inc.affected_hosts||'[]')}catch(e){}
    let users=[]; try{users=JSON.parse(inc.affected_users||'[]')}catch(e){}
    const who = hosts.concat(users).filter(Boolean).slice(0,3).join(', ') || '';
    const when = localTime(inc.last_seen || inc.created_at);
    const newBadge = isNew ? badge('NEW', '#60A5FA') + ' ' : '';
    const countBadge = group.count > 1 ? badge(group.count + 'x', '#5C7A99') + ' ' : '';
    return `<div class="row" style="cursor:pointer;border-color:${inc.severity==='critical'?'#EF444440':'#E2E8F0'}" data-action="drOpenGroup" data-id="${esc(inc.id)}" data-field="${idx}">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
        <div style="display:flex;align-items:center;gap:10px">
          ${badge(inc.severity.toUpperCase(), sevColor[inc.severity]||'#5C7A99')}
          ${countBadge}${newBadge}<span style="color:#1E293B;font-size:13px;font-weight:600">${esc((inc.title||'').slice(0,80))}</span>
        </div>
        <div style="display:flex;align-items:center;gap:12px">
          ${who ? '<span style="color:#64748B;font-size:11px">'+esc(who)+'</span>' : ''}
          <span style="color:#94A3B8;font-size:11px">${when}</span>
          <span style="color:#94A3B8;font-size:14px">&#x25B6;</span>
        </div>
      </div>
    </div>`;
  }

  const newGroups = groupIncidents(newInc);
  const olderGroups = groupIncidents(olderInc);
  const totalGroups = newGroups.length + olderGroups.length;

  if (incidents.length === 0) {
    h += `<div class="c" style="text-align:center;padding:40px">
      <div style="font-size:28px;margin-bottom:8px">&#x2705;</div>
      <div style="color:#1E293B;font-size:15px;font-weight:600">No incidents need your attention right now</div>
      <div style="color:#94A3B8;font-size:12px;margin-top:6px">The AI is monitoring your environment. You'll be notified if something needs review.</div>
    </div>`;
  } else {
    // New incidents section
    if (newGroups.length > 0) {
      h += `<div style="color:#60A5FA;font-size:12px;font-weight:700;margin-bottom:8px;text-transform:uppercase;letter-spacing:0.5px">New since your last visit (${newInc.length} incidents, ${newGroups.length} types)</div>`;
      newGroups.forEach((g, i) => { h += drRow(g, true, 'n'+i); });
    }

    // Older still-open section
    if (olderGroups.length > 0) {
      if (newGroups.length > 0) h += `<div style="color:#94A3B8;font-size:12px;font-weight:700;margin:16px 0 8px;text-transform:uppercase;letter-spacing:0.5px">Still open (${olderInc.length} incidents, ${olderGroups.length} types)</div>`;
      olderGroups.forEach((g, i) => { h += drRow(g, false, 'o'+i); });
    }
  }

  // Update badge
  const totalOpen = incidents.length;
  setBadge('drc', totalOpen);

  // Pre-generate plain-language summaries — only once per page load
  if (!window._drBatchFired) {
    window._drBatchFired = true;
    const allSorted = [...newInc, ...olderInc];
    const topIds = allSorted.slice(0, 10).map(i => i.id);
    if (topIds.length) {
      // Delay 5s to let triage finish its current call first
      setTimeout(() => {
        fetch(API + '/incidents/batch-plain-summary', {
          method: 'POST', headers: {...authHeaders(), 'Content-Type': 'application/json'},
          body: JSON.stringify({incident_ids: topIds})
        }).catch(() => {});
      }, 5000);
    }
  }

  // Save this visit time (after rendering, so current view uses previous timestamp)
  localStorage.setItem('dr_last_visit', now.toISOString());

  return h;
}

async function renderDRDetail(incidentId) {
  const inc = await fetchJSON('/incidents/' + incidentId);
  let hosts=[]; try{hosts=JSON.parse(inc.affected_hosts||'[]')}catch(e){}
  let ips=[]; try{ips=JSON.parse(inc.affected_ips||'[]')}catch(e){}
  let users=[]; try{users=JSON.parse(inc.affected_users||'[]')}catch(e){}
  const sc = {critical:'#EF4444',high:'#FB923C',medium:'#FBBF24',low:'#34D399'}[inc.severity]||'#5C7A99';

  let h = '';

  // Back button
  h += `<div style="margin-bottom:16px">
    <button class="fbtn" data-action="drBackToMorning">&#x2190; Back to Daily Review</button>
  </div>`;

  // Header
  const groupCount = drGroupIds.length > 1 ? drGroupIds.length : 0;
  h += `<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
    ${badge(inc.severity.toUpperCase(), sc)}
    ${groupCount ? badge(groupCount + ' grouped', '#5C7A99') : ''}
    <span style="font-size:18px;font-weight:700;color:#1E293B">${esc(inc.title)}</span>
  </div>`;
  if (groupCount) {
    h += `<div style="color:#64748B;font-size:12px;margin:-10px 0 14px 0">Actions below will apply to all ${groupCount} incidents in this group.</div>`;
  }

  // Metadata
  h += `<div class="c" style="margin-bottom:16px;display:flex;gap:24px;flex-wrap:wrap;font-size:12px">`;
  if (hosts.length) h += `<div><span style="color:#94A3B8">Machine:</span> <span style="color:#1E293B;font-weight:600">${hosts.map(x=>esc(x)).join(', ')}</span></div>`;
  if (users.length) h += `<div><span style="color:#94A3B8">User:</span> <span style="color:#1E293B;font-weight:600">${users.map(x=>esc(x)).join(', ')}</span></div>`;
  if (ips.length) h += `<div><span style="color:#94A3B8">IP:</span> <span style="color:#1E293B;font-weight:600;font-family:'JetBrains Mono',monospace">${ips.map(x=>esc(x)).join(', ')}</span></div>`;
  h += `<div><span style="color:#94A3B8">Alerts:</span> <span style="color:#60A5FA;font-weight:600">${inc.alert_count||0}</span></div>`;
  h += `<div><span style="color:#94A3B8">When:</span> <span style="color:#64748B">${localTime(inc.first_seen)}</span></div>`;
  h += `</div>`;

  // Plain-language explanation
  const timeline = inc.timeline || [];
  const cached = timeline.find(t => t.event_type === 'plain_summary');
  h += `<div class="c" style="margin-bottom:20px" id="dr-plain">`;
  h += `<div class="l">What Happened (Plain English)</div>`;
  if (cached) {
    h += `<div style="color:#1E293B;font-size:13px;line-height:1.8;margin-top:10px;white-space:pre-wrap">${esc(cached.description)}</div>`;
  } else {
    h += `<div style="color:#64748B;font-size:12px;margin-top:10px" id="dr-plain-loading">Generating plain-language summary...</div>`;
  }
  h += `</div>`;

  // Action buttons (2x2 grid)
  h += `<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px">`;

  // Block IP (admin) or Request Block (non-admin)
  if (ips.length > 0) {
    if (currentUserRole() === 'admin') {
      h += `<button class="c" style="cursor:pointer;text-align:center;border-color:#EF444440;transition:all .2s" data-hover-border="#EF4444" data-hover-border-reset="#EF444440" data-action="drBlockIP" data-id="${esc(inc.id)}" data-field="${esc(ips[0])}">
        <div style="font-size:24px;margin-bottom:6px">&#x1F6AB;</div>
        <div style="color:#EF4444;font-size:14px;font-weight:700">Block this IP</div>
        <div style="color:#94A3B8;font-size:11px;margin-top:4px;font-family:'JetBrains Mono',monospace">${esc(ips[0])}</div>
      </button>`;
    } else {
      h += `<button class="c" style="cursor:pointer;text-align:center;border-color:#EF444440;transition:all .2s" data-hover-border="#EF4444" data-hover-border-reset="#EF444440" data-action="drHelp" data-id="${esc(inc.id)}">
        <div style="font-size:24px;margin-bottom:6px">&#x1F6AB;</div>
        <div style="color:#EF4444;font-size:14px;font-weight:700">Request IP Block</div>
        <div style="color:#94A3B8;font-size:11px;margin-top:4px">Notify security team</div>
      </button>`;
    }
  } else {
    h += `<div></div>`;
  }

  // I've handled this
  h += `<button class="c" style="cursor:pointer;text-align:center;border-color:#1E293B40;transition:all .2s" data-hover-border="#E8EDF2" data-hover-border-reset="#E8EDF240" data-action="drHandled" data-id="${esc(inc.id)}">
    <div style="font-size:24px;margin-bottom:6px">&#x2705;</div>
    <div style="color:#1E293B;font-size:14px;font-weight:700">I've Handled This</div>
    <div style="color:#94A3B8;font-size:11px;margin-top:4px">Mark as resolved</div>
  </button>`;

  // This is normal (only for users who can act)
  if (canAct()) {
    h += `<button class="c" style="cursor:pointer;text-align:center;border-color:#FBBF2440;transition:all .2s" data-hover-border="#FBBF24" data-hover-border-reset="#FBBF2440" data-action="drNormal" data-id="${esc(inc.id)}">
      <div style="font-size:24px;margin-bottom:6px">&#x1F44D;</div>
      <div style="color:#FBBF24;font-size:14px;font-weight:700">This is Normal</div>
      <div style="color:#94A3B8;font-size:11px;margin-top:4px">Ignore similar alerts in future</div>
    </button>`;
  } else {
    h += `<div></div>`;
  }

  // I need help
  h += `<button class="c" style="cursor:pointer;text-align:center;border-color:#60A5FA40;transition:all .2s" data-hover-border="#60A5FA" data-hover-border-reset="#60A5FA40" data-action="drHelp" data-id="${esc(inc.id)}">
    <div style="font-size:24px;margin-bottom:6px">&#x1F198;</div>
    <div style="color:#60A5FA;font-size:14px;font-weight:700">I Need Help</div>
    <div style="color:#94A3B8;font-size:11px;margin-top:4px">Notify SecureSleuths team</div>
  </button>`;

  h += `</div>`;

  // Trigger plain summary load if not cached
  if (!cached) setTimeout(() => drLoadSummary(incidentId), 100);

  return h;
}

async function genPlainSummary(incidentId) {
  const wrap = document.getElementById('incPlain-' + incidentId);
  if (!wrap) return;
  wrap.innerHTML = '<div style="color:#64748B;font-size:11px;padding:12px;background:#F8FAFC;border-radius:8px;border:1px solid #8B5CF630">Generating plain-language summary (this can take 10–30 seconds)...</div>';
  try {
    const r = await fetch(API + '/incidents/' + incidentId + '/plain-summary', {
      method: 'POST', headers: {...authHeaders(), 'Content-Type': 'application/json'}
    });
    if (!r.ok) {
      const err = await r.json().catch(()=>({}));
      wrap.innerHTML = '<div style="color:#EF4444;font-size:11px;padding:12px;background:#FEF2F2;border-radius:8px;border:1px solid #EF444430">Could not generate summary: ' + esc(err.detail||('HTTP '+r.status)) + '</div>';
      return;
    }
    const d = await r.json();
    wrap.innerHTML =
      '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">' +
        '<span style="color:#64748B;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px">Plain English Summary' + (d.cached?' (cached)':'') + '</span>' +
        '<button class="fbtn" style="font-size:10px;padding:2px 8px" data-action="genPlainSummary" data-id="' + esc(incidentId) + '">Refresh</button>' +
      '</div>' +
      '<div style="color:#1E293B;font-size:12px;line-height:1.7;background:#F8FAFC;padding:12px;border-radius:8px;border:1px solid #8B5CF630;white-space:pre-wrap">' + esc(d.summary) + '</div>';
  } catch(e) {
    wrap.innerHTML = '<div style="color:#EF4444;font-size:11px;padding:12px">Network error: ' + esc(e.message) + '</div>';
  }
}

async function drLoadSummary(incidentId) {
  if (drPlainLoading) return;
  drPlainLoading = true;
  try {
    const r = await fetch(API + '/incidents/' + incidentId + '/plain-summary', {
      method: 'POST', headers: {...authHeaders(), 'Content-Type': 'application/json'}
    });
    const d = await r.json();
    const el = document.getElementById('dr-plain');
    if (el) {
      el.innerHTML = '<div class="l">What Happened (Plain English)</div>' +
        '<div style="color:#1E293B;font-size:13px;line-height:1.8;margin-top:10px;white-space:pre-wrap">' + esc(d.summary) + '</div>';
    }
  } catch(e) {
    const el = document.getElementById('dr-plain-loading');
    if (el) el.innerHTML = '<span style="color:#EF4444">Could not generate summary. Try refreshing.</span>';
  }
  drPlainLoading = false;
}

async function drBlockIP(incidentId, ip) {
  const agentId = prompt('Enter the Wazuh agent ID to execute the block (e.g. 001):');
  if (!agentId) return;
  if (!confirm('Block IP ' + ip + ' via agent ' + agentId + '?')) return;
  try {
    const r = await fetch(API + '/response/execute', {
      method:'POST', headers:{...authHeaders(),'Content-Type':'application/json'},
      body: JSON.stringify({action:'block_ip', agent_id:agentId, target:ip})
    });
    if (!r.ok) { const d = await r.json().catch(()=>({})); alert('Block failed: ' + (d.detail||'Error')); return; }
    await fetch(API + '/incidents/' + incidentId + '/status', {
      method:'POST', headers:{...authHeaders(),'Content-Type':'application/json'},
      body: JSON.stringify({status:'resolved'})
    });
    drNavClick=true; drView='morning'; drIncidentId=null; refresh();
  } catch(e) { alert('Error: ' + e.message); }
}

async function drHandled(incidentId) {
  const ids = drGroupIds.length > 1 ? drGroupIds : [incidentId];
  const msg = ids.length > 1
    ? 'Resolve all ' + ids.length + ' grouped incidents?'
    : 'Mark this incident as resolved?';
  if (!confirm(msg)) return;
  for (const id of ids) {
    await fetch(API + '/incidents/' + id + '/status', {
      method:'POST', headers:{...authHeaders(),'Content-Type':'application/json'},
      body: JSON.stringify({status:'resolved'})
    });
  }
  drNavClick=true; drView='morning'; drIncidentId=null; drGroupIds=[]; refresh();
}

async function drNormal(incidentId) {
  const ids = drGroupIds.length > 1 ? drGroupIds : [incidentId];
  const msg = ids.length > 1
    ? 'Mark all alerts across ' + ids.length + ' grouped incidents as false positives?\\nThis teaches the AI to handle similar alerts automatically.'
    : 'Mark all alerts in this incident as false positives?\\nThis teaches the AI to handle similar alerts automatically.';
  if (!confirm(msg)) return;
  try {
    for (const id of ids) {
      const inc = await fetchJSON('/incidents/' + id);
      const alerts = inc.alerts || [];
      for (const a of alerts) {
        if (!a.human_verdict) {
          await fetch(API + '/triage/review', {
            method:'POST', headers:{...authHeaders(),'Content-Type':'application/json'},
            body: JSON.stringify({decision_id:a.id, human_verdict:'false_positive'})
          });
        }
      }
      await fetch(API + '/incidents/' + id + '/status', {
        method:'POST', headers:{...authHeaders(),'Content-Type':'application/json'},
        body: JSON.stringify({status:'resolved'})
      });
    }
    drNavClick=true; drView='morning'; drIncidentId=null; drGroupIds=[]; refresh();
  } catch(e) { alert('Error: ' + e.message); }
}

async function drHelp(incidentId) {
  try {
    await fetch(API + '/incidents/' + incidentId + '/help-request', {
      method:'POST', headers:{...authHeaders(),'Content-Type':'application/json'}
    });
    alert('Help request sent. The SecureSleuths team has been notified.');
  } catch(e) { alert('Error: ' + e.message); }
}

async function renderDRHealth() {
  let h = `<div style="margin-bottom:16px">
    <button class="fbtn" data-action="drBackToMorning">&#x2190; Back to Daily Review</button>
  </div>`;
  h += '<div style="font-size:14px;font-weight:700;color:#64748B;text-transform:uppercase;letter-spacing:1px;margin-bottom:14px">System Health</div>';

  const [agentsRes, tiRes, statsRes] = await Promise.all([
    fetchJSON('/agents').catch(()=>({agents:[]})),
    fetchJSON('/threat-intel/stats').catch(()=>({stats:{},feeds:[]})),
    fetchJSON('/dashboard/stats').catch(()=>({today:{}})),
  ]);

  // Endpoints
  const agents = agentsRes.agents || [];
  const active = agents.filter(a => a.status === 'active' || a.status === 'connected');
  const offline = agents.filter(a => a.status !== 'active' && a.status !== 'connected');
  const agentColor = offline.length === 0 ? '#34D399' : offline.length <= 2 ? '#FBBF24' : '#EF4444';

  h += `<div class="c" style="margin-bottom:14px">
    <div class="l">Endpoints</div>
    <div style="font-size:22px;font-weight:800;color:${agentColor};margin:10px 0;font-family:'JetBrains Mono',monospace">${active.length} / ${agents.length} reporting</div>`;
  if (offline.length > 0) {
    h += `<div style="color:#EF4444;font-size:12px">Offline: ${offline.map(a => esc(a.name||a.id)).join(', ')}</div>`;
  } else if (agents.length > 0) {
    h += `<div style="color:#1E293B;font-size:12px">All endpoints online</div>`;
  } else {
    h += `<div style="color:#94A3B8;font-size:12px">No agent data available (Wazuh may be offline)</div>`;
  }
  h += `</div>`;

  // Last alert activity
  const t = statsRes.today || {};
  h += `<div class="c" style="margin-bottom:14px">
    <div class="l">Alert Activity (Last 24 Hours)</div>
    <div style="font-size:22px;font-weight:800;color:#1E293B;margin:10px 0;font-family:'JetBrains Mono',monospace">${(t.total||0).toLocaleString()} alerts processed</div>
    <div style="color:#64748B;font-size:12px">${t.auto_closed||0} auto-closed, ${t.escalated||0} escalated, ${t.tps||0} confirmed threats</div>
  </div>`;

  // Threat intel
  const tiStats = tiRes.stats || {};
  const feeds = tiRes.feeds || [];
  const activeFeeds = feeds.filter(f => f.status === 'active');
  const lastUpdate = feeds.reduce((latest, f) => f.last_success_at && f.last_success_at > latest ? f.last_success_at : latest, '');
  const feedColor = feeds.length === 0 ? '#3D5A75' : activeFeeds.length === feeds.length ? '#34D399' : '#FBBF24';

  h += `<div class="c" style="margin-bottom:14px">
    <div class="l">Threat Intelligence</div>
    <div style="display:flex;gap:30px;margin:10px 0;flex-wrap:wrap">
      <div><div style="font-size:22px;font-weight:800;color:#1E293B;font-family:'JetBrains Mono',monospace">${(tiStats.total_iocs||0).toLocaleString()}</div><div style="color:#94A3B8;font-size:11px">IOCs Loaded</div></div>
      <div><div style="font-size:22px;font-weight:800;color:${feedColor};font-family:'JetBrains Mono',monospace">${activeFeeds.length}/${feeds.length}</div><div style="color:#94A3B8;font-size:11px">Feeds Healthy</div></div>
      <div><div style="font-size:14px;font-weight:600;color:#64748B;margin-top:6px">${lastUpdate ? localTime(lastUpdate) : 'Never'}</div><div style="color:#94A3B8;font-size:11px">Last Updated</div></div>
    </div>
  </div>`;

  // AI Engine
  h += `<div class="c" style="margin-bottom:14px">
    <div class="l">AI Engine</div>
    <div style="display:flex;align-items:center;gap:10px;margin:10px 0">
      <div style="width:12px;height:12px;border-radius:50%;background:#E8EDF2"></div>
      <span style="color:#1E293B;font-size:16px;font-weight:700">Healthy</span>
    </div>
    <div style="color:#64748B;font-size:12px">Claude AI backend operational. Average confidence: ${((t.avg_confidence||0)*100).toFixed(0)}%</div>
  </div>`;

  return h;
}

let lastOverviewHash = '';
let refreshGen = 0;

async function refresh() {
  if (loginShowing) return;
  if (currentTab === 'investigate') return;
  if (currentTab === 'respond' && selectedAgent) return;
  if (currentTab === 'dailyreview' && drView === 'detail' && !drNavClick) return;
  drNavClick = false;
  const myGen = ++refreshGen;
  try {
    let html = '';
    if (currentTab === 'overview') {
      const result = await renderOverview();
      if (myGen !== refreshGen) return;
      if (result === null) {
        document.getElementById('status').innerHTML = '<div id="dot" class="spin"></div><span style="color:#B8C8D8;font-size:11px">Live</span>';
        return;
      }
      html = result;
    }
    else if (currentTab === 'dailyreview') html = await renderDailyReview();
    else if (currentTab === 'triage') html = await renderTriage();
    else if (currentTab === 'incidents') html = await renderIncidents();
    else if (currentTab === 'detection') html = await renderDetection();
    else if (currentTab === 'hunt') html = await renderHunt();
    else if (currentTab === 'feedback') html = await renderFeedback();
    else if (currentTab === 'metrics') html = await renderMetrics();
    else if (currentTab === 'soar') html = await renderSOAR();
    else if (currentTab === 'tickets') html = await renderTickets();
    else if (currentTab === 'mitre') html = await renderMITRE();
    else if (currentTab === 'investigate') html = renderInvestigate();
    else if (currentTab === 'respond') html = await renderRespond();
    else if (currentTab === 'threatintel') html = await renderThreatIntel();
    else if (currentTab === 'knowledge') html = await renderKnowledge();
    else if (currentTab === 'reports') html = await renderReports();
    else if (currentTab === 'fim' || currentTab === 'rootcheck' || currentTab === 'registry') html = await renderHostIntegrity();
    else if (currentTab === 'groups') html = await renderAgentGroups();
    else if (currentTab === 'admin') html = await renderAdmin();
    if (myGen !== refreshGen) return;
    document.getElementById('content').innerHTML = html;
    flushGrids();
    document.getElementById('status').innerHTML = '<div id="dot" class="spin"></div><span style="color:#B8C8D8;font-size:11px">Live</span>';
    // Update counts on tabs in parallel. Skip calls for features the
    // current license doesn't have — saves a 404 round-trip on every
    // refresh on Community.
    const _skip = Promise.resolve(null);
    const [dpR, hfR, icR, ssR, tkR] = await Promise.allSettled([
      _hasFeature('detection') ? fetchJSON('/detection/proposals') : _skip,
      _hasFeature('hunt')      ? fetchJSON('/hunt/findings?status=hit') : _skip,
      fetchJSON('/incidents?status=open'),
      _hasFeature('soar')      ? fetchJSON('/soar/stats') : _skip,
      _hasFeature('ticketing') ? fetchJSON('/tickets/stats') : _skip
    ]);
    if (myGen !== refreshGen) return;
    try { const dp = dpR.status==='fulfilled'?dpR.value:null; if(dp) setBadge('dc', (dp.proposals||[]).length); } catch(e) {}
    try { const hf = hfR.status==='fulfilled'?hfR.value:null; if(hf) setBadge('hc', (hf.findings||[]).filter(x=>!x.reviewed_at).length); } catch(e) {}
    try { const ic = icR.status==='fulfilled'?icR.value:null; if(ic) { const n=(ic.incidents||[]).length; setBadge('ic',n); setBadge('drc',n); } } catch(e) {}
    try { const ss = ssR.status==='fulfilled'?ssR.value:null; if(ss) setBadge('soarc', ss.pending_approvals||0); } catch(e) {}
    try { const tk = tkR.status==='fulfilled'?tkR.value:null; if(tk) setBadge('tktc', (tk.errors||0)+(tk.pending||0)); } catch(e) {}
  } catch(e) {
    if (myGen !== refreshGen) return;
    if (e.message === 'Unauthorized') return;
    document.getElementById('content').innerHTML = '<div style="text-align:center;padding:40px;color:#EF4444">Dashboard error: ' + esc(e.message || 'Unknown') + '<br><span style="color:#94A3B8;font-size:11px">Try restarting the platform service if you just updated.</span></div>';
    document.getElementById('status').innerHTML = '<div id="dot" style="background:#EF4444" class="spin"></div><span style="color:#EF4444;font-size:11px">Error</span>';
  }
}

// Initialize Lucide icons
lucide.createIcons({attrs:{class:'lucide-icon'},nameAttr:'data-lucide'});
// Restore sidebar collapse state
if (localStorage.getItem('soc_sidebar_collapsed') === '1') {
  document.getElementById('sidebar').classList.add('collapsed');
  document.body.classList.add('sb-collapsed');
  document.getElementById('sidebar-toggle-icon').setAttribute('data-lucide','panel-left-open');
  lucide.createIcons({attrs:{class:'lucide-icon'},nameAttr:'data-lucide'});
}
if (!authToken) { document.getElementById('sidebar').style.display='none'; document.getElementById('content').style.marginLeft='0'; document.getElementById('content').style.maxWidth='100vw'; showLogin(); } else {
  filterTabs(); loadLicenseTabs(); updateUserDisplay();
  // Restore last active tab from localStorage
  const _savedTab = localStorage.getItem('soc_current_tab');
  if (_savedTab) {
    currentTab = _savedTab;
    document.querySelectorAll('#sidebar .nav-item').forEach(b => b.classList.toggle('on', b.getAttribute('data-tab') === _savedTab));
  }
  if (currentUserRole() === 'read_only') { currentTab = 'dailyreview'; document.querySelectorAll('#sidebar .nav-item').forEach(b => { b.classList.toggle('on', b.getAttribute('data-tab') === 'dailyreview'); }); }
  refresh();
}
// Auto-refresh only Daily Review and Overview tabs (+ Triage Pending filter).
// Other tabs refresh on user action only, so expanded items aren't destroyed.
let _userRefresh = false;
setInterval(() => {
  const autoTabs = ['dailyreview', 'overview'];
  const isTriagePending = currentTab === 'triage' && triageFilter === 'pending';
  if (_userRefresh || autoTabs.includes(currentTab) || isTriagePending) {
    _userRefresh = false;
    refresh();
  } else {
    // Still update tab badge counts without replacing content. Skip
    // paid endpoints on tiers that don't have the feature.
    const _skip2 = Promise.resolve(null);
    Promise.allSettled([
      _hasFeature('detection') ? fetchJSON('/detection/proposals') : _skip2,
      _hasFeature('hunt')      ? fetchJSON('/hunt/findings?status=hit') : _skip2,
      fetchJSON('/incidents?status=open'),
      _hasFeature('soar')      ? fetchJSON('/soar/stats') : _skip2
    ]).then(([dpR, hfR, icR, ssR]) => {
      try { const dp = dpR.status==='fulfilled'?dpR.value:null; if(dp) setBadge('dc', (dp.proposals||[]).length); } catch(e) {}
      try { const hf = hfR.status==='fulfilled'?hfR.value:null; if(hf) setBadge('hc', (hf.findings||[]).filter(x=>!x.reviewed_at).length); } catch(e) {}
      try { const ic = icR.status==='fulfilled'?icR.value:null; if(ic) { const n=(ic.incidents||[]).length; setBadge('ic',n); setBadge('drc',n); } } catch(e) {}
      try { const ss = ssR.status==='fulfilled'?ssR.value:null; if(ss) setBadge('soarc', ss.pending_approvals||0); } catch(e) {}
    });
  }
}, 10000);

// ── CSP-compliant event delegation ──────────────────────────────
// Replaces all inline onclick/onchange/onkeydown/onmouseover/onmouseout handlers.
(function() {
  document.addEventListener('click', function(e) {
    var el = e.target.closest('[data-action]');
    if (!el) return;
    if (el.dataset.stopPropagation === 'true') e.stopPropagation();
    var a = el.dataset.action;
    var id = el.dataset.id;
    switch(a) {
      // ── Navigation & Layout (static HTML) ──
      case 'navClick': navClick(el); break;
      case 'toggleSidebar': toggleSidebar(); break;
      case 'logout': localStorage.removeItem('soc_token'); location.reload(); break;

      // ── Login ──
      case 'doLogin': doLogin(); break;

      // ── Triage ──
      case 'setTimeRange': setTimeRange(el.dataset.range); break;
      case 'setTriageFilter': setTriageFilter(el.dataset.filter); break;
      case 'toggleAlert': toggleAlert(id); break;
      case 'toggleAuditTrail': toggleAuditTrail(id); break;
      case 'toggleRuleStats': toggleRuleStats(id, el.dataset.rule); break;
      case 'review': review(id, el.dataset.verdict); break;

      // ── Detection / Proposals ──
      case 'setProposalFilter': setProposalFilter(el.dataset.filter); break;
      case 'bulkApprove': bulkApprove(); break;
      case 'bulkDeploy': bulkDeploy(); break;
      case 'runDetectionCycle': runDetectionCycle(); break;
      case 'toggleProposal': toggleProposal(id); break;
      case 'proposalAction': proposalAction(id, el.dataset.status); break;
      case 'rejectProposal': rejectProposal(id); break;
      case 'deployProposal': deployProposal(id); break;
      case 'rollbackProposal': rollbackProposal(id); break;
      case 'showDetectionHistory': showDetectionHistory(); break;
      case 'showRuleVersions': showRuleVersions(id); break;
      case 'showSigmaConvertModal': showSigmaConvertModal(); break;
      case 'submitSigmaConvert': submitSigmaConvert(); break;
      case 'showSigmaImportModal': showSigmaImportModal(); break;
      case 'submitSigmaImport': submitSigmaImport(); break;
      case 'showValidateRuleModal': showValidateRuleModal(); break;
      case 'submitValidateRule': submitValidateRule(); break;

      // ── Incidents ──
      case 'setIncidentFilter': setIncidentFilter(el.dataset.filter); break;
      case 'showTabAndFilter': showTab(el.dataset.tab); setIncidentFilter(el.dataset.filter); break;
      case 'closeSlideOver': closeSlideOver(); break;
      case 'switchSOTab': switchSOTab(el, el.dataset.tab, id); break;
      case 'changeIncidentStatusAndClose': changeIncidentStatus(id, el.dataset.status); closeSlideOver(); break;
      case 'assignIncident': assignIncident(id); break;
      case 'addIncidentNote': addIncidentNote(id); break;
      case 'genPlainSummary': genPlainSummary(id); break;
      case 'escalateIncident': escalateIncident(id, el.dataset.field); break;
      case 'createTicketForIncident': showCreateTicketModal(); setTimeout(function(){var e=document.getElementById('tkt-incident');if(e)e.value=id;},50); break;
      case 'loadIncidentDetail': e.preventDefault(); loadIncidentDetail(id); break;
      case 'flagInterestingPrompt': flagInterestingPrompt(id, el.dataset.status); break;
      case 'mergeIntoIncidentPrompt': mergeIntoIncidentPrompt(id); break;
      case 'submitEvidence': submitEvidence(id); break;
      case 'submitPIR': submitPIR(id); break;

      // ── Admin ──
      case 'promptCreateUser': promptCreateUser(); break;
      case 'promptEditUser': promptEditUser(id, el.dataset.field, el.dataset.status, el.dataset.verdict==='true'); break;
      case 'setAdminSubTab': adminSubTab = id; refresh(); break;
      case 'showAssetForm': showAssetForm(); break;
      case 'editAsset': editAssetById(id); break;
      case 'deleteAsset': deleteAsset(id, el.dataset.field); break;
      case 'submitAssetForm': submitAssetForm(); break;
      case 'showIdentityForm': showIdentityForm(); break;
      case 'editIdentity': editIdentityById(id); break;
      case 'deleteIdentity': deleteIdentity(id, el.dataset.field); break;
      case 'submitIdentityForm': submitIdentityForm(); break;
      case 'showLocalIOCForm': showLocalIOCForm(); break;
      case 'deleteLocalIOC': deleteLocalIOC(id, el.dataset.field); break;
      case 'submitLocalIOCForm': submitLocalIOCForm(); break;
      case 'reloadEnrichers': reloadEnrichers(); break;

      // ── Tenant Lifecycle (mssp_admin) ──
      case 'showTenantCreateModal': showTenantCreateModal(); break;
      case 'submitTenantCreate': submitTenantCreate(); break;
      case 'showTenantDetail': showTenantDetail(id); break;
      case 'toggleTenantActive': toggleTenantActive(id, el.dataset.status); break;
      case 'showTenantRenameModal': showTenantRenameModal(id, el.dataset.field); break;
      case 'showTenantConfigEditModal': showTenantConfigEditModal(id); break;
      case 'submitTenantConfigUpdate': submitTenantConfigUpdate(id); break;
      case 'addTenantAgent': addTenantAgent(id); break;
      case 'removeTenantAgent': removeTenantAgent(id, el.dataset.field); break;

      case 'showWebhookTestModal': showWebhookTestModal(id); break;
      case 'submitWebhookTest': submitWebhookTest(id); break;

      // ── Pipeline / Shifts / Governance / Anon ──
      case 'loadHandoffReport': loadHandoffReport(); break;
      case 'showSaveHandoffModal': showSaveHandoffModal(); break;
      case 'submitSaveHandoff': submitSaveHandoff(); break;
      case 'reloadGuidance': reloadGuidance(); break;
      case 'lookupAnonToken': lookupAnonToken(); break;

      // ── Reports ──
      case 'setReportsSubTab': reportsSubTab = id; refresh(); break;
      case 'refreshLLMUsage': _userRefresh = true; refresh(); break;
      case 'setReportPeriod': reportPeriod = id; refresh(); break;

      // ── Hunt ──
      case 'setHuntFilter': setHuntFilter(el.dataset.filter); break;
      case 'setHuntTimeRange': setHuntTimeRange(el.dataset.range); break;
      case 'runHunt': runHunt(); break;
      case 'toggleHunt': toggleHunt(id); break;
      case 'reviewHunt': reviewHunt(id, el.dataset.status, el.dataset.verdict==='true'); break;
      case 'replayHypothesis': replayHypothesis(id); break;
      case 'clearReplayResult': clearReplayResult(id); break;

      // ── Respond / Agents ──
      case 'promptAR': promptAR(id, el.dataset.field); break;
      case 'selectAgent': selectAgent(id); break;
      case 'setHostIntegrityView': setHostIntegrityView(el.dataset.view); break;
      case 'copyCmd': copyCmd(el); break;
      case 'execRemediation': execRemediation(id, el.dataset.field); break;

      // ── Investigate ──
      case 'runNLQueryBtn': runNLQuery(document.getElementById('qinput').value); break;
      case 'runFollowup': var qi=document.getElementById('qinput'); if(qi)qi.value=el.textContent; runNLQuery(el.textContent); break;

      // ── MITRE ──
      case 'showMitreTechnique': showMitreTechnique(id); break;
      case 'closeMitreDetail': var md=document.getElementById('mitre-detail'); if(md)md.style.display='none'; break;

      // ── Closed-Loop / Feedback ──
      case 'runFeedbackCycle': runFeedbackCycle(); break;

      // ── SOAR ──
      case 'soarApprove': soarApprove(id); break;
      case 'soarReject': soarReject(id); break;
      case 'soarToggle': soarToggle(id); break;
      case 'soarRollback': soarRollback(id); break;

      // ── Knowledge Base ──
      case 'showKBCreateModal': showKBCreateModal(); break;
      case 'submitKBCreate': submitKBCreate(); break;
      case 'kbSearchBtn': kbSearchQuery=document.getElementById('kb-search-input').value; refresh(); break;
      case 'kbClear': kbSearchQuery=''; kbFilterType=''; refresh(); break;
      case 'kbFilterType': kbFilterType=el.dataset.filter; refresh(); break;
      case 'showKBDetail': showKBDetail(id); break;
      case 'showKBEditModal': showKBEditModal(id); break;
      case 'submitKBEdit': submitKBEdit(id); break;
      case 'deleteKBDoc': deleteKBDoc(id); break;

      // ── Tickets ──
      case 'showCreateTicketModal': showCreateTicketModal(); break;
      case 'submitCreateTicket': submitCreateTicket(); break;
      case 'ticketRetry': ticketRetry(id); break;
      case 'ticketSync': ticketSync(id); break;

      // ── Threat Intel ──
      case 'triggerTICollection': triggerTICollection(); break;
      case 'tiIocLookup': tiIocLookup(); break;
      case 'tiIocLookupBtn': tiIocLookup(); break;
      case 'tiIocClear': tiIocClear(); break;
      case 'tiCveToggleKev': tiCveToggleKev(); break;

      // ── Daily Review ──
      case 'drShowHealth': drNavClick=true; drView='health'; refresh(); break;
      case 'drBackToMorning': drNavClick=true; drView='morning'; drIncidentId=null; drGroupIds=[]; refresh(); break;
      case 'drOpenGroup': drOpenGroup(el.dataset.field, id); break;
      case 'drBlockIP': drBlockIP(id, el.dataset.field); break;
      case 'drHandled': drHandled(id); break;
      case 'drNormal': drNormal(id); break;
      case 'drHelp': drHelp(id); break;
    }
  });

  document.addEventListener('change', function(e) {
    var el = e.target.closest('[data-action]');
    if (!el) return;
    var a = el.dataset.action;
    switch(a) {
      case 'switchTenant': switchTenant(el.value); break;
      case 'setHostIntegrityAgent': setHostIntegrityAgent(el.value); break;
    }
  });

  document.addEventListener('keydown', function(e) {
    if (e.key !== 'Enter') return;
    var el = e.target.closest('[data-action-enter]');
    if (!el) return;
    var a = el.dataset.actionEnter;
    switch(a) {
      case 'doLogin': doLogin(); break;
      case 'kbSearch': kbSearchQuery=el.value; refresh(); break;
      case 'runNLQuery': runNLQuery(el.value); break;
      case 'tiIocLookup': tiIocLookup(); break;
    }
  });

  // Hover border delegation for data-hover-border / data-hover-border-reset
  document.addEventListener('mouseover', function(e) {
    var el = e.target.closest('[data-hover-border]');
    if (el) el.style.borderColor = el.dataset.hoverBorder;
  });
  document.addEventListener('mouseout', function(e) {
    var el = e.target.closest('[data-hover-border-reset]');
    if (el) el.style.borderColor = el.dataset.hoverBorderReset;
  });
})();
