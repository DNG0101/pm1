/* ============================================================
   POSTMANWEB v4 — app.js
   ============================================================ */
'use strict';

// ─────────────────────────────────────────────────────────────
// STATE
// ─────────────────────────────────────────────────────────────
const S = {
  tabs:        [],
  activeId:    null,
  workspaces:  load('pw_ws',      [{ id:'ws_default', name:'My Workspace' }]),
  activeWS:    load('pw_aws',     'ws_default'),
  collections: load('pw_colls',   []),
  envs:        load('pw_envs',    []),
  activeEnv:   load('pw_aenv',    null),
  history:     fixHistory(load('pw_hist', [])),
  globals:     load('pw_globals', {}),
  cookies:     load('pw_cookies', {}),
  mocks:       load('pw_mocks',   []),
  settings:    load('pw_settings', {
    corsEnabled: false,
    proxyUrl:    'https://square-credit-8186.donthulanithish53.workers.dev/?url=',
    historyOn:   true,
    theme:       'dark',
  }),
};

// Normalise legacy history: pinned must be explicit true, never undefined/null
function fixHistory(arr) {
  if (!Array.isArray(arr)) return [];
  return arr.map(h => ({ ...h, pinned: h.pinned === true }));
}

let _bodyType    = 'none';
let _testResults = [];
let _consoleLogs = [];
let _abortCtrl   = null;
let _wsConn      = null;
let _localVars   = {};
let _iterInfo    = { iteration:0, iterationCount:1, dataRow:{} };

// Current response object — needed by enlarge/fullscreen
let _lastResponse = null;

// Advanced repeat state
let _advEntry    = null;   // history entry being repeated
let _advRunning  = false;

// ─────────────────────────────────────────────────────────────
// STORAGE
// ─────────────────────────────────────────────────────────────
function load(k, def) {
  try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : def; }
  catch { return def; }
}
function save() {
  try {
    localStorage.setItem('pw_colls',    JSON.stringify(S.collections));
    localStorage.setItem('pw_envs',     JSON.stringify(S.envs));
    localStorage.setItem('pw_aenv',     JSON.stringify(S.activeEnv));
    localStorage.setItem('pw_hist',     JSON.stringify(S.history.slice(0, 500)));
    localStorage.setItem('pw_globals',  JSON.stringify(S.globals));
    localStorage.setItem('pw_cookies',  JSON.stringify(S.cookies));
    localStorage.setItem('pw_mocks',    JSON.stringify(S.mocks));
    localStorage.setItem('pw_settings', JSON.stringify(S.settings));
    localStorage.setItem('pw_ws',       JSON.stringify(S.workspaces));
    localStorage.setItem('pw_aws',      JSON.stringify(S.activeWS));
  } catch(e) { console.error('Save error', e); }
}

// ─────────────────────────────────────────────────────────────
// PRIVATE IP DETECTION
// ─────────────────────────────────────────────────────────────
const PRIV = [
  /^localhost$/i,
  /^127\.\d+\.\d+\.\d+$/,
  /^10\.\d+\.\d+\.\d+$/,
  /^192\.168\.\d+\.\d+$/,
  /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,
  /^169\.254\.\d+\.\d+$/,
  /^::1$/, /^0\.0\.0\.0$/,
];
function isPrivate(urlStr) {
  try { return PRIV.some(p => p.test(new URL(urlStr).hostname)); }
  catch { return false; }
}
function refreshDirectBadge(urlStr) {
  const b = document.getElementById('direct-badge');
  if (b) b.classList.toggle('visible', isPrivate(urlStr || ''));
}

// ─────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────
function uid()  { return Date.now().toString(36) + Math.random().toString(36).slice(2); }
function esc(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function notify(msg, type='info') {
  const el = document.createElement('div');
  el.className = 'notif ' + type;
  el.textContent = msg;
  document.getElementById('notifs').appendChild(el);
  setTimeout(() => el.remove(), 3500);
}
function openModal(html) {
  const c = document.getElementById('modals');
  c.innerHTML = html;
  c.querySelector('.modal-bg')?.addEventListener('click', e => {
    if (e.target === e.currentTarget) closeModal();
  });
}
function closeModal() { document.getElementById('modals').innerHTML = ''; }
function dl(content, filename) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], { type:'application/json' }));
  a.download = filename; a.click(); URL.revokeObjectURL(a.href);
}

// ─────────────────────────────────────────────────────────────
// CRYPTO
// ─────────────────────────────────────────────────────────────
async function _hmac(algo, key, data) {
  const enc = new TextEncoder();
  const kd  = typeof key === 'string' ? enc.encode(key) : key;
  const ck  = await crypto.subtle.importKey('raw', kd, { name:'HMAC', hash:algo }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', ck, enc.encode(data)));
}
async function hmacB64(algo, key, data) {
  const b = await _hmac(algo, key, data);
  return btoa(String.fromCharCode(...b));
}
async function sha256hex(s) {
  const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2,'0')).join('');
}
function pct(s) {
  return encodeURIComponent(String(s ?? '')).replace(/[!'()*]/g, c =>
    '%' + c.charCodeAt(0).toString(16).toUpperCase());
}
function md5(str) {
  function safe(x,y){const m=(65535&x)+(65535&y);return(x>>16)+(y>>16)+(m>>16)<<16|65535&m}
  function rot(x,n){return x<<n|x>>>32-n}
  const enc=s=>{const a=[];for(let i=0;i<s.length*8;i+=8)a[i>>5]|=(255&s.charCodeAt(i/8))<<i%32;return a};
  const core=(x,l)=>{
    x[l>>5]|=128<<l%32;x[14+(l+64>>>9<<4)]=l;
    let a=1732584193,b=-271733879,c=-1732584194,d=271733878;
    const ff=(a,b,c,d,x,s,t)=>safe(rot(safe(safe(a,b&c|~b&d),safe(x,t)),s),b);
    const gg=(a,b,c,d,x,s,t)=>safe(rot(safe(safe(a,b&d|c&~d),safe(x,t)),s),b);
    const hh=(a,b,c,d,x,s,t)=>safe(rot(safe(safe(a,b^c^d),safe(x,t)),s),b);
    const ii=(a,b,c,d,x,s,t)=>safe(rot(safe(safe(a,c^(b|~d)),safe(x,t)),s),b);
    for(let k=0;k<x.length;k+=16){
      const[A,B,C,D]=[a,b,c,d];
      a=ff(a,b,c,d,x[k],7,-680876936);d=ff(d,a,b,c,x[k+1],12,-389564586);c=ff(c,d,a,b,x[k+2],17,606105819);b=ff(b,c,d,a,x[k+3],22,-1044525330);
      a=ff(a,b,c,d,x[k+4],7,-176418897);d=ff(d,a,b,c,x[k+5],12,1200080426);c=ff(c,d,a,b,x[k+6],17,-1473231341);b=ff(b,c,d,a,x[k+7],22,-45705983);
      a=ff(a,b,c,d,x[k+8],7,1770035416);d=ff(d,a,b,c,x[k+9],12,-1958414417);c=ff(c,d,a,b,x[k+10],17,-42063);b=ff(b,c,d,a,x[k+11],22,-1990404162);
      a=ff(a,b,c,d,x[k+12],7,1804603682);d=ff(d,a,b,c,x[k+13],12,-40341101);c=ff(c,d,a,b,x[k+14],17,-1502002290);b=ff(b,c,d,a,x[k+15],22,1236535329);
      a=gg(a,b,c,d,x[k+1],5,-165796510);d=gg(d,a,b,c,x[k+6],9,-1069501632);c=gg(c,d,a,b,x[k+11],14,643717713);b=gg(b,c,d,a,x[k],20,-373897302);
      a=gg(a,b,c,d,x[k+5],5,-701558691);d=gg(d,a,b,c,x[k+10],9,38016083);c=gg(c,d,a,b,x[k+15],14,-660478335);b=gg(b,c,d,a,x[k+4],20,-405537848);
      a=gg(a,b,c,d,x[k+9],5,568446438);d=gg(d,a,b,c,x[k+14],9,-1019803690);c=gg(c,d,a,b,x[k+3],14,-187363961);b=gg(b,c,d,a,x[k+8],20,1163531501);
      a=gg(a,b,c,d,x[k+13],5,-1444681467);d=gg(d,a,b,c,x[k+2],9,-51403784);c=gg(c,d,a,b,x[k+7],14,1735328473);b=gg(b,c,d,a,x[k+12],20,-1926607734);
      a=hh(a,b,c,d,x[k+5],4,-378558);d=hh(d,a,b,c,x[k+8],11,-2022574463);c=hh(c,d,a,b,x[k+11],16,1839030562);b=hh(b,c,d,a,x[k+14],23,-35309556);
      a=hh(a,b,c,d,x[k+1],4,-1530992060);d=hh(d,a,b,c,x[k+4],11,1272893353);c=hh(c,d,a,b,x[k+7],16,-155497632);b=hh(b,c,d,a,x[k+10],23,-1094730640);
      a=hh(a,b,c,d,x[k+13],4,681279174);d=hh(d,a,b,c,x[k],11,-358537222);c=hh(c,d,a,b,x[k+3],16,-722521979);b=hh(b,c,d,a,x[k+6],23,76029189);
      a=hh(a,b,c,d,x[k+9],4,-640364487);d=hh(d,a,b,c,x[k+12],11,-421815835);c=hh(c,d,a,b,x[k+15],16,530742520);b=hh(b,c,d,a,x[k+2],23,-995338651);
      a=ii(a,b,c,d,x[k],6,-198630844);d=ii(d,a,b,c,x[k+7],10,1126891415);c=ii(c,d,a,b,x[k+14],15,-1416354905);b=ii(b,c,d,a,x[k+5],21,-57434055);
      a=ii(a,b,c,d,x[k+12],6,1700485571);d=ii(d,a,b,c,x[k+3],10,-1894986606);c=ii(c,d,a,b,x[k+10],15,-1051523);b=ii(b,c,d,a,x[k+1],21,-2054922799);
      a=ii(a,b,c,d,x[k+8],6,1873313359);d=ii(d,a,b,c,x[k+15],10,-30611744);c=ii(c,d,a,b,x[k+6],15,-1560198380);b=ii(b,c,d,a,x[k+13],21,1309151649);
      a=ii(a,b,c,d,x[k+4],6,-145523070);d=ii(d,a,b,c,x[k+11],10,-1120210379);c=ii(c,d,a,b,x[k+2],15,718787259);b=ii(b,c,d,a,x[k+9],21,-343485551);
      a=safe(a,A);b=safe(b,B);c=safe(c,C);d=safe(d,D);
    }
    return[a,b,c,d];
  };
  const arr=enc(str),r=core(arr,str.length*8);
  let h='';for(const n of r)for(let j=0;j<4;j++)h+=(n>>>j*8&255).toString(16).padStart(2,'0');
  return h;
}

// ─────────────────────────────────────────────────────────────
// VARIABLE RESOLUTION
// ─────────────────────────────────────────────────────────────
function getEnv()       { return S.envs.find(e => e.id === S.activeEnv) || null; }
function getActiveTab() { return S.tabs.find(t => t.id === S.activeId); }

const DYN = {
  '$timestamp':          ()=>String(Date.now()),
  '$isoTimestamp':       ()=>new Date().toISOString(),
  '$randomInt':          ()=>String(Math.floor(Math.random()*1000)),
  '$randomFloat':        ()=>(Math.random()*100).toFixed(2),
  '$guid':               ()=>'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,c=>{const r=Math.random()*16|0;return(c==='x'?r:r&0x3|0x8).toString(16);}),
  '$randomUUID':         ()=>DYN['$guid'](),
  '$randomAlphaNumeric': ()=>Math.random().toString(36).slice(2,10),
  '$randomBoolean':      ()=>String(Math.random()>.5),
  '$randomFirstName':    ()=>['Alice','Bob','Charlie','Diana','Eve','Frank','Grace','Hank','Ivy','Jack'][Math.floor(Math.random()*10)],
  '$randomLastName':     ()=>['Smith','Jones','Williams','Brown','Davis','Miller','Wilson','Taylor','Clark','Lee'][Math.floor(Math.random()*10)],
  '$randomFullName':     ()=>DYN['$randomFirstName']()+' '+DYN['$randomLastName'](),
  '$randomEmail':        ()=>`user${Math.floor(Math.random()*90000+10000)}@example.com`,
  '$randomUrl':          ()=>`https://example${Math.floor(Math.random()*100)}.com`,
  '$randomIP':           ()=>[1,2,3,4].map(()=>Math.floor(Math.random()*255)).join('.'),
  '$randomColor':        ()=>['red','green','blue','yellow','pink','purple','orange'][Math.floor(Math.random()*7)],
  '$randomHexColor':     ()=>'#'+Math.floor(Math.random()*16777215).toString(16).padStart(6,'0'),
  '$randomCountry':      ()=>['India','USA','UK','Germany','France','Japan','Brazil','Canada'][Math.floor(Math.random()*8)],
  '$randomCity':         ()=>['Mumbai','New York','London','Berlin','Paris','Tokyo','Sydney','Toronto'][Math.floor(Math.random()*8)],
  '$randomJobTitle':     ()=>['Engineer','Manager','Designer','Analyst','Director','Developer'][Math.floor(Math.random()*6)],
  '$randomCompanyName':  ()=>['Acme Corp','Tech Inc','Global Ltd','Prime Co','NextGen LLC'][Math.floor(Math.random()*5)],
  '$randomPrice':        ()=>(Math.random()*999+1).toFixed(2),
  '$randomCurrencyCode': ()=>['USD','EUR','GBP','JPY','INR','AUD','CAD'][Math.floor(Math.random()*7)],
  '$randomDateFuture':   ()=>new Date(Date.now()+Math.random()*365*86400000).toISOString().slice(0,10),
  '$randomDatePast':     ()=>new Date(Date.now()-Math.random()*365*86400000).toISOString().slice(0,10),
  '$randomSemver':       ()=>`${Math.floor(Math.random()*10)}.${Math.floor(Math.random()*10)}.${Math.floor(Math.random()*100)}`,
};

function resolveVars(str, extra={}) {
  if (str===null||str===undefined) return str;
  str=String(str);
  const env=getEnv(), ev=env?.variables||{}, tab=getActiveTab(), cv=tab?.collVars||{};
  str=str.replace(/\{\{\s*(\$[a-zA-Z]+)\s*\}\}/g,(m,k)=>{ const fn=DYN[k]||DYN[k.slice(1)]; return fn?fn():m; });
  str=str.replace(/\{\{([^}]+?)\}\}/g,(m,k)=>{ k=k.trim(); return _localVars[k]??cv[k]??ev[k]??S.globals[k]??_iterInfo.dataRow[k]??extra[k]??m; });
  return str;
}

// ─────────────────────────────────────────────────────────────
// JSON SCHEMA VALIDATOR
// ─────────────────────────────────────────────────────────────
function validateSchema(data, schema) {
  const errors=[];
  function chk(d,s,p){
    if(!s||s===true)return;
    if(s===false){errors.push(`${p}: schema is false`);return;}
    if(s.type){const types=Array.isArray(s.type)?s.type:[s.type];const actual=d===null?'null':Array.isArray(d)?'array':typeof d;if(!types.includes(actual))errors.push(`${p}: expected [${types}], got ${actual}`);}
    if('const'in s&&JSON.stringify(d)!==JSON.stringify(s.const))errors.push(`${p}: expected const`);
    if(s.enum&&!s.enum.some(v=>JSON.stringify(v)===JSON.stringify(d)))errors.push(`${p}: not in enum`);
    if(typeof d==='string'){if(s.minLength!==undefined&&d.length<s.minLength)errors.push(`${p}: minLength ${s.minLength}`);if(s.maxLength!==undefined&&d.length>s.maxLength)errors.push(`${p}: maxLength`);if(s.pattern&&!new RegExp(s.pattern).test(d))errors.push(`${p}: pattern failed`);}
    if(typeof d==='number'){if(s.minimum!==undefined&&d<s.minimum)errors.push(`${p}: min ${s.minimum}`);if(s.maximum!==undefined&&d>s.maximum)errors.push(`${p}: max ${s.maximum}`);}
    if(Array.isArray(d)){if(s.minItems!==undefined&&d.length<s.minItems)errors.push(`${p}: minItems`);if(s.maxItems!==undefined&&d.length>s.maxItems)errors.push(`${p}: maxItems`);if(s.items)d.forEach((x,i)=>chk(x,s.items,`${p}[${i}]`));}
    if(d!==null&&typeof d==='object'&&!Array.isArray(d)){(s.required||[]).forEach(k=>{if(!(k in d))errors.push(`${p}: missing '${k}'`);});if(s.properties)Object.entries(s.properties).forEach(([k,ps])=>{if(k in d)chk(d[k],ps,`${p}.${k}`);});}
    if(s.allOf)s.allOf.forEach((sub,i)=>chk(d,sub,`${p}/allOf[${i}]`));
  }
  chk(data,schema,'#');
  if(errors.length)throw new Error('Schema validation failed:\n'+errors.join('\n'));
}

// ─────────────────────────────────────────────────────────────
// PM SANDBOX
// ─────────────────────────────────────────────────────────────
function buildPM(response, collVars={}) {
  _testResults=[]; _consoleLogs=[]; _localVars={};
  const env=getEnv(), tab=getActiveTab();

  const chai=(val)=>{
    const self={
      equal:      x=>{if(val!==x)throw new Error(`Expected ${JSON.stringify(x)}, got ${JSON.stringify(val)}`);return self;},
      eql:        x=>{if(JSON.stringify(val)!==JSON.stringify(x))throw new Error(`Deep equal failed`);return self;},
      include:    x=>{const s=typeof val==='string'?val:JSON.stringify(val);if(!s.includes(x))throw new Error(`Expected to include "${x}"`);return self;},
      match:      r=>{if(!r.test(String(val)))throw new Error(`Expected to match ${r}`);return self;},
      matchSchema:s=>{validateSchema(val,s);return self;},
      keys:       a=>{a.forEach(k=>{if(typeof val!=='object'||!(k in val))throw new Error(`Missing key: ${k}`);});return self;},
      deep:{equal:x=>{if(JSON.stringify(val)!==JSON.stringify(x))throw new Error('Deep equal failed');return self;}},
      not:{
        equal:  x=>{if(val===x)throw new Error(`Expected NOT ${JSON.stringify(x)}`);return self;},
        include:x=>{if(String(val).includes(x))throw new Error(`Expected NOT to include "${x}"`);return self;},
        empty:  ()=>{if(!val||val.length===0)throw new Error('Expected non-empty');return self;},
        ok:     ()=>{if(val)throw new Error('Expected falsy');return self;},
        have:{property:p=>{if(typeof val==='object'&&val!==null&&p in val)throw new Error(`Expected NOT to have "${p}"`);return self;}},
        be:{above:x=>{if(val>x)throw new Error(`Expected <= ${x}`);return self;},below:x=>{if(val<x)throw new Error(`Expected >= ${x}`);return self;}},
      },
      be:{
        below:  x=>{if(!(val<x))throw new Error(`Expected ${val} < ${x}`);return self;},
        above:  x=>{if(!(val>x))throw new Error(`Expected ${val} > ${x}`);return self;},
        at:{least:x=>{if(!(val>=x))throw new Error(`Expected >= ${x}`);return self;},most:x=>{if(!(val<=x))throw new Error(`Expected <= ${x}`);return self;}},
        ok:()=>{if(!val)throw new Error('Expected truthy');return self;},
        true:()=>{if(val!==true)throw new Error('Expected true');return self;},
        false:()=>{if(val!==false)throw new Error('Expected false');return self;},
        null:()=>{if(val!==null)throw new Error('Expected null');return self;},
        undefined:()=>{if(val!==undefined)throw new Error('Expected undefined');return self;},
        a:t=>{const at=Array.isArray(val)?'array':typeof val;if(at!==t)throw new Error(`Expected type ${t}, got ${at}`);return self;},
        an:t=>{const at=Array.isArray(val)?'array':typeof val;if(at!==t)throw new Error(`Expected type ${t}, got ${at}`);return self;},
        empty:()=>{if(val&&val.length>0)throw new Error('Expected empty');return self;},
        json:()=>{try{JSON.parse(response?._body||'null');}catch{throw new Error('Not JSON');}return self;},
        string:()=>{if(typeof val!=='string')throw new Error('Expected string');return self;},
        number:()=>{if(typeof val!=='number')throw new Error('Expected number');return self;},
        array:()=>{if(!Array.isArray(val))throw new Error('Expected array');return self;},
        object:()=>{if(typeof val!=='object'||Array.isArray(val))throw new Error('Expected object');return self;},
        oneOf:a=>{if(!a.includes(val))throw new Error(`Expected one of [${a}]`);return self;},
        closeTo:(x,d=2)=>{if(Math.abs(val-x)>d)throw new Error(`Expected ${val} ≈ ${x}`);return self;},
      },
      have:{
        property:(p,v)=>{if(typeof val!=='object'||val===null||!(p in val))throw new Error(`Expected property "${p}"`);if(v!==undefined&&val[p]!==v)throw new Error(`Property "${p}" expected ${JSON.stringify(v)}`);return self;},
        length:n=>{if(!val||val.length!==n)throw new Error(`Expected length ${n}, got ${val?.length}`);return self;},
        lengthOf:n=>{if(!val||val.length!==n)throw new Error(`Expected length ${n}`);return self;},
        members:a=>{if(!Array.isArray(val))throw new Error('Expected array');a.forEach(m=>{if(!val.includes(m))throw new Error(`Missing member: ${m}`);});return self;},
        status:code=>{if(!response)throw new Error('No response');if(response.status!==code)throw new Error(`Expected status ${code}, got ${response.status}`);return self;},
        header:(key,value)=>{if(!response)throw new Error('No response');const hv=response._headers?.[key.toLowerCase()];if(!hv)throw new Error(`Missing header: ${key}`);if(value!==undefined&&hv!==String(value))throw new Error(`Header "${key}" expected "${value}"`);return self;},
        jsonBody:path=>{const body=JSON.parse(response._body);const v=path.split('.').reduce((o,k)=>o?.[k],body);if(v===undefined)throw new Error(`JSON path "${path}" not found`);return self;},
        body:{that:{includes:s=>{if(!response._body.includes(s))throw new Error(`Body missing: "${s}"`);return self;}}},
      },
    };
    self.to=self;self.and=self;self.is=self;self.that=self;
    return self;
  };

  const pmResp=response?{
    code:response.status,status:response.statusText,statusCode:response.status,
    responseTime:response._time||0,size:response._size||0,
    json:()=>{try{return JSON.parse(response._body);}catch{throw new Error('Response is not valid JSON. Preview: '+String(response._body).slice(0,80));}},
    text:()=>response._body||'',
    cookies:response._cookies||{},
    headers:{get:k=>response._headers?.[k.toLowerCase()],has:k=>!!(response._headers?.[k.toLowerCase()]),toObject:()=>({...response._headers}),all:()=>({...response._headers})},
    to:{
      have:{
        status:code=>{if(response.status!==code)throw new Error(`Expected status ${code}, got ${response.status}`);},
        header:(k,v)=>{const hv=response._headers?.[k.toLowerCase()];if(!hv)throw new Error(`Missing header: ${k}`);if(v!==undefined&&hv!==String(v))throw new Error(`Header "${k}" expected "${v}"`);},
        jsonBody:path=>{const body=JSON.parse(response._body);const v=path.split('.').reduce((o,k)=>o?.[k],body);if(v===undefined)throw new Error(`JSON path "${path}" not found`);},
        body:{that:{includes:s=>{if(!response._body.includes(s))throw new Error(`Body missing: "${s}"`);}}},
      },
      be:{
        ok:()=>{if(response.status<200||response.status>=300)throw new Error(`Not OK: ${response.status}`);},
        json:()=>{try{JSON.parse(response._body);}catch{throw new Error('Not JSON');}},
        success:()=>{if(response.status<200||response.status>=300)throw new Error(`Not 2xx: ${response.status}`);},
        error:()=>{if(response.status<400)throw new Error(`Not 4xx/5xx: ${response.status}`);},
        serverError:()=>{if(response.status<500)throw new Error(`Not 5xx: ${response.status}`);},
        clientError:()=>{if(response.status<400||response.status>=500)throw new Error(`Not 4xx: ${response.status}`);},
        notFound:()=>{if(response.status!==404)throw new Error(`Not 404`);},
        created:()=>{if(response.status!==201)throw new Error(`Not 201`);},
      },
      not:{have:{status:code=>{if(response.status===code)throw new Error(`Status should NOT be ${code}`);}}},
    },
  }:{code:0,status:'',responseTime:0,size:0,json:()=>({}),text:()=>'',cookies:{},headers:{get:()=>null,has:()=>false,toObject:()=>({}),all:()=>({})},to:{have:{status:()=>{},header:()=>{},jsonBody:()=>{}},be:{ok:()=>{},json:()=>{},success:()=>{},error:()=>{}},not:{have:{status:()=>{}}}}};

  const pm={
    test:(name,fn)=>{ try{fn();_testResults.push({name,pass:true});}catch(e){_testResults.push({name,pass:false,error:e.message});} },
    expect:chai,
    response:pmResp,
    request:{
      url:{
        toString:()=>resolveVars(document.getElementById('url-in')?.value||''),
        getHost:()=>{try{return new URL(resolveVars(document.getElementById('url-in')?.value||'')).hostname;}catch{return '';}},
        getPath:()=>{try{return new URL(resolveVars(document.getElementById('url-in')?.value||'')).pathname;}catch{return '';}},
      },
      method:document.getElementById('method-sel')?.value||'GET',
      headers:{
        add:(k,v)=>{const t=getActiveTab();if(t){t.headers.push({id:uid(),on:true,k,v,desc:''});loadKV('headers',t.headers);}},
        remove:k=>{const t=getActiveTab();if(t){t.headers=t.headers.filter(h=>h.k!==k);loadKV('headers',t.headers);}},
        get:k=>readKV('headers').find(h=>h.k?.toLowerCase()===k.toLowerCase())?.v,
        has:k=>!!readKV('headers').find(h=>h.k?.toLowerCase()===k.toLowerCase()),
        toObject:()=>Object.fromEntries(readKV('headers').filter(h=>h.on&&h.k).map(h=>[h.k,h.v])),
      },
      body:{raw:document.getElementById('code-raw')?.value||'',mode:_bodyType},
    },
    environment:{
      get:k=>env?.variables?.[k],
      set:(k,v)=>{if(env){if(!env.variables)env.variables={};env.variables[k]=String(v??'');save();}},
      unset:k=>{if(env?.variables){delete env.variables[k];save();}},
      has:k=>env?.variables!==undefined&&k in(env.variables||{}),
      clear:()=>{if(env){env.variables={};save();}},
      toObject:()=>({...(env?.variables||{})}),
    },
    globals:{
      get:k=>S.globals[k],
      set:(k,v)=>{S.globals[k]=String(v??'');save();},
      unset:k=>{delete S.globals[k];save();},
      has:k=>k in S.globals,
      clear:()=>{S.globals={};save();},
      toObject:()=>({...S.globals}),
    },
    variables:{
      get:k=>_localVars[k]??env?.variables?.[k]??S.globals[k],
      set:(k,v)=>{_localVars[k]=String(v??'');},
      unset:k=>{delete _localVars[k];},
      has:k=>k in _localVars,
      toObject:()=>({..._localVars}),
      replaceIn:s=>resolveVars(s),
    },
    collectionVariables:{
      get:k=>collVars[k]??tab?.collVars?.[k],
      set:(k,v)=>{collVars[k]=String(v??'');if(tab){if(!tab.collVars)tab.collVars={};tab.collVars[k]=String(v??'');}},
      unset:k=>{delete collVars[k];if(tab?.collVars)delete tab.collVars[k];},
      has:k=>k in(collVars||{}),
      clear:()=>{Object.keys(collVars).forEach(k=>delete collVars[k]);},
      toObject:()=>({...collVars}),
    },
    info:{iteration:_iterInfo.iteration,iterationCount:_iterInfo.iterationCount,requestName:tab?.name||'',requestId:tab?.id||''},
    sendRequest:(opts,cb)=>{
      if(typeof opts==='string')opts={url:opts,method:'GET'};
      const url=resolveVars(opts.url||'');
      const direct=isPrivate(url);
      const fu=(!direct&&S.settings.corsEnabled)?S.settings.proxyUrl+encodeURIComponent(url):url;
      const h={};
      if(opts.header){if(Array.isArray(opts.header))opts.header.forEach(x=>{h[x.key]=x.value;});else Object.assign(h,opts.header);}
      if(opts.headers)Object.assign(h,opts.headers);
      const fo={method:(opts.method||'GET').toUpperCase(),headers:h};
      if(opts.body)fo.body=typeof opts.body==='string'?opts.body:opts.body?.raw?opts.body.raw:JSON.stringify(opts.body);
      fetch(fu,fo).then(async r=>{
        const body=await r.text(),hdrs={};
        r.headers.forEach((v,k)=>{hdrs[k]=v;});
        const res={code:r.status,status:r.statusText,_body:body,_headers:hdrs,json:()=>JSON.parse(body),text:()=>body,headers:{get:k=>hdrs[k.toLowerCase()],has:k=>!!(hdrs[k.toLowerCase()]),toObject:()=>({...hdrs})},to:{have:{status:code=>{if(r.status!==code)throw new Error(`${r.status}!=${code}`);}}}};
        if(cb)cb(null,res);
      }).catch(e=>{if(cb)cb(e,null);});
    },
  };
  return{pm,expect:chai};
}

function runScript(code,pmObj){
  if(!code?.trim())return;
  const con={
    log:(...a)=>_consoleLogs.push({type:'log',msg:a.map(x=>typeof x==='object'?JSON.stringify(x,null,2):String(x)).join(' ')}),
    warn:(...a)=>_consoleLogs.push({type:'warn',msg:a.map(x=>typeof x==='object'?JSON.stringify(x):String(x)).join(' ')}),
    error:(...a)=>_consoleLogs.push({type:'error',msg:a.map(x=>typeof x==='object'?JSON.stringify(x):String(x)).join(' ')}),
    info:(...a)=>_consoleLogs.push({type:'info',msg:a.map(x=>typeof x==='object'?JSON.stringify(x):String(x)).join(' ')}),
    table:d=>_consoleLogs.push({type:'log',msg:JSON.stringify(d,null,2)}),
    dir:d=>_consoleLogs.push({type:'log',msg:JSON.stringify(d,null,2)}),
    assert:(c,m)=>{if(!c)_consoleLogs.push({type:'error',msg:'Assertion failed: '+(m||'')});},
    group:()=>{},groupEnd:()=>{},time:()=>{},timeEnd:()=>{},clear:()=>{_consoleLogs=[];},
  };
  try{new Function('pm','console','expect','require',code)(pmObj.pm,con,pmObj.expect,mod=>{_consoleLogs.push({type:'warn',msg:`require('${mod}') not supported`});return{};});}
  catch(e){_consoleLogs.push({type:'error',msg:'Script error: '+e.message});}
}

// ─────────────────────────────────────────────────────────────
// TABS
// ─────────────────────────────────────────────────────────────
const MC={GET:'var(--get)',POST:'var(--post)',PUT:'var(--put)',PATCH:'var(--patch)',DELETE:'var(--delete)',HEAD:'var(--head)',OPTIONS:'var(--options)'};

function mkTab(d={}){
  return{
    id:uid(),name:d.name||'New Request',method:d.method||'GET',url:d.url||'',
    params:d.params||[{id:uid(),on:true,k:'',v:'',desc:''}],
    pathVars:d.pathVars||[],
    headers:d.headers||[{id:uid(),on:true,k:'',v:'',desc:''}],
    bodyType:d.bodyType||'none',rawFmt:d.rawFmt||'json',rawBody:d.rawBody||'',
    formData:d.formData||[],urlEncoded:d.urlEncoded||[],
    gqlQ:d.gqlQ||'',gqlV:d.gqlV||'',
    authType:d.authType||'none',authData:d.authData||{},
    preScript:d.preScript||'',testScript:d.testScript||'',
    response:null,collVars:d.collVars||{},collId:d.collId||null,
  };
}
function newTab(d){const t=mkTab(d);S.tabs.push(t);S.activeId=t.id;renderTabs();loadTabUI(t);showResponse(null);}
function switchTab(id){saveTabUI();S.activeId=id;const t=S.tabs.find(t=>t.id===id);loadTabUI(t);renderTabs();showResponse(t?.response);}
function closeTab(id,e){
  if(e)e.stopPropagation();
  const idx=S.tabs.findIndex(t=>t.id===id);if(idx===-1)return;
  S.tabs.splice(idx,1);
  if(!S.tabs.length){newTab();return;}
  S.activeId=S.tabs[Math.min(idx,S.tabs.length-1)].id;
  const t=S.tabs.find(t=>t.id===S.activeId);loadTabUI(t);showResponse(t?.response);renderTabs();
}
function renderTabs(){
  document.getElementById('tabs').innerHTML=S.tabs.map(t=>
    `<div class="tab-item${t.id===S.activeId?' active':''}" onclick="switchTab('${t.id}')">
       <span class="tab-method" style="color:${MC[t.method]||'var(--text2)'}">${t.method}</span>
       <span class="tab-name">${esc(t.name)}</span>
       <button class="tab-close" onclick="closeTab('${t.id}',event)">✕</button>
     </div>`
  ).join('');
}
function saveTabUI(){
  const t=getActiveTab();if(!t)return;
  t.method=document.getElementById('method-sel').value;
  t.url=document.getElementById('url-in').value;
  t.bodyType=_bodyType;
  t.rawBody=document.getElementById('code-raw')?.value||'';
  t.rawFmt=document.getElementById('raw-fmt')?.value||'json';
  t.gqlQ=document.getElementById('gql-q')?.value||'';
  t.gqlV=document.getElementById('gql-v')?.value||'';
  t.authType=document.getElementById('auth-sel')?.value||'none';
  t.authData=readAuthData();
  t.preScript=document.getElementById('pre-script')?.value||'';
  t.testScript=document.getElementById('test-script')?.value||'';
  t.params=readKV('params');t.pathVars=readPathVars();
  t.headers=readKV('headers');t.urlEncoded=readKV('urlenc');t.formData=readFormData();
}
function loadTabUI(t){
  if(!t)return;
  document.getElementById('method-sel').value=t.method;
  document.getElementById('url-in').value=t.url;
  document.getElementById('code-raw').value=t.rawBody||'';
  document.getElementById('raw-fmt').value=t.rawFmt||'json';
  document.getElementById('gql-q').value=t.gqlQ||'';
  document.getElementById('gql-v').value=t.gqlV||'';
  document.getElementById('auth-sel').value=t.authType||'none';
  document.getElementById('pre-script').value=t.preScript||'';
  document.getElementById('test-script').value=t.testScript||'';
  loadKV('params',t.params);loadKV('headers',t.headers);loadKV('urlenc',t.urlEncoded||[]);
  loadFormData(t.formData||[]);setBody(t.bodyType||'none');
  renderAuthFields(t.authData||{});colorMethod();
  updatePathVars(t.url,t.pathVars||[]);refreshDirectBadge(t.url);
}

// ─────────────────────────────────────────────────────────────
// KV TABLES
// ─────────────────────────────────────────────────────────────
function addKVRow(type,k='',v='',desc='',on=true){
  const tbody=document.getElementById('kv-'+type);if(!tbody)return;
  const tr=document.createElement('tr');tr.dataset.id=uid();
  tr.innerHTML=`<td><input type="checkbox" class="kv-chk"${on?' checked':''}></td><td><input type="text" placeholder="Key" value="${esc(k)}"></td><td><input type="text" placeholder="Value" value="${esc(v)}"></td><td><input type="text" placeholder="Description" value="${esc(desc)}"></td><td><button class="kv-del" onclick="this.closest('tr').remove()">✕</button></td>`;
  tbody.appendChild(tr);
}
function readKV(type){
  const rows=[];
  document.querySelectorAll('#kv-'+type+' tr').forEach(tr=>{
    const inp=tr.querySelectorAll('input');
    if(inp.length>=3)rows.push({id:tr.dataset.id||uid(),on:inp[0].type==='checkbox'?inp[0].checked:true,k:inp[1]?.value||'',v:inp[2]?.value||'',desc:inp[3]?.value||''});
  });
  return rows;
}
function loadKV(type,rows=[]){
  const tbody=document.getElementById('kv-'+type);if(!tbody)return;
  tbody.innerHTML='';
  rows.forEach(r=>addKVRow(type,r.k||r.key||'',r.v||r.value||'',r.desc||'',r.on!==false&&r.enabled!==false));
  if(!rows.length)addKVRow(type);
}
function addFormRow(k='',v='',type='text'){
  const tbody=document.getElementById('kv-form');if(!tbody)return;
  const tr=document.createElement('tr');const isFile=type==='file';
  tr.innerHTML=`<td><input type="checkbox" class="kv-chk" checked></td><td><input type="text" placeholder="Key" value="${esc(k)}"></td><td class="fv-cell"><div class="fv-text"${isFile?' style="display:none"':''}><input type="text" placeholder="Value" value="${esc(v)}"></div><div class="fv-file"${!isFile?' style="display:none"':''}><input type="file"></div></td><td><select class="fv-type-sel" onchange="toggleFormType(this)"><option value="text"${!isFile?' selected':''}>Text</option><option value="file"${isFile?' selected':''}>File</option></select></td><td><button class="kv-del" onclick="this.closest('tr').remove()">✕</button></td>`;
  tbody.appendChild(tr);
}
function toggleFormType(sel){const tr=sel.closest('tr'),file=sel.value==='file';tr.querySelector('.fv-text').style.display=file?'none':'';tr.querySelector('.fv-file').style.display=file?'':'none';}
function readFormData(){
  const rows=[];
  document.querySelectorAll('#kv-form tr').forEach(tr=>{
    const chk=tr.querySelector('.kv-chk'),key=tr.querySelectorAll('input[type=text]')[0]?.value||'',type=tr.querySelector('.fv-type-sel')?.value||'text';
    if(!chk?.checked||!key)return;
    if(type==='file'){const f=tr.querySelector('.fv-file input[type=file]')?.files?.[0];rows.push({on:true,k:key,v:'',type:'file',file:f});}
    else rows.push({on:true,k:key,v:tr.querySelector('.fv-text input')?.value||'',type:'text'});
  });
  return rows;
}
function loadFormData(rows=[]){
  const tbody=document.getElementById('kv-form');if(!tbody)return;
  tbody.innerHTML='';rows.forEach(r=>addFormRow(r.k||'',r.v||'',r.type||'text'));
  if(!rows.length)addFormRow();
}

// ─────────────────────────────────────────────────────────────
// PATH VARIABLES
// ─────────────────────────────────────────────────────────────
function updatePathVars(url='',saved=[]){
  const tbody=document.getElementById('kv-pathvars'),el=document.getElementById('pv-empty');if(!tbody)return;
  const found=[];
  [/:([a-zA-Z_][a-zA-Z0-9_]*)(?=\/|$|\?|#)/g,/\{([a-zA-Z_][a-zA-Z0-9_]*)\}/g].forEach(re=>{let m;while((m=re.exec(url))!==null)if(!found.includes(m[1]))found.push(m[1]);});
  tbody.innerHTML='';
  const sm=Object.fromEntries(saved.map(r=>[r.k,r]));
  found.forEach(p=>{
    const sv=sm[p]||{};const tr=document.createElement('tr');tr.dataset.key=p;
    tr.innerHTML=`<td style="padding:3px 6px;font-family:var(--mono);font-size:12px;color:var(--accent);white-space:nowrap">:${esc(p)}</td><td><input type="text" placeholder="value or {{variable}}" value="${esc(sv.v||'')}"></td><td><input type="text" placeholder="Description" value="${esc(sv.desc||'')}"></td><td></td>`;
    tbody.appendChild(tr);
  });
  if(el)el.style.display=found.length?'none':'';
}
function readPathVars(){
  const rows=[];
  document.querySelectorAll('#kv-pathvars tr').forEach(tr=>{const k=tr.dataset.key||'';if(!k)return;const inp=tr.querySelectorAll('input');rows.push({k,v:inp[0]?.value||'',desc:inp[1]?.value||''});});
  return rows;
}
function resolvePathInUrl(url){
  readPathVars().forEach(row=>{
    if(!row.k)return;const val=encodeURIComponent(resolveVars(row.v));
    url=url.replace(new RegExp(':'+row.k+'(?=/|$|\\?|#)','g'),val);
    url=url.replace(new RegExp('\\{'+row.k+'\\}','g'),val);
  });
  return url;
}

// ─────────────────────────────────────────────────────────────
// BODY
// ─────────────────────────────────────────────────────────────
function setBody(type){
  _bodyType=type;
  document.querySelectorAll('.btype-btn').forEach(b=>b.classList.toggle('active',b.dataset.type===type));
  ['none','form','urlenc','raw','binary','graphql'].forEach(t=>{const el=document.getElementById('body-'+t);if(el)el.style.display=t===type?'block':'none';});
}
function beautifyRaw(){
  const ta=document.getElementById('code-raw'),fmt=document.getElementById('raw-fmt')?.value;
  if(!ta?.value.trim())return;
  if(fmt==='json'){try{ta.value=JSON.stringify(JSON.parse(ta.value),null,2);notify('Beautified ✨','success');}catch(e){notify('Invalid JSON: '+e.message,'error');}}
  else notify('Beautify only supported for JSON','info');
}
function onRawFmtChange(){const fmt=document.getElementById('raw-fmt')?.value,ta=document.getElementById('code-raw');if(!ta||ta.value.trim())return;const h={json:'{"key":"value"}',xml:'<root>\n  <el>value</el>\n</root>',html:'<h1>Hello</h1>',text:'text here',javascript:'console.log("hi")'};ta.placeholder=h[fmt]||'';}
function showBinFile(input){const f=input.files?.[0];if(f)document.getElementById('bin-label').textContent=`📎 ${f.name} (${formatBytes(f.size)})`;}
function handleBinDrop(e){e.preventDefault();document.getElementById('bin-drop').classList.remove('dov');const f=e.dataTransfer?.files?.[0];if(!f)return;const dt=new DataTransfer();dt.items.add(f);document.getElementById('bin-file').files=dt.files;document.getElementById('bin-label').textContent=`📎 ${f.name} (${formatBytes(f.size)})`;}

// ─────────────────────────────────────────────────────────────
// AUTH
// ─────────────────────────────────────────────────────────────
const AUTH_HTML={
  none:`<p class="auth-info">No authorization will be sent with this request.</p>`,
  bearer:`<div class="af"><label>TOKEN</label><input type="text" id="a-token" placeholder="Bearer token (supports {{variable}})"></div><p class="auth-info">Adds <code>Authorization: Bearer &lt;token&gt;</code> automatically.</p>`,
  apikey:`<div class="af"><label>KEY NAME</label><input type="text" id="a-key" placeholder="e.g. X-API-Key"></div><div class="af"><label>KEY VALUE</label><input type="text" id="a-key-val" placeholder="your-api-key"></div><div class="af"><label>ADD TO</label><select id="a-key-in"><option value="header">Header</option><option value="query">Query Params</option></select></div>`,
  basic:`<div class="af"><label>USERNAME</label><input type="text" id="a-user" placeholder="username"></div><div class="af"><label>PASSWORD</label><input type="password" id="a-pass" placeholder="password"></div><p class="auth-info">Encodes as Base64 → <code>Authorization: Basic &lt;base64(user:pass)&gt;</code></p>`,
  digest:`<div class="af"><label>USERNAME</label><input type="text" id="a-du" placeholder="username"></div><div class="af"><label>PASSWORD</label><input type="password" id="a-dp" placeholder="password"></div><div class="af"><label>REALM (auto from 401)</label><input type="text" id="a-realm" placeholder="leave blank for auto-detect"></div><div class="af"><label>NONCE (auto from 401)</label><input type="text" id="a-nonce" placeholder="leave blank for auto-detect"></div><div class="af"><label>QOP</label><input type="text" id="a-qop" placeholder="auth"></div>`,
  oauth1:`<div class="af"><label>CONSUMER KEY</label><input type="text" id="a-ck" placeholder="Consumer Key"></div><div class="af"><label>CONSUMER SECRET</label><input type="text" id="a-cs" placeholder="Consumer Secret"></div><div class="af"><label>ACCESS TOKEN</label><input type="text" id="a-at" placeholder="Access Token (optional)"></div><div class="af"><label>TOKEN SECRET</label><input type="text" id="a-ts" placeholder="Token Secret (optional)"></div><div class="af"><label>SIGNATURE METHOD</label><select id="a-sm"><option value="HMAC-SHA1">HMAC-SHA1</option><option value="HMAC-SHA256">HMAC-SHA256</option></select></div>`,
  oauth2:`<div class="af"><label>ACCESS TOKEN</label><input type="text" id="a-o2" placeholder="Paste your OAuth 2.0 access token"></div><div class="af"><label>HEADER PREFIX</label><input type="text" id="a-o2p" value="Bearer" placeholder="Bearer"></div>`,
  hawk:`<div class="af"><label>HAWK AUTH ID</label><input type="text" id="a-hid" placeholder="Hawk Auth ID"></div><div class="af"><label>HAWK AUTH KEY</label><input type="text" id="a-hkey" placeholder="Hawk Auth Key"></div><div class="af"><label>ALGORITHM</label><select id="a-halg"><option value="sha256">sha256</option><option value="sha1">sha1</option></select></div>`,
  aws:`<div class="af"><label>ACCESS KEY ID</label><input type="text" id="a-ak" placeholder="AKIAIOSFODNN7EXAMPLE"></div><div class="af"><label>SECRET ACCESS KEY</label><input type="password" id="a-sk" placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"></div><div class="af"><label>AWS REGION</label><input type="text" id="a-region" placeholder="us-east-1"></div><div class="af"><label>SERVICE</label><input type="text" id="a-svc" placeholder="execute-api"></div><div class="af"><label>SESSION TOKEN (optional)</label><input type="text" id="a-sess" placeholder="For temporary credentials"></div>`,
  ntlm:`<div class="af"><label>USERNAME</label><input type="text" id="a-nu" placeholder="username or DOMAIN\\username"></div><div class="af"><label>PASSWORD</label><input type="password" id="a-np" placeholder="password"></div><div class="af"><label>DOMAIN</label><input type="text" id="a-nd" placeholder="DOMAIN (optional)"></div><div class="af"><label>WORKSTATION</label><input type="text" id="a-nw" placeholder="optional"></div>`,
};
function renderAuthFields(data={}){
  const type=document.getElementById('auth-sel')?.value||'none';
  document.getElementById('auth-fields').innerHTML=AUTH_HTML[type]||'';
  const tab=getActiveTab();const ad=(data&&Object.keys(data).length>0)?data:(tab?.authData||{});
  document.querySelectorAll('#auth-fields input, #auth-fields select').forEach(el=>{if(el.id&&ad[el.id]!==undefined)el.value=ad[el.id];});
}
function readAuthData(){const d={};document.querySelectorAll('#auth-fields input, #auth-fields select').forEach(el=>{if(el.id)d[el.id]=el.value;});return d;}

async function computeAuth(method,url){
  const type=document.getElementById('auth-sel')?.value||'none';
  const headers={},queryParams={};
  if(type==='bearer'){const t=resolveVars(document.getElementById('a-token')?.value?.trim()||'');if(t)headers['Authorization']='Bearer '+t;}
  else if(type==='basic'){const u=resolveVars(document.getElementById('a-user')?.value||''),p=resolveVars(document.getElementById('a-pass')?.value||'');headers['Authorization']='Basic '+btoa(unescape(encodeURIComponent(u+':'+p)));}
  else if(type==='apikey'){const loc=document.getElementById('a-key-in')?.value,k=resolveVars(document.getElementById('a-key')?.value?.trim()||''),v=resolveVars(document.getElementById('a-key-val')?.value||'');if(k&&v){if(loc==='query')queryParams[k]=v;else headers[k]=v;}}
  else if(type==='oauth2'){const t=resolveVars(document.getElementById('a-o2')?.value?.trim()||''),p=document.getElementById('a-o2p')?.value||'Bearer';if(t)headers['Authorization']=p+' '+t;}
  else if(type==='oauth1'){const ck=document.getElementById('a-ck')?.value?.trim()||'',cs=document.getElementById('a-cs')?.value?.trim()||'',at=document.getElementById('a-at')?.value?.trim()||'',ts=document.getElementById('a-ts')?.value?.trim()||'',sm=document.getElementById('a-sm')?.value||'HMAC-SHA1';if(ck&&cs){try{headers['Authorization']=await signOAuth1(method,url,ck,cs,at,ts,sm);}catch(e){console.error('OAuth1',e);}}}
  else if(type==='hawk'){const id=document.getElementById('a-hid')?.value?.trim()||'',key=document.getElementById('a-hkey')?.value?.trim()||'',alg=document.getElementById('a-halg')?.value||'sha256';if(id&&key){try{headers['Authorization']=await signHawk(method,url,id,key,alg);}catch(e){console.error('Hawk',e);}}}
  else if(type==='aws'){const ak=document.getElementById('a-ak')?.value?.trim()||'',sk=document.getElementById('a-sk')?.value?.trim()||'',reg=document.getElementById('a-region')?.value?.trim()||'us-east-1',svc=document.getElementById('a-svc')?.value?.trim()||'execute-api',ses=document.getElementById('a-sess')?.value?.trim()||'';if(ak&&sk){try{Object.assign(headers,await signAWSv4(method,url,null,ak,sk,reg,svc,ses));}catch(e){console.error('AWS',e);}}}
  return{headers,queryParams};
}

async function signOAuth1(method,url,ck,cs,at,ts,sm='HMAC-SHA1'){
  let uo;try{uo=new URL(url);}catch{uo=new URL('https://example.com');}
  const bu=uo.protocol+'//'+uo.host+uo.pathname,qp={};uo.searchParams.forEach((v,k)=>{qp[k]=v;});
  const nonce=Math.random().toString(36).slice(2)+Math.random().toString(36).slice(2),ts2=String(Math.floor(Date.now()/1000));
  const op={oauth_consumer_key:ck,oauth_nonce:nonce,oauth_signature_method:sm,oauth_timestamp:ts2,oauth_version:'1.0',...(at?{oauth_token:at}:{})};
  const allP={...qp,...op};
  const pStr=Object.keys(allP).sort().map(k=>`${pct(k)}=${pct(allP[k])}`).join('&');
  const base=[method.toUpperCase(),pct(bu),pct(pStr)].join('&');
  const sigKey=`${pct(cs)}&${pct(ts||'')}`;
  const sig=await hmacB64(sm.includes('256')?'SHA-256':'SHA-1',sigKey,base);
  op.oauth_signature=sig;
  return 'OAuth '+Object.keys(op).sort().map(k=>`${k}="${pct(op[k])}"`).join(', ');
}
async function signHawk(method,url,id,key,algo='sha256'){
  const ts=Math.floor(Date.now()/1000),nonce=Math.random().toString(36).slice(2,8);
  let p;try{p=new URL(url);}catch{p=new URL('https://example.com');}
  const resource=p.pathname+(p.search||''),host=p.hostname,port=p.port||(p.protocol==='https:'?'443':'80');
  const norm=['hawk.1.header',ts,nonce,method.toUpperCase(),resource,host,port,'','','',''].join('\n')+'\n';
  const mac=await hmacB64(algo==='sha1'?'SHA-1':'SHA-256',key,norm);
  return `Hawk id="${id}", ts="${ts}", nonce="${nonce}", mac="${mac}"`;
}
async function signAWSv4(method,url,body,ak,sk,region,service,session){
  let u;try{u=new URL(url);}catch{return{};}
  const now=new Date(),date=now.toISOString().slice(0,10).replace(/-/g,''),dt=now.toISOString().replace(/[:\-]|\.\d{3}/g,'').slice(0,15)+'Z';
  const bHash=await sha256hex(body||'');
  const sH={'host':u.hostname+(u.port?':'+u.port:''),'x-amz-date':dt,'x-amz-content-sha256':bHash,...(session?{'x-amz-security-token':session}:{})};
  const sN=Object.keys(sH).sort(),cH=sN.map(k=>`${k}:${sH[k]}`).join('\n')+'\n',sHStr=sN.join(';');
  const qa=[];u.searchParams.forEach((v,k)=>qa.push([encodeURIComponent(k),encodeURIComponent(v)]));qa.sort(([a],[b])=>a<b?-1:a>b?1:0);
  const cQ=qa.map(([k,v])=>`${k}=${v}`).join('&');
  const cR=[method.toUpperCase(),u.pathname||'/',cQ,cH,sHStr,bHash].join('\n');
  const scope=`${date}/${region}/${service}/aws4_request`;
  const sts=['AWS4-HMAC-SHA256',dt,scope,await sha256hex(cR)].join('\n');
  const kD=await _hmac('SHA-256','AWS4'+sk,date),kR=await _hmac('SHA-256',kD,region),kS=await _hmac('SHA-256',kR,service),kSn=await _hmac('SHA-256',kS,'aws4_request');
  const sigB=await _hmac('SHA-256',kSn,sts);
  const sig=[...sigB].map(b=>b.toString(16).padStart(2,'0')).join('');
  return{'Authorization':`AWS4-HMAC-SHA256 Credential=${ak}/${scope}, SignedHeaders=${sHStr}, Signature=${sig}`,'x-amz-date':dt,'x-amz-content-sha256':bHash,...(session?{'x-amz-security-token':session}:{})};
}

function colorMethod(){
  const sel=document.getElementById('method-sel');if(!sel)return;
  sel.style.color=MC[sel.value]||'var(--text1)';
  const t=getActiveTab();if(t){t.method=sel.value;renderTabs();}
}

// ─────────────────────────────────────────────────────────────
// CORS
// ─────────────────────────────────────────────────────────────
function toggleCORS(){
  S.settings.corsEnabled=!S.settings.corsEnabled;
  if(!S.settings.proxyUrl)S.settings.proxyUrl='https://square-credit-8186.donthulanithish53.workers.dev/?url=';
  save();refreshCORSBtn();
  notify(S.settings.corsEnabled?'⚡ CORS Proxy ENABLED':'🔴 CORS Proxy disabled',S.settings.corsEnabled?'success':'info');
}
function refreshCORSBtn(){
  const btn=document.getElementById('cors-btn');if(!btn)return;
  btn.textContent=S.settings.corsEnabled?'⚡ CORS: ON':'⚡ CORS: OFF';
  btn.className=S.settings.corsEnabled?'on':'';btn.id='cors-btn';
}

// ─────────────────────────────────────────────────────────────
// MOCK
// ─────────────────────────────────────────────────────────────
function checkMock(method,url){
  if(!document.getElementById('opt-mock')?.checked)return null;
  for(const m of S.mocks){if(!m.enabled)continue;if(m.method!=='*'&&m.method!==method)continue;const rx=new RegExp('^'+m.path.replace(/[.*+?^${}()|[\]\\]/g,'\\$&').replace(/\\\*/g,'.*')+'$');if(rx.test(url)||url.includes(m.path))return m;}
  return null;
}

// ─────────────────────────────────────────────────────────────
// SEND REQUEST
// ─────────────────────────────────────────────────────────────
function cancelReq(){
  _abortCtrl?.abort();
  document.getElementById('cancel-btn').style.display='none';
  document.getElementById('send-btn').disabled=false;
  document.getElementById('send-btn').textContent='Send ➤';
}

async function sendRequest(){
  saveTabUI();
  const tab=getActiveTab(),method=document.getElementById('method-sel').value,rawUrl=document.getElementById('url-in').value.trim();
  if(!rawUrl){notify('Enter a URL first','error');return;}
  const preCode=document.getElementById('pre-script').value;
  if(preCode.trim()){const pmObj=buildPM(null,tab?.collVars||{});runScript(preCode,pmObj);flushConsole();}
  let url=resolveVars(rawUrl);url=resolvePathInUrl(url);
  const paramRows=readKV('params').filter(r=>r.on&&r.k);
  const hdrRows=readKV('headers').filter(r=>r.on&&r.k);
  const{headers:authH,queryParams:authQP}=await computeAuth(method,url);
  let finalUrl=url;
  const qpAll={...Object.fromEntries(paramRows.map(r=>[resolveVars(r.k),resolveVars(r.v)])),...authQP};
  const qpStr=new URLSearchParams(qpAll).toString();
  if(qpStr)finalUrl+=(url.includes('?')?'&':'?')+qpStr;
  const headers={};hdrRows.forEach(h=>{headers[resolveVars(h.k)]=resolveVars(h.v);});Object.assign(headers,authH);
  const disableBody=document.getElementById('opt-nobody')?.checked;
  let body=null;
  if(!disableBody&&!['GET','HEAD'].includes(method)){
    if(_bodyType==='raw'){body=resolveVars(document.getElementById('code-raw').value);if(!headers['Content-Type']&&!headers['content-type']){const ctMap={json:'application/json',xml:'application/xml',html:'text/html',text:'text/plain',javascript:'application/javascript'};headers['Content-Type']=ctMap[document.getElementById('raw-fmt').value]||'text/plain';}}
    else if(_bodyType==='urlenc'){const rows=readKV('urlenc').filter(r=>r.on&&r.k);body=rows.map(r=>`${encodeURIComponent(resolveVars(r.k))}=${encodeURIComponent(resolveVars(r.v))}`).join('&');headers['Content-Type']='application/x-www-form-urlencoded';}
    else if(_bodyType==='form'){const fd=new FormData();document.querySelectorAll('#kv-form tr').forEach(tr=>{const chk=tr.querySelector('.kv-chk'),key=tr.querySelectorAll('input[type=text]')[0]?.value,typ=tr.querySelector('.fv-type-sel')?.value||'text';if(!chk?.checked||!key)return;if(typ==='file'){const f=tr.querySelector('.fv-file input[type=file]')?.files?.[0];if(f)fd.append(key,f);}else fd.append(key,resolveVars(tr.querySelector('.fv-text input')?.value||''));});body=fd;}
    else if(_bodyType==='graphql'){let vars={};try{vars=JSON.parse(resolveVars(document.getElementById('gql-v').value||'{}'));}catch{}body=JSON.stringify({query:resolveVars(document.getElementById('gql-q').value),variables:vars});if(!headers['Content-Type'])headers['Content-Type']='application/json';}
    else if(_bodyType==='binary'){const f=document.getElementById('bin-file')?.files?.[0];if(f){body=f;if(!headers['Content-Type'])headers['Content-Type']=f.type||'application/octet-stream';}}
  }
  const mock=checkMock(method,finalUrl);
  if(mock){
    await sleep(mock.delay||0);
    const fr={status:mock.statusCode||200,statusText:'OK (Mock)',_body:resolveVars(mock.body||'{}'),_headers:{'content-type':mock.contentType||'application/json',...Object.fromEntries((mock.headers||[]).filter(h=>h.k).map(h=>[h.k.toLowerCase(),h.v]))},_time:mock.delay||0,_size:new Blob([mock.body||'']).size,_mock:true};
    if(tab)tab.response=fr;_lastResponse=fr;
    const pmObj=buildPM(fr,tab?.collVars||{});const testCode=document.getElementById('test-script').value;
    if(testCode.trim())runScript(testCode,pmObj);
    showResponse(fr);renderTests();flushConsole();notify('🎭 Mock '+fr.status,'info');return;
  }
  const isDirect=isPrivate(finalUrl);
  const fetchUrl=isDirect?finalUrl:(S.settings.corsEnabled?S.settings.proxyUrl+encodeURIComponent(finalUrl):finalUrl);
  const sendBtn=document.getElementById('send-btn'),cancelBtn=document.getElementById('cancel-btn');
  sendBtn.disabled=true;sendBtn.textContent='Sending…';cancelBtn.style.display='';
  const timeout=parseInt(document.getElementById('opt-timeout')?.value)||30000;
  _abortCtrl=new AbortController();
  const tId=setTimeout(()=>_abortCtrl?.abort(),timeout);
  const t0=Date.now();
  try{
    const opts={method,headers,signal:_abortCtrl.signal};if(body)opts.body=body;
    if(document.getElementById('auth-sel')?.value==='digest'){
      const r0=await fetch(fetchUrl,{...opts,headers:{...headers}}).catch(()=>null);
      if(r0?.status===401){const wa=r0.headers.get('www-authenticate')||'';const realm=wa.match(/realm="([^"]+)"/i)?.[1]||document.getElementById('a-realm')?.value||'';const nonce=wa.match(/nonce="([^"]+)"/i)?.[1]||document.getElementById('a-nonce')?.value||'';const qop=wa.match(/qop="?([^",]+)/i)?.[1]?.trim()||'auth';const u2=document.getElementById('a-du')?.value||'',p2=document.getElementById('a-dp')?.value||'';if(realm&&nonce){const nc='00000001',cnonce=Math.random().toString(36).slice(2,10);let uri;try{uri=new URL(finalUrl).pathname;}catch{uri='/';}const ha1=md5(`${u2}:${realm}:${p2}`),ha2=md5(`${method}:${uri}`),res=md5(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`);headers['Authorization']=`Digest username="${u2}", realm="${realm}", nonce="${nonce}", uri="${uri}", nc=${nc}, cnonce="${cnonce}", qop=${qop}, response="${res}"`;opts.headers=headers;}}
    }
    const resp=await fetch(fetchUrl,opts);clearTimeout(tId);
    const elapsed=Date.now()-t0,respTxt=await resp.text(),respH={};
    resp.headers.forEach((v,k)=>{respH[k]=v;});
    const size=new Blob([respTxt]).size;
    try{const domain=new URL(finalUrl).hostname,sc=resp.headers.get('set-cookie')||respH['set-cookie']||'';if(sc){if(!S.cookies[domain])S.cookies[domain]={};sc.split(/,(?=[^;]+=[^;]+)/).forEach(c=>{const[kv]=c.trim().split(';');const[ck,...cv]=kv.split('=');if(ck?.trim())S.cookies[domain][ck.trim()]=cv.join('=').trim();});save();}}catch{}
    const ro={status:resp.status,statusText:resp.statusText,_body:respTxt,_headers:respH,_time:elapsed,_size:size};
    if(tab)tab.response=ro;_lastResponse=ro;
    _testResults=[];const testCode=document.getElementById('test-script').value;
    if(testCode.trim()){const pmObj=buildPM(ro,tab?.collVars||{});runScript(testCode,pmObj);}
    addHistory({method,url:rawUrl,status:resp.status,time:elapsed});
    showResponse(ro);flushConsole();renderTests();
    notify(`${resp.status} ${resp.statusText} — ${elapsed}ms`,resp.status>=500?'error':resp.status>=400?'warn':'success');
  }catch(e){
    clearTimeout(tId);
    if(e.name==='AbortError'){notify('Request cancelled / timed out','info');}
    else{
      const hint=isDirect?`${e.message}\n\n💡 Private/internal IP — ensure server is reachable from your browser network.`:S.settings.corsEnabled?e.message:`${e.message}\n\n💡 Enable ⚡ CORS Proxy to bypass browser CORS restrictions.`;
      showErrorResp(hint,Date.now()-t0);notify('Request failed — '+e.message,'error');
    }
  }finally{sendBtn.disabled=false;sendBtn.textContent='Send ➤';cancelBtn.style.display='none';_abortCtrl=null;}
}

// Helper for advanced repeat / collection runner direct fetch
async function fetchDirect(url, method, headers={}, body=null) {
  const isDirect=isPrivate(url);
  const fu=isDirect?url:(S.settings.corsEnabled?S.settings.proxyUrl+encodeURIComponent(url):url);
  const opts={method:method||'GET',headers};
  if(body&&!['GET','HEAD'].includes((method||'GET').toUpperCase()))opts.body=body;
  const t0=Date.now();
  const resp=await fetch(fu,opts);
  const txt=await resp.text();
  const hdrs={};resp.headers.forEach((v,k)=>{hdrs[k]=v;});
  return{status:resp.status,statusText:resp.statusText,_body:txt,_headers:hdrs,_time:Date.now()-t0,_size:new Blob([txt]).size};
}

// ─────────────────────────────────────────────────────────────
// RESPONSE DISPLAY
// ─────────────────────────────────────────────────────────────
function formatBytes(n){if(n<1024)return n+' B';if(n<1048576)return(n/1024).toFixed(1)+' KB';return(n/1048576).toFixed(1)+' MB';}

function jsonHL(json){
  let s=JSON.stringify(json,null,2);s=s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  return s.replace(/("(?:\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,m=>{
    let c='jn';if(/^"/.test(m))c=/:$/.test(m)?'jk':'js';else if(/true|false/.test(m))c='jb';else if(/null/.test(m))c='jl';return`<span class="${c}">${m}</span>`;
  });
}

// Detect if response is HTML (by content-type OR by content sniffing)
function isHtmlResponse(r) {
  if (!r) return false;
  const ct = (r._headers?.['content-type'] || '').toLowerCase();
  if (ct.includes('text/html') || ct.includes('application/xhtml')) return true;
  // Sniff: if body starts with <!doctype or <html
  const body = (r._body || '').trimStart().toLowerCase();
  return body.startsWith('<!doctype') || body.startsWith('<html') || body.startsWith('<head') || body.startsWith('<body');
}

// Write HTML into iframe safely using blob URL (avoids srcdoc encoding issues)
function writeIframe(iframe, html) {
  if (!iframe) return;
  // Revoke old blob URL if any
  if (iframe._blobUrl) { URL.revokeObjectURL(iframe._blobUrl); iframe._blobUrl = null; }
  const blob = new Blob([html], { type: 'text/html; charset=utf-8' });
  const blobUrl = URL.createObjectURL(blob);
  iframe._blobUrl = blobUrl;
  iframe.src = blobUrl;
}

function showResponse(r) {
  const pill=document.getElementById('r-pill'),rtime=document.getElementById('r-time'),
        rsize=document.getElementById('r-size'),hint=document.getElementById('r-hint'),acts=document.getElementById('r-acts');
  if(!r){
    [pill,rtime,rsize,acts].forEach(el=>{if(el)el.style.display='none';});
    if(hint)hint.style.display='';
    document.getElementById('resp-pretty').innerHTML='';
    document.getElementById('resp-raw').textContent='';
    // Clear iframe
    const iframe=document.getElementById('resp-preview');
    if(iframe){if(iframe._blobUrl){URL.revokeObjectURL(iframe._blobUrl);iframe._blobUrl=null;}iframe.src='about:blank';}
    return;
  }

  pill.style.display='';
  pill.textContent=`${r.status} ${r.statusText}`;
  pill.className=`spill ${r._mock?'smock':'s'+Math.floor(r.status/100)}`;

  rtime.style.display='';
  rtime.innerHTML=`Time: <b${r._time>2000?' class="slow"':''}'>${r._time}ms</b>`;

  rsize.style.display='';rsize.innerHTML=`Size: <b>${formatBytes(r._size)}</b>`;
  hint.style.display='none';acts.style.display='';

  // ── Pretty body ─────────────────────────────────────────
  const ct=(r._headers?.['content-type']||'').toLowerCase();
  let pretty='';
  if(ct.includes('json')||/^\s*[\[{]/.test(r._body)){
    try{pretty=jsonHL(JSON.parse(r._body));}catch{pretty=esc(r._body);}
  } else {
    pretty=esc(r._body);
  }
  document.getElementById('resp-pretty').innerHTML=pretty;
  document.getElementById('resp-raw').textContent=r._body;

  // ── Preview: use blob URL for proper HTML rendering ──────
  const iframe=document.getElementById('resp-preview');
  if(isHtmlResponse(r)){
    writeIframe(iframe, r._body);
  } else {
    // For non-HTML, show a helpful message in the preview
    if(iframe._blobUrl){URL.revokeObjectURL(iframe._blobUrl);iframe._blobUrl=null;}
    const previewHtml=`<html><body style="font-family:sans-serif;padding:20px;color:#666;background:#f9f9f9">
      <p style="font-size:14px">Preview is only available for HTML responses.</p>
      <p style="font-size:12px;margin-top:8px">Content-Type: <code>${esc(ct||'unknown')}</code></p>
      <p style="font-size:12px">Use the <strong>Pretty</strong> or <strong>Raw</strong> tab to view this response.</p>
    </body></html>`;
    writeIframe(iframe, previewHtml);
  }

  // ── Headers table ────────────────────────────────────────
  document.getElementById('r-headers-tbl').innerHTML=
    Object.entries(r._headers||{}).map(([k,v])=>`<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join('')||
    `<tr><td colspan="2" style="color:var(--text3);padding:10px">No headers</td></tr>`;

  renderCookiesPanel();
}

function showErrorResp(msg,time){
  const pill=document.getElementById('r-pill');pill.style.display='';pill.className='spill serr';pill.textContent='Error';
  document.getElementById('r-time').style.display='';document.getElementById('r-time').innerHTML=`Time: <b class="e">${time}ms</b>`;
  document.getElementById('r-size').style.display='none';document.getElementById('r-hint').style.display='none';document.getElementById('r-acts').style.display='none';
  document.getElementById('resp-pretty').innerHTML=`<span style="color:var(--err);white-space:pre-wrap">${esc(msg)}</span>`;
  document.getElementById('resp-raw').textContent=msg;
}

function renderTests(){
  const c=document.getElementById('test-output'),badge=document.getElementById('test-badge');
  if(!_testResults.length){c.innerHTML='<div class="empty-state"><div class="ei">🧪</div><p>No tests ran.</p></div>';badge.style.display='none';return;}
  const pass=_testResults.filter(t=>t.pass).length;
  badge.textContent=`${pass}/${_testResults.length}`;badge.style.display='';
  badge.style.background=pass===_testResults.length?'var(--ok)':pass===0?'var(--err)':'var(--warn)';badge.style.color='#000';
  c.innerHTML=`<div class="test-summary"><span style="font-size:20px">${pass===_testResults.length?'✅':pass===0?'❌':'⚠️'}</span><span style="font-weight:700">${pass} / ${_testResults.length} passed</span><span style="color:var(--text3);font-size:11px">${_testResults.length-pass} failed</span></div>`+
    _testResults.map(t=>`<div class="tr-item ${t.pass?'tr-pass':'tr-fail'}"><span class="tr-icon">${t.pass?'✅':'❌'}</span><div><div class="tr-name">${esc(t.name)}</div>${t.error?`<div class="tr-err">${esc(t.error)}</div>`:''}</div></div>`).join('');
}

function flushConsole(){document.getElementById('console-out').innerHTML=_consoleLogs.map(l=>`<div class="con-row ${l.type}"><span class="ct">${l.type}</span><span class="cm">${esc(l.msg)}</span></div>`).join('');}
function clearConsole(){_consoleLogs=[];flushConsole();}

function renderCookiesPanel(){
  const p=document.getElementById('cookies-out'),domains=Object.keys(S.cookies);
  if(!domains.length){p.innerHTML='<div class="empty-state"><div class="ei">🍪</div><p>No cookies stored.</p></div>';return;}
  p.innerHTML=domains.map(d=>`<div class="ck-domain"><div class="ck-domain-nm">${esc(d)}</div>${Object.entries(S.cookies[d]).map(([k,v])=>`<div class="ck-row"><span class="ck-name">${esc(k)}</span><span class="ck-val" title="${esc(v)}">${esc(v)}</span></div>`).join('')}</div>`).join('');
}

function copyResponse(){navigator.clipboard.writeText(document.getElementById('resp-raw').textContent).then(()=>notify('Copied!','success'));}
function saveRespFile(){const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([document.getElementById('resp-raw').textContent],{type:'text/plain'}));a.download='response.txt';a.click();}

// ─────────────────────────────────────────────────────────────
// ENLARGE / FULLSCREEN OVERLAY
// ─────────────────────────────────────────────────────────────
let _fsCurrentView = 'pretty';   // tracks which sub-tab is active in fullscreen body view
let _fsPanel       = 'body';     // which panel is enlarged

function openEnlargeResp() {
  _fsPanel = 'body';
  const overlay = document.getElementById('fs-overlay');
  const title   = document.getElementById('fs-title');
  const toolbar = document.getElementById('fs-toolbar');
  const fsBody  = document.getElementById('fs-body');
  const copyBtn = document.getElementById('fs-copy-btn');
  const saveBtn = document.getElementById('fs-save-btn');

  title.textContent = 'Response Body';
  copyBtn.style.display = '';
  saveBtn.style.display = '';

  // Build sub-tabs
  toolbar.innerHTML =
    `<button class="fs-tab${_fsCurrentView==='pretty'?' active':''}" onclick="fsSwitchView('pretty')">Pretty</button>
     <button class="fs-tab${_fsCurrentView==='raw'?' active':''}"    onclick="fsSwitchView('raw')">Raw</button>
     <button class="fs-tab${_fsCurrentView==='preview'?' active':''}" onclick="fsSwitchView('preview')">Preview</button>`;

  fsBuildBodyContent(_fsCurrentView, fsBody);
  overlay.style.display = 'flex';
  overlay.focus && overlay.focus();
}

function fsSwitchView(view) {
  _fsCurrentView = view;
  document.querySelectorAll('.fs-tab').forEach(b => b.classList.toggle('active', b.textContent.toLowerCase() === view));
  fsBuildBodyContent(view, document.getElementById('fs-body'));
}

function fsBuildBodyContent(view, container) {
  const r = _lastResponse;
  if (!r) { container.innerHTML = '<p style="padding:20px;color:var(--text3)">No response yet.</p>'; return; }
  container.innerHTML = '';

  if (view === 'pretty') {
    const pre = document.createElement('pre');
    const ct = (r._headers?.['content-type'] || '').toLowerCase();
    if (ct.includes('json') || /^\s*[\[{]/.test(r._body)) {
      try { pre.innerHTML = jsonHL(JSON.parse(r._body)); }
      catch { pre.textContent = r._body; }
    } else {
      pre.textContent = r._body;
    }
    container.appendChild(pre);
  } else if (view === 'raw') {
    const pre = document.createElement('pre');
    pre.textContent = r._body;
    container.appendChild(pre);
  } else if (view === 'preview') {
    const iframe = document.createElement('iframe');
    iframe.sandbox = 'allow-scripts allow-same-origin allow-forms allow-popups allow-modals';
    iframe.referrerPolicy = 'no-referrer';
    iframe.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;border:none;background:#fff;';
    container.appendChild(iframe);
    writeIframe(iframe, isHtmlResponse(r) ? r._body :
      `<html><body style="font-family:sans-serif;padding:20px;color:#666">Preview only available for HTML responses.</body></html>`);
  }
}

function openEnlargePanel(panel) {
  _fsPanel = panel;
  const overlay = document.getElementById('fs-overlay');
  const title   = document.getElementById('fs-title');
  const toolbar = document.getElementById('fs-toolbar');
  const fsBody  = document.getElementById('fs-body');
  const copyBtn = document.getElementById('fs-copy-btn');
  const saveBtn = document.getElementById('fs-save-btn');

  toolbar.innerHTML = '';

  if (panel === 'headers') {
    title.textContent = 'Response Headers';
    copyBtn.style.display = '';
    saveBtn.style.display = '';
    const r = _lastResponse;
    const table = document.createElement('table');
    table.innerHTML = Object.entries(r?._headers || {})
      .map(([k,v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join('') ||
      '<tr><td colspan="2" style="color:var(--text3);padding:14px">No headers</td></tr>';
    fsBody.innerHTML = '';
    fsBody.appendChild(table);

  } else if (panel === 'cookies') {
    title.textContent = 'Cookies';
    copyBtn.style.display = 'none';
    saveBtn.style.display = 'none';
    const clone = document.getElementById('cookies-out').cloneNode(true);
    clone.style.padding = '14px';
    fsBody.innerHTML = '';
    fsBody.appendChild(clone);

  } else if (panel === 'tests') {
    title.textContent = 'Test Results';
    copyBtn.style.display = 'none';
    saveBtn.style.display = 'none';
    const clone = document.getElementById('test-output').cloneNode(true);
    clone.style.padding = '14px';
    fsBody.innerHTML = '';
    fsBody.appendChild(clone);

  } else if (panel === 'console') {
    title.textContent = 'Console';
    copyBtn.style.display = 'none';
    saveBtn.style.display = 'none';
    const clone = document.getElementById('console-out').cloneNode(true);
    clone.style.padding = '0';
    fsBody.innerHTML = '';
    fsBody.appendChild(clone);
  }

  overlay.style.display = 'flex';
}

function closeEnlarge() {
  const overlay = document.getElementById('fs-overlay');
  overlay.style.display = 'none';
  // Clean up any blob URLs inside fs-body
  document.querySelectorAll('#fs-body iframe').forEach(iframe => {
    if (iframe._blobUrl) { URL.revokeObjectURL(iframe._blobUrl); iframe._blobUrl = null; }
    iframe.src = 'about:blank';
  });
  document.getElementById('fs-body').innerHTML = '';
}

function fsAction(action) {
  if (action === 'copy') {
    let text = '';
    if (_fsPanel === 'body') text = _lastResponse?._body || '';
    else if (_fsPanel === 'headers') text = Object.entries(_lastResponse?._headers||{}).map(([k,v])=>`${k}: ${v}`).join('\n');
    navigator.clipboard.writeText(text).then(() => notify('Copied!','success'));
  } else if (action === 'save') {
    const content = _lastResponse?._body || '';
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([content],{type:'text/plain'}));
    a.download = 'response.txt'; a.click();
  }
}

// ─────────────────────────────────────────────────────────────
// PANEL SWITCHING
// ─────────────────────────────────────────────────────────────
function switchReqPanel(id){document.querySelectorAll('#req-ptabs .ptab').forEach(t=>t.classList.toggle('active',t.dataset.panel===id));document.querySelectorAll('.tpanel').forEach(p=>p.classList.toggle('active',p.id==='rp-'+id));}
function switchRespPanel(id){document.querySelectorAll('.rptab').forEach(t=>t.classList.toggle('active',t.dataset.panel===id));document.querySelectorAll('.rtpanel').forEach(p=>p.classList.toggle('active',p.id==='rsp-'+id));}
function switchRespBody(id){
  document.querySelectorAll('.rbview').forEach(b=>b.classList.toggle('active',b.dataset.view===id));
  document.querySelectorAll('.rbpanel').forEach(p=>p.classList.toggle('active',p.id==='rbp-'+id));
  // If switching to preview and we have a response, ensure iframe is loaded
  if (id==='preview' && _lastResponse) {
    const iframe = document.getElementById('resp-preview');
    if (!iframe.src || iframe.src === 'about:blank' || !iframe._blobUrl) {
      writeIframe(iframe, isHtmlResponse(_lastResponse) ? _lastResponse._body :
        `<html><body style="font-family:sans-serif;padding:20px;color:#666;background:#f9f9f9"><p>Preview only available for HTML responses.</p></body></html>`);
    }
  }
}
function switchSB(id){document.querySelectorAll('.sb-tab').forEach(t=>t.classList.toggle('active',t.dataset.sb===id));document.querySelectorAll('.sb-panel').forEach(p=>p.classList.toggle('active',p.id==='sbp-'+id));}
function toggleSB(){document.getElementById('sidebar').classList.toggle('hidden');}

// ─────────────────────────────────────────────────────────────
// HISTORY  — pin/unpin/del/adv all delegated
// ─────────────────────────────────────────────────────────────
function toggleHistRec(){S.settings.historyOn=document.getElementById('hist-toggle').checked;save();refreshHistDot();notify(S.settings.historyOn?'History ON':'History OFF','info');}
function refreshHistDot(){const d=document.getElementById('hist-dot'),t=document.getElementById('hist-toggle');if(d)d.className='hrec-dot'+(S.settings.historyOn===false?' off':'');if(t)t.checked=S.settings.historyOn!==false;}

function addHistory(entry){
  if(S.settings.historyOn===false)return;
  S.history.unshift({id:uid(),...entry,at:new Date().toLocaleTimeString(),pinned:false});
  if(S.history.length>500)S.history.pop();
  save();renderHistory();
}

function renderHistory(){
  const list=document.getElementById('hist-list');
  refreshHistDot();
  if(!S.history.length){list.innerHTML='<div class="empty-state"><div class="ei">📭</div><p>No history yet.</p></div>';return;}
  const pinned=S.history.filter(h=>h.pinned===true);
  const recent=S.history.filter(h=>h.pinned!==true);
  const row=h=>{
    const p=h.pinned===true;
    return `<div class="hist-row${p?' pinned':''}" data-hid="${h.id}">
      <span class="mbadge ${h.method}" style="color:${MC[h.method]||'var(--text2)'}">${h.method}</span>
      <span class="hist-url" title="${esc(h.url)}">${esc(h.url)}</span>
      <span class="hist-time">${h.at||''}</span>
      <div class="hist-acts">
        <button class="hist-adv-btn" data-action="adv" data-hid="${h.id}" title="Advanced: repeat this request N times">Adv</button>
        <button class="hist-pin-btn" data-action="pin" data-hid="${h.id}" data-pinned="${p?1:0}" title="${p?'Unpin':'Pin'}">${p?'📌':'📍'}</button>
        <button class="hist-del-btn" data-action="del" data-hid="${h.id}" title="Delete">🗑</button>
      </div>
    </div>`;
  };
  let html='';
  if(pinned.length)html+=`<div class="hist-sec">📌 PINNED</div>`+pinned.map(row).join('');
  if(recent.length){if(pinned.length)html+=`<div class="hist-sec">🕐 RECENT</div>`;html+=recent.map(row).join('');}
  list.innerHTML=html;
}

function initHistoryEvents(){
  const list=document.getElementById('hist-list');
  list.addEventListener('click',function(e){
    const advBtn=e.target.closest('[data-action="adv"]');
    if(advBtn){e.stopPropagation();e.preventDefault();const id=advBtn.dataset.hid;const h=S.history.find(x=>x.id===id);if(h)openAdvPopover(h,advBtn);return;}
    const pinBtn=e.target.closest('[data-action="pin"]');
    if(pinBtn){e.stopPropagation();e.preventDefault();const id=pinBtn.dataset.hid;const h=S.history.find(x=>x.id===id);if(!h)return;h.pinned=!h.pinned;S.history.sort((a,b)=>(b.pinned===true?1:0)-(a.pinned===true?1:0));save();renderHistory();notify(h.pinned?'📌 Pinned':'Unpinned','info');return;}
    const delBtn=e.target.closest('[data-action="del"]');
    if(delBtn){e.stopPropagation();e.preventDefault();const id=delBtn.dataset.hid;S.history=S.history.filter(x=>x.id!==id);save();renderHistory();return;}
    const row=e.target.closest('.hist-row');
    if(row){const id=row.dataset.hid;const h=S.history.find(x=>x.id===id);if(h)newTab({method:h.method,url:h.url,name:h.url.replace(/^https?:\/\//,'').slice(0,40)||'Request'});}
  });
}

function clearHistory(){if(!confirm('Delete ALL history including pinned?'))return;S.history=[];save();renderHistory();notify('History cleared','info');}
function unpinAllHistory(){
  const n=S.history.filter(h=>h.pinned===true).length;
  if(!n){notify('Nothing is pinned','info');return;}
  S.history.forEach(h=>{h.pinned=false;});
  save();renderHistory();notify(`Unpinned ${n} item${n!==1?'s':''}  ✓`,'success');
}

// ─────────────────────────────────────────────────────────────
// ADVANCED REPEAT POPOVER
// ─────────────────────────────────────────────────────────────
function openAdvPopover(histEntry, anchorEl) {
  _advEntry = histEntry;
  const pop = document.getElementById('adv-popover');
  // Reset state
  document.getElementById('adv-count').value = '5';
  document.getElementById('adv-delay').value = '0';
  document.getElementById('adv-results').innerHTML = '';
  document.getElementById('adv-pw').style.display = 'none';
  document.getElementById('adv-pb').style.width = '0';
  document.getElementById('adv-pt').textContent = '0 / 0';
  document.getElementById('adv-run-btn').disabled = false;
  document.getElementById('adv-run-btn').textContent = '▶ Run';
  _advRunning = false;

  // Position popover near the Adv button
  const rect = anchorEl.getBoundingClientRect();
  pop.style.top  = Math.min(rect.bottom + 6, window.innerHeight - 420) + 'px';
  pop.style.left = Math.max(4, Math.min(rect.left - 100, window.innerWidth - 292)) + 'px';
  pop.style.display = 'block';
}

function closeAdvPopover(){
  _advRunning = false;
  document.getElementById('adv-popover').style.display = 'none';
  _advEntry = null;
}

async function runAdvRepeat() {
  if (!_advEntry) return;
  if (_advRunning) return;

  const count = Math.max(1, Math.min(500, parseInt(document.getElementById('adv-count').value) || 5));
  const delay = Math.max(0, parseInt(document.getElementById('adv-delay').value) || 0);
  const resultsEl = document.getElementById('adv-results');
  const pbWrap = document.getElementById('adv-pw');
  const pb     = document.getElementById('adv-pb');
  const pt     = document.getElementById('adv-pt');
  const runBtn = document.getElementById('adv-run-btn');

  _advRunning = true;
  runBtn.disabled = true;
  runBtn.textContent = '⏳ Running…';
  resultsEl.innerHTML = '';
  pbWrap.style.display = 'block';
  pb.style.width = '0';
  pt.textContent = `0 / ${count}`;

  const h = _advEntry;
  let passed = 0, failed = 0;

  for (let i = 0; i < count; i++) {
    if (!_advRunning) break;
    const num = i + 1;
    try {
      const url = resolveVars(h.url || '');
      const fHeaders = {};
      // Build a minimal request matching the history entry
      // (history stores method+url; for full headers/body, load from tab or use saved)
      const resp = await fetchDirect(url, h.method || 'GET', fHeaders, null);
      const ok = resp.status >= 200 && resp.status < 300;
      if (ok) passed++; else failed++;

      const row = document.createElement('div');
      row.className = 'adv-result-row';
      row.innerHTML = `
        <span class="adv-result-num">#${num}</span>
        <span class="adv-result-stat ${ok?'ok':'err'}">${resp.status} ${resp.statusText}</span>
        <span class="adv-result-time">${resp._time}ms</span>
      `;
      resultsEl.appendChild(row);
      resultsEl.scrollTop = resultsEl.scrollHeight;

    } catch(e) {
      failed++;
      const row = document.createElement('div');
      row.className = 'adv-result-row';
      row.innerHTML = `<span class="adv-result-num">#${num}</span><span class="adv-result-stat err">Error</span><span class="adv-result-time" style="color:var(--err);max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.message)}</span>`;
      resultsEl.appendChild(row);
      resultsEl.scrollTop = resultsEl.scrollHeight;
    }

    // Update progress
    pb.style.width = Math.round(num / count * 100) + '%';
    pt.textContent = `${num} / ${count}`;
    pb.style.background = failed > 0 ? 'var(--warn)' : 'var(--ok)';

    if (delay > 0 && i < count - 1) await sleep(delay);
  }

  _advRunning = false;
  runBtn.disabled = false;
  runBtn.textContent = '▶ Run Again';
  notify(`Repeat done: ✅ ${passed}  ❌ ${failed}`, failed === 0 ? 'success' : 'warn');
}

// ─────────────────────────────────────────────────────────────
// COLLECTIONS
// ─────────────────────────────────────────────────────────────
function renderCollections(){
  const q=document.getElementById('coll-search').value.toLowerCase(),list=document.getElementById('coll-list');
  const filtered=S.collections.filter(c=>c.name.toLowerCase().includes(q));
  if(!filtered.length){list.innerHTML='<div class="empty-state"><div class="ei">📂</div><p>No collections yet.</p></div>';return;}
  list.innerHTML=filtered.map(c=>renderCollItem(c)).join('');
}
function renderCollItem(c){
  const items=(c.requests||[]).map(item=>item._isFolder?`<div class="coll-folder"><div class="folder-header" onclick="toggleFolder('${c.id}','${item.id}')"><span class="folder-arrow" id="fa-${item.id}">▶</span>📁 ${esc(item.name)}</div><div class="folder-reqs" id="fr-${item.id}">${(item.requests||[]).map(r=>reqRowHtml(c.id,r,true)).join('')}</div></div>`:reqRowHtml(c.id,item,false)).join('');
  return`<div class="coll-item" id="coll-${c.id}"><div class="coll-header" onclick="toggleColl('${c.id}')"><span class="coll-arrow" id="ca-${c.id}">▶</span><span class="coll-name" title="${esc(c.name)}">${esc(c.name)}</span><div class="coll-btns"><button class="icon-btn" title="Run" onclick="runCollModal(event,'${c.id}')">▶</button><button class="icon-btn" title="Add folder" onclick="addFolder(event,'${c.id}')">📁</button><button class="icon-btn" title="Add current request" onclick="addToColl(event,'${c.id}')">+</button><button class="icon-btn" title="Export" onclick="exportColl(event,'${c.id}')">⬇</button><button class="icon-btn del" title="Delete" onclick="delColl(event,'${c.id}')">🗑</button></div></div><div class="coll-reqs" id="cr-${c.id}">${items||'<div style="padding:8px;color:var(--text3);font-size:11px">Empty collection</div>'}</div></div>`;
}
function reqRowHtml(collId,r,inFolder=false){return`<div class="req-row${inFolder?' folder-req-row':''}" onclick="loadCollReq('${collId}','${r.id}')"><span class="mbadge ${r.method}" style="color:${MC[r.method]||'var(--text2)'}">${r.method}</span><span class="req-name" title="${esc(r.name)}">${esc(r.name)}</span><div class="req-btns"><button class="icon-btn" title="Duplicate" onclick="dupReq(event,'${collId}','${r.id}')">⧉</button><button class="icon-btn del" title="Delete" onclick="delReq(event,'${collId}','${r.id}')">✕</button></div></div>`;}
function toggleColl(id){document.getElementById('cr-'+id)?.classList.toggle('open');document.getElementById('ca-'+id)?.classList.toggle('open');}
function toggleFolder(cid,fid){document.getElementById('fr-'+fid)?.classList.toggle('open');document.getElementById('fa-'+fid)?.classList.toggle('open');}
function addFolder(e,collId){e.stopPropagation();const name=prompt('Folder name:');if(!name)return;const coll=S.collections.find(c=>c.id===collId);if(!coll)return;if(!coll.requests)coll.requests=[];coll.requests.push({id:uid(),name,_isFolder:true,requests:[]});save();renderCollections();}

function runCollModal(e,id){
  e.stopPropagation();const coll=S.collections.find(c=>c.id===id);if(!coll?.requests?.length){notify('Collection is empty','error');return;}
  const reqs=(coll.requests||[]).filter(r=>!r._isFolder);
  openModal(`<div class="modal-bg"><div class="modal lg"><div class="mh"><span class="mh-title">▶ Collection Runner — ${esc(coll.name)}</span><button class="m-close" onclick="closeModal()">✕</button></div><div class="mb"><div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:16px"><div class="fg"><label>ITERATIONS</label><input type="number" id="cr-iter" value="1" min="1" max="1000"></div><div class="fg"><label>DELAY (ms)</label><input type="number" id="cr-delay" value="0" min="0"></div><div class="fg"><label>STOP ON ERROR</label><label class="toggle" style="margin-top:6px"><input type="checkbox" id="cr-stop"><span class="t-slider"></span></label></div></div><div class="fg"><label>DATA FILE (CSV/JSON)</label><input type="file" id="cr-data" accept=".json,.csv"></div><div style="margin-bottom:10px"><div class="field-label">SELECT REQUESTS</div>${reqs.map(r=>`<div class="cr-req-item"><input type="checkbox" class="cr-req-chk kv-chk" data-rid="${r.id}" checked><span class="mbadge ${r.method}" style="color:${MC[r.method]||'var(--text2)'}">${r.method}</span><span>${esc(r.name)}</span></div>`).join('')}</div><div class="cr-progress-wrap"><div class="cr-progress-bar" id="cr-bar"></div></div><div id="cr-results" style="max-height:280px;overflow-y:auto;"></div></div><div class="mf"><button class="btn secondary" onclick="closeModal()">Close</button><button class="btn primary" onclick="doRunColl('${id}')">▶ Run</button></div></div></div>`);
}
async function doRunColl(id){
  const coll=S.collections.find(c=>c.id===id);if(!coll)return;
  const iters=parseInt(document.getElementById('cr-iter')?.value)||1,delay=parseInt(document.getElementById('cr-delay')?.value)||0,stop=document.getElementById('cr-stop')?.checked;
  const checkedIds=new Set([...document.querySelectorAll('.cr-req-chk:checked')].map(el=>el.dataset.rid));
  const reqs=(coll.requests||[]).filter(r=>!r._isFolder&&checkedIds.has(r.id));
  if(!reqs.length){notify('No requests selected','error');return;}
  let dataRows=[{}];const dataFile=document.getElementById('cr-data')?.files?.[0];
  if(dataFile){try{const txt=await dataFile.text();if(dataFile.name.endsWith('.json')){dataRows=JSON.parse(txt);if(!Array.isArray(dataRows))dataRows=[dataRows];}else{const lines=txt.trim().split('\n'),hdrs=lines[0].split(',').map(h=>h.trim().replace(/^"|"$/g,''));dataRows=lines.slice(1).map(line=>{const vals=line.split(',').map(v=>v.trim().replace(/^"|"$/g,''));return Object.fromEntries(hdrs.map((h,i)=>[h,vals[i]||'']));});}}catch(e){notify('Data file error: '+e.message,'error');return;}}
  const total=iters*dataRows.length*reqs.length;let done=0,passed=0,failed=0;
  const resultEl=document.getElementById('cr-results');resultEl.innerHTML='';
  for(let iter=0;iter<iters;iter++){for(const dataRow of dataRows){_iterInfo={iteration:iter,iterationCount:iters,dataRow};for(const req of reqs){
    try{
      const url=resolveVars(req.url||'',dataRow);const h={};(req.headers||[]).filter(x=>x.on!==false&&(x.k||x.key)).forEach(x=>{h[resolveVars(x.k||x.key,dataRow)]=resolveVars(x.v||x.value||'',dataRow);});
      if(req.preScript?.trim()){const pm=buildPM(null,coll.variables||{});runScript(req.preScript,pm);}
      const ro=await fetchDirect(url,req.method||'GET',h,req.rawBody&&!['GET','HEAD'].includes(req.method)?resolveVars(req.rawBody,dataRow):null);
      _testResults=[];if(req.testScript?.trim()){const pm=buildPM(ro,coll.variables||{});runScript(req.testScript,pm);}
      const pt2=_testResults.filter(t=>t.pass).length,isOk=ro.status>=200&&ro.status<300&&(!_testResults.length||pt2===_testResults.length);
      if(isOk)passed++;else failed++;
      resultEl.innerHTML+=`<div class="cr-result-item ${isOk?'pass':'fail'}"><span>${isOk?'✅':'❌'}</span><div><div style="font-weight:600;font-size:12px">[${iter+1}/${iters}] ${esc(req.name)} — ${ro.status} ${ro.statusText}</div>${_testResults.map(t=>`<div style="font-size:11px;color:${t.pass?'var(--ok)':'var(--err)'};margin-top:2px">${t.pass?'✓':'✗'} ${esc(t.name)}${t.error?' — '+esc(t.error):''}</div>`).join('')}</div></div>`;
      if(!isOk&&stop){notify('Stopped on error','warn');return;}
    }catch(err){failed++;resultEl.innerHTML+=`<div class="cr-result-item fail"><span>❌</span><div><div style="font-weight:600;font-size:12px">${esc(req.name)}</div><div style="font-size:11px;color:var(--err)">${esc(err.message)}</div></div></div>`;if(stop){notify('Stopped on error','warn');return;}}
    done++;const bar=document.getElementById('cr-bar');if(bar)bar.style.width=Math.round(done/total*100)+'%';resultEl.scrollTop=resultEl.scrollHeight;if(delay>0)await sleep(delay);
  }}}
  notify(`Runner done: ✅ ${passed} passed  ❌ ${failed} failed`,failed===0?'success':'warn');
}

function openNewColl(){openModal(`<div class="modal-bg"><div class="modal sm"><div class="mh"><span class="mh-title">New Collection</span><button class="m-close" onclick="closeModal()">✕</button></div><div class="mb"><div class="fg"><label>NAME</label><input id="nc-name" placeholder="My Collection" autofocus></div><div class="fg"><label>DESCRIPTION</label><textarea id="nc-desc" rows="2" style="width:100%;resize:none" placeholder="Optional"></textarea></div></div><div class="mf"><button class="btn secondary" onclick="closeModal()">Cancel</button><button class="btn primary" onclick="createColl()">Create</button></div></div></div>`);setTimeout(()=>document.getElementById('nc-name')?.focus(),50);}
function createColl(){const name=document.getElementById('nc-name').value.trim();if(!name){notify('Name required','error');return;}S.collections.push({id:uid(),name,desc:document.getElementById('nc-desc').value,requests:[],variables:{},created:Date.now()});save();renderCollections();closeModal();notify('Collection created!','success');}
function delColl(e,id){e.stopPropagation();if(!confirm('Delete this collection?'))return;S.collections=S.collections.filter(c=>c.id!==id);save();renderCollections();}
function addToColl(e,id){
  e.stopPropagation();saveTabUI();const tab=getActiveTab(),coll=S.collections.find(c=>c.id===id);if(!coll||!tab)return;
  const name=prompt('Request name:',tab.name||'New Request');if(!name)return;
  if(!coll.requests)coll.requests=[];
  coll.requests.push({id:uid(),name,method:tab.method||'GET',url:tab.url||'',headers:tab.headers||[],params:tab.params||[],rawBody:tab.rawBody||'',bodyType:tab.bodyType||'none',rawFmt:tab.rawFmt||'json',authType:tab.authType||'none',authData:tab.authData||{},preScript:tab.preScript||'',testScript:tab.testScript||''});
  save();renderCollections();notify('Saved to collection!','success');
}
function saveToCollection(){
  saveTabUI();const tab=getActiveTab();if(!S.collections.length){openNewColl();return;}
  openModal(`<div class="modal-bg"><div class="modal sm"><div class="mh"><span class="mh-title">💾 Save Request</span><button class="m-close" onclick="closeModal()">✕</button></div><div class="mb"><div class="fg"><label>REQUEST NAME</label><input id="sr-name" value="${esc(tab?.name||'New Request')}"></div><div class="fg"><label>COLLECTION</label><select id="sr-coll" style="width:100%">${S.collections.map(c=>`<option value="${c.id}">${esc(c.name)}</option>`).join('')}</select></div></div><div class="mf"><button class="btn secondary" onclick="closeModal()">Cancel</button><button class="btn primary" onclick="doSave()">Save</button></div></div></div>`);
}
function doSave(){const name=document.getElementById('sr-name').value.trim(),id=document.getElementById('sr-coll').value;const coll=S.collections.find(c=>c.id===id),tab=getActiveTab();if(!coll||!name)return;if(!coll.requests)coll.requests=[];coll.requests.push({id:uid(),name,method:tab?.method||'GET',url:tab?.url||'',headers:tab?.headers||[],params:tab?.params||[],rawBody:tab?.rawBody||'',bodyType:tab?.bodyType||'none',rawFmt:tab?.rawFmt||'json',authType:tab?.authType||'none',authData:tab?.authData||{},preScript:tab?.preScript||'',testScript:tab?.testScript||''});if(tab)tab.name=name;save();renderCollections();renderTabs();closeModal();notify('Saved!','success');}
function loadCollReq(cid,rid){const coll=S.collections.find(c=>c.id===cid);let req=coll?.requests?.find(r=>r.id===rid);if(!req){for(const item of coll?.requests||[]){if(item._isFolder){req=item.requests?.find(r=>r.id===rid);if(req)break;}}}if(!req)return;newTab({...req});}
function dupReq(e,cid,rid){e.stopPropagation();const coll=S.collections.find(c=>c.id===cid),req=coll?.requests?.find(r=>r.id===rid);if(!req||!coll)return;coll.requests.push({...req,id:uid(),name:req.name+' (copy)'});save();renderCollections();notify('Duplicated!','success');}
function delReq(e,cid,rid){e.stopPropagation();const coll=S.collections.find(c=>c.id===cid);if(!coll)return;coll.requests=coll.requests.filter(r=>r.id!==rid);save();renderCollections();}

function mapToPostman(r){
  return {
    name:r.name,
    request:{
      method:r.method||'GET',
      url:{raw:r.url||'',host:[],path:[],query:[],variable:[]},
      header:(r.headers||[]).filter(h=>h.k).map(h=>({key:h.k,value:h.v,disabled:!h.on})),
      body:r.bodyType!=='none'?{mode:r.bodyType==='raw'?'raw':r.bodyType,raw:r.rawBody||''}:undefined,
      auth:r.authType!=='none'?{type:r.authType}:undefined
    },
    event:[
      ...(r.preScript?[{listen:'prerequest',script:{exec:r.preScript.split('\n'),type:'text/javascript'}}]:[]),
      ...(r.testScript?[{listen:'test',script:{exec:r.testScript.split('\n'),type:'text/javascript'}}]:[])
    ]
  };
}
function exportColl(e,id){e.stopPropagation();const coll=S.collections.find(c=>c.id===id);if(!coll)return;dl(JSON.stringify({info:{name:coll.name,description:coll.desc||'',schema:'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'},variable:Object.entries(coll.variables||{}).map(([k,v])=>({key:k,value:v})),item:(coll.requests||[]).map(r=>r._isFolder?{name:r.name,item:(r.requests||[]).map(mapToPostman)}:mapToPostman(r))},null,2),coll.name.replace(/\s+/g,'_')+'.postman_collection.json');notify('Exported!','success');}
function exportAllColls(){dl(JSON.stringify(S.collections,null,2),'postmanweb_collections.json');notify('All collections exported!','success');}

// ─────────────────────────────────────────────────────────────
// ENVIRONMENTS
// ─────────────────────────────────────────────────────────────
function renderEnvs(){const list=document.getElementById('env-list');if(!S.envs.length){list.innerHTML='<div class="empty-state"><div class="ei">🌍</div><p>No environments.</p></div>';return;}list.innerHTML=S.envs.map(e=>`<div class="env-row${e.id===S.activeEnv?' active-env':''}" onclick="setEnv('${e.id}')"><div class="env-dot${e.id===S.activeEnv?' on':''}"></div><span class="env-nm">${esc(e.name)}</span><button class="btn-s" onclick="editEnv(event,'${e.id}')">Edit</button><button class="btn-s" onclick="exportEnv(event,'${e.id}')">⬇</button><button class="btn-s" onclick="delEnv(event,'${e.id}')">🗑</button></div>`).join('');refreshEnvQuick();}
function refreshEnvQuick(){const sel=document.getElementById('env-quick');if(!sel)return;sel.innerHTML='<option value="">No Environment</option>'+S.envs.map(e=>`<option value="${e.id}"${e.id===S.activeEnv?' selected':''}>${esc(e.name)}</option>`).join('');}
function quickEnvSwitch(id){S.activeEnv=id||null;save();renderEnvs();notify(id?`Env: ${S.envs.find(e=>e.id===id)?.name}`:'No environment','info');}
function setEnv(id){S.activeEnv=S.activeEnv===id?null:id;save();renderEnvs();const e=S.envs.find(e=>e.id===S.activeEnv);notify(S.activeEnv?`Env: ${e?.name}`:'No environment','info');}
function openNewEnv(){openModal(`<div class="modal-bg"><div class="modal sm"><div class="mh"><span class="mh-title">New Environment</span><button class="m-close" onclick="closeModal()">✕</button></div><div class="mb"><div class="fg"><label>NAME</label><input id="ne-name" placeholder="Production" autofocus></div></div><div class="mf"><button class="btn secondary" onclick="closeModal()">Cancel</button><button class="btn primary" onclick="createEnv()">Create</button></div></div></div>`);setTimeout(()=>document.getElementById('ne-name')?.focus(),50);}
function createEnv(){const name=document.getElementById('ne-name').value.trim();if(!name)return;const env={id:uid(),name,variables:{}};S.envs.push(env);save();renderEnvs();closeModal();editEnv(null,env.id);}
function editEnv(e,id){if(e)e.stopPropagation();const env=S.envs.find(x=>x.id===id);if(!env)return;openModal(`<div class="modal-bg"><div class="modal lg"><div class="mh"><span class="mh-title">Edit: ${esc(env.name)}</span><button class="m-close" onclick="closeModal()">✕</button></div><div class="mb"><div id="ev-list">${Object.entries(env.variables||{}).map(([k,v])=>`<div class="ev-row"><input placeholder="Variable" value="${esc(k)}"><input placeholder="Value" value="${esc(v)}"><button class="ev-del" onclick="this.parentElement.remove()">✕</button></div>`).join('')}</div><button class="add-row-btn" onclick="addEvRow()" style="margin-top:8px">+ Add Variable</button></div><div class="mf"><button class="btn secondary" onclick="closeModal()">Cancel</button><button class="btn primary" onclick="saveEnv('${id}')">Save</button></div></div></div>`);}
function addEvRow(){const div=document.createElement('div');div.className='ev-row';div.innerHTML='<input placeholder="Variable"><input placeholder="Value"><button class="ev-del" onclick="this.parentElement.remove()">✕</button>';document.getElementById('ev-list').appendChild(div);}
function saveEnv(id){const env=S.envs.find(x=>x.id===id);if(!env)return;env.variables={};document.querySelectorAll('#ev-list .ev-row').forEach(row=>{const[k,v]=row.querySelectorAll('input');if(k.value.trim())env.variables[k.value.trim()]=v.value;});save();renderEnvs();closeModal();notify('Environment saved!','success');}
function delEnv(e,id){e.stopPropagation();if(!confirm('Delete this environment?'))return;S.envs=S.envs.filter(x=>x.id!==id);if(S.activeEnv===id)S.activeEnv=null;save();renderEnvs();}
function exportEnv(e,id){e.stopPropagation();const env=S.envs.find(x=>x.id===id);if(!env)return;dl(JSON.stringify({id:env.id,name:env.name,values:Object.entries(env.variables||{}).map(([k,v])=>({key:k,value:v,enabled:true}))},null,2),env.name.replace(/\s+/g,'_')+'.postman_environment.json');}
function openEnvSB(){switchSB('envs');document.getElementById('sidebar').classList.remove('hidden');}

// ─────────────────────────────────────────────────────────────
// GLOBALS
// ─────────────────────────────────────────────────────────────
function openGlobals(){openModal(`<div class="modal-bg"><div class="modal lg"><div class="mh"><span class="mh-title">🌐 Global Variables</span><button class="m-close" onclick="closeModal()">✕</button></div><div class="mb"><div id="gv-list">${Object.entries(S.globals).map(([k,v])=>`<div class="ev-row"><input placeholder="Variable" value="${esc(k)}"><input placeholder="Value" value="${esc(v)}"><button class="ev-del" onclick="this.parentElement.remove()">✕</button></div>`).join('')}</div><button class="add-row-btn" onclick="addGVRow()" style="margin-top:8px">+ Add Variable</button></div><div class="mf"><button class="btn secondary" onclick="closeModal()">Cancel</button><button class="btn primary" onclick="saveGlobals()">Save</button></div></div></div>`);}
function addGVRow(){const div=document.createElement('div');div.className='ev-row';div.innerHTML='<input placeholder="Variable"><input placeholder="Value"><button class="ev-del" onclick="this.parentElement.remove()">✕</button>';document.getElementById('gv-list').appendChild(div);}
function saveGlobals(){S.globals={};document.querySelectorAll('#gv-list .ev-row').forEach(row=>{const[k,v]=row.querySelectorAll('input');if(k.value.trim())S.globals[k.value.trim()]=v.value;});save();closeModal();notify('Globals saved!','success');}

// ─────────────────────────────────────────────────────────────
// CODE GENERATION
// ─────────────────────────────────────────────────────────────
function openCodegen(){
  saveTabUI();
  openModal(`<div class="modal-bg"><div class="modal xl"><div class="mh"><span class="mh-title">{ } Code Snippet</span><button class="m-close" onclick="closeModal()">✕</button></div><div class="mb"><div class="lang-tabs">${['cURL','JavaScript (Fetch)','JavaScript (Axios)','Python (requests)','Java (OkHttp)','C# (HttpClient)','Go (net/http)','PHP (Guzzle)','Ruby','Swift','Kotlin','Rust','Node.js','PowerShell'].map(l=>`<button class="lang-tab${l==='cURL'?' active':''}" onclick="switchLang('${esc(l)}',this)">${l}</button>`).join('')}</div><textarea id="cg-out" readonly spellcheck="false"></textarea><div style="display:flex;gap:8px;margin-top:10px"><button class="btn primary" onclick="copyCG()">📋 Copy Code</button></div></div></div></div>`);
  genCode('cURL');
}
function switchLang(lang,btn){document.querySelectorAll('.lang-tab').forEach(b=>b.classList.remove('active'));btn.classList.add('active');genCode(lang);}
function copyCG(){navigator.clipboard.writeText(document.getElementById('cg-out').value).then(()=>notify('Copied!','success'));}
function genCode(lang){
  const method=document.getElementById('method-sel').value,url=document.getElementById('url-in').value;
  const hRows=readKV('headers').filter(h=>h.on!==false&&h.k);
  const authType=document.getElementById('auth-sel')?.value;const authH={};
  if(authType==='bearer'){const t=document.getElementById('a-token')?.value;if(t)authH['Authorization']='Bearer '+t;}
  else if(authType==='basic'){const u=document.getElementById('a-user')?.value||'',p=document.getElementById('a-pass')?.value||'';authH['Authorization']='Basic '+btoa(u+':'+p);}
  else if(authType==='apikey'&&document.getElementById('a-key-in')?.value==='header'){const k=document.getElementById('a-key')?.value,v=document.getElementById('a-key-val')?.value;if(k&&v)authH[k]=v;}
  else if(authType==='oauth2'){const t=document.getElementById('a-o2')?.value;if(t)authH['Authorization']=(document.getElementById('a-o2p')?.value||'Bearer')+' '+t;}
  const rawBody=document.getElementById('code-raw')?.value||'';
  const allH={...Object.fromEntries(hRows.map(h=>[h.k,h.v])),...authH};
  const hasBody=_bodyType==='raw'&&rawBody;
  const hJ=JSON.stringify(allH,null,2),hJ4=JSON.stringify(allH,null,4);
  const codes={
    'cURL':()=>{let c=`curl --location --request ${method} '${url}'`;Object.entries(allH).forEach(([k,v])=>{c+=` \\\n  --header '${k}: ${v}'`;});if(hasBody)c+=` \\\n  --data-raw '${rawBody.replace(/'/g,"'\\''")}'`;return c;},
    'JavaScript (Fetch)':()=>`const myHeaders = new Headers(${hJ});\n\nconst requestOptions = {\n  method: "${method}",\n  headers: myHeaders,\n  ${hasBody?`body: ${JSON.stringify(rawBody)},\n  `:''}redirect: "follow"\n};\n\nfetch("${url}", requestOptions)\n  .then(response => response.json())\n  .then(result => console.log(result))\n  .catch(error => console.error("Error:", error));`,
    'JavaScript (Axios)':()=>{const cfg={method:method.toLowerCase(),url,headers:allH};if(hasBody){try{cfg.data=JSON.parse(rawBody);}catch{cfg.data=rawBody;}}return`import axios from 'axios';\n\nconst config = ${JSON.stringify(cfg,null,2)};\n\naxios(config)\n  .then(response => console.log(JSON.stringify(response.data)))\n  .catch(error => console.error(error));`;},
    'Python (requests)':()=>{let c=`import requests\nimport json\n\nurl = "${url}"\n\nheaders = ${hJ4}\n`;if(hasBody)c+=`\npayload = json.dumps(${rawBody})\n\nresponse = requests.request("${method}", url, headers=headers, data=payload)`;else c+=`\nresponse = requests.request("${method}", url, headers=headers)`;return c+'\n\nprint(response.status_code)\nprint(response.json())';},
    'Java (OkHttp)':()=>{const hStr=Object.entries(allH).map(([k,v])=>`.addHeader("${k}", "${v}")`).join('\n    ');return`OkHttpClient client = new OkHttpClient().newBuilder().build();\n${hasBody?`MediaType mediaType = MediaType.parse("application/json");\nRequestBody body = RequestBody.create(mediaType, ${JSON.stringify(rawBody)});\n`:''}\nRequest request = new Request.Builder()\n    .url("${url}")\n    .method("${method}", ${hasBody?'body':'null'})\n    ${hStr}\n    .build();\n\nResponse response = client.newCall(request).execute();\nSystem.out.println(response.body().string());`;},
    'C# (HttpClient)':()=>{const hStr=Object.entries(allH).map(([k,v])=>`client.DefaultRequestHeaders.Add("${k}", "${v}");`).join('\n');return`using System.Net.Http;\nusing System.Text;\n\nvar client = new HttpClient();\n${hStr}\n${hasBody?`var content = new StringContent(${JSON.stringify(rawBody)}, Encoding.UTF8, "application/json");\nvar response = await client.${method[0]+method.slice(1).toLowerCase()}Async("${url}", content);`:`var response = await client.${method[0]+method.slice(1).toLowerCase()}Async("${url}");`}\nvar body = await response.Content.ReadAsStringAsync();\nConsole.WriteLine(body);`;},
    'Go (net/http)':()=>{const bl=hasBody?`strings.NewReader(${JSON.stringify(rawBody)})`:'nil';const hStr=Object.entries(allH).map(([k,v])=>`  req.Header.Add("${k}", "${v}")`).join('\n');return`package main\n\nimport (\n  "fmt"\n  "net/http"\n  "io/ioutil"\n  "strings"\n)\n\nfunc main() {\n  client := &http.Client{}\n  payload := ${bl}\n  req, _ := http.NewRequest("${method}", "${url}", payload)\n${hStr}\n  res, _ := client.Do(req)\n  defer res.Body.Close()\n  body, _ := ioutil.ReadAll(res.Body)\n  fmt.Println(string(body))\n}`;},
    'PHP (Guzzle)':()=>{const hStr=Object.entries(allH).map(([k,v])=>`    '${k}' => '${v}'`).join(',\n');return`<?php\n\n$client = new \\GuzzleHttp\\Client();\n\n$response = $client->request('${method}', '${url}', [\n  'headers' => [\n${hStr}\n  ],\n${hasBody?`  'body' => ${JSON.stringify(rawBody)},\n`:''}]);\n\necho $response->getBody()->getContents();`;},
    'Ruby':()=>`require 'net/http'\nrequire 'json'\n\nuri = URI('${url}')\nhttp = Net::HTTP.new(uri.host, uri.port)\nhttp.use_ssl = uri.scheme == 'https'\n\nrequest = Net::HTTP::${method[0]+method.slice(1).toLowerCase()}.new(uri)\n${Object.entries(allH).map(([k,v])=>`request['${k}'] = '${v}'`).join('\n')}\n${hasBody?`request.body = ${JSON.stringify(rawBody)}\n`:''}\nresponse = http.request(request)\nputs response.body`,
    'Swift':()=>{const hStr=Object.entries(allH).map(([k,v])=>`request.setValue("${v}", forHTTPHeaderField: "${k}")`).join('\n');return`import Foundation\n\nvar request = URLRequest(url: URL(string: "${url}")!)\nrequest.httpMethod = "${method}"\n${hStr}\n${hasBody?`request.httpBody = Data(${JSON.stringify(rawBody)}.utf8)\n`:''}\nURLSession.shared.dataTask(with: request) { data, response, error in\n    if let data = data { print(String(data: data, encoding: .utf8)!) }\n}.resume()`;},
    'Kotlin':()=>{const hStr=Object.entries(allH).map(([k,v])=>`.addHeader("${k}", "${v}")`).join('\n    ');return`import okhttp3.*\n\nval client = OkHttpClient()\n${hasBody?`val body = "${rawBody}".toRequestBody("application/json".toMediaType())\n`:''}\nval request = Request.Builder()\n    .url("${url}")\n    ${hasBody?`.${method.toLowerCase()}(body)`:`.${method.toLowerCase()}()`}\n    ${hStr}\n    .build()\n\nval response = client.newCall(request).execute()\nprintln(response.body?.string())`;},
    'Rust':()=>{const hStr=Object.entries(allH).map(([k,v])=>`.header("${k}", "${v}")`).join('\n    ');return`use reqwest;\n\n#[tokio::main]\nasync fn main() -> Result<(), Box<dyn std::error::Error>> {\n    let client = reqwest::Client::new();\n    let res = client.${method.toLowerCase()}("${url}")\n    ${hStr}\n    ${hasBody?`.body(${JSON.stringify(rawBody)})\n    `:''}.send().await?;\n    println!("{}", res.text().await?);\n    Ok(())\n}`;},
    'Node.js':()=>`const https = require('https');\nconst url = new URL('${url}');\n\nconst options = {\n  hostname: url.hostname,\n  port: url.port || 443,\n  path: url.pathname + url.search,\n  method: '${method}',\n  headers: ${hJ}\n};\n\nconst req = https.request(options, res => {\n  let data = '';\n  res.on('data', chunk => data += chunk);\n  res.on('end', () => console.log(data));\n});\n${hasBody?`req.write(${JSON.stringify(rawBody)});\n`:''}req.on('error', console.error);\nreq.end();`,
    'PowerShell':()=>{const hStr=Object.entries(allH).map(([k,v])=>`  '${k}' = '${v}'`).join('\n');return`$headers = @{\n${hStr}\n}\n\n${hasBody?`$body = ${JSON.stringify(rawBody)}\n\n`:''}$response = Invoke-RestMethod -Method ${method} -Uri '${url}' -Headers $headers${hasBody?' -Body $body -ContentType "application/json"':''}\n$response | ConvertTo-Json`;},
  };
  const out=document.getElementById('cg-out');if(out)out.value=(codes[lang]||codes['cURL'])();
}

// ─────────────────────────────────────────────────────────────
// WEBSOCKET
// ─────────────────────────────────────────────────────────────
function openWS(){openModal(`<div class="modal-bg"><div class="modal lg"><div class="mh"><span class="mh-title">🔌 WebSocket Client</span><button class="m-close" onclick="closeModal();wsDisconnect()">✕</button></div><div class="mb"><div style="display:flex;gap:8px;margin-bottom:10px"><input id="ws-url" type="text" placeholder="wss://echo.websocket.org" style="flex:1"><button class="btn primary" id="ws-btn" onclick="wsToggle()">Connect</button></div><div style="display:flex;gap:8px;margin-bottom:10px"><input id="ws-msg" type="text" placeholder='{"type":"ping"}' style="flex:1"><button class="btn secondary" onclick="wsSend()">Send</button></div><div id="ws-msgs" style="background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);min-height:200px;max-height:350px;overflow-y:auto;padding:4px"></div></div><div class="mf"><button class="btn secondary" onclick="closeModal();wsDisconnect()">Close</button></div></div></div>`);}
function wsToggle(){if(_wsConn&&_wsConn.readyState===WebSocket.OPEN)wsDisconnect();else wsConnect();}
function wsConnect(){const url=document.getElementById('ws-url')?.value?.trim();if(!url){notify('Enter WebSocket URL','error');return;}try{_wsConn=new WebSocket(url);wsLog(`• Connecting to ${url}...`,'sys');_wsConn.onopen=()=>{wsLog('✅ Connected!','sys');const b=document.getElementById('ws-btn');if(b){b.textContent='Disconnect';b.style.background='var(--err)';}};_wsConn.onmessage=e=>wsLog('← '+e.data,'recv');_wsConn.onerror=()=>wsLog('❌ Error','sys');_wsConn.onclose=()=>{wsLog('• Closed','sys');const b=document.getElementById('ws-btn');if(b){b.textContent='Connect';b.style.background='';}}}catch(e){wsLog('❌ '+e.message,'sys');}}
function wsDisconnect(){if(_wsConn){_wsConn.close();_wsConn=null;}}
function wsSend(){const msg=document.getElementById('ws-msg')?.value?.trim();if(!msg)return;if(!_wsConn||_wsConn.readyState!==WebSocket.OPEN){notify('Not connected','error');return;}_wsConn.send(msg);wsLog('→ '+msg,'sent');document.getElementById('ws-msg').value='';}
function wsLog(msg,cls){const d=document.getElementById('ws-msgs');if(!d)return;const div=document.createElement('div');div.className='ws-line '+cls;div.textContent=msg;d.appendChild(div);d.scrollTop=d.scrollHeight;}

// ─────────────────────────────────────────────────────────────
// gRPC
// ─────────────────────────────────────────────────────────────
function openGRPC(){openModal(`<div class="modal-bg"><div class="modal lg"><div class="mh"><span class="mh-title">gRPC Client</span><button class="m-close" onclick="closeModal()">✕</button></div><div class="mb"><div class="fg"><label>SERVER URL</label><input id="grpc-url" placeholder="https://grpc.example.com"></div><div class="fg"><label>SERVICE METHOD</label><input id="grpc-method" placeholder="package.Service/Method"></div><div class="fg"><label>REQUEST BODY (JSON)</label><textarea id="grpc-body" rows="6" class="code-area" placeholder='{"key":"value"}'></textarea></div><div class="fg"><label>METADATA (JSON)</label><textarea id="grpc-meta" rows="3" class="code-area" placeholder='{"authorization":"Bearer token"}'></textarea></div><div id="grpc-resp" style="background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);min-height:80px;max-height:200px;overflow-y:auto;padding:10px;font-family:var(--mono);font-size:12px;color:var(--text3);margin-top:8px">gRPC response will appear here...</div></div><div class="mf"><button class="btn secondary" onclick="closeModal()">Close</button><button class="btn primary" onclick="invokeGRPC()">Invoke</button></div></div></div>`);}
async function invokeGRPC(){const url=document.getElementById('grpc-url')?.value?.trim(),method=document.getElementById('grpc-method')?.value?.trim(),body=document.getElementById('grpc-body')?.value?.trim(),meta=document.getElementById('grpc-meta')?.value?.trim(),respEl=document.getElementById('grpc-resp');if(!url||!method){notify('URL and method required','error');return;}respEl.innerHTML='<span style="color:var(--text3)">⏳ Invoking...</span>';const direct=isPrivate(url);const proxyUrl=(!direct&&S.settings.corsEnabled)?S.settings.proxyUrl+encodeURIComponent(url+'/'+method):url+'/'+method;const h={'Content-Type':'application/grpc-web+json','x-grpc-web':'1'};if(meta){try{Object.assign(h,JSON.parse(meta));}catch{}}try{const r=await fetch(proxyUrl,{method:'POST',headers:h,body:body||'{}'});const txt=await r.text();let p;try{p=JSON.parse(txt);}catch{p=txt;}respEl.innerHTML=`<span style="color:var(--ok)">Status: ${r.status} ${r.statusText}</span>\n\n${esc(typeof p==='string'?p:JSON.stringify(p,null,2))}`;notify('gRPC: '+r.status,r.ok?'success':'error');}catch(e){respEl.innerHTML=`<span style="color:var(--err)">${esc(e.message)}</span>`;notify('gRPC error: '+e.message,'error');}}

// ─────────────────────────────────────────────────────────────
// MOCK SERVER
// ─────────────────────────────────────────────────────────────
function openMockServer(){openModal(`<div class="modal-bg"><div class="modal lg"><div class="mh"><span class="mh-title">🎭 Mock Server</span><button class="m-close" onclick="closeModal()">✕</button></div><div class="mb"><p style="font-size:12px;color:var(--text3);margin-bottom:12px">Enable "Use Mock Response" in Request Settings to intercept matching requests.</p><div id="mock-rules">${S.mocks.length?S.mocks.map((m,i)=>mockRuleHtml(m,i)).join(''):'<p style="color:var(--text3);font-size:12px">No mock rules yet.</p>'}</div><button class="add-row-btn" style="margin-top:10px" onclick="addMockRule()">+ Add Mock Rule</button></div><div class="mf"><button class="btn secondary" onclick="closeModal()">Close</button><button class="btn primary" onclick="saveMockRules()">Save Rules</button></div></div></div>`);}
function mockRuleHtml(m,i){return`<div class="mock-rule" id="mock-rule-${i}"><div class="mock-rule-hdr" style="margin-bottom:8px"><select style="width:90px" id="mr-method-${i}">${['*','GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'].map(x=>`<option${x===m.method?' selected':''}>${x}</option>`).join('')}</select><input type="text" id="mr-path-${i}" value="${esc(m.path||'')}" placeholder="/api/users" style="flex:1"><select id="mr-status-${i}" style="width:80px">${[200,201,204,400,401,403,404,422,500,502,503].map(s=>`<option${s===m.statusCode?' selected':''}>${s}</option>`).join('')}</select><input type="number" id="mr-delay-${i}" value="${m.delay||0}" style="width:70px"><label class="toggle"><input type="checkbox" id="mr-en-${i}"${m.enabled!==false?' checked':''}><span class="t-slider"></span></label><button class="icon-btn del" onclick="removeMockRule(${i})">🗑</button></div><div class="fg"><label>RESPONSE BODY</label><textarea id="mr-body-${i}" class="code-area" rows="4">${esc(m.body||'{}')}</textarea></div><div class="fg"><label>CONTENT TYPE</label><input type="text" id="mr-ct-${i}" value="${esc(m.contentType||'application/json')}"></div></div>`;}
function addMockRule(){S.mocks.push({id:uid(),method:'GET',path:'',statusCode:200,body:'{}',contentType:'application/json',delay:0,enabled:true});document.getElementById('mock-rules').innerHTML=S.mocks.map((m,i)=>mockRuleHtml(m,i)).join('');}
function removeMockRule(i){S.mocks.splice(i,1);save();openMockServer();}
function saveMockRules(){S.mocks=S.mocks.map((_,i)=>({id:S.mocks[i].id||uid(),method:document.getElementById('mr-method-'+i)?.value||'GET',path:document.getElementById('mr-path-'+i)?.value||'',statusCode:parseInt(document.getElementById('mr-status-'+i)?.value)||200,body:document.getElementById('mr-body-'+i)?.value||'{}',contentType:document.getElementById('mr-ct-'+i)?.value||'application/json',delay:parseInt(document.getElementById('mr-delay-'+i)?.value)||0,enabled:document.getElementById('mr-en-'+i)?.checked!==false}));save();closeModal();notify('Mock rules saved!','success');}

// ─────────────────────────────────────────────────────────────
// IMPORT
// ─────────────────────────────────────────────────────────────
function openImport(){openModal(`<div class="modal-bg"><div class="modal md"><div class="mh"><span class="mh-title">📥 Import</span><button class="m-close" onclick="closeModal()">✕</button></div><div class="mb"><div class="fg"><label>PASTE JSON (Postman Collection v2.1, Environment, OpenAPI) OR cURL COMMAND</label><textarea id="imp-txt" rows="10" style="width:100%;background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:10px;color:var(--text1);font-family:var(--mono);font-size:12px;resize:vertical" placeholder="Paste here..."></textarea></div><div class="fg"><label>OR UPLOAD FILE</label><input type="file" id="imp-file" accept=".json,.yaml,.yml" onchange="loadImpFile(this)"></div></div><div class="mf"><button class="btn secondary" onclick="closeModal()">Cancel</button><button class="btn primary" onclick="doImport()">Import</button></div></div></div>`);}
function loadImpFile(inp){const f=inp.files?.[0];if(!f)return;const r=new FileReader();r.onload=e=>{document.getElementById('imp-txt').value=e.target.result;};r.readAsText(f);}
function doImport(){
  const text=document.getElementById('imp-txt').value.trim();if(!text){notify('Nothing to import','error');return;}
  if(text.toLowerCase().startsWith('curl')){importCurl(text);closeModal();return;}
  try{
    const data=JSON.parse(text);
    if(data.info&&data.item){
      const coll={id:uid(),name:data.info.name||'Imported',desc:data.info.description||'',requests:[],variables:{}};
      if(data.variable)data.variable.forEach(v=>{coll.variables[v.key]=v.value;});
      const flat=(items,target)=>items?.forEach(item=>{if(item.item){const folder={id:uid(),name:item.name,_isFolder:true,requests:[]};flat(item.item,folder.requests);target.push(folder);}else if(item.request){target.push({id:uid(),name:item.name||'Request',method:item.request.method||'GET',url:typeof item.request.url==='string'?item.request.url:(item.request.url?.raw||''),headers:(item.request.header||[]).map(h=>({id:uid(),on:!h.disabled,k:h.key,v:h.value,desc:h.description||''})),rawBody:item.request.body?.raw||'',bodyType:item.request.body?.mode==='raw'?'raw':item.request.body?.mode||'none',rawFmt:'json',authType:item.request.auth?.type||'none',authData:{},preScript:item.event?.find(e=>e.listen==='prerequest')?.script?.exec?.join('\n')||'',testScript:item.event?.find(e=>e.listen==='test')?.script?.exec?.join('\n')||''});}});
      flat(data.item,coll.requests);S.collections.push(coll);save();renderCollections();closeModal();notify(`✅ Imported "${coll.name}" — ${coll.requests.length} items`,'success');return;
    }
    if(data.values&&(data.name||data.id)){const env={id:uid(),name:data.name||'Imported Env',variables:{}};(data.values||[]).forEach(v=>{env.variables[v.key]=v.value;});S.envs.push(env);save();renderEnvs();closeModal();notify(`✅ Env "${env.name}" imported`,'success');return;}
    if(Array.isArray(data)&&data[0]?.requests){S.collections.push(...data);save();renderCollections();closeModal();notify(`Imported ${data.length} collections`,'success');return;}
    if(data.openapi||data.swagger){importOpenAPI(data);closeModal();return;}
    notify('Unrecognized format','error');
  }catch(e){notify('Invalid JSON: '+e.message,'error');}
}
function importCurl(curl){
  try{const mm=curl.match(/-X\s+(\w+)/i)||curl.match(/--request\s+(\w+)/i);const um=curl.match(/curl\s+(?:-[^\s]+\s+)*['"]?([^\s'"]+)['"]?/);const hm=[...curl.matchAll(/-H\s+['"]([^'"]+)['"]/gi)];const dm=curl.match(/(?:--data(?:-raw|-binary)?|-d)\s+['"]([^'"]*)['"]/i)||curl.match(/--data '([^']*)'/i);const method=(mm?.[1]||'GET').toUpperCase(),url=um?.[1]||'';const headers=hm.map(m=>{const[k,...v]=m[1].split(':');return{id:uid(),on:true,k:k.trim(),v:v.join(':').trim(),desc:''};});const body=dm?.[1]||'';newTab({method,url,name:url.replace(/^https?:\/\//,'').slice(0,40)||'Imported',headers,rawBody:body,bodyType:body?'raw':'none',rawFmt:'json'});notify('Imported from cURL!','success');}catch(e){notify('cURL parse error: '+e.message,'error');}
}
function importOpenAPI(spec){const coll={id:uid(),name:spec.info?.title||'OpenAPI Import',desc:spec.info?.description||'',requests:[],variables:{}};const base=(spec.servers?.[0]?.url||'')+(spec.basePath||'');Object.entries(spec.paths||{}).forEach(([path,pathItem])=>{['get','post','put','patch','delete','head','options'].forEach(m=>{if(!pathItem[m])return;const op=pathItem[m];const headers=[],params=[];(op.parameters||[]).forEach(p=>{if(p.in==='header')headers.push({id:uid(),on:true,k:p.name,v:p.example||'',desc:p.description||''});else if(p.in==='query')params.push({id:uid(),on:true,k:p.name,v:p.example||'',desc:p.description||''});});let rawBody='',bodyType='none';if(op.requestBody){const ct=op.requestBody.content||{};const j=ct['application/json'];if(j?.example){rawBody=JSON.stringify(j.example,null,2);bodyType='raw';}}coll.requests.push({id:uid(),name:op.summary||op.operationId||(m.toUpperCase()+' '+path),method:m.toUpperCase(),url:base+path,headers,params,rawBody,bodyType,rawFmt:'json',authType:'none',authData:{},preScript:'',testScript:''});});});S.collections.push(coll);save();renderCollections();notify(`✅ OpenAPI imported — ${coll.requests.length} endpoints`,'success');}

// ─────────────────────────────────────────────────────────────
// COOKIE MANAGER
// ─────────────────────────────────────────────────────────────
function openCookies(){openModal(`<div class="modal-bg"><div class="modal lg"><div class="mh"><span class="mh-title">🍪 Cookie Manager</span><button class="m-close" onclick="closeModal()">✕</button></div><div class="mb"><div style="display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap"><input id="ck-d" placeholder="Domain (api.example.com)" style="flex:1;min-width:140px"><input id="ck-n" placeholder="Name" style="width:120px"><input id="ck-v" placeholder="Value" style="flex:1;min-width:100px"><button class="btn primary" onclick="addCK()">+ Add</button></div><div id="ck-list">${renderCKList()}</div></div><div class="mf"><button class="btn danger" onclick="clearAllCK()">🗑 Clear All</button><button class="btn secondary" onclick="closeModal()">Close</button></div></div></div>`);}
function renderCKList(){const d=Object.keys(S.cookies);if(!d.length)return'<div class="empty-state"><div class="ei">🍪</div><p>No cookies stored.</p></div>';return d.map(domain=>`<div class="ck-domain"><div class="ck-domain-nm">${esc(domain)}</div>${Object.entries(S.cookies[domain]).map(([k,v])=>`<div class="ck-row"><span class="ck-name">${esc(k)}</span><span class="ck-val">${esc(v)}</span><button onclick="delCK('${esc(domain)}','${esc(k)}')" style="color:var(--err);background:none;border:none;cursor:pointer;margin-left:auto">✕</button></div>`).join('')}</div>`).join('');}
function addCK(){const d=document.getElementById('ck-d').value.trim(),n=document.getElementById('ck-n').value.trim(),v=document.getElementById('ck-v').value;if(!d||!n){notify('Domain and name required','error');return;}if(!S.cookies[d])S.cookies[d]={};S.cookies[d][n]=v;save();document.getElementById('ck-list').innerHTML=renderCKList();notify('Cookie added!','success');}
function delCK(d,n){if(S.cookies[d]){delete S.cookies[d][n];if(!Object.keys(S.cookies[d]).length)delete S.cookies[d];}save();document.getElementById('ck-list').innerHTML=renderCKList();}
function clearAllCK(){if(!confirm('Clear all cookies?'))return;S.cookies={};save();document.getElementById('ck-list').innerHTML=renderCKList();}

// ─────────────────────────────────────────────────────────────
// SETTINGS
// ─────────────────────────────────────────────────────────────
function openSettings(){
  const s=S.settings;
  openModal(`<div class="modal-bg"><div class="modal lg"><div class="mh"><span class="mh-title">⚙ Settings</span><button class="m-close" onclick="closeModal()">✕</button></div><div class="mb">
    <div class="s-sec"><div class="s-sec-title">CORS PROXY</div>
      <div class="s-row"><div><div class="s-label">Enable CORS Proxy</div><div class="s-desc">Route public API requests through Cloudflare Worker. Private IPs always go DIRECT.</div></div><label class="toggle"><input type="checkbox" id="set-cors"${s.corsEnabled?' checked':''} onchange="toggleCORSFromSettings()"><span class="t-slider"></span></label></div>
      <div class="fg" style="margin-top:10px"><label>PROXY URL</label><input id="set-proxy" value="${esc(s.proxyUrl||'https://square-credit-8186.donthulanithish53.workers.dev/?url=')}"></div>
      <button class="btn-s" style="margin-top:6px" onclick="testProxy()">🔍 Test Worker</button>
      <span id="proxy-test-res" style="font-size:11px;margin-left:10px;color:var(--text3)"></span>
    </div>
    <div class="s-sec"><div class="s-sec-title">THEME</div>
      <div class="s-row"><div><div class="s-label">Dark Mode</div><div class="s-desc">Toggle dark/light theme</div></div><label class="toggle"><input type="checkbox" id="set-dark"${s.theme!=='light'?' checked':''} onchange="toggleThemeFromSettings(this)"><span class="t-slider"></span></label></div>
    </div>
    <div class="s-sec"><div class="s-sec-title">TOOLS</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn-s accent" onclick="closeModal();openGlobals()">🌐 Global Variables</button>
        <button class="btn-s accent" onclick="closeModal();openCookies()">🍪 Cookie Manager</button>
        <button class="btn-s accent" onclick="closeModal();openMockServer()">🎭 Mock Server</button>
      </div>
    </div>
    <div class="s-sec"><div class="s-sec-title">DATA MANAGEMENT</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn-s" onclick="exportAll()">⬇ Export All Data</button>
        <button class="btn-s" onclick="importAll()">⬆ Import Backup</button>
        <button class="btn-s danger" onclick="resetAll()">🗑 Reset Everything</button>
      </div>
    </div>
    <div class="s-sec"><div class="s-sec-title">KEYBOARD SHORTCUTS</div>
      <div style="font-size:11px;color:var(--text2);line-height:2.2;font-family:var(--mono)">
        <b>Ctrl+Enter</b> Send &nbsp; <b>Ctrl+T</b> New Tab &nbsp; <b>Ctrl+W</b> Close Tab<br>
        <b>Ctrl+S</b> Save &nbsp; <b>Ctrl+\</b> Toggle Sidebar &nbsp; <b>Esc</b> Cancel / Close Enlarge
      </div>
    </div>
    <div class="s-sec"><div class="s-sec-title">ABOUT</div>
      <p style="font-size:12px;color:var(--text3);line-height:1.8">PostmanWeb v4 — Full API Testing Platform.<br>
      All data stored locally. Private IPs always called DIRECTLY.<br>
      Worker: <span style="color:var(--accent)">square-credit-8186.donthulanithish53.workers.dev</span></p>
    </div>
  </div><div class="mf"><button class="btn secondary" onclick="closeModal()">Cancel</button><button class="btn primary" onclick="saveSettings()">Save Settings</button></div></div></div>`);
}
function toggleCORSFromSettings(){const c=document.getElementById('set-cors');if(c){S.settings.corsEnabled=c.checked;save();refreshCORSBtn();}}
function toggleThemeFromSettings(el){S.settings.theme=el.checked?'dark':'light';save();applyTheme();}
async function testProxy(){const purl=document.getElementById('set-proxy').value.trim(),res=document.getElementById('proxy-test-res');res.textContent='⏳ Testing...';res.style.color='var(--text3)';try{const r=await fetch(purl+encodeURIComponent('https://httpbin.org/get'),{signal:AbortSignal.timeout(8000)});if(r.ok){res.textContent='✅ Worker is working!';res.style.color='var(--ok)';}else{res.textContent=`⚠ Worker: ${r.status}`;res.style.color='var(--warn)';}}catch(e){res.textContent='❌ '+e.message;res.style.color='var(--err)';}}
function saveSettings(){S.settings.corsEnabled=document.getElementById('set-cors').checked;S.settings.proxyUrl=document.getElementById('set-proxy').value.trim();save();refreshCORSBtn();closeModal();notify('Settings saved!','success');}
function exportAll(){dl(JSON.stringify({collections:S.collections,envs:S.envs,globals:S.globals,history:S.history,settings:S.settings,mocks:S.mocks},null,2),'postmanweb_backup.json');notify('Backup exported!','success');}
function importAll(){const inp=document.createElement('input');inp.type='file';inp.accept='.json';inp.onchange=e=>{const f=e.target.files[0];if(!f)return;const r=new FileReader();r.onload=ev=>{try{const d=JSON.parse(ev.target.result);if(d.collections)S.collections=d.collections;if(d.envs)S.envs=d.envs;if(d.globals)S.globals=d.globals;if(d.history)S.history=fixHistory(d.history);if(d.settings)S.settings=d.settings;if(d.mocks)S.mocks=d.mocks;save();renderAll();notify('Backup imported!','success');}catch(e){notify('Invalid file: '+e.message,'error');};};r.readAsText(f);};inp.click();}
function resetAll(){if(!confirm('⚠ This will permanently delete ALL your data. Are you sure?'))return;localStorage.clear();location.reload();}

// ─────────────────────────────────────────────────────────────
// WORKSPACES + THEME
// ─────────────────────────────────────────────────────────────
function renderWorkspaces(){const sel=document.getElementById('ws-sel');if(!sel)return;sel.innerHTML=S.workspaces.map(w=>`<option value="${w.id}"${w.id===S.activeWS?' selected':''}>${esc(w.name)}</option>`).join('');}
function switchWorkspace(id){S.activeWS=id;save();notify('Workspace switched','info');}
function openNewWorkspace(){const name=prompt('Workspace name:');if(!name)return;const ws={id:uid(),name};S.workspaces.push(ws);S.activeWS=ws.id;save();renderWorkspaces();notify('Workspace created!','success');}
function applyTheme(){document.documentElement.setAttribute('data-theme',S.settings.theme||'dark');const btn=document.getElementById('theme-btn');if(btn)btn.textContent=S.settings.theme==='light'?'🌙':'☀️';}
function toggleTheme(){S.settings.theme=S.settings.theme==='light'?'dark':'light';save();applyTheme();}

// ─────────────────────────────────────────────────────────────
// RESIZE
// ─────────────────────────────────────────────────────────────
function initResize(){
  const handle=document.getElementById('resizer'),wrap=document.getElementById('split');
  let drag=false,sy=0,sh=0;
  handle.addEventListener('mousedown',e=>{drag=true;sy=e.clientY;sh=document.getElementById('req-area').offsetHeight;document.body.style.userSelect='none';document.body.style.cursor='ns-resize';});
  document.addEventListener('mousemove',e=>{if(!drag)return;const nh=Math.max(80,Math.min(wrap.offsetHeight-80,sh+(e.clientY-sy)));document.getElementById('req-area').style.height=nh+'px';});
  document.addEventListener('mouseup',()=>{drag=false;document.body.style.userSelect='';document.body.style.cursor='';});
}

// ─────────────────────────────────────────────────────────────
// RENDER ALL + INIT
// ─────────────────────────────────────────────────────────────
function renderAll(){renderTabs();renderCollections();renderHistory();renderEnvs();renderWorkspaces();}

function init(){
  applyTheme();
  newTab();
  renderAll();
  initResize();
  initHistoryEvents();
  refreshCORSBtn();
  refreshHistDot();

  // Close fullscreen / adv popover on Escape
  document.addEventListener('keydown',e=>{
    const mod=e.ctrlKey||e.metaKey;
    if(e.key==='Escape'){
      if(document.getElementById('fs-overlay').style.display!=='none'){closeEnlarge();return;}
      if(document.getElementById('adv-popover').style.display!=='none'){closeAdvPopover();return;}
      if(_abortCtrl)cancelReq();
    }
    if(mod&&e.key==='Enter'){e.preventDefault();sendRequest();}
    if(mod&&e.key==='t'){e.preventDefault();newTab();}
    if(mod&&e.key==='w'){e.preventDefault();closeTab(S.activeId);}
    if(mod&&e.key==='s'){e.preventDefault();saveToCollection();}
    if(mod&&e.key==='\\'){e.preventDefault();toggleSB();}
  });

  // Close adv popover when clicking outside
  document.addEventListener('click', e => {
    const pop = document.getElementById('adv-popover');
    if(pop.style.display !== 'none' && !pop.contains(e.target) && !e.target.closest('[data-action="adv"]')) {
      closeAdvPopover();
    }
  });

  // URL input: auto-name, path vars, direct badge
  document.getElementById('url-in').addEventListener('input',e=>{
    const tab=getActiveTab();
    if(tab&&e.target.value){
      tab.url=e.target.value;
      tab.name=e.target.value.replace(/^https?:\/\//,'').replace(/\?.*$/,'').slice(0,40)||'New Request';
      renderTabs();
      updatePathVars(e.target.value,tab.pathVars||[]);
      refreshDirectBadge(e.target.value);
    }
  });

  document.getElementById('method-sel').addEventListener('change',colorMethod);
}

init();
