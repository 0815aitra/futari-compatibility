const enc=new TextEncoder(),dec=new TextDecoder();
const json=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store'}});
const b64=b=>{let s='';new Uint8Array(b).forEach(x=>s+=String.fromCharCode(x));return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')};
const unb64=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');const x=atob(s);return Uint8Array.from(x,c=>c.charCodeAt(0))};
const random=(n=24)=>b64(crypto.getRandomValues(new Uint8Array(n)));
async function hash(v){return b64(await crypto.subtle.digest('SHA-256',enc.encode(v)))}
async function key(env){return crypto.subtle.importKey('raw',unb64(env.ENCRYPTION_KEY),{name:'AES-GCM'},false,['encrypt','decrypt'])}
async function seal(value,env){const iv=crypto.getRandomValues(new Uint8Array(12));const data=await crypto.subtle.encrypt({name:'AES-GCM',iv},await key(env),enc.encode(JSON.stringify(value)));return{iv:b64(iv),payload:b64(data)}}
async function open(row,env){const data=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(row.iv)},await key(env),unb64(row.payload));return JSON.parse(dec.decode(data))}
const validAnswers=a=>Array.isArray(a)&&[8,16].includes(a.length)&&a.every(x=>Number.isInteger(x)&&x>=0&&x<=2);
const validPerson=p=>p&&typeof p.n==='string'&&p.n.trim()&&p.n.length<=16&&validAnswers(p.a);
async function role(row,token){if(!token)return null;const h=await hash(token);return h===row.owner_hash?'owner':h===row.partner_hash?'partner':null}
function view(row,payload,userRole){return{role:userRole,firstName:payload.first.n,mode:payload.first.m||'couple-deep',ready:Boolean(payload.partner),result:payload.partner?{first:payload.first,partner:payload.partner,challenge:payload.challenge||[]}:null,expiresAt:row.expires_at}}
async function api(request,env,url){
  if(request.method==='POST'&&url.pathname==='/api/sessions'){
    const input=await request.json();if(!validPerson(input.first))return json({error:'invalid answers'},400);
    const id=random(12),ownerToken=random(),partnerToken=random(),expires=Date.now()+30*86400000,mode=['couple-deep','couple-light','before-deep','before-light'].includes(input.first.m)?input.first.m:'couple-deep';
    const box=await seal({first:{n:input.first.n.trim(),a:input.first.a,m:mode},partner:null,challenge:[]},env);
    await env.DB.prepare('INSERT INTO sessions(id,owner_hash,partner_hash,expires_at,iv,payload) VALUES(?,?,?,?,?,?)').bind(id,await hash(ownerToken),await hash(partnerToken),expires,box.iv,box.payload).run();
    const base=`${url.origin}/index.html`;return json({ownerUrl:`${base}?session=${id}&token=${ownerToken}`,partnerUrl:`${base}?session=${id}&token=${partnerToken}`},201);
  }
  const m=url.pathname.match(/^\/api\/sessions\/([A-Za-z0-9_-]+)(?:\/(partner|challenge))?$/);if(!m)return json({error:'not found'},404);
  const row=await env.DB.prepare('SELECT * FROM sessions WHERE id=?').bind(m[1]).first();if(!row||row.expires_at<Date.now())return json({error:'not found'},404);
  const token=url.searchParams.get('token')||request.headers.get('x-futari-token'),userRole=await role(row,token);if(!userRole)return json({error:'forbidden'},403);let payload=await open(row,env);
  if(request.method==='GET'&&!m[2])return json(view(row,payload,userRole));
  if(request.method==='POST'&&m[2]==='partner'){
    if(userRole!=='partner')return json({error:'partner only'},403);const input=await request.json();if(!validPerson(input.partner)||input.partner.a.length!==payload.first.a.length)return json({error:'invalid answers'},400);payload.partner={n:input.partner.n.trim(),a:input.partner.a};const box=await seal(payload,env);await env.DB.prepare('UPDATE sessions SET iv=?,payload=? WHERE id=?').bind(box.iv,box.payload,m[1]).run();return json(view(row,payload,userRole));
  }
  if(request.method==='PATCH'&&m[2]==='challenge'){
    if(!payload.partner)return json({error:'not ready'},409);const input=await request.json();if(!Array.isArray(input.checked)||input.checked.some(x=>!Number.isInteger(x)||x<0||x>6))return json({error:'invalid progress'},400);payload.challenge=[...new Set(input.checked)];const box=await seal(payload,env);await env.DB.prepare('UPDATE sessions SET iv=?,payload=? WHERE id=?').bind(box.iv,box.payload,m[1]).run();return json({challenge:payload.challenge});
  }
  if(request.method==='DELETE'&&!m[2]){if(userRole!=='owner')return json({error:'owner only'},403);await env.DB.prepare('DELETE FROM sessions WHERE id=?').bind(m[1]).run();return json({deleted:true})}
  return json({error:'method not allowed'},405);
}
export default{async fetch(request,env){const url=new URL(request.url);try{if(url.pathname.startsWith('/api/'))return await api(request,env,url);return env.ASSETS.fetch(request)}catch(e){console.error(e);return json({error:'server error'},500)}}};

