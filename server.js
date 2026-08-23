const http=require('http');
const fs=require('fs');
const path=require('path');
const crypto=require('crypto');

const root=__dirname;
const dataDir=path.join(root,'.private-data');
const storeFile=path.join(dataDir,'sessions.json');
const keyFile=path.join(dataDir,'local-encryption-key');
const port=Number(process.env.PORT||4173);
fs.mkdirSync(dataDir,{recursive:true});

function encryptionKey(){
  if(process.env.FUTARI_ENCRYPTION_KEY)return crypto.createHash('sha256').update(process.env.FUTARI_ENCRYPTION_KEY).digest();
  if(!fs.existsSync(keyFile))fs.writeFileSync(keyFile,crypto.randomBytes(32).toString('hex'),{mode:0o600});
  return Buffer.from(fs.readFileSync(keyFile,'utf8').trim(),'hex');
}
const key=encryptionKey();
function readStore(){try{return JSON.parse(fs.readFileSync(storeFile,'utf8'))}catch{return{sessions:{}}}}
function writeStore(store){const tmp=storeFile+'.tmp';fs.writeFileSync(tmp,JSON.stringify(store));fs.renameSync(tmp,storeFile)}
function seal(value){const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',key,iv);const encrypted=Buffer.concat([cipher.update(JSON.stringify(value)),cipher.final()]);return{iv:iv.toString('base64url'),tag:cipher.getAuthTag().toString('base64url'),data:encrypted.toString('base64url')}}
function open(box){const decipher=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(box.iv,'base64url'));decipher.setAuthTag(Buffer.from(box.tag,'base64url'));return JSON.parse(Buffer.concat([decipher.update(Buffer.from(box.data,'base64url')),decipher.final()]).toString())}
function hash(token){return crypto.createHash('sha256').update(token).digest('hex')}
function random(size=24){return crypto.randomBytes(size).toString('base64url')}
function validAnswers(a){return Array.isArray(a)&&[8,16].includes(a.length)&&a.every(x=>Number.isInteger(x)&&x>=0&&x<=2)}
function validPerson(p){return p&&typeof p.n==='string'&&p.n.trim().length>0&&p.n.length<=16&&validAnswers(p.a)}
function tokenRole(record,token){if(!token)return null;const h=Buffer.from(hash(token));if(crypto.timingSafeEqual(h,Buffer.from(record.ownerHash)))return'owner';if(crypto.timingSafeEqual(h,Buffer.from(record.partnerHash)))return'partner';return null}
function json(res,status,value){const body=JSON.stringify(value);res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','content-length':Buffer.byteLength(body)});res.end(body)}
function body(req){return new Promise((resolve,reject)=>{let raw='';req.on('data',c=>{raw+=c;if(raw.length>20000)req.destroy()});req.on('end',()=>{try{resolve(JSON.parse(raw||'{}'))}catch{reject(new Error('invalid json'))}});req.on('error',reject)})}
function publicView(record,payload,role){return{role,firstName:payload.first.n,mode:payload.first.m||'couple-deep',ready:Boolean(payload.partner),result:payload.partner?{first:payload.first,partner:payload.partner,challenge:payload.challenge||[]}:null,expiresAt:record.expiresAt}}
async function api(req,res,url){
  if(req.method==='POST'&&url.pathname==='/api/sessions'){
    const input=await body(req);if(!validPerson(input.first))return json(res,400,{error:'invalid answers'});
    const id=random(12),ownerToken=random(),partnerToken=random(),now=Date.now(),store=readStore();
    const mode=['couple-deep','couple-light','before-deep','before-light'].includes(input.first.m)?input.first.m:'couple-deep';store.sessions[id]={ownerHash:hash(ownerToken),partnerHash:hash(partnerToken),createdAt:now,expiresAt:now+30*86400000,payload:seal({first:{n:input.first.n.trim(),a:input.first.a,m:mode},partner:null,challenge:[]})};writeStore(store);
    const protocol=(req.headers['x-forwarded-proto']||url.protocol.replace(':','')).split(',')[0];const base=`${protocol}://${req.headers.host}${url.pathname.replace('/api/sessions','/index.html')}`;
    return json(res,201,{ownerUrl:`${base}?session=${id}&token=${ownerToken}`,partnerUrl:`${base}?session=${id}&token=${partnerToken}`});
  }
  const match=url.pathname.match(/^\/api\/sessions\/([A-Za-z0-9_-]+)(?:\/(partner|challenge))?$/);if(!match)return false;
  const store=readStore(),record=store.sessions[match[1]];if(!record||record.expiresAt<Date.now())return json(res,404,{error:'not found'});
  const token=url.searchParams.get('token')||req.headers['x-futari-token'],role=tokenRole(record,token);if(!role)return json(res,403,{error:'forbidden'});let payload=open(record.payload);
  if(req.method==='GET'&&!match[2])return json(res,200,publicView(record,payload,role));
  if(req.method==='POST'&&match[2]==='partner'){
    if(role!=='partner')return json(res,403,{error:'partner only'});const input=await body(req);if(!validPerson(input.partner)||input.partner.a.length!==payload.first.a.length)return json(res,400,{error:'invalid answers'});payload.partner={n:input.partner.n.trim(),a:input.partner.a};record.payload=seal(payload);writeStore(store);return json(res,200,publicView(record,payload,role));
  }
  if(req.method==='PATCH'&&match[2]==='challenge'){
    if(!payload.partner)return json(res,409,{error:'not ready'});const input=await body(req);if(!Array.isArray(input.checked)||input.checked.some(x=>!Number.isInteger(x)||x<0||x>6))return json(res,400,{error:'invalid progress'});payload.challenge=[...new Set(input.checked)];record.payload=seal(payload);writeStore(store);return json(res,200,{challenge:payload.challenge});
  }
  if(req.method==='DELETE'&&!match[2]){if(role!=='owner')return json(res,403,{error:'owner only'});delete store.sessions[match[1]];writeStore(store);return json(res,200,{deleted:true})}
  return json(res,405,{error:'method not allowed'});
}
function staticFile(req,res,url){let rel=decodeURIComponent(url.pathname);if(rel==='/'||rel==='/index.html')rel='/index.html';const file=path.resolve(root,'.'+rel);if(!file.startsWith(root)||!fs.existsSync(file)||!fs.statSync(file).isFile()){res.writeHead(404);return res.end('Not found')}const ext=path.extname(file);const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8'};res.writeHead(200,{'content-type':types[ext]||'application/octet-stream','cache-control':'no-cache'});fs.createReadStream(file).pipe(res)}
const server=http.createServer(async(req,res)=>{const url=new URL(req.url,`http://${req.headers.host}`);try{if(url.pathname.startsWith('/api/')){const handled=await api(req,res,url);if(handled===false)json(res,404,{error:'not found'})}else staticFile(req,res,url)}catch(e){console.error(e);if(!res.headersSent)json(res,500,{error:'server error'})}});
server.listen(port,process.env.HOST||'0.0.0.0',()=>console.log(`FUTARI: http://127.0.0.1:${port}`));

