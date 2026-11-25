// Stores ONLY encrypted records (the browser encrypts everything with your password). Access needs the password-derived x-auth token.
import {getStore} from "@netlify/blobs";
import {createHash,timingSafeEqual} from "node:crypto";
const J=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{"Content-Type":"application/json","Cache-Control":"no-store"}});
const h=t=>createHash("sha256").update(String(t)).digest();
const OK=/^(idx|[ri]:\d{1,9})$/;
export default async req=>{
 const st=getStore("rentals"),url=new URL(req.url),u=url.pathname.replace(/^\/api\//,"");
 const meta=await st.get("meta",{type:"json"});
 if(u=="status")return J({exists:!!meta,salt:meta?.salt});
 if(u=="setup"&&req.method=="POST"){if(meta)return J({},409);const b=await req.json();if(!b.salt||!b.auth||!b.iv||!b.ct)return J({},400);
  await st.setJSON("idx",{iv:b.iv,ct:b.ct});await st.setJSON("meta",{salt:b.salt,v:h(b.auth).toString("hex")});return J({ok:1})}
 if(!meta)return J({},404);
 const a=h(req.headers.get("x-auth")||""),v=Buffer.from(meta.v,"hex");
 if(a.length!=v.length||!timingSafeEqual(a,v))return J({},401);
 if(u=="list"){const p=url.searchParams.get("p");if(p!="r:"&&p!="i:")return J({},400);const l=await st.list({prefix:p});return J(l.blobs.map(b=>b.key))}
 if(u=="rec"){const k=url.searchParams.get("k");if(!OK.test(k||""))return J({},400);
  if(req.method=="GET"){const d=await st.get(k,{type:"json"});return d?J(d):J({},404)}
  if(req.method=="PUT"){const b=await req.json();if(!b.iv||!b.ct)return J({},400);await st.setJSON(k,{iv:b.iv,ct:b.ct});return J({ok:1})}}
 return J({},404)};
export const config={path:"/api/*"};
