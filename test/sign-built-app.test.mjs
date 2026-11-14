import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { signBuiltApp } from '../tools/release.mjs';
test('signs built nested code inside out with runtime/timestamp and preserves original entitlements', async () => {
 const work=await mkdtemp(path.join(os.tmpdir(),'etcpro6-sign-order-'));
 try {
  const app=path.join(work,'ETCPRO6.app'), child=path.join(app,'Contents/Frameworks/Sparkle.framework/Versions/B/Downloader.xpc');
  await mkdir(path.join(child,'Contents/MacOS'),{recursive:true});
  const binary=path.join(child,'Contents/MacOS/Downloader'); await writeFile(binary,Buffer.from('cffaedfe00000000','hex'));
  const calls=[]; const execute=(tool,args)=>{calls.push({tool,args});return {status:0,stderr:'',stdout:tool.endsWith('plutil')?'{}':args[0]==='-d'?'<plist><dict/></plist>':''};};
  await signBuiltApp(app,work,{APPLE_SIGNING_IDENTITY:'fixture'},execute);
  const signed=calls.filter(c=>c.args[0]==='--force'); assert.deepEqual(signed.map(c=>c.args.at(-1)),[binary,child,path.join(app,'Contents/Frameworks/Sparkle.framework'),app]);
  for(const c of signed){assert.equal(c.tool,'/usr/bin/codesign');assert.equal(c.args.includes('--deep'),false);assert.equal(c.args.includes('--timestamp'),true);assert.equal(c.args[c.args.indexOf('--options')+1],'runtime');assert.equal(c.args.includes('--entitlements'),true);}
  assert.equal(calls.some(c=>c.tool.includes('xcodebuild')),false);
 } finally {await rm(work,{recursive:true,force:true});}
});
test('rejects debugger entitlement before signing any object',async()=>{
 const work=await mkdtemp(path.join(os.tmpdir(),'etcpro6-sign-denial-'));try{
 const app=path.join(work,'ETCPRO6.app');await mkdir(app);let signed=false;
 await assert.rejects(signBuiltApp(app,work,{APPLE_SIGNING_IDENTITY:'fixture'},(tool,args)=>{if(args[0]==='--force')signed=true;return{status:0,stderr:'',stdout:tool.endsWith('plutil')?'{"com.apple.security.get-task-allow":true}':'<plist/>'};}),/Debugger/);assert.equal(signed,false);
 }finally{await rm(work,{recursive:true,force:true});}
});
