import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync,writeFileSync,rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { readRelease,deliverMedia } from '../services/media/platform-release.mjs';

test('corrupt release identity and invalid inventory cannot be served',()=>{
 for(const change of [
  m=>{m.product='tenant';},m=>{m.files=[];},m=>{delete m.files;}
 ]){
  const root=mkdtempSync(path.join(tmpdir(),'lh-corrupt-'));
  try{
   const manifest={product:'learnhouse',files:{}};change(manifest);
   const raw=JSON.stringify(manifest);
   writeFileSync(path.join(root,'release-media-manifest.json'),raw);
   writeFileSync(path.join(root,'release-media.json'),JSON.stringify({product:'learnhouse',release:createHash('sha256').update(raw).digest('hex')}));
   assert.throws(()=>readRelease(root,'true'),/Invalid platform release/);
  }finally{rmSync(root,{recursive:true});}
 }
});
test('invalid keys and disabled publishing deny access before fetching',async()=>{
 const original=process.env.WC_PLATFORM_MEDIA_ENABLED;
 process.env.WC_PLATFORM_MEDIA_ENABLED='false';
 try{
  assert.equal((await deliverMedia(new Request('https://studio.example'),['a.png'])).status,404);
  const release={release:'a'.repeat(64),files:{'a/b.png':{},'.hidden.png':{}}};
  for(const segments of [['a/b.png'],['.hidden.png']]){
   assert.equal((await deliverMedia(new Request('https://studio.example'),segments,{release})).status,404);
  }
 }finally{if(original===undefined)delete process.env.WC_PLATFORM_MEDIA_ENABLED;else process.env.WC_PLATFORM_MEDIA_ENABLED=original;}
});
