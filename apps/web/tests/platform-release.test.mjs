import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync,writeFileSync,rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { readRelease,isReleaseMedia,deliverMedia } from '../services/media/platform-release.mjs';

test('only exact reviewed release paths bypass tenant routing',()=>{
 const root=mkdtempSync(path.join(tmpdir(),'lh-media-'));
 try{
  const raw=JSON.stringify({product:'learnhouse',files:{'logo.svg':{}}});
  writeFileSync(path.join(root,'release-media-manifest.json'),raw);
  writeFileSync(path.join(root,'release-media.json'),JSON.stringify({product:'learnhouse',release:createHash('sha256').update(raw).digest('hex')}));
  assert.equal(readRelease(root,'false'),null);
  const release=readRelease(root,'true');
  assert.equal(readRelease(root,'true'),release);
  assert.equal(isReleaseMedia('/logo.svg',release),true);
  assert.equal(isReleaseMedia('/tenant/private.svg',release),false);
  assert.equal(isReleaseMedia('/%zz',release),false);
 }finally{rmSync(root,{recursive:true});}
});
test('private cookies and authorization never enter the platform media request',async()=>{
 const release={release:'a'.repeat(64),files:{'logo.svg':{}}};
 const request=new Request('https://studio.example/api/platform-media/logo.svg',
  {headers:{cookie:'private',authorization:'Bearer private',range:'bytes=1-3'}});
 let call;
 const response=await deliverMedia(request,['logo.svg'],{release,origin:'http://platform-media:8092',
  fetch:async(url,options)=>{call={url,options};return new Response('abc',{status:206,headers:{
   'content-type':'image/svg+xml','cache-control':'public, max-age=31536000, immutable','set-cookie':'bad',
   'content-range':'bytes 1-3/10','etag':'"digest"'}});}});
 assert.equal(response.status,206);assert.equal(await response.text(),'abc');
 assert.equal(call.options.headers.get('cookie'),null);assert.equal(call.options.headers.get('authorization'),null);
 assert.equal(call.options.headers.get('range'),'bytes=1-3');
 assert.equal(response.headers.get('set-cookie'),null);
 assert.equal(call.url.hostname,'platform-media');
});
test('unknown paths, methods and unavailable upstream fail closed',async()=>{
 const options={release:{release:'a'.repeat(64),files:{'logo.svg':{}}},origin:'http://platform-media:8092'};
 for(const segments of [['private.svg'],['..','logo.svg'],['logo.svg/../bad']]){
  assert.equal((await deliverMedia(new Request('https://studio.example'),segments,options)).status,404);
 }
 assert.equal((await deliverMedia(new Request('https://studio.example',{method:'POST'}),['logo.svg'],options)).status,405);
 assert.equal((await deliverMedia(new Request('https://studio.example'),['logo.svg'],{...options,origin:''})).status,503);
 assert.equal((await deliverMedia(new Request('https://studio.example'),['logo.svg'],{...options,fetch:async()=>{throw Error('secret')}})).status,503);
 const head=await deliverMedia(new Request('https://studio.example',{method:'HEAD'}),['logo.svg'],
  {...options,fetch:async()=>new Response(null,{headers:{'content-length':'123'}})});
 assert.equal(await head.text(),'');assert.equal(head.headers.get('content-length'),'123');
});
