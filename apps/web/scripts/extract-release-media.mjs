import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
const { splitMedia } = await import(pathToFileURL(process.argv[2]).href);
const root='/app', artifact='/release-public', bundle='/release-media';
await mkdir(path.join(artifact,'_next'),{recursive:true});
await cp(path.join(root,'public'),artifact,{recursive:true});
await cp(path.join(root,'.next/static'),path.join(artifact,'_next/static'),{recursive:true});
await splitMedia(artifact,bundle,'learnhouse');
await rm(path.join(root,'public'),{recursive:true});
await rm(path.join(root,'.next/static'),{recursive:true});
await mkdir(path.join(root,'public'));
await cp(path.join(artifact,'_next/static'),path.join(root,'.next/static'),{recursive:true});
await rm(path.join(artifact,'_next'),{recursive:true});
await cp(artifact,path.join(root,'public'),{recursive:true});
await cp(path.join(artifact,'release-media.json'),path.join(root,'release-media.json'));
await cp(path.join(bundle,'manifest.json'),path.join(root,'release-media-manifest.json'));
// Standalone tracing can include imported source images. Their delivery copies
// are now in the object bundle; remove those duplicate raster/vector sources.
async function removeMedia(dir) {
 const { readdir, unlink }=await import('node:fs/promises');
 for(const e of await readdir(dir,{withFileTypes:true})){
  const file=path.join(dir,e.name);
  if(e.isDirectory() && e.name!=='node_modules') await removeMedia(file);
  else if(e.isFile() && /\.(png|jpe?g|webp|avif|svg|gif|ico|mp4|webm|mp3|wav|ogg|pdf)$/i.test(e.name)) await unlink(file);
 }
}
await removeMedia(path.join(root,'.next/standalone'));
