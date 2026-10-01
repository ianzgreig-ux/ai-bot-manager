import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const code=readFileSync(new URL('../src/worker.js',import.meta.url),'utf8');
const request=`## Requested change
from 'Find jobs by powder' - remove the word 'by'

## Request details
- Change type: Screen or layout
- Screen or feature: Find jobs by Powder Code
- Exact field or wording: Not specified`;

function load(fetch=()=>{throw new Error('Unexpected fetch');}){
  const sandbox={fetch,console,TextEncoder,TextDecoder,atob,btoa,Response,Request,Headers,URL};
  vm.createContext(sandbox);
  vm.runInContext(code.replace('export default {','const worker = {')+'\nthis.subject={worker,repositoryContext,relevantExcerpt,applyAiProposal,simpleWordingProposal,createProposal,permittedProposalPath};',sandbox);
  return sandbox.subject;
}

function mockRepository(files){
  const reads=[];
  const fetch=async url=>{
    const u=new URL(url),path=u.pathname.replace('/repos/owner/bot','');
    reads.push(u);
    let result;
    if(!path)result={default_branch:'main'};
    else if(path==='/git/ref/heads/main')result={object:{sha:'snapshot-sha'}};
    else if(path==='/git/trees/snapshot-sha')result={tree:Object.entries(files).map(([path,content])=>({path,type:'blob',size:Buffer.byteLength(content)}))};
    else if(path.startsWith('/contents/')){
      assert.equal(u.searchParams.get('ref'),'snapshot-sha');
      const name=path.slice('/contents/'.length);
      assert.ok(Object.hasOwn(files,name));
      result={sha:'blob-'+name,encoding:'base64',content:Buffer.from(files[name]).toString('base64')};
    }else throw new Error('Unexpected path '+path);
    return Response.json(result);
  };
  return {fetch,reads};
}

test('large source is kept within the context budget, never replaced by README',async()=>{
  const source='/* filler */\n'.repeat(12000)+'<span>Find jobs by powder</span>\n'+'/* tail */\n'.repeat(4000);
  const {fetch,reads}=mockRepository({'README.md':'# topex-search-bot','package.json':'{}','src/worker.js':source});
  const {repositoryContext}=load(fetch);
  const repo=await repositoryContext({GITHUB_TOKEN:'test'},{repository:'owner/bot'},request);
  assert.deepEqual(Array.from(repo.files,file=>file.path),['src/worker.js']);
  assert.ok(repo.files[0].excerpt.includes('Find jobs by powder'));
  assert.ok(repo.files[0].excerpt.length<=22000);
  assert.equal(repo.files[0].content,source);
  assert.equal(reads.some(url=>url.pathname.endsWith('README.md')),false);
});

test('relevant component is found beyond the first two source files',async()=>{
  const {fetch}=mockRepository({'src/worker.js':'export default {}','src/index.js':'export const n=1;','src/app.js':'export const a=1;','src/PowderPanel.jsx':'<span>Find jobs by powder</span>','README.md':'Find jobs by powder'});
  const repo=await load(fetch).repositoryContext({GITHUB_TOKEN:'test'},{repository:'owner/bot'},request);
  assert.equal(repo.files[0].path,'src/PowderPanel.jsx');
  assert.ok(repo.files.reduce((n,file)=>n+file.excerpt.length,0)<=22000);
});

test('exact request changes the visible label only, without AI or writes',async()=>{
  const source='<span class="powder-label">Find jobs by powder</span><p>find jobs by Powder Code, or type your question.</p>';
  const {fetch}=mockRepository({'src/worker.js':source,'README.md':'# topex-search-bot'});
  const proposal=await load(fetch).createProposal({GITHUB_TOKEN:'test'},{repository:'owner/bot'},{body:request});
  assert.equal(proposal.files[0].path,'src/worker.js');
  assert.equal(proposal.files[0].content,source.replace('>Find jobs by powder<','>Find jobs powder<'));
});

test('unmatched or ambiguous wording fails instead of inventing another edit',()=>{
  const {simpleWordingProposal}=load();
  for(const files of [[{path:'src/worker.js',content:'<span>Other label</span>'}],['one','two'].map(name=>({path:'src/'+name+'.js',content:'<span>Find jobs by powder</span>'}))]){
    assert.throws(()=>simpleWordingProposal(request,{files}),/could not be matched safely/);
  }
});

test('README change from failed PR is rejected even if README is supplied',()=>{
  const {applyAiProposal}=load();
  const repo={requestBody:request,files:[{path:'README.md',content:'# topex-search-bot'}]};
  const result=applyAiProposal({files:[{path:'README.md',edits:[{find:'# topex-search-bot',replace:'# topex-search'}]}]},repo);
  assert.match(result.error,/not available or relevant/);
});

test('unrelated code edit, full-file replacement, and ambiguous finds are rejected',()=>{
  const {applyAiProposal}=load();
  const repo={requestBody:request,files:[{path:'src/worker.js',content:'const title="Topex"; <span>Find jobs by powder</span><span>Find jobs by powder</span>'}]};
  for(const item of [
    {edits:[{find:'const title="Topex";',replace:'const title="Other";'}]},
    {content:'<span>Find jobs powder</span>'},
    {edits:[{find:'Find jobs by powder',replace:'Find jobs powder'}]}
  ])assert.ok(applyAiProposal({files:[{path:'src/worker.js',...item}]},repo).error);
});

test('valid targeted AI edit retains the rest of the source',()=>{
  const {applyAiProposal}=load();
  const repo={requestBody:request,files:[{path:'src/worker.js',sha:'abc',content:'before <span>Find jobs by powder</span> after'}]};
  const result=applyAiProposal({files:[{path:'src/worker.js',edits:[{find:'>Find jobs by powder<',replace:'>Find jobs powder<'}]}]},repo);
  assert.equal(result.files[0].content,'before <span>Find jobs powder</span> after');
  assert.equal(result.files[0].sha,'abc');
});

test('explicit documentation requests still permit README edits',()=>{
  const {permittedProposalPath}=load();
  assert.equal(permittedProposalPath('README.md','## Requested change\nUpdate the README documentation'),true);
  assert.equal(permittedProposalPath('.github/workflows/build.yml',request),false);
});

test('revisions bypass the original deterministic wording change',async()=>{
  const {fetch}=mockRepository({'src/worker.js':'<span>Find jobs by powder</span>'});
  let calls=0;
  const AI={run:async()=>{calls++;return {response:JSON.stringify({files:[{path:'src/worker.js',edits:[{find:'>Find jobs by powder<',replace:'>Search powders<'}]}]})};}};
  const proposal=await load(fetch).createProposal({GITHUB_TOKEN:'test',AI},{repository:'owner/bot'},{body:request},'Use Search powders instead');
  assert.equal(calls,1);
  assert.equal(proposal.files[0].content,'<span>Search powders</span>');
});

test('async request errors return readable JSON instead of an unhandled 500',async()=>{
  const {worker}=load();
  const response=await worker.fetch(new Request('https://manager.example/api/requests/prepare',{method:'POST',headers:{Origin:'https://different.example'},body:'{}'}),{});
  assert.equal(response.status,403);
  assert.equal(typeof (await response.json()).error,'string');
});
