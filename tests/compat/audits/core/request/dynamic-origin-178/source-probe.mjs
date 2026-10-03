import {resolveBaseURL} from './package/dist/utils/url.mjs';
import {matchesOriginPattern} from './package/dist/auth/trusted-origins.mjs';
const config={allowedHosts:['*.example.test','localhost:8080'],protocol:'auto',fallback:'https://fallback.test'};
const hosts=[['a.example.test','https://a.example.test','https://evil.test'],['a.example.test.evil.test','https://internal.test','https://b.example.test'],['localhost:8080','http://localhost:8080','https://evil.test']];
const resolutions=[];
for(const [host,url,forwarded] of hosts) for(const trust of [false,true]){
 const request=new Request(url+'/api/auth/ok',{headers:{host,'x-forwarded-host':new URL(forwarded).host,'x-forwarded-proto':'http'}});
 resolutions.push({host,url,trust,result:resolveBaseURL(config,'/api/auth',request,false,trust)});
}
const callbacks=[['https://b.example.test:443/cb?q=1#fragment','https://*.example.test'],['https://user:pass@b.example.test/cb','https://*.example.test'],['https://b.example.test:444/cb','https://*.example.test'],['https://b.example.test.evil.test/cb','https://*.example.test'],['myapp://CLIENT/cb/sub?q=1#fragment','myapp://client/cb'],['myapp://client/cb/%2e%2e/evil','myapp://client/cb'],['myapp://client:123/cb','myapp://client/cb'],['myapp://user@client/cb','myapp://client/cb'],['myapp://client/cb?q=1','myapp://client/cb'],['myapp://client/cb?q=1','myapp://*']];
console.log(JSON.stringify({resolutions,patterns:callbacks.map(([url,pattern])=>({url,pattern,result:matchesOriginPattern(url,pattern)}))},null,2));
