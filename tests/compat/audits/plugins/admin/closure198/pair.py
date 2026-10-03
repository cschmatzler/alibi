import json
from pathlib import Path
root=Path(__file__).resolve().parent
import gzip
def records(file,prefix=''):
 out=[]
 for l in gzip.decompress((root/(file+'.gz')).read_bytes()).decode().splitlines():
  if prefix and not l.startswith(prefix):continue
  try:r=json.loads(l.removeprefix(prefix))
  except:continue
  out.append(r)
 return out
fields=['id','name','email','emailVerified','image','createdAt','updatedAt','banned','banReason','banExpires','score','reviewedAt','profile']
pairs=[]
source=records('source-custom-final.log');native=records('native-custom-final.log','custom observation: ')
assert len(source)==7 and len(native)==14
for n in native:
 s=next(s for s in source if all(s[k]==n[k] for k in ['field','operator','value','sort','direction']))
 assert s['status']==n['status'];assert all(s['body'][k]==n['body'][k] for k in ['total','limit','offset'])
 assert [{k:u.get(k) for k in fields} for u in s['body']['users']]==[{k:u.get(k) for k in fields} for u in n['body']['users']],('custom',n)
 pairs.append({'kind':'custom','source':s,'native':n})
source=records('source-admission-final.log');native=records('native-admission-final.log','admission observation: ')
assert len(source)==13 and len(native)==26
for n in native:
 s=next(s for s in source if all(s[k]==n[k] for k in ['mode','delta','target']))
 assert all(s[k]==n[k] for k in ['clockMs','status','events'])
 sb=json.loads(s['body']) if s['body'] else None;nb=json.loads(n['body']) if n['body'] else None
 if n['status']!=200:assert sb==nb,('admission-error',n['mode'],sb,nb)
 else:
  assert {k:sb['user'].get(k) for k in fields[:10]}=={k:nb['user'].get(k) for k in fields[:10]},('admission-user',n['mode'],sb,nb)
  keys=['userId','impersonatedBy','expiresAt','createdAt','updatedAt','ipAddress','userAgent']
  assert {k:sb['session'].get(k) for k in keys}=={k:nb['session'].get(k) for k in keys},('admission-session',n['mode'],sb,nb)
 pairs.append({'kind':'admission','source':s,'native':n})
source=records('source-nodb-final.log');native=records('native-nodb.log','no-db observation: ')
assert len(source)==6 and len(native)==6
for n in native:
 s=next(s for s in source if all(s[k]==n[k] for k in ['path','delta']))
 assert all(s[k]==n[k] for k in ['clockMs','status'])
 sb=json.loads(s['body']) if s['body'] else None;nb=json.loads(n['body']) if n['body'] else None
 if n['status']!=200:assert sb==nb
 else:
  assert sb['user']['id']==s['target'];assert nb['user']['id']==n['before']['target']['id']
  fs=['email','name','emailVerified','image','createdAt','updatedAt','banned','banReason','banExpires']
  assert {k:sb['user'].get(k) for k in fs}=={k:nb['user'].get(k) for k in fs},('no-db-user',sb,nb)
 pairs.append({'kind':'no-db','source':s,'native':n})
# Paired originals are retained; verify without rewriting artifacts.

print('ALL PAIRED',len(pairs))
