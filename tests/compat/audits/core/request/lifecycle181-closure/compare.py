import json
from pathlib import Path
import sys
root=Path(sys.argv[1]) if len(sys.argv)>1 else Path(__file__).parent
src=[json.loads(l) for l in (root/'source-context.jsonl').read_text().splitlines()]
native=[json.loads(l) for l in (root/'composition-rebased.log').read_text().splitlines() if l.startswith('{"backend"')]

def norm(d):
 ids=d['actors']; text=json.dumps(d)
 for i,uid in enumerate(ids):text=text.replace(uid,'actor-'+['a','b'][i])
 d=json.loads(text)
 result=d['result'].copy()
 if result.get('rejected'):result.pop('message',None)
 else:
  try:result['body']=json.loads(result['body'])
  except json.JSONDecodeError:pass
  result['headers']=sorted(result['headers'])
 rows=d['rows']
 if isinstance(rows,list):rows={row['email'].split('@')[0]:row['name'] for row in rows}
 return {'mode':d['mode'],'result':result,'events':d['events'],'rows':rows,'physicalUsers':d['physicalUsers'] if isinstance(d['physicalUsers'],int) else d['physicalUsers']['n'],'physicalSessions':d['physicalSessions'] if isinstance(d['physicalSessions'],int) else d['physicalSessions']['n']}
issues=[]
for backend in ['integration::storage::Sqlx','integration::storage::SeaOrm']:
 ns=[n for n in native if n['backend']==backend]; assert len(ns)==len(src)==17,(backend,len(ns),len(src))
 for s,n in zip(src,ns):
  a,b=norm(s),norm(n)
  if a!=b:
   differences={k:{'source':a[k],'native':b[k]} for k in a if a[k]!=b[k]};issues.append({'backend':backend,'mode':s['mode'],'differences':differences})
(root/'comparison.json').write_text(json.dumps({'observationsPerBackend':len(src),'differences':issues},indent=2)+'\n')
print(json.dumps(issues,indent=2));assert not issues
