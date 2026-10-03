"""Bounded raw HTTP/physical-state receipt; only disposable local fixture users."""
import base64
import hashlib
import hmac
import http.client
import json
import sys
import urllib.parse
import uuid

base, destination = sys.argv[1:]
url = urllib.parse.urlsplit(base)
path = '/__test/profiles/multi-session-fractional/api/auth'
observations = []

def call(route, data=None, cookie=''):
    connection = http.client.HTTPConnection(url.hostname, url.port)
    headers = {'content-type': 'application/json', 'origin': base}
    if cookie:
        headers['cookie'] = cookie
    payload = json.dumps(data) if data is not None else None
    connection.request('POST' if data is not None else 'GET', route, payload, headers)
    response = connection.getresponse()
    raw = response.read().decode()
    record = {'path': route, 'requestBody': data, 'requestCookie': cookie,
              'status': response.status, 'headers': response.getheaders(), 'body': raw}
    observations.append(record)
    connection.close()
    return record, json.loads(raw) if raw else None

def signup(label):
    return call(path + '/sign-up/email', {
        'email': f'{label}-{uuid.uuid4().hex}@fixture.test',
        'password': 'password123', 'name': label})

def state(user):
    return call('/__test/user-state?' + urllib.parse.urlencode({'userId': user['id']}))[1]

issued, owner = signup('raw-retirement-owner')
foreign_issued, foreign = signup('raw-foreign-owner')
owner_before, foreign_before = state(owner['user']), state(foreign['user'])
cookies = [value for key, value in issued['headers'] if key.lower() == 'set-cookie']
proof = next(raw.split(';')[0] for raw in cookies if '_multi-' in raw)
credential = proof.split('=', 1)[1]
secret = b'compat-test-only-key-not-real-minimum-32chars'
assert urllib.parse.unquote(credential) == owner['token'] + '.' + base64.b64encode(hmac.new(secret, owner['token'].encode(), hashlib.sha256).digest()).decode()
empty = urllib.parse.quote('.' + base64.b64encode(hmac.new(secret, b'', hashlib.sha256).digest()).decode(), safe="~()*!.'-")
held = '; '.join([raw.split(';')[0] for raw in cookies] + [
    'another_multi-proof=' + credential, 'empty_multi-proof=' + empty, 'invalid_multi-proof=bad'])
logout, body = call(path + '/sign-out', {}, held)
owner_after, foreign_after = state(owner['user']), state(foreign['user'])
assert body == {'success': True}
assert len(owner_before['sessions']) == 1 and not owner_after['sessions']
assert foreign_after == foreign_before
retired = [value for key, value in logout['headers'] if key.lower() == 'set-cookie' and '_multi-' in value]
assert all('Max-Age=0' in value for value in retired)
result = {'baseURL': base, 'observations': observations, 'ownerBefore': owner_before,
          'ownerAfter': owner_after, 'foreignBefore': foreign_before, 'foreignAfter': foreign_after,
          'retiredProofHeaders': retired, 'emptyProofRetired': any(raw.startswith('empty_multi-proof=') for raw in retired)}
with open(destination, 'w') as stream:
    json.dump(result, stream, indent=2)
    stream.write('\n')
print(json.dumps({'destination': destination, 'retiredProofs': len(retired), 'emptyProofRetired': result['emptyProofRetired'], 'sessionsBeforeAfter': [len(owner_before['sessions']), len(owner_after['sessions'])]}))
