"""Compare measured response bodies and token/session relationships without aliases."""
import gzip
import json
from pathlib import Path

root = Path(__file__).resolve().parent

def read(name):
    path = root / name
    if path.exists():
        return json.loads(path.read_text())
    return json.loads(gzip.decompress(path.with_suffix(path.suffix + '.gz').read_bytes()))

source = read('source.json')
pairs = []
for backend in ('Sqlx', 'SeaOrm'):
    native = read(f'{backend}-decisions.json')
    trace, effects = native['trace'], native['effects']
    for index in range(2):
        decided = json.loads(effects[index * 2]['decided'][0])[0]
        status = decided['status']
        reference = next(item for item in source if item['last'] == status)
        decisions = [item for item in trace if item['path'] in ('/device/approve', '/device/deny')][index * 3:(index + 1) * 3]
        expected = [item for item in reference['trace'] if item['path'] in ('/device/approve', '/device/deny')]
        # Completion order is intentionally controlled only in Source. Match the
        # two overlapping endpoint responses by path; sequential approval follows.
        actual_order = sorted(decisions[:2], key=lambda item: item['path']) + decisions[2:]
        expected_order = sorted(expected[:2], key=lambda item: item['path']) + expected[2:]
        for actual, reference_response in zip(actual_order, expected_order, strict=True):
            assert (actual['path'], actual['status'], actual['body']) == (
                reference_response['path'], reference_response['status'], reference_response['body'])
        tokens = [item for item in trace if item['path'] == '/device/token'][index * 2:(index + 1) * 2]
        expected_tokens = [item for item in reference['trace'] if item['path'] == '/device/token']
        for actual, reference_response in zip(tokens, expected_tokens, strict=True):
            assert actual['status'] == reference_response['status']
            if actual['status'] != 200:
                assert actual['body'] == reference_response['body']
            else:
                body = json.loads(actual['body'])
                sessions = json.loads(effects[index * 2 + 1]['after'][3])
                admitted = [row for row in sessions if row['token'] == body['access_token']]
                assert len(admitted) == 1 and admitted[0]['user_id'] == decided['user_id']
                assert body['scope'] == 'profile raw' and body['token_type'] == 'Bearer'
        pairs.append({'backend': backend, 'reverseInitialPolling': effects[index * 2]['reverse'],
                      'persistedDecision': status, 'literalDecisionResponses': 3,
                      'tokenResponses': 2, 'ownerSessionVerified': status == 'approved'})
(root / 'comparison.json').write_text(json.dumps(pairs, indent=2) + '\n')
print('Both adapters: literal decision/rejection/denial/replay pairs match Source; successful tokens bind physical owner sessions.')
