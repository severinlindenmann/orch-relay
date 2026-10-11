"""P3-D12/13/18–25 checkpoint relay contract; test support, never server code.

State is JSON-portable. dispatch preflights on a copy and commits only a success.
F1 event/checkpoint encodings are pinned to orch-core f1094b3.
"""
import copy
import re
from datetime import datetime

from ref import orch_protocol_ref as R

ZERO = 'sha256:' + '0' * 64
EMPTY = {'seq': 0, 'head': None, 'acc': ZERO}
HOUR = 3600000
DAY = 24 * HOUR
CP_CAP = 2 * 1024 * 1024
LINE_CAP = 524288
REQUEST_CAP = CP_CAP + LINE_CAP + 65536
PAGE_CAP = 4 * 1024 * 1024
STAGE_CAP = 64 * 1024 * 1024
REQUEST_CAPS = {'genesis': 65536, 'page': PAGE_CAP, 'manifest': PAGE_CAP,
                'baseline': 16384, 'publish': REQUEST_CAP}
STRENGTH = {'lost': 1, 'retired': 1, 'compromised': 2}
# Failed final publications per workspace per hour (§19.8, P3-D17 style refusal, never eviction).
FAILURE_BUDGET = 16
BUNDLE_FIELDS = {'restore_id', 'log', 'source_hash', 'target_hash', 'target_n', 'line', 'cert', 'authz'}


class Refusal(Exception):
    def __init__(self, code, status=409, **fields):
        self.result = {'status': status, 'error': code, **fields}


def need(ok, code='malformed', status=400, **fields):
    if not ok:
        raise Refusal(code, status, **fields)


def hash_bytes(value):
    need(isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value))
    return bytes.fromhex(value[7:])


def digest(data):
    return 'sha256:' + R.H(data).hex()


def checkpoint_hash(cp):
    return digest(R.L['h_checkpoint'] + R.cj(cp['o']))


def log_acc(acc, head):
    return digest(R.L['h_log_acc'] + hash_bytes(acc) + hash_bytes(head))


def event_head(line):
    return digest(R.L['h_event'] + R.cj(line))


def event_bytes(S, line, ws, log, host=False):
    omit = {'host_sig'} if host else {'seq', 'at', 'prev', 'ws_seq', 'sig', 'host_sig'}
    label = 'sig_host_event' if host else 'sig_ws_event' if log == 'workspace' else 'sig_ticket_event'
    return R.L[label] + R.cj({'contract': 1, 'suite': S.id, 'workspace_id': ws, 'log': log,
                             'event': {k: v for k, v in line.items() if k not in omit}})


def timestamp(at):
    need(isinstance(at, str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', at))
    return int(datetime.fromisoformat(at.replace('Z', '+00:00')).timestamp() * 1000)


def integer(n, minimum=0):
    need(type(n) is int and minimum <= n <= R.MAX_SAFE_INT)


def entries(cp):
    return {'workspace': cp['o']['workspace_log'], **cp['o']['tickets']}


def reference(cp):
    return {'n': cp['o']['n'], 'hash': checkpoint_hash(cp)} if cp else None


def initial(ws, wsk_pub, owner_pk, delegation, members):
    return {'ws': ws, 'wsk_pub': wsk_pub, 'owner_pk': owner_pk, 'delegation': delegation,
            'members': members, 'persons': {delegation['o']['owner_person_id']: owner_pk},
            'ever_devices': sorted(members), 'revocations': {}, 'genesis': None, 'held': None,
            'checkpoints': {}, 'gone': [], 'nodes': {}, 'staging': {}, 'transitions': [],
            'baselines': {}, 'receipts': {}, 'failures': []}


def owner(S, state, cert, now, extra=()):
    # Every known revocation refuses the signer, at the relay and at a historical receiver alike (review 1).
    checked = R.verify_cert(S, cert, R.unb64u(state['owner_pk']), now, set(state['revocations']) | set(extra))
    need('ok' in checked, 'restore_not_owner', 409)
    c = checked['ok']
    need(c['person_id'] == state['delegation']['o']['owner_person_id'] and
         'operate' in c['scopes_max'] and
         not any(x.startswith('drop:') for x in c['scopes_max']), 'restore_not_owner', 409)
    return c


def genesis(S, state, body, now):
    need(set(body) == {'pin', 'cert'})
    pin = body['pin']
    if state['genesis']:
        need(pin == state['genesis']['pin'], 'genesis_mismatch', 409)
        return {}
    cert = owner(S, state, body['cert'], now)
    o = R.verify_object(S, R.unb64u(cert['dk_sig_pub']), pin, 'genesis_pin')
    need(o is not None, 'bad_signature', 401)
    need(set(o) == {'v', 'suite', 'kind', 'workspace_id', 'wsk_pub', 'genesis'})
    hash_bytes(o['genesis'])
    need(o['workspace_id'] == state['ws'] and o['wsk_pub'] == state['wsk_pub'], 'genesis_mismatch', 409)
    state['genesis'] = body
    return {}


def page_digest(page):
    # Explicit transport convention in §19.8; not an F1 hash domain.
    return digest(R.cj({k: v for k, v in page.items() if k != 'digest'}))


def stage_key(source, target):
    if source is not None:
        hash_bytes(source)
    hash_bytes(target)
    return (source or 'null') + '/' + target


def descriptor(i, page):
    return {k: page[k] for k in ('kind', 'log', 'after_seq', 'digest')} | {'i': i, 'count': len(page['heads'])}


def completeness(stage):
    if stage['manifest'] is None:
        return {'complete': False, 'missing': []}
    missing = [d['i'] for d in stage['manifest']['pages'] if str(d['i']) not in stage['pages']]
    return {'complete': not missing, 'missing': missing}


def staging(state, body, now, source, target, i=None, wire=None):
    wire = R.cj(body) if wire is None else wire
    key = stage_key(source, target)
    state['staging'] = {k: v for k, v in state['staging'].items() if v['expires_ms'] > now}
    if key not in state['staging']:
        need(len(state['staging']) < 2, 'quota_exceeded', 429)
        state['staging'][key] = {'expires_ms': now + HOUR, 'pages': {}, 'manifest': None, 'wire_pages': {}, 'wire_manifest': None}
    st = state['staging'][key]
    if i is not None:
        integer(i)
        need(len(wire) <= PAGE_CAP, 'too_large', 413)
        need(set(body) == {'kind', 'log', 'after_seq', 'from_acc', 'heads', 'digest'})
        need(body['kind'] in ('appended', 'abandoned', 'retained'))
        need(body['log'] == 'workspace' or re.fullmatch(r'[0-9A-HJKMNP-TV-Z]{26}', body['log']))
        integer(body['after_seq'])
        hash_bytes(body['from_acc'])
        need(isinstance(body['heads'], list) and bool(body['heads']))
        for h in body['heads']:
            hash_bytes(h)
        need(body['digest'] == page_digest(body))
        if str(i) in st['pages']:
            need(st['wire_pages'][str(i)] == wire.hex(), 'staging_conflict', 409)
            return {}
        if st['manifest'] is not None:
            need(descriptor(i, body) in st['manifest']['pages'], 'staging_conflict', 409)
        need(staged_bytes(state) + len(wire) <= STAGE_CAP, 'quota_exceeded', 429)
        st['pages'][str(i)] = body
        st['wire_pages'][str(i)] = wire.hex()
        return {}
    need(set(body) == {'pages'} and isinstance(body['pages'], list))
    need(len(wire) <= PAGE_CAP, 'too_large', 413)
    if st['manifest'] is not None:
        need(st['wire_manifest'] == wire.hex(), 'staging_conflict', 409)
        return completeness(st)
    previous, seen = {}, set()
    order = []
    for d in body['pages']:
        need(set(d) == {'i', 'kind', 'log', 'after_seq', 'count', 'digest'})
        integer(d['i']); integer(d['after_seq']); integer(d['count'], 1)
        hash_bytes(d['digest'])
        need(d['kind'] in ('appended', 'abandoned', 'retained'))
        need(d['i'] not in seen)
        seen.add(d['i'])
        group = (d['kind'], d['log'])
        need(group not in previous or previous[group] == d['after_seq'])
        previous[group] = d['after_seq'] + d['count']
        order.append((*group, d['after_seq']))
        if str(d['i']) in st['pages']:
            need(descriptor(d['i'], st['pages'][str(d['i'])]) == d, 'staging_conflict', 409)
    need(order == sorted(order))
    need(set(st['pages']) <= {str(i) for i in seen}, 'staging_conflict', 409)
    need(staged_bytes(state) + len(wire) <= STAGE_CAP, 'quota_exceeded', 429)
    st['manifest'] = body
    st['wire_manifest'] = wire.hex()
    return completeness(st)


def staged_bytes(state):
    # Page and manifest bytes share the per-workspace quota (review 11).
    return sum(len(p) // 2 for s in state['staging'].values()
               for p in [*s['wire_pages'].values(), s['wire_manifest'] or ''])


def node(state, log, acc):
    return EMPTY if acc == ZERO else state['nodes'].get(log, {}).get(acc)


def walk(state, log, start, endpoint):
    """Walk the endpoint's immutable branch, never the current mutable head."""
    out, acc = [], endpoint['acc']
    while acc != start:
        n = node(state, log, acc)
        need(n is not None and n['seq'] > 0, 'chain_diverged', 409)
        out.append(n['head'])
        acc = n['prev_acc']
    return list(reversed(out))


def at_seq(state, log, endpoint, seq):
    n = endpoint
    while n['seq'] > seq:
        n = node(state, log, n['acc'])
        need(n is not None, 'restore_invalid', 409)
        n = node(state, log, n['prev_acc'])
        need(n is not None, 'restore_invalid', 409)
    need(n['seq'] == seq, 'restore_invalid', 409)
    return {k: n[k] for k in ('seq', 'head', 'acc')}


def extend(state, log, old, heads):
    current = old.copy()
    for head in heads:
        acc = log_acc(current['acc'], head)
        n = {'seq': current['seq'] + 1, 'head': head, 'acc': acc, 'prev_acc': current['acc']}
        nodes = state['nodes'].setdefault(log, {})
        need(acc not in nodes or nodes[acc] == n, 'chain_diverged', 409)
        nodes[acc] = n
        current = {k: n[k] for k in ('seq', 'head', 'acc')}
    return current


def proof_pages(state, stage, kind, log, start, used):
    current = {k: start[k] for k in ('seq', 'head', 'acc')}
    for d in stage['manifest']['pages']:
        if d['kind'] != kind or d['log'] != log:
            continue
        p = stage['pages'][str(d['i'])]
        need(p['after_seq'] == current['seq'] and p['from_acc'] == current['acc'], 'chain_diverged', 409)
        current = extend(state, log, current, p['heads'])
        used.add(d['i'])
    return current


def validate_checkpoint(S, state, cp):
    need(len(R.cj(cp)) <= CP_CAP, 'too_large', 400)
    o = cp['o']
    need(o.get('suite') == S.id, 'wrong_suite', 400)
    need(set(o) == {'v', 'suite', 'kind', 'workspace_id', 'genesis', 'n', 'at', 'workspace_log', 'tickets'})
    need(o['kind'] == 'workspace_checkpoint' and o['v'] == 2)
    need(R.verify_object(S, R.unb64u(state['wsk_pub']), cp, 'workspace_checkpoint') is not None, 'bad_signature', 401)
    need(state['genesis'] is not None, 'no_genesis', 409)
    need(o['workspace_id'] == state['ws'] and o['genesis'] == state['genesis']['pin']['o']['genesis'], 'genesis_mismatch', 409)
    integer(o['n'], 1); timestamp(o['at'])
    need(isinstance(o['tickets'], dict))
    for uid in o['tickets']:
        need(re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}', uid))
    for entry in entries(cp).values():
        need(set(entry) == {'seq', 'head', 'acc'})
        integer(entry['seq'], 1); hash_bytes(entry['head']); hash_bytes(entry['acc'])


def restore_shape(line):
    fields = {'v', 'id', 'seq', 'at', 'type', 'actor', 'based_on', 'prev', 'hash_v', 'host_sig',
              'sig', 'auth', 'roster_v', 'from_seq', 'head', 'abandoned', 'abandoned_decisions', 'reason', 'source', 'revocations'}
    need(fields <= set(line) <= fields | {'note', 'ws_seq'})
    need(type(line['hash_v']) is int and line['v'] == 2 and line['hash_v'] == 1 and line['type'] == 'restore')
    need(set(line['actor']) == {'kind', 'id', 'device'} and line['actor']['kind'] == 'person')
    need(re.fullmatch(r'p_[0-9a-f]{32}', line['actor']['id']) and re.fullmatch(r'd_[0-9a-f]{32}', line['actor']['device']))
    need(re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}', line['id']))
    integer(line['seq'], 1); integer(line['from_seq'], 1); integer(line['roster_v'])
    if 'ws_seq' in line:
        integer(line['ws_seq'], 1)
    hash_bytes(line['based_on']); hash_bytes(line['prev']); hash_bytes(line['head']); timestamp(line['at'])
    need(line['seq'] == line['from_seq'] + 1 and line['prev'] == line['head'])
    need(line['auth'] in ('passphrase', 'secure-enclave', 'secure-enclave-unlocked', 'webauthn', 'tpm', 'windows-hello'))
    need(line['reason'] in ('rollback', 'diverged', 'broken', 'other'))
    need(isinstance(line['abandoned_decisions'], list) and len(set(line['abandoned_decisions'])) == len(line['abandoned_decisions']))
    for ident in line['abandoned_decisions']:
        need(re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}', ident))
    if 'note' in line:
        note = line['note']
        need(isinstance(note, str) and len(note.encode()) <= 280 and not any(ord(c) < 32 or ord(c) == 127 for c in note))
    if line['source'] is not None:
        need(set(line['source']) == {'n', 'hash'})
        integer(line['source']['n'], 1); hash_bytes(line['source']['hash'])
    if line['abandoned'] is not None:
        need(set(line['abandoned']) == {'seq', 'head'})
        integer(line['abandoned']['seq'], line['from_seq'] + 1); hash_bytes(line['abandoned']['head'])
    R.unb64u(line['sig'], 64); R.unb64u(line['host_sig'], 64)
    need(isinstance(line['revocations'], list))


def revocation_evidence(S, state, line, log, persons=None):
    """F1 B1 entries. A known person's pk_pub must equal the stored key; any other person is accepted
    self-certifying, because verify_cert binds person_id = H(h_person_id || suite || pk_pub) (review 5)."""
    persons = state['persons'] if persons is None else persons
    need(log == 'workspace' or line['revocations'] == [], 'restore_invalid', 409)
    listed = {}
    order = []
    for item in line['revocations']:
        need(set(item) == {'revocation', 'device_cert', 'pk_pub'}, 'restore_invalid', 409)
        pk = R.unb64u(item['pk_pub'])
        c = item['device_cert']['o']
        need(persons.get(c['person_id'], item['pk_pub']) == item['pk_pub'], 'restore_invalid', 409)
        checked = R.verify_cert(S, item['device_cert'], pk, c['created_ms'])
        need('ok' in checked, 'restore_invalid', 409)
        rev = R.verify_revocation(S, item['revocation'], pk, checked['ok'])
        need('ok' in rev, 'restore_invalid', 409)
        d = rev['ok']['device_id']
        need(d not in listed, 'restore_invalid', 409)
        order.append(d); listed[d] = item['revocation']
    need(order == sorted(order), 'restore_invalid', 409)
    return listed


def revocation_coverage(state, listed, signer, log):
    if log == 'workspace':
        devices = set(state['ever_devices']) | set(listed) | {signer}
        missing = sorted(d for d in devices if d in state['revocations'] and
                         (d not in listed or STRENGTH[listed[d]['o']['reason']] < STRENGTH[state['revocations'][d]['o']['reason']]))
        need(not missing, 'restore_missing_revocation', 409, devices=missing)


def owner_policy(S, state, bundle, now, extra=(), historical=False):
    """P3-D24: historical receivers omit the relay-only current-list/current-clock checks.

    They never omit a revocation they already know: any known revocation of the signer, of any reason
    and whatever its revoked_ms, refuses (review 1). "Later" knowledge is defined by the receiver's own
    commit order (sync_walk), never by the host-chosen line.at."""
    line = bundle['line']
    if historical:
        # Internal evidence is mandatory even when relay-local completeness is irrelevant.
        listed = revocation_evidence(S, state, line, 'ticket' if 'ws_seq' in line else 'workspace')
        extra = set(extra) | set(listed)
    cert = owner(S, state, bundle['cert'], timestamp(line['at']), extra)
    if not historical:
        owner(S, state, bundle['cert'], now, extra)
        need('operate' in state['members'].get(cert['device_id'], []), 'restore_not_owner', 409)
    authz = bundle['authz']
    need(set(authz) == {'delegation'}, 'restore_not_owner', 409)
    need(R.verify_delegation(S, authz['delegation'], R.unb64u(state['owner_pk'])).get('ok') == state['delegation']['o'], 'restore_not_owner', 409)
    need(line['actor']['id'] == 'p_' + cert['person_id'] and
         line['actor']['device'] == 'd_' + cert['device_id'], 'restore_not_owner', 409)
    return cert


def restore_check(S, state, body, target, held, stage, used, now):
    bundle = body['restore']
    try:
        need(set(bundle) == {'line', 'cert', 'authz', 'log'})
        line = bundle['line']
        restore_shape(line)
        log = bundle['log']
        # The request names its log (review 3): exactly one signed context is ever verified.
        need((log == 'workspace') == ('ws_seq' not in line))
        need(len(R.cj(line)) + 1 <= LINE_CAP, 'too_large', 400)
    except (KeyError, TypeError, ValueError, Refusal) as exc:
        if isinstance(exc, Refusal) and exc.result['error'] == 'too_large':
            raise
        raise Refusal('restore_invalid') from exc
    need(line['source'] == reference(held), 'restore_source_mismatch', 409)
    need(line['id'] not in {t['restore_id'] for t in state['transitions']}, 'restore_reused', 409)
    pub = R.unb64u(bundle['cert']['o']['dk_sig_pub'])
    need(S.verify(pub, R.unb64u(line['sig']), event_bytes(S, line, state['ws'], log)) and
         S.verify(R.unb64u(state['wsk_pub']), R.unb64u(line['host_sig']), event_bytes(S, line, state['ws'], log, True)),
         'restore_invalid', 409)
    listed = revocation_evidence(S, state, line, log)
    cert = owner_policy(S, state, bundle, now, listed)
    revocation_coverage(state, listed, cert['device_id'], log)
    need((not held or timestamp(held['o']['at']) <= timestamp(line['at'])) and
         timestamp(line['at']) <= timestamp(target['o']['at']), 'restore_invalid', 409)
    if 'ws_seq' in line:
        need(line['ws_seq'] <= target['o']['workspace_log']['seq'], 'restore_invalid', 409)
    old = entries(held).get(log, EMPTY) if held else EMPTY
    if line['from_seq'] < old['seq']:
        retained = at_seq(state, log, old, line['from_seq'])
        # A stored path needs no retained page. Any supplied page must bind to that branch.
        retained_pages = [d for d in stage['manifest']['pages'] if d['kind'] == 'retained' and d['log'] == log]
        if retained_pages:
            first = stage['pages'][str(retained_pages[0]['i'])]
            start = node(state, log, first['from_acc'])
            need(start is not None and start['seq'] == first['after_seq'], 'restore_invalid', 409)
            walk(state, log, first['from_acc'], old)
            proved = proof_pages(state, stage, 'retained', log, start, used)
            need(proved == retained, 'restore_invalid', 409)
        abandoned = proof_pages(state, stage, 'abandoned', log, retained, used)
        need(abandoned == old, 'restore_invalid', 409)
        ab = line['abandoned']
        need(ab is not None and ab['seq'] >= old['seq'] and (ab['seq'] != old['seq'] or ab['head'] == old['head']), 'restore_invalid', 409)
    else:
        retained = proof_pages(state, stage, 'retained', log, old, used)
    need(retained['seq'] == line['from_seq'] and retained['head'] == line['head'], 'restore_invalid', 409)
    if log == 'workspace':
        root = at_seq(state, log, retained, 1)
        need(root['head'] == state['genesis']['pin']['o']['genesis'], 'restore_invalid', 409)
    result = extend(state, log, retained, [event_head(line)])
    need(entries(target).get(log) == result, 'restore_invalid', 409)
    for d, rev in listed.items():
        if d not in state['revocations'] or STRENGTH[rev['o']['reason']] > STRENGTH[state['revocations'][d]['o']['reason']]:
            state['revocations'][d] = rev
    state['ever_devices'] = sorted(set(state['ever_devices']) | set(listed) | {cert['device_id']})
    state['transitions'].append({'restore_id': line['id'], 'source_hash': body['source_hash'],
                                 'target_hash': checkpoint_hash(target), 'target_n': target['o']['n'], **bundle})
    if held:
        state['checkpoints'][checkpoint_hash(held)]['permanent'] = True
    return log


def publish(S, state, body, now):
    need(len(R.cj(body)) <= REQUEST_CAP, 'too_large', 400)
    need(set(body) in ({'checkpoint', 'source_hash'}, {'checkpoint', 'source_hash', 'restore'}))
    target = body['checkpoint']
    validate_checkpoint(S, state, target)
    h = checkpoint_hash(target)
    receipt = digest(R.cj(body))
    if receipt in state['receipts']:
        return state['receipts'][receipt]
    held = state['held']
    result = {'result': 'accepted', 'n': target['o']['n'], 'hash': h}
    if held and target['o']['n'] <= held['o']['n']:
        if target['o'] == held['o'] and 'restore' not in body:
            return result
        if target['o']['n'] == held['o']['n'] or 'restore' in body:
            raise Refusal('restore_source_mismatch' if 'restore' in body else 'chain_diverged')
        old = entries(held)
        need(all(k in old and (e['seq'] < old[k]['seq'] or e == old[k]) for k, e in entries(target).items()), 'chain_diverged', 409)
        return {**result, 'result': 'ignored'}
    need(body['source_hash'] == (checkpoint_hash(held) if held else None), 'restore_source_mismatch', 409)
    need(timestamp(target['o']['at']) <= now + 300000 and
         (not held or timestamp(target['o']['at']) >= timestamp(held['o']['at'])), 'checkpoint_time', 409)
    key = stage_key(body['source_hash'], h)
    stage = state['staging'].get(key)
    need(stage is not None and stage['expires_ms'] > now and completeness(stage)['complete'], 'staging_incomplete', 409)
    used = set()
    old = entries(held) if held else {}
    offered = entries(target)
    need(not old.keys() - offered.keys(), 'chain_diverged', 409)
    try:
        restored = restore_check(S, state, body, target, held, stage, used, now) if 'restore' in body else None
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
        raise Refusal('restore_invalid') from exc
    for log, entry in offered.items():
        if log == restored:
            continue
        start = old.get(log, EMPTY)
        calculated = proof_pages(state, stage, 'appended', log, start, used)
        need(calculated == entry, 'chain_diverged', 409)
        if log == 'workspace':
            need(at_seq(state, log, entry, 1)['head'] == target['o']['genesis'], 'genesis_mismatch', 409)
    need(used == {d['i'] for d in stage['manifest']['pages']}, 'chain_diverged', 409)
    if held:
        state['checkpoints'][checkpoint_hash(held)]['superseded_ms'] = now
    state['held'] = target
    state['checkpoints'][h] = {'checkpoint': target, 'superseded_ms': None, 'permanent': restored is not None}
    state['receipts'][receipt] = result
    del state['staging'][key]
    return result


def expire(state, now):
    state['baselines'] = {k: b for k, b in state['baselines'].items() if b['until_ms'] > now}
    for h, c in list(state['checkpoints'].items()):
        if not c['permanent'] and c['superseded_ms'] is not None and now >= c['superseded_ms'] + DAY and h not in state['baselines']:
            del state['checkpoints'][h]
            state['gone'].append(h)


def get_checkpoint(state, h, now):
    expire(state, now)
    if h is None:
        need(state['held'] is not None, 'not_found', 404)
        h = checkpoint_hash(state['held'])
    hash_bytes(h)
    need(h not in state['gone'], 'checkpoint_gone', 410)
    need(h in state['checkpoints'], 'not_found', 404)
    return state['checkpoints'][h]['checkpoint']


def read(state, op, args, now):
    cp = get_checkpoint(state, args.get('hash') if op == 'get' else args['to'], now)
    if op == 'get':
        return {'genesis': state['genesis'], 'checkpoint': cp,
                'transitions_head': max((t['target_n'] for t in state['transitions'] if t['target_n'] <= cp['o']['n']), default=0)}
    limit = args.get('limit', 16 if op == 'transitions' else 65536)
    integer(limit, 1)
    need(limit <= (16 if op == 'transitions' else 65536))
    if op == 'transitions':
        after = args.get('after_n', 0); integer(after)
        all_items = sorted((t for t in state['transitions'] if after < t['target_n'] <= cp['o']['n']), key=lambda t: t['target_n'])
        page = []
        for item in all_items[:limit]:
            if len(R.cj({'transitions': page + [item], 'next': str(item['target_n'])})) > PAGE_CAP:
                break
            page.append(item)
        return {'transitions': page, 'next': str(page[-1]['target_n']) if len(page) < len(all_items) else None}
    log, start = args['log'], args['from']
    hash_bytes(start)
    need(log in entries(cp) and node(state, log, start) is not None, 'not_found', 404)
    try:
        heads = walk(state, log, start, entries(cp)[log])
    except Refusal as exc:
        raise Refusal('not_found', 404) from exc
    page, acc = [], start
    for head in heads[:limit]:
        # A hash string is 73 JSON bytes, plus its comma; retain framing headroom.
        if (len(page) + 1) * 74 + 128 > PAGE_CAP:
            break
        page.append(head); acc = log_acc(acc, head)
    return {'heads': page, 'next': acc if len(page) < len(heads) else None}


def baseline(state, body, now, delete=False, role='host'):
    h = body['hash']; hash_bytes(h)
    expire(state, now)
    if delete:
        # W(g) releases any pin. A D(m) member releases only the pin whose offer_id it names, so one
        # member cannot push another device's pairing onto the 24 h fallback (review 10).
        need(role in ('host', 'member') and set(body) <= {'hash', 'offer_id'})
        pin = state['baselines'].get(h)
        if pin and (role == 'host' or body.get('offer_id') == pin['offer_id']):
            del state['baselines'][h]
        return {}
    need(set(body) == {'hash', 'offer_id'})
    R.unhex(body['offer_id'], 16)
    get_checkpoint(state, h, now)
    if h in state['baselines']:
        return {'until_ms': state['baselines'][h]['until_ms']}
    need(len(state['baselines']) < 16, 'quota_exceeded', 429)
    state['baselines'][h] = {'offer_id': body['offer_id'], 'until_ms': now + 7 * DAY}
    return {'until_ms': now + 7 * DAY}


# ---------------------------------------------------------------------------------------------
# Device side (§19.8 "Device synchronisation"): the checkpoint-only receiver and its sync walk.
# judge_offer ports orch-core f1094b3 store/checkpoints.judge_offer with the relay's primitives and
# returns F1's codes, so F1's transition_cases/workspace_n_offers run against it unchanged.
# ---------------------------------------------------------------------------------------------
DIVERGED, INCOMPLETE = 'chain.diverged', 'sync.incomplete'
WALK_CODES = {DIVERGED: 'chain_diverged', INCOMPLETE: 'sync_incomplete', 'trust.genesis_mismatch': 'genesis_mismatch',
              'ignored': 'chain_diverged'}


def fold(acc, heads):
    for head in heads:
        acc = log_acc(acc, head)
    return acc


def extension(old, new, heads):
    """Exactly new.seq - old.seq heads, ending at new.head and folding old.acc to new.acc (P3-D19)."""
    try:
        return (isinstance(heads, list) and len(heads) == new['seq'] - old['seq'] and
                (heads[-1] if heads else old['head']) == new['head'] and fold(old['acc'], heads) == new['acc'])
    except (Refusal, KeyError, TypeError):
        return False


def judge_offer(S, held, offered, *, genesis, wsk_pub, restore=None, applied=(), proofs=None, known=(),
                owner_pk=None, initial_proof=False):
    """held/offered are checkpoint `o` objects. Returns (code, recorded restore id or None).

    owner_pk pins the pairing owner key (P3-D24); initial_proof demands full proof from acc_0 and the
    genesis root for a first checkpoint (P3's stricter rule; F1 accepts it without ancestry)."""
    if offered['genesis'] != genesis:
        return 'trust.genesis_mismatch', None
    if held and offered['workspace_id'] != held['workspace_id']:
        return DIVERGED, None
    h = {'workspace': held['workspace_log'], **held['tickets']} if held else {}
    o = {'workspace': offered['workspace_log'], **offered['tickets']}
    proofs = {} if proofs is None else proofs
    if held and offered['n'] == held['n']:
        return ('ok' if offered == held else DIVERGED), None
    if held and offered['n'] < held['n']:
        bad = any(k not in h or v['seq'] > h[k]['seq'] or (v['seq'] == h[k]['seq'] and v != h[k]) for k, v in o.items())
        return (DIVERGED if bad else 'ignored'), None
    if held and (offered['at'] < held['at'] or h.keys() - o.keys()):
        return DIVERGED, None
    if not isinstance(proofs, dict):
        return INCOMPLETE, None
    restored = None
    if restore is not None:
        try:
            ev, log, c, target = restore['event'], restore['log'], restore['C'], restore['T']
            wsk = R.unb64u(wsk_pub)
            if target['o'] != offered or R.verify_object(S, wsk, target, 'workspace_checkpoint') is None:
                return DIVERGED, None
            restore_shape(ev)
            if (log == 'workspace') != ('ws_seq' not in ev):
                return DIVERGED, None
            # Source binding (R2-equivalent): the person-signed source is exactly the held checkpoint.
            if ev['id'] in applied or ev['source'] != reference(c):
                return DIVERGED, None
            if (held is None) != (c is None) or (held is not None and c['o'] != held):
                return DIVERGED, None
            if c and R.verify_object(S, wsk, c, 'workspace_checkpoint') is None:
                return DIVERGED, None
            if owner_pk is not None and restore['pk_pub'] != owner_pk:
                return DIVERGED, None
            pk = R.unb64u(restore['pk_pub'])
            at_ms = timestamp(ev['at'])
            checked = R.verify_cert(S, restore['device_cert'], pk, at_ms)
            delegation = R.verify_delegation(S, restore['delegation'], pk)
            if 'ok' not in checked or 'ok' not in delegation:
                return DIVERGED, None
            cert, delegation = checked['ok'], delegation['ok']
            if (delegation['workspace_id'] != offered['workspace_id'] or delegation['wsk_pub'] != wsk_pub or
                    ev['actor']['id'] != 'p_' + cert['person_id'] or ev['actor']['device'] != 'd_' + cert['device_id'] or
                    'operate' not in cert['scopes_max'] or any(x.startswith('drop:') for x in cert['scopes_max'])):
                return DIVERGED, None
            ws = offered['workspace_id']
            if not (S.verify(R.unb64u(cert['dk_sig_pub']), R.unb64u(ev['sig']), event_bytes(S, ev, ws, log)) and
                    S.verify(wsk, R.unb64u(ev['host_sig']), event_bytes(S, ev, ws, log, True))):
                return DIVERGED, None
            if len(R.cj(ev)) + 1 > LINE_CAP or (held and ev['at'] < held['at']):
                return DIVERGED, None
            listed = revocation_evidence(S, {'persons': {}}, ev, log)
            if cert['device_id'] in listed:
                return DIVERGED, None
            for item in known:
                rev = item['revocation']['o']
                # Review 1: any revocation already known refuses its signer, whenever it arrived.
                if (log == 'workspace' and (rev['device_id'] not in listed or (
                        rev['reason'] == 'compromised' and listed[rev['device_id']]['o']['reason'] != 'compromised'))
                        ) or ev['actor']['device'] == 'd_' + rev['device_id']:
                    return DIVERGED, None
            acc = restore.get('acc_from')
            try:
                hash_bytes(acc)
            except Refusal:
                return INCOMPLETE, None
            retained = {'seq': ev['from_seq'], 'head': ev['head'], 'acc': acc}
            base = h.get(log, EMPTY)
            if log == 'workspace' and base['seq'] == 0:
                forward = restore.get('forward_heads')
                if not isinstance(forward, list) or not forward or forward[0] != genesis:
                    return INCOMPLETE, None
            if ev['from_seq'] >= base['seq']:
                if not extension(base, retained, restore.get('forward_heads', [])):
                    return INCOMPLETE, None
            else:
                try:
                    if log_acc(restore.get('acc_before'), ev['head']) != acc:
                        return INCOMPLETE, None
                except Refusal:
                    return INCOMPLETE, None
                if not extension(retained, base, restore.get('abandoned_heads')):
                    return INCOMPLETE, None
                ab = ev['abandoned']
                if not ab or ab['seq'] < base['seq'] or (ab['seq'] == base['seq'] and ab['head'] != base['head']):
                    return DIVERGED, None
            if log == 'workspace' and ev['from_seq'] == 1 and (ev['head'] != genesis or acc != log_acc(ZERO, genesis)):
                return INCOMPLETE, None
            tail = proofs.get(log)
            if (not isinstance(tail, list) or not tail or tail[0] != event_head(ev) or log not in o or
                    not extension(retained, o[log], tail)):
                return INCOMPLETE, None
            restored = (log, ev['id'])
        except (KeyError, TypeError, ValueError, IndexError, AttributeError, Refusal):
            return DIVERGED, None
    if held is None and restore is None and not initial_proof:
        return 'ok', None
    for log, entry in o.items():
        if restored and log == restored[0]:
            continue
        old = h.get(log, EMPTY)
        if entry['seq'] < old['seq'] or (entry['seq'] == old['seq'] and entry != old):
            return DIVERGED, None
        heads = proofs.get(log, [])
        if not extension(old, entry, heads):
            return INCOMPLETE, None
        if initial_proof and log == 'workspace' and old['seq'] == 0 and heads[0] != genesis:
            return INCOMPLETE, None
    return 'ok', restored[1] if restored else None


def device_initial(ws, wsk_pub, owner_pk, genesis, held=None):
    """A paired device: pairing-pinned owner PK, WSK and genesis; held is its verified baseline or None."""
    return {'ws': ws, 'wsk_pub': wsk_pub, 'owner_pk': owner_pk, 'genesis': genesis, 'held': held,
            'applied': [], 'revocations': {}, 'alarms': []}


def stronger(revocations, rev):
    d = rev['o']['device_id']
    if d not in revocations or STRENGTH[rev['o']['reason']] > STRENGTH[revocations[d]['o']['reason']]:
        revocations[d] = rev


def sync_walk(S, dev, relay, now, endpoint=None):
    """§19.8 device synchronisation against an immutable endpoint E. relay is read only through the
    public GET routes. The device commits only after the whole walk verifies; any refusal leaves it as is."""
    dev = copy.deepcopy(dev)
    ws, genesis = dev['ws'], dev['genesis']

    def get(op, **args):
        try:
            return read(relay, op, args, now)
        except Refusal as exc:
            if exc.result['error'] == 'checkpoint_gone':
                raise  # restart with a new E; H unchanged
            raise Refusal('sync_incomplete', 409) from exc  # missing evidence, never re-pairing

    def fetch(h):
        cp = get('get', hash=h)['checkpoint']
        # Hash-addressed objects are bound to their hash, signature, workspace and pinned genesis.
        need(checkpoint_hash(cp) == h, 'chain_diverged', 409)
        need(R.verify_object(S, R.unb64u(dev['wsk_pub']), cp, 'workspace_checkpoint') is not None and
             cp['o']['workspace_id'] == ws, 'chain_diverged', 409)
        need(cp['o']['genesis'] == genesis, 'genesis_mismatch', 409)
        return cp

    def heads(log, start, to):
        out = []
        while True:
            page = get('proof', log=log, to=to, **{'from': start})
            need(page['heads'] or page['next'] is None, 'sync_incomplete', 409)
            out += page['heads']
            if page['next'] is None:
                return out
            start = page['next']

    def growth(work, x, skip=None):
        old = entries(work) if work else {}
        return {log: heads(log, old.get(log, EMPTY)['acc'], checkpoint_hash(x))
                for log, e in entries(x).items() if log != skip and e['seq'] > old.get(log, EMPTY)['seq']}

    def judge(work, x, **kw):
        code, recorded = judge_offer(S, work['o'] if work else None, x['o'], genesis=genesis, wsk_pub=dev['wsk_pub'],
                                     owner_pk=dev['owner_pk'], applied=dev['applied'], initial_proof=True, **kw)
        return code, recorded

    top = get('get', **({'hash': endpoint} if endpoint else {}))
    end = fetch(checkpoint_hash(top['checkpoint']))
    if endpoint:
        need(checkpoint_hash(end) == endpoint, 'chain_diverged', 409)
    end_hash = checkpoint_hash(end)
    work = dev['held']
    learned, signers = dict(dev['revocations']), []
    after = last = work['o']['n'] if work else 0
    while work is None or end['o']['n'] > work['o']['n']:
        page = get('transitions', to=end_hash, after_n=after)
        for b in page['transitions']:
            need(isinstance(b, dict) and set(b) == BUNDLE_FIELDS and b['restore_id'] == b['line']['id'],
                 'chain_diverged', 409)
            # Ascending target_n, bounded by E.
            need(type(b['target_n']) is int and last < b['target_n'] <= end['o']['n'], 'chain_diverged', 409)
            last = b['target_n']
            if b['source_hash'] is not None and (work is None or b['source_hash'] != checkpoint_hash(work)):
                # Prove the exact extension work -> B.source; a lower or equal source never qualifies.
                c = fetch(b['source_hash'])
                need(work is None or c['o']['n'] > work['o']['n'], 'chain_diverged', 409)
                need(judge(work, c, proofs=growth(work, c))[0] == 'ok', 'chain_diverged', 409)
                work = c
            t = fetch(b['target_hash'])
            need(t['o']['n'] == b['target_n'], 'chain_diverged', 409)
            line, log = b['line'], b['log']
            old = entries(work).get(log, EMPTY) if work else EMPTY
            fs = line['from_seq']
            restore = {'event': line, 'log': log, 'C': work, 'T': t, 'pk_pub': dev['owner_pk'],
                       'device_cert': b['cert'], 'delegation': b['authz']['delegation']}
            known = [{'revocation': r} for r in learned.values()]
            # Signatures, source binding, owner policy and revocations first; only then fetch proofs.
            code, _ = judge(work, t, restore=restore, known=known)
            need(code == INCOMPLETE, WALK_CODES.get(code, 'chain_diverged'), 409)
            if type(fs) is int and 1 <= fs < old['seq']:
                full = heads(log, ZERO, b['target_hash'])
                need(len(full) > fs, 'sync_incomplete', 409)
                restore['acc_before'] = fold(ZERO, full[:fs - 1])
                restore['acc_from'] = log_acc(restore['acc_before'], full[fs - 1])
                restore['abandoned_heads'] = heads(log, restore['acc_from'], checkpoint_hash(work))
                tail = full[fs:]
            else:
                seg = heads(log, old['acc'], b['target_hash'])
                k = fs - old['seq'] if type(fs) is int else 0
                restore['forward_heads'], tail = seg[:k], seg[k:]
                restore['acc_from'] = fold(old['acc'], seg[:k])
            proofs = {**growth(work, t, skip=log), log: tail}
            code, recorded = judge(work, t, restore=restore, proofs=proofs, known=known)
            need(code == 'ok' and recorded == line['id'], WALK_CODES.get(code, 'chain_diverged'), 409)
            for item in line['revocations']:
                stronger(learned, item['revocation'])
            signers.append(b['cert']['o']['device_id'])
            dev['applied'].append(line['id'])
            work = t
        if page['next'] is None:
            break
        after = int(page['next'])
    result = 'ok'
    if work is None or checkpoint_hash(work) != end_hash:
        code, _ = judge(work, end, proofs=growth(work, end) if not work or end['o']['n'] > work['o']['n'] else {})
        if code == 'ignored' and work is dev['held']:
            result = 'ignored'  # a lagging relay: keep H, never downgrade
        else:
            need(code == 'ok', WALK_CODES.get(code, 'chain_diverged'), 409)
            work = end
    for d, rev in learned.items():
        # A compromised revocation first learned after its device's transition was judged: history stays,
        # the device raises an alarm (P3-D24).
        if rev['o']['reason'] == 'compromised' and d in signers and d not in dev['alarms']:
            dev['alarms'].append(d)
    dev['held'], dev['revocations'] = work, learned
    return {'result': result, 'device': dev}


def contract(state):
    """The state a refusal must leave unchanged; the failure budget alone is charged by refusals."""
    return {k: v for k, v in state.items() if k != 'failures'}


def dispatch(S, state, op, body=None, now_ms=0, **args):
    if op == 'publish':
        # Charged even on refusal, so an invalid final request cannot be repeated without limit (review 3).
        state['failures'] = [t for t in state.get('failures', []) if t > now_ms - HOUR]
        if len(state['failures']) >= FAILURE_BUDGET:
            return {'status': 429, 'error': 'quota_exceeded'}
    result = _dispatch(S, state, op, body, now_ms, **args)
    if op == 'publish' and result['status'] >= 400:
        state['failures'].append(now_ms)
    return result


def _dispatch(S, state, op, body, now_ms, **args):
    trial = copy.deepcopy(state)
    try:
        wire = None
        if isinstance(body, (str, bytes)):
            raw = body.encode() if isinstance(body, str) else body
            cap = REQUEST_CAPS.get(op, 65536)
            need(len(raw) <= cap, 'too_large', 400 if op == 'publish' else 413)
            body = R.parse_json(raw)
            wire = raw
        if op == 'genesis':
            result = genesis(S, trial, body, now_ms)
        elif op in ('page', 'manifest'):
            result = staging(trial, body, now_ms, wire=wire, **args)
        elif op == 'owner_policy':
            owner_policy(S, trial, body, now_ms, historical=args.get('historical', False))
            result = {}
        elif op == 'publish':
            result = publish(S, trial, body, now_ms)
        elif op in ('get', 'proof', 'transitions'):
            result = read(trial, op, args, now_ms)
        elif op in ('baseline', 'baseline_delete'):
            result = baseline(trial, body, now_ms, op == 'baseline_delete', args.get('role', 'host'))
        elif op == 'device_sync':
            result = sync_walk(S, body, trial, now_ms, args.get('endpoint'))
        else:
            raise ValueError('unknown operation')
    except Refusal as exc:
        return exc.result
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return {'status': 400, 'error': 'malformed'}
    state.clear(); state.update(trial)
    return {'status': 200, **result}
