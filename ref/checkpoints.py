"""P3-D12/13/18–25 checkpoint relay contract; test support, never server code.

State is JSON-portable. dispatch preflights on a copy and commits only a success.
F1 event/checkpoint encodings and the receiver are pinned to orch-core 8a07c5ab (#397: revocations per
(device, person), on top of #387 and #377).
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
# Across holder generations: a WSK holder may always take over (P3-D10), so takeovers are not rate limited;
# instead refusals are bounded per workspace-hour, and each new generation still gets its own slice (review F1).
WORKSPACE_FAILURE_CEILING = 48
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
    try:
        return int(datetime.fromisoformat(at.replace('Z', '+00:00')).timestamp() * 1000)
    except ValueError as exc:  # an impossible calendar date is malformed, not a crash
        raise Refusal('malformed', 400) from exc


def integer(n, minimum=0):
    need(type(n) is int and minimum <= n <= R.MAX_SAFE_INT)


def entries(cp):
    return {'workspace': cp['o']['workspace_log'], **cp['o']['tickets']}


def reference(cp):
    return {'n': cp['o']['n'], 'hash': checkpoint_hash(cp)} if cp else None


def initial(ws, wsk_pub, owner_pk, delegation, members, registry, person_keys):
    """registry is the relay's global device registry (device -> person, §19.1/§6.2) and person_keys its
    account keys (person -> pk_pub). Both are live directory state, read at check time. Every member device
    must be registered; nothing defaults (review F3)."""
    owner_person = delegation['o']['owner_person_id']
    need(all(d in registry for d in members) and person_keys.get(owner_person) == owner_pk)
    return {'ws': ws, 'wsk_pub': wsk_pub, 'owner_pk': owner_pk, 'delegation': delegation,
            'members': members, 'registry': dict(registry), 'person_keys': dict(person_keys),
            'bound': {}, 'global_revocations': {}, 'generation': 1,
            'ever_devices': sorted(members), 'revocations': {}, 'genesis': None, 'held': None,
            'checkpoints': {}, 'gone': [], 'nodes': {}, 'staging': {}, 'transitions': [],
            'baselines': {}, 'receipts': {}, 'failures': []}


def held_pair(state, device, person):
    """Does the relay hold a revocation of this (device, person) pair: this workspace's chain pairs or the global
    (§19.5) set? Signer refusal is per pair (orch-core #397): another person's revocation of the id is not one."""
    key = device + ':' + person
    return key in state['revocations'] or key in state['global_revocations']


def owner(S, state, cert, now, extra=()):
    # Every held revocation of the signer's (device, person) pair refuses it, at the relay and at a historical
    # receiver alike (review 1, orch-core #397); `extra` are device ids the bundle itself lists (self-revocation,
    # refused by device id whatever the person).
    o = cert.get('o') if isinstance(cert, dict) else None
    device, person = (o.get('device_id'), o.get('person_id')) if isinstance(o, dict) else (None, None)
    revoked = {device} if isinstance(device, str) and (device in set(extra) or (
        isinstance(person, str) and held_pair(state, device, person))) else set()
    checked = R.verify_cert(S, cert, R.unb64u(state['owner_pk']), now, revoked)
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


def authority(state, device):
    """The association of a device (orch-core #397 known_devices at the relay): the live §19.1 registry, written
    under the person's account key, or a restore signer this relay verified. Restore evidence never writes either."""
    return state['registry'].get(device) or state['bound'].get(device)


def known_holder(state, device):
    """(person_id, pk_pub or None) the relay associates with a device, or None for a device without association.

    Only associations bind the identity of carried evidence (orch-core #397): held revocations, this workspace's
    chain pairs and the global set alike, bind nothing (a tombstone is evidence, not an association), so another
    person's entry for a tombstoned or unknown device id is a new pair. The key is the directory account key when
    known; person_id = H(pk_pub) binds any evidence key to the person anyway. Strict: the association maps are
    required state, read at check time (review F3)."""
    person = authority(state, device)
    return (person, state['person_keys'].get(person)) if person is not None else None


def chain_revoked(state, device):
    """Any chain-learned revocation of this device id, whatever the person: this model's chain pairs (the relay's
    `checkpoint_revocations`, recorded by accepted restores). Out-of-band (global-only) pairs are not chain-learned."""
    prefix = device + ':'
    return any(k.startswith(prefix) for k in state['revocations'])


def register_device(state, body):
    """The global registry's first-writer-wins registration (G1), as far as checkpoints need it (P3-D30, orch-52
    rulings 2 and 4). route 'device_put' is PUT /v2/devices/{device}, 'account' is POST /v2/accounts (which also
    records the new person's account key).

    A NEW registration (no registry row, and always for 'account') is 403 revoked when any chain-learned revocation
    of the id exists, of any person, or when the new pair itself is revoked; out-of-band evidence of another person
    alone never refuses it. A registered device is cut off per pair, under its registry person (never the request's).
    Then 'account' refuses a person who already has an account (409 account_exists), and another person's device is
    409 cert_conflict. This keeps the registry from ever contradicting a chain pair (the F1 §5.10 stranding limit)."""
    route = body.get('route', 'device_put')
    need(set(body) == ({'device_id', 'person_id'} if route == 'device_put' else
                       {'device_id', 'person_id', 'route', 'pk_pub'}) and route in ('device_put', 'account'))
    d, person = body['device_id'], body['person_id']
    registered = state['registry'].get(d)
    if registered is None or route == 'account':
        need(not chain_revoked(state, d) and not held_pair(state, d, person), 'revoked', 403)
    else:
        need(not held_pair(state, d, registered), 'revoked', 403)
    if route == 'account':
        need(person not in state['person_keys'], 'account_exists', 409)
    need(registered in (None, person), 'cert_conflict', 409)
    state['registry'][d] = person
    if route == 'account':
        state['person_keys'][person] = body['pk_pub']
    return {}


def revocation_evidence(S, state, line, log):
    """F1 B1 entries, keyed by (device, person): unique and sorted by pair (orch-core #397). Evidence for a device
    the relay associates with a person (registry, earlier signer) must come from that person and its stored key, as
    F1's host restore does (review N1). A device without association is self-certified by each pair: two persons'
    entries for one such device are two pairs, both accepted (held revocations never bind)."""
    need(log == 'workspace' or line['revocations'] == [], 'restore_invalid', 409)
    listed = {}
    order = []
    for item in line['revocations']:
        need(set(item) == {'revocation', 'device_cert', 'pk_pub'}, 'restore_invalid', 409)
        pk = R.unb64u(item['pk_pub'])
        c = item['device_cert']['o']
        checked = R.verify_cert(S, item['device_cert'], pk, c['created_ms'])
        need('ok' in checked, 'restore_invalid', 409)
        rev = R.verify_revocation(S, item['revocation'], pk, checked['ok'])
        need('ok' in rev, 'restore_invalid', 409)
        pair = (rev['ok']['device_id'], rev['ok']['person_id'])
        holder = known_holder(state, pair[0]) if state is not None else None
        need(holder is None or (pair[1] == holder[0] and holder[1] in (None, item['pk_pub'])),
             'restore_invalid', 409)
        need(pair not in listed, 'restore_invalid', 409)
        order.append(pair); listed[pair] = item
    need(order == sorted(order), 'restore_invalid', 409)
    return listed


def revocation_coverage(state, listed, signer, log):
    """R4 completeness per (device, person) pair, from this workspace's own chain pairs only: each chain pair of a
    device in ever_devices or in this restore needs a carried entry of the same pair at the same or a stronger
    reason; another person's entry never stands in for it (orch-core #397)."""
    if log == 'workspace':
        devices = set(state['ever_devices']) | {d for d, _ in listed} | {signer}
        missing = set()
        for key, rev in state['revocations'].items():
            d, person = key.split(':')
            got = listed.get((d, person))
            if d in devices and (got is None or STRENGTH[got['revocation']['o']['reason']] < STRENGTH[rev['o']['reason']]):
                missing.add(d)
        need(not missing, 'restore_missing_revocation', 409, devices=sorted(missing))


def owner_policy(S, state, bundle, now, extra=(), historical=False):
    """P3-D24: historical receivers omit the relay-only current-list/current-clock checks.

    They never omit a revocation they already know: any known revocation of the signer, of any reason
    and whatever its revoked_ms, refuses (review 1). "Later" knowledge is defined by the receiver's own
    commit order (sync_walk), never by the host-chosen line.at."""
    line = bundle['line']
    if historical:
        # Internal evidence is mandatory even when relay-local completeness is irrelevant.
        listed = revocation_evidence(S, state, line, 'ticket' if 'ws_seq' in line else 'workspace')
        extra = set(extra) | {d for d, _ in listed}
    cert = owner(S, state, bundle['cert'], timestamp(line['at']), extra)
    if not historical:
        owner(S, state, bundle['cert'], now, extra)
        need('operate' in state['members'].get(cert['device_id'], []), 'restore_not_owner', 409)
    authz = bundle['authz']
    need(set(authz) == {'delegation'}, 'restore_not_owner', 409)
    # Card binding: the delegation's content is the card's (orch-52 24305776: an owner re-signing the same
    # content is the same delegation), and it verifies under the owner PK.
    need(isinstance(authz['delegation'], dict) and authz['delegation'].get('o') == state['delegation']['o'] and
         'ok' in R.verify_delegation(S, authz['delegation'], R.unb64u(state['owner_pk'])), 'restore_not_owner', 409)
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
    cert = owner_policy(S, state, bundle, now, {d for d, _ in listed})
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
    for (d, person), item in listed.items():
        rev, key = item['revocation'], d + ':' + person
        # Restore evidence never registers its device (no first-come association, orch-core #397): it is retained
        # per pair, globally (§19.5 intake, upgrade only) and as this workspace's chain pair (monotonic).
        for store in (state['global_revocations'], state['revocations']):
            if key not in store or STRENGTH[rev['o']['reason']] > STRENGTH[store[key]['o']['reason']]:
                store[key] = rev
    state['bound'][cert['device_id']] = cert['person_id']
    state['ever_devices'] = sorted(set(state['ever_devices']) | {d for d, _ in listed} | {cert['device_id']})
    state['transitions'].append({'restore_id': line['id'], 'source_hash': body['source_hash'],
                                 'target_hash': checkpoint_hash(target), 'target_n': target['o']['n'], **bundle})
    if held:
        state['checkpoints'][checkpoint_hash(held)]['permanent'] = True
    return log


def publish(S, state, body, now):
    need(len(R.cj(body)) <= REQUEST_CAP, 'too_large', 400)
    need(set(body) in ({'checkpoint', 'source_hash'}, {'checkpoint', 'source_hash', 'restore'}))
    receipt = digest(R.cj(body))
    if receipt in state['receipts']:
        return state['receipts'][receipt]  # an exact retry is served even when the budget is spent (N5)
    need(sum(1 for g, _ in state['failures'] if g == state['generation']) < FAILURE_BUDGET and
         len(state['failures']) < WORKSPACE_FAILURE_CEILING, 'quota_exceeded', 429)
    target = body['checkpoint']
    validate_checkpoint(S, state, target)
    h = checkpoint_hash(target)
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


def baseline(state, body, now, delete=False, role=None):
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
# judge_offer ports orch-core 8a07c5ab (#397) store/checkpoints.judge_offer with the relay's primitives and
# returns F1's codes, so F1's transition_cases/workspace_n_offers run against it unchanged.
# ---------------------------------------------------------------------------------------------
DIVERGED, INCOMPLETE, FUTURE = 'chain.diverged', 'sync.incomplete', 'checkpoint.future'
SKEW = 300000
CP_FIELDS = {'v', 'suite', 'kind', 'workspace_id', 'genesis', 'n', 'at', 'workspace_log', 'tickets'}
WALK_CODES = {DIVERGED: 'chain_diverged', INCOMPLETE: 'sync_incomplete', 'trust.genesis_mismatch': 'genesis_mismatch',
              FUTURE: 'checkpoint_time', 'ignored': 'chain_diverged'}


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


def offer_ok(S, o):
    """The §5.10 workspace checkpoint `o` shape: exact fields, strict timestamp, n >= 1, entry shapes."""
    try:
        if not (isinstance(o, dict) and set(o) == CP_FIELDS and o['v'] == 2 and o['suite'] == S.id and
                o['kind'] == 'workspace_checkpoint' and re.fullmatch(r'[0-9a-f]{32}', o['workspace_id']) and
                isinstance(o['tickets'], dict)):
            return False
        integer(o['n'], 1); timestamp(o['at']); hash_bytes(o['genesis'])
        for uid in o['tickets']:
            need(re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}', uid))
        for entry in [o['workspace_log'], *o['tickets'].values()]:
            need(isinstance(entry, dict) and set(entry) == {'seq', 'head', 'acc'})
            integer(entry['seq'], 1); hash_bytes(entry['head']); hash_bytes(entry['acc'])
        return True
    except (Refusal, KeyError, TypeError, AttributeError):
        return False


def verdict(code, recorded=None, alarms=(), unpublished=(), pairs=(), evidence=()):
    """orch-core's Verdict as a tuple: (code, restore_id, alarms, unpublished, unpublished_pairs,
    unpublished_evidence)."""
    return code, recorded, alarms, unpublished, pairs, evidence


def pair_of(item):
    """The (device_id, person_id) key of a held or carried revocation entry, bare hex (orch-core #397)."""
    o = item['revocation']['o']
    return o['device_id'], o['person_id']


def pair_key(item):
    """The JSON-portable key of a pair in device and relay state: 'device_id:person_id'."""
    return ':'.join(pair_of(item))


def same_or_stronger(got, held):
    """`got` carries `held`'s pair under the same person key (where `held` names one), at equal or greater strength."""
    return (('pk_pub' not in held or got['pk_pub'] == held['pk_pub']) and
            STRENGTH[got['revocation']['o']['reason']] >= STRENGTH[held['revocation']['o']['reason']])


def judge_offer(S, held, offered, *, genesis, workspace_id, now, wsk_pub, known_devices, known, local, learned_later,
                restore=None, applied=(), proofs=None, card=None, initial_proof=False):
    """held/offered are checkpoint `o` objects; now is the receiver clock in ms.
    Returns (code, recorded id, alarms, unpublished, unpublished_pairs, unpublished_evidence), orch-core's Verdict.

    Ports orch-core judge_offer at 8a07c5ab (#397), F1 codes included. Like F1's ReceiverView, every view field is
    required (B1): known_devices ({device_id: {person_id, pk_pub?}}, workspace associations; {} says the receiver
    knows no device), known (the chain-learned revocations held when judging: signer refusal and per-pair
    completeness), local (every other verified revocation held when judging, out of band: signer refusal only; never
    filtered) and learned_later (revocations first learned after this judgment: never refuse; a compromised one of an
    accepted restore's signer pair is reported in alarms, C3). Entries of known/local/learned_later are
    {revocation, pk_pub?, ...}; further fields (device_cert, provenance) are ignored here. Every held revocation is
    keyed by (device, person): it refuses the signer only when it names the signer's pair, whatever known_devices
    says. Only known_devices binds the identity of carried entries (held revocations bind nothing). An accepted
    workspace restore reports the local pairs it does not carry under the same person key at equal or greater
    strength (revocation.unpublished, non-blocking), leaving out the signer's device and devices whose known
    association names another person: unpublished_pairs (sorted ('d_…', 'p_…')), unpublished (their d_ hints) and
    unpublished_evidence (per pair, the strongest held entry, the first on a tie). Relay addition: initial_proof
    (full proof from acc_0 for a first checkpoint, where F1 accepts it without ancestry). The walk passes the
    pairing-pinned owner PK as restore['pk_pub']."""
    if not offer_ok(S, offered):
        return verdict(DIVERGED)
    if offered['genesis'] != genesis:
        return verdict('trust.genesis_mismatch')
    if offered['workspace_id'] != workspace_id or (held and held['workspace_id'] != workspace_id):
        return verdict(DIVERGED)
    h = {'workspace': held['workspace_log'], **held['tickets']} if held else {}
    o = {'workspace': offered['workspace_log'], **offered['tickets']}
    proofs = {} if proofs is None else proofs
    if held and offered['n'] == held['n']:
        return verdict('ok' if offered == held else DIVERGED)
    if held and offered['n'] < held['n']:
        bad = any(k not in h or v['seq'] > h[k]['seq'] or (v['seq'] == h[k]['seq'] and v != h[k]) for k, v in o.items())
        return verdict(DIVERGED if bad else 'ignored')
    if timestamp(offered['at']) > now + SKEW:
        return verdict(FUTURE)
    if held and (offered['at'] < held['at'] or h.keys() - o.keys()):
        return verdict(DIVERGED)
    if not isinstance(proofs, dict):
        return verdict(INCOMPLETE)
    restored = None
    if restore is not None:
        code, restored = judge_restore(S, held, offered, h, o, restore, proofs, genesis, applied, wsk_pub,
                                       known, local, card, known_devices)
        if code != 'ok':
            return verdict(code)
    if held is None and restore is None and not initial_proof:
        return verdict('ok')
    for log, entry in o.items():
        if restored and log == restored[0]:
            continue
        old = h.get(log, EMPTY)
        if entry['seq'] < old['seq'] or (entry['seq'] == old['seq'] and entry != old):
            return verdict(DIVERGED)
        heads = proofs.get(log, [])
        if not extension(old, entry, heads):
            return verdict(INCOMPLETE)
        if initial_proof and log == 'workspace' and old['seq'] == 0 and heads[0] != genesis:
            return verdict(INCOMPLETE)
    if not restored:
        return verdict('ok')
    _, restore_id, signer, signer_person, reported = restored
    # C3: learned after the judgment, a compromised revocation of the signer pair alarms, never refuses.
    alarms = tuple(sorted({'d_' + signer for later in learned_later
                           if pair_of(later) == (signer, signer_person) and
                           later['revocation']['o']['reason'] == 'compromised'}))
    pairs = tuple(key for key, _ in reported)
    hints = tuple(sorted({d for d, _ in pairs}))
    return verdict('ok', restore_id, alarms, hints, pairs, tuple(item for _, item in reported))


def judge_restore(S, held, offered, h, o, restore, proofs, genesis, applied, wsk_pub, known, local, card,
                  known_devices):
    """The restore half of judge_offer: ('ok', (log, id, signer, signer person, reported)) or (code, None)."""
    diverged = DIVERGED, None
    try:
        ev, log, c, target = restore['event'], restore['log'], restore['C'], restore['T']
        wsk = R.unb64u(wsk_pub)
        if len(R.cj(ev)) + 1 > LINE_CAP:
            return diverged  # bounded before any signature check, T's included (orch-core #397)
        if target['o'] != offered or R.verify_object(S, wsk, target, 'workspace_checkpoint') is None:
            return diverged
        restore_shape(ev)
        if (log == 'workspace') != ('ws_seq' not in ev):
            return diverged
        # Source binding (R2-equivalent): the person-signed source is exactly the held checkpoint.
        if ev['id'] in applied or ev['source'] != reference(c):
            return diverged
        if (held is None) != (c is None) or (held is not None and c['o'] != held):
            return diverged
        if c and R.verify_object(S, wsk, c, 'workspace_checkpoint') is None:
            return diverged
        # The delegation's content must be the pinned card's (orch-core #377), not any the PK signed.
        if not isinstance(card, dict) or not isinstance(restore['delegation'], dict) or \
                restore['delegation'].get('o') != card.get('o'):
            return diverged
        pk = R.unb64u(restore['pk_pub'])
        at_ms = timestamp(ev['at'])
        checked = R.verify_cert(S, restore['device_cert'], pk, at_ms)
        delegation = R.verify_delegation(S, restore['delegation'], pk)
        if 'ok' not in checked or 'ok' not in delegation:
            return diverged
        cert, delegation = checked['ok'], delegation['ok']
        if (delegation['workspace_id'] != offered['workspace_id'] or delegation['wsk_pub'] != wsk_pub or
                ev['actor']['id'] != 'p_' + delegation['owner_person_id'] or
                ev['actor']['id'] != 'p_' + cert['person_id'] or ev['actor']['device'] != 'd_' + cert['device_id'] or
                'operate' not in cert['scopes_max'] or any(x.startswith('drop:') for x in cert['scopes_max'])):
            return diverged
        ws = offered['workspace_id']
        if not S.verify(R.unb64u(cert['dk_sig_pub']), R.unb64u(ev['sig']), event_bytes(S, ev, ws, log)):
            return diverged
        if not S.verify(wsk, R.unb64u(ev['host_sig']), event_bytes(S, ev, ws, log, True)):
            return diverged
        # C.o.at <= line.at <= T.o.at
        if (c is not None and ev['at'] < c['o']['at']) or ev['at'] > offered['at']:
            return diverged
        if log != 'workspace' and ev['ws_seq'] > offered['workspace_log']['seq']:
            return diverged
        # Verified, unique and sorted per (device, person) (orch-core #397); the device binds identity below.
        carried = {pair_of(item): item for item in revocation_evidence(S, None, ev, log).values()}
        signer, signer_person = cert['device_id'], cert['person_id']  # the delegation owner (checked above)
        if any(d == signer for d, _ in carried):
            return diverged  # the bundle revokes its own signer's device id: a log-free receiver cannot place it
        # Evidence identity (F1 §5.10, orch-core #397): a carried entry for a device in known_devices (a workspace
        # association, active or revoked) is of its person and stored key. Held revocations, chain-learned or out of
        # band, impose no identity constraint: an extra carried pair is harmless (refusal, completeness and reporting
        # are all per pair).
        for (d, _), got in carried.items():
            kd = known_devices.get(d)
            if kd is not None and (got['revocation']['o']['person_id'] != kd['person_id'] or
                                   (kd.get('pk_pub') is not None and got['pk_pub'] != kd['pk_pub'])):
                return diverged
        # C3: a held revocation of the signer pair, chain-learned or out of band, refuses at any reason and any
        # host-chosen position, whatever known_devices says; another person's revocation of the id never does.
        if any(pair_of(k) == (signer, signer_person) for k in [*known, *local]):
            return diverged
        if log == 'workspace':  # completeness: every chain-learned pair, same person key, at its strength
            for item in known:
                got = carried.get(pair_of(item))
                if got is None or not same_or_stronger(got, item):
                    return diverged
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
                return diverged
        if log == 'workspace' and ev['from_seq'] == 1 and (ev['head'] != genesis or acc != log_acc(ZERO, genesis)):
            return INCOMPLETE, None
        tail = proofs.get(log)
        if not isinstance(tail, list) or not tail or log not in o or not extension(retained, o[log], tail):
            return INCOMPLETE, None
        # A consistent proof whose first head is another event: T is signed over another head (orch-core #377).
        if tail[0] != event_head(ev):
            return diverged
        reported = {}
        if log == 'workspace':  # out-of-band pairs the accepted restore does not carry at their strength
            for item in local:
                d, person = pair_of(item)
                kd = known_devices.get(d)
                if d == signer or (kd is not None and kd['person_id'] != person):
                    # not reported (still retained and enforced): the signer's device, whose association this
                    # restore's certificate establishes, or a device whose known association names another person
                    continue
                got = carried.get((d, person))
                if got is None or not same_or_stronger(got, item):
                    key = ('d_' + d, 'p_' + person)
                    have = reported.get(key)
                    if have is None or STRENGTH[item['revocation']['o']['reason']] > STRENGTH[have['revocation']['o']['reason']]:
                        reported[key] = item  # the strongest held entry of the pair, the first on a tie
        return 'ok', (log, ev['id'], signer, signer_person, tuple(sorted(reported.items())))
    except (KeyError, TypeError, ValueError, IndexError, AttributeError, Refusal):
        return diverged


# Per-walk ceiling on proof heads a device fetches (review L3): WSK-signed heights alone are not a bound.
DEVICE_MAX_HEADS = 1 << 22


def device_initial(ws, wsk_pub, owner_pk, genesis, card, devices, held=None):
    """A paired device: pairing-pinned owner PK, WSK, genesis and card delegation; held is its verified baseline or
    None. devices ({device_id: {person_id, pk_pub?}}) are this workspace's associations as the device knows them
    (orch-core #397 known_devices): the pairing member list, then applied restore signers. Restore evidence never
    adds one (a tombstone is evidence, not an association).

    Revocations (F1 §5.10 at orch-core 8a07c5ab, #397), every store keyed by pair 'device_id:person_id':
    `revocations` are chain-learned for this workspace, each {revocation, device_cert, pk_pub, provenance}: the
    strongest reason whose occurrence (an accepted restore's entry) the device authenticated against this workspace's
    accepted history; provenance names that occurrence (checkpoint n and hash, log, event id, seq, head and
    accumulator node), never a height alone. They are monotonic and sticky: later restores, abandoned suffixes and
    failed walks never remove them, and out-of-band evidence never replaces or demotes them. `local` is every
    other verified revocation (device_learn, another workspace, a failed walk), each {revocation, device_cert,
    pk_pub} verified under the named person's key, with its own strongest reason; a stronger out-of-band reason of a
    chain pair is tracked here beside it. Both refuse a signer of the same pair; only chain-learned ones are demanded
    as restore evidence; neither binds the identity of carried entries. `local` is capped (make_room), never by
    refusing a walk. `forward` lists pairs an accepted workspace restore did not carry (revocation.unpublished)
    whose device this workspace associates with the same person: the runtime forwards them to the host and retries
    until an accepted restore carries them at that strength (an acknowledgement is not publication). `pending` holds
    the pairs of devices without association (unknown, or known only through tombstones): kept, never forwarded.
    `signers` records each applied transition's signer device and person, across walks; `alarms` the C3 alarms."""
    return {'ws': ws, 'wsk_pub': wsk_pub, 'owner_pk': owner_pk, 'genesis': genesis, 'card': card, 'held': held,
            'devices': dict(devices), 'applied': [], 'signers': {}, 'revocations': {}, 'local': {}, 'alarms': [],
            'forward': [], 'pending': []}


def card_owner(dev):
    return ((dev.get('card') or {}).get('o') or {}).get('owner_person_id')


def signer_pairs(dev):
    """The committed signer pairs (device, person). A restore signer is always the card's owner (P3-D23: the judge
    requires actor = delegation owner = certificate person), so a round-2 record (a bare device id) resolves its
    person to the pinned card's owner first, then through the known devices; an unresolvable one yields no pair
    (F1 §5.10, orch-core #397)."""
    owner = card_owner(dev)
    devices = dev.get('devices', {})
    pairs = set()
    for s in dev['signers'].values():
        d = s if isinstance(s, str) else s['device']
        person = None if isinstance(s, str) else s.get('person_id')
        person = person or owner or (devices.get(d) or {}).get('person_id')
        if person:
            pairs.add((d, person))
    return pairs


def raise_alarms(dev, revocations):
    """P3-D24, F1 row 150: a compromised revocation of a committed signer pair (device and person) raises the
    alarm. revocations are revocation objects. Matching by device alone would let any keypair holder raise a false C3
    alarm; an unresolvable legacy signer raises none (its evidence is still kept)."""
    for d, person in sorted(signer_pairs(dev)):
        if d not in dev['alarms'] and any(
                r['o']['reason'] == 'compromised' and r['o']['device_id'] == d and r['o']['person_id'] == person
                for r in revocations):
            dev['alarms'].append(d)


def evidence_ok(S, item):
    """Protocol §6.2: a {revocation, device_cert, pk_pub} item verifies under the person key it names, against a device
    certificate of that same person (verify_cert binds person_id = H(pk_pub)). Returns the device id or None."""
    try:
        if not isinstance(item, dict) or set(item) - {'provenance'} != {'revocation', 'device_cert', 'pk_pub'}:
            return None
        pk = R.unb64u(item['pk_pub'])
        checked = R.verify_cert(S, item['device_cert'], pk, item['device_cert']['o']['created_ms'])
        rev = R.verify_revocation(S, item['revocation'], pk, checked['ok']) if 'ok' in checked else {}
        return rev['ok']['device_id'] if 'ok' in rev else None
    except (KeyError, TypeError, ValueError, AttributeError, IndexError, Refusal):
        return None


# Held out-of-band evidence caps (F1 §5.10 runtime requirements, orch-core #397): per person (members included; the
# pinned card owner is exempt), per device id and in total. A walk also harvests at most MAX_HELD_EVIDENCE entries,
# from lines within LINE_CAP, before any signature check.
MAX_PERSONS_PER_DEVICE = 8
MAX_ENTRIES_PER_PERSON = 64
MAX_HELD_EVIDENCE = 4096


def member_persons(dev):
    """The current or past workspace members as the device knows them now: the persons of its associations and the
    card owner. Read at eviction time, never frozen when evidence was stored."""
    return {kd['person_id'] for kd in dev['devices'].values()} | {card_owner(dev)} - {None}


def make_room(dev, key):
    """May a new local entry for pair `key` be stored (evicting to make room)? Never refuses a walk.
    - Per person: at most MAX_ENTRIES_PER_PERSON local entries, members included; over it the new entry is dropped.
      The pinned card owner is exempt, so a genuine owner revocation is never dropped.
    - Per device id (MAX_PERSONS_PER_DEVICE) and in total (MAX_HELD_EVIDENCE): a new non-member entry never evicts
      anything and is dropped when the cap is full; a member's entry evicts the oldest non-member entry in scope
      (never a chain-learned pair's), and is kept over the cap when there is none (it is bounded per person)."""
    d, person = key.split(':')
    members = member_persons(dev)
    if person != card_owner(dev) and sum(
            1 for k in dev['local'] if k.split(':')[1] == person) >= MAX_ENTRIES_PER_PERSON:
        return False
    for in_scope, cap in ((lambda k: k.split(':')[0] == d, MAX_PERSONS_PER_DEVICE), (lambda k: True, MAX_HELD_EVIDENCE)):
        scoped = [k for k in dev['local'] if in_scope(k)]
        if len(scoped) < cap:
            continue
        if person not in members:
            return False
        victims = [k for k in scoped if k.split(':')[1] not in members and k not in dev['revocations']]
        if victims:
            del dev['local'][victims[0]]  # the oldest: local keeps arrival order
    return True


def admit_local(S, dev, item):
    """Store verified out-of-band evidence in dev['local'] under its pair (strongest reason kept, F1 §5.10). Every
    verified revocation is retained per pair whatever the associations say; only the caps can drop a new one.
    Evidence that does not verify is never an input. Returns whether the pair is held."""
    if evidence_ok(S, item) is None:
        return False
    key = pair_key(item)
    old = dev['local'].get(key)
    if old is None and not make_room(dev, key):
        return False
    if old is None or STRENGTH[item['revocation']['o']['reason']] > STRENGTH[old['revocation']['o']['reason']]:
        dev['local'][key] = {k: item[k] for k in ('revocation', 'device_cert', 'pk_pub')}
    return True


def device_learn(S, dev, item):
    """Out-of-band evidence {revocation, device_cert, pk_pub} (the relay's feed, another workspace, the owner).
    Verified and retained here under its pair, never trusted from the caller. Alarms at once, independent of any
    sync, so a relay that fails every walk cannot suppress it (review F6). `admitted` is false only when a cap
    drops it."""
    dev = copy.deepcopy(dev)
    need(evidence_ok(S, item) is not None, 'malformed', 400)
    admitted = admit_local(S, dev, item)
    raise_alarms(dev, held_evidence(dev))
    return {'device': dev, 'admitted': admitted}


def held_evidence(dev, learned=None):
    """Every verified revocation object the device holds: chain-learned and local (alarms, C3)."""
    chain = dev['revocations'] if learned is None else learned
    return [x['revocation'] for x in [*chain.values(), *dev['local'].values()]]


def chain_learn(learned, item, provenance):
    """A chain occurrence of verified evidence, per pair: the strongest reason wins, an equal one keeps its first
    occurrence. Sticky: nothing ever removes or demotes it."""
    key = pair_key(item)
    old = learned.get(key)
    if old is None or STRENGTH[item['revocation']['o']['reason']] > STRENGTH[old['revocation']['o']['reason']]:
        learned[key] = {'revocation': item['revocation'], 'device_cert': item['device_cert'], 'pk_pub': item['pk_pub'],
                        'provenance': provenance}


def keep_failed_walk(S, committed, seen):
    """F1 rows 149/150: a walk that fails commits nothing (no H, applied id, signer or chain provenance), but every
    revocation it verified stays as local evidence, retained per pair in walk order; a compromised one of the signer
    of an already committed transition raises and persists the alarm. Alarms about the uncommitted transitions are
    dropped."""
    kept = copy.deepcopy(committed)
    for item in seen:
        admit_local(S, kept, item)
    raise_alarms(kept, held_evidence(kept))
    return kept


def sync_walk(S, dev, relay, now, endpoint=None, script=None, max_heads=None):
    """§19.8 device synchronisation against an immutable endpoint E. relay is read only through the public GET routes.
    The walk commits only after it verifies completely, in one atomic replacement of the device state (judgments as
    applied ids and signers, walk position H, chain evidence with provenance, local evidence, forwarding, alarms). A
    refusal commits none of that; it only keeps the evidence the walk verified and the alarms it causes (F1 rows
    149/150), returned as `device` with the refusal when anything changed."""
    committed, seen = dev, []
    try:
        return _walk(S, copy.deepcopy(dev), relay, now, endpoint, script, max_heads, seen)
    except (Refusal, KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
        failure = exc if isinstance(exc, Refusal) else Refusal('malformed', 400)
        kept = keep_failed_walk(S, committed, seen)
        if kept != committed:
            failure.result['device'] = kept
        raise failure from (None if failure is exc else exc)


def _walk(S, dev, relay, now, endpoint, script, max_heads, seen):
    ws, genesis = dev['ws'], dev['genesis']
    budget = [DEVICE_MAX_HEADS if max_heads is None else max_heads]
    # A scripted relay (vectors only): queued responses per read op served before the real ones.
    script = copy.deepcopy(script or {})

    def get(op, **args):
        if script.get(op):
            return script[op].pop(0)
        try:
            return read(relay, op, args, now)
        except Refusal as exc:
            if exc.result['error'] == 'checkpoint_gone':
                raise  # restart with a new E; H unchanged
            raise Refusal('sync_incomplete', 409) from exc  # missing evidence, never re-pairing

    def fetch(h):
        cp = get('get', hash=h)['checkpoint']
        # Hash-addressed objects are bound to their hash, the WSK signature and the workspace.
        need(checkpoint_hash(cp) == h, 'chain_diverged', 409)
        need(R.verify_object(S, R.unb64u(dev['wsk_pub']), cp, 'workspace_checkpoint') is not None,
             'chain_diverged', 409)
        return cp

    def heads(log, start, to, cap):
        # Bounded by the signed heights and by the device's own per-walk ceiling (review L3).
        need(cap <= budget[0], 'sync_incomplete', 409)
        out = []
        while True:
            page = get('proof', log=log, to=to, **{'from': start})
            need(page['heads'] or page['next'] is None, 'sync_incomplete', 409)
            out += page['heads']
            need(len(out) <= cap, 'sync_incomplete', 409)
            if page['next'] is None:
                budget[0] -= len(out)
                return out
            start = page['next']

    def growth(work, x, skip=None):
        old = entries(work) if work else {}
        return {log: heads(log, old.get(log, EMPTY)['acc'], checkpoint_hash(x), e['seq'] - old.get(log, EMPTY)['seq'])
                for log, e in entries(x).items() if log != skip and e['seq'] > old.get(log, EMPTY)['seq']}

    def judge(work, x, **kw):
        # One transition against the serialized snapshot: chain evidence of the bundles accepted so far in this walk
        # and before it, and the local evidence. The walk raises C3 alarms itself, across walks (raise_alarms).
        return judge_offer(S, work['o'] if work else None, x['o'], genesis=genesis, workspace_id=ws, now=now,
                           wsk_pub=dev['wsk_pub'], applied=dev['applied'], card=dev['card'], initial_proof=True,
                           known_devices=dev['devices'], known=list(learned.values()),
                           local=list(dev['local'].values()), learned_later=(), **kw)

    def refuse_unless(code, wanted):
        need(code == wanted, WALK_CODES.get(code, 'chain_diverged'), 409)

    top = get('get', **({'hash': endpoint} if endpoint else {}))
    end = fetch(checkpoint_hash(top['checkpoint']))
    if endpoint:
        need(checkpoint_hash(end) == endpoint, 'chain_diverged', 409)
    end_hash = checkpoint_hash(end)
    work = dev['held']
    learned = copy.deepcopy(dev['revocations'])  # monotonic: only ever grows or strengthens
    flagged = set()
    harvest = [MAX_HELD_EVIDENCE]
    after = work['o']['n'] if work else 0
    walked = False
    while work is None or end['o']['n'] > work['o']['n']:
        page = get('transitions', to=end_hash, after_n=after)
        for b in page['transitions']:
            need(isinstance(b, dict) and set(b) == BUNDLE_FIELDS and b['restore_id'] == b['line']['id'],
                 'chain_diverged', 409)
            # Evidence the walk verifies stays local evidence even if this bundle or the walk fails (F1 row 150).
            # Bounded before any signature check: the line within LINE_CAP, at most MAX_HELD_EVIDENCE per walk.
            line_ = b['line']
            listed = line_.get('revocations') if isinstance(line_, dict) else None
            if isinstance(listed, list) and len(R.cj(line_)) + 1 <= LINE_CAP:
                for item in listed[:harvest[0]]:
                    harvest[0] -= 1
                    if evidence_ok(S, item) is not None:
                        seen.append(item)
            # Ascending order and the E bound follow from T.n == target_n and each judged step (n grows,
            # and the final judge refuses a work state above E); they need no separate check.
            need(type(b['target_n']) is int, 'chain_diverged', 409)
            if b['source_hash'] is not None and (work is None or b['source_hash'] != checkpoint_hash(work)):
                # Prove the exact extension work -> B.source; a lower or equal source never qualifies.
                c = fetch(b['source_hash'])
                need(work is None or c['o']['n'] > work['o']['n'], 'chain_diverged', 409)
                refuse_unless(judge(work, c, proofs=growth(work, c))[0], 'ok')
                work = c
            t = fetch(b['target_hash'])
            need(t['o']['n'] == b['target_n'], 'chain_diverged', 409)
            line, log = b['line'], b['log']
            old = entries(work).get(log, EMPTY) if work else EMPTY
            fs = line['from_seq']
            restore = {'event': line, 'log': log, 'C': work, 'T': t, 'pk_pub': dev['owner_pk'],
                       'device_cert': b['cert'], 'delegation': b['authz']['delegation']}
            # Signatures, source binding, owner policy and revocations first; only then fetch proofs.
            refuse_unless(judge(work, t, restore=restore)[0], INCOMPLETE)
            top_seq = entries(t).get(log, EMPTY)['seq']
            if type(fs) is int and 1 <= fs < old['seq']:
                full = heads(log, ZERO, b['target_hash'], top_seq)
                need(len(full) > fs, 'sync_incomplete', 409)
                restore['acc_before'] = fold(ZERO, full[:fs - 1])
                restore['acc_from'] = log_acc(restore['acc_before'], full[fs - 1])
                restore['abandoned_heads'] = heads(log, restore['acc_from'], checkpoint_hash(work), old['seq'] - fs)
                tail = full[fs:]
            else:
                seg = heads(log, old['acc'], b['target_hash'], top_seq - old['seq'])
                k = fs - old['seq'] if type(fs) is int else 0
                restore['forward_heads'], tail = seg[:k], seg[k:]
                restore['acc_from'] = fold(old['acc'], seg[:k])
            proofs = {**growth(work, t, skip=log), log: tail}
            code, recorded, _, _, unpublished, _ = judge(work, t, restore=restore, proofs=proofs)
            refuse_unless(code, 'ok')
            need(recorded == line['id'], 'chain_diverged', 409)
            # The occurrence of every listed entry, authenticated in accepted history: T (WSK-signed, accepted) commits
            # event_head(line) at from_seq + 1 of `log`, reached from acc_from by the verified tail proof.
            head = event_head(line)
            provenance = {'checkpoint': reference(t), 'log': log, 'event': line['id'], 'seq': fs + 1, 'head': head,
                          'acc': log_acc(restore['acc_from'], head)}
            for item in line['revocations']:
                # A tombstone is evidence, not an association: no first-come known_devices entry (orch-core #397).
                chain_learn(learned, item, provenance)
            flagged.update(d[2:] + ':' + p[2:] for d, p in unpublished)
            signer = b['cert']['o']
            dev['signers'][line['id']] = {'device': signer['device_id'], 'person_id': signer['person_id']}
            dev['devices'].setdefault(signer['device_id'], {'person_id': signer['person_id'], 'pk_pub': dev['owner_pk']})
            dev['applied'].append(line['id'])
            work, walked = t, True
        if page['next'] is None:
            break
        # The cursor strictly advances and stays within E, so the paging loop is bounded by E.n.
        cursor = int(page['next'])
        need(page['transitions'] and after < cursor <= end['o']['n'], 'sync_incomplete', 409)
        after = cursor
    result = 'ok'
    if work is None or checkpoint_hash(work) != end_hash:
        code = judge(work, end, proofs=growth(work, end) if not work or end['o']['n'] > work['o']['n'] else {})[0]
        if code == 'ignored' and not walked:
            result = 'ignored'  # a lagging relay: keep H, never downgrade
        else:
            refuse_unless(code, 'ok')
            work = end
    # revocation.unpublished (F1 §5.10, per pair): retained across walks until an accepted restore carries the pair
    # at its local strength (then it is chain-learned: published). Reporting is not eligibility: forwarded only when
    # this workspace associates the device with the same person; a device without association (unknown, or known
    # only through tombstones) stays pending; a device associated with another person is never forwarded.
    forward, pending = [], []
    for key in sorted(set(dev['forward']) | set(dev['pending']) | flagged):
        item, chain = dev['local'].get(key), learned.get(key)
        if item is None or (chain is not None and
                            STRENGTH[chain['revocation']['o']['reason']] >= STRENGTH[item['revocation']['o']['reason']]):
            continue
        d, person = key.split(':')
        kd = dev['devices'].get(d)
        if kd is None:
            pending.append(key)
        elif kd['person_id'] == person:
            forward.append(key)
    dev['held'], dev['revocations'], dev['forward'], dev['pending'] = work, learned, forward, pending
    # P3-D24 / review N3: a compromised revocation of any device that signed an applied transition, in this walk or an
    # earlier one, raises an alarm; history stays valid. Idempotent across walks.
    raise_alarms(dev, held_evidence(dev, learned))
    return {'result': result, 'device': dev}


def contract(state):
    """The state a refusal must leave unchanged; only the failure budget and the holder generation move."""
    return {k: v for k, v in state.items() if k not in ('failures', 'generation')}


def dispatch(S, state, op, body=None, now_ms=0, **args):
    if op == 'publish':
        # The caller already passed W(g) authentication; `generation` is its Orch-Holder generation (required).
        gen = args.pop('generation', None)
        if type(gen) is not int:
            return {'status': 400, 'error': 'malformed'}
        if gen < state['generation']:
            return {'status': 409, 'error': 'fenced'}  # a stale holder is never charged to the new one
        state['generation'] = gen  # a newer generation gets its own 16; the workspace ceiling still binds
        state['failures'] = [f for f in state['failures'] if f[1] > now_ms - HOUR]
    result = _dispatch(S, state, op, body, now_ms, **args)
    if op == 'publish' and result['status'] >= 400 and result['error'] != 'quota_exceeded':
        # Charged even on refusal, so an invalid final request cannot be repeated without limit (review 3).
        state['failures'].append([state['generation'], now_ms])
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
            result = baseline(trial, body, now_ms, op == 'baseline_delete', args.get('role'))
        elif op == 'register_device':
            result = register_device(trial, body)
        elif op == 'device_learn':
            result = device_learn(S, body['device'], body['evidence'])
        elif op == 'device_sync':
            result = sync_walk(S, body, trial, now_ms, args.get('endpoint'), args.get('script'), args.get('max_heads'))
        else:
            raise ValueError('unknown operation')
    except Refusal as exc:
        return exc.result
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return {'status': 400, 'error': 'malformed'}
    state.clear(); state.update(trial)
    return {'status': 200, **result}
