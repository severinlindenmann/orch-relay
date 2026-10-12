"""P3-D31 vectors: retrieval of unpublished revocation evidence (suite 2 only).

Section `unpublished`: each case is a relay state plus steps, as `checkpoints_g4`, replayed by
tests/test_checkpoint_vectors.py against the reference model and the production relay. Steps use the
checkpoint ops plus `unpublished_get` ({query}: the exact HTTP query strings), `unpublished_ack` ({body}),
`notices` (host-poll `notices.unpublished`), `revoke` (POST /v2/revocations) and `restart` (a new relay process
on the same database). Every served item verifies on its own (U11.2, `verify_item`). Public FAKE seeds only.
Built after ref/_checkpoint_g4_vectors.py.
"""
import copy

from ref import checkpoints as C
from ref import orch_protocol_ref as R
from ref._checkpoint_vectors import NOW, at, replay

S = R.SUITES[2]


def verify_item(item):
    """U11.2, the host's independent check of one served item: the person id is the key's, the certificate verifies
    under the key at its own created_ms, the revocation verifies against that certificate, the fields match and the
    digest is the record's. Returns None or the first failure."""
    try:
        if set(item) != {'device_id', 'person_id', 'reason', 'revocation', 'device_cert', 'pk_pub', 'provenance',
                         'chain_reason'} or set(item['provenance']) != {'cursor', 'digest'}:
            return 'shape'
        pk = R.unb64u(item['pk_pub'])
        if R.person_id(S, pk).hex() != item['person_id']:
            return 'person_id'
        cert = R.verify_cert(S, item['device_cert'], pk, item['device_cert']['o']['created_ms'])
        if 'ok' not in cert or cert['ok']['device_id'] != item['device_id']:
            return 'device_cert'
        rev = R.verify_revocation(S, item['revocation'], pk, cert['ok'])
        if 'ok' not in rev:
            return 'revocation'
        o = rev['ok']
        if (o['device_id'], o['person_id'], o['reason']) != (item['device_id'], item['person_id'], item['reason']):
            return 'fields'
        if item['provenance']['digest'] != C.digest(R.cj(item['revocation'])):
            return 'digest'
        if item['chain_reason'] is not None and C.STRENGTH[item['chain_reason']] >= C.STRENGTH[item['reason']]:
            return 'chain_reason'
    except (KeyError, TypeError, ValueError, AttributeError):
        return 'malformed'
    return None


def add_unpublished(out):
    v = out['suites']['2']
    keys = {n: S.sig_key(bytes.fromhex(k['seed'])) for n, k in v['keys'].items() if n.endswith('.sig')}
    certs = v['certs']['signed']
    ws, ws_b = v['ids']['workspace_a'], v['ids']['workspace_b']
    alice, bob = v['ids']['person_alice'], v['ids']['person_bob']
    intruder_pk = bytes.fromhex(v['keys']['intruder.sig']['pub'])
    intruder = R.person_id(S, intruder_pk).hex()
    phone, laptop = certs['phone']['o']['device_id'], certs['laptop']['o']['device_id']
    bob_phone, primary = certs['bob_phone']['o']['device_id'], certs['primary']['o']['device_id']
    delegation = v['card']['card']['delegation']
    cs = {c['name']: c for c in v['checkpoints']['cases']}
    accepted = cs['checkpoint_gone_all_endpoint_routes']['state']
    person_key = {alice: 'person_alice.sig', bob: 'person_bob.sig', intruder: 'intruder.sig'}

    def rev(device, person, reason, ms=NOW - 1000):
        return R.sign_object(S, keys[person_key[person]], {'v': 2, 'suite': 2, 'kind': 'revocation',
                             'person_id': person, 'device_id': device, 'revoked_ms': ms, 'reason': reason})

    def cert_of(device, person):
        found = next((c for c in certs.values() if c['o']['device_id'] == device), None)
        if found['o']['person_id'] == person:
            return found
        return R.sign_object(S, keys[person_key[person]], {**found['o'], 'person_id': person})

    def entry_of(item):
        o = item['o']
        return {'revocation': item, 'device_cert': cert_of(o['device_id'], o['person_id']),
                'pk_pub': R.b64u(bytes.fromhex(v['keys'][person_key[o['person_id']]]['pub']))}

    # Workspace A lists the owner's phone (the restore signer), alice's laptop and bob's phone.
    base = copy.deepcopy(accepted)
    base['members'] = {phone: ['look', 'decide', 'operate'], laptop: ['look', 'decide'],
                       bob_phone: ['look', 'decide']}
    base['registry'] = {phone: alice, laptop: alice, bob_phone: bob}
    base['certs'] = {d: cert_of(d, p) for d, p in base['registry'].items()}
    base['list_devices'] = sorted(base['members'])
    base['ever_devices'] = sorted(base['members'])
    base['cursors'] = {}
    assert set(base['person_keys']) == {alice, bob}

    def held(state, *revs, chain=()):
        """Preconditions: global §19.5 rows in cursor order, and pairs this workspace's chain holds."""
        state = copy.deepcopy(state)
        for r in revs:
            assert C.intake(state, r)
        for r in chain:
            state['revocations'][C.pair_key({'revocation': r})] = r
        return state

    def token(c, workspace=ws):
        return C.unpublished_token(workspace, c)

    cases = []

    def new(name, state):
        c = {'name': name, 'state': copy.deepcopy(state), 'steps': []}
        cases.append(c)
        return c, copy.deepcopy(state)

    def run(c, state, inp, error=None):
        inp = {'now_ms': NOW, **copy.deepcopy(inp)}
        if inp['op'] == 'publish':
            inp.setdefault('generation', 1)
        result = C.dispatch(S, state, **copy.deepcopy(inp))
        assert result.get('error') == error, (c['name'], inp['op'], result, error)
        for item in result.get('items', []):
            assert verify_item(item) is None, (c['name'], verify_item(item))
        c['steps'].append({'input': inp, 'expect': result})
        return result

    def get(c, state, error=None, **query):
        return run(c, state, {'op': 'unpublished_get', 'query': query}, error)

    def branch(state):
        """The held checkpoint's workspace-log heads, oldest first."""
        acc, heads = state['held']['o']['workspace_log']['acc'], []
        while acc != C.ZERO:
            n = state['nodes']['workspace'][acc]
            heads.append(n['head'])
            acc = n['prev_acc']
        return heads[::-1]

    def entry(hs):
        acc = C.ZERO
        for h in hs:
            acc = C.log_acc(acc, h)
        return {'seq': len(hs), 'head': hs[-1], 'acc': acc}

    def restore(c, state, ident, evidence=(), error=None):
        """An owner-signed workspace restore that keeps the whole held branch (no proof pages) and carries
        `evidence` (revocation objects of sorted pairs) as its revocation entries."""
        source = state['held']
        hs = branch(state)
        line = {'v': 2, 'hash_v': 1, 'id': ident, 'seq': len(hs) + 1, 'at': at(NOW), 'type': 'restore',
                'actor': {'kind': 'person', 'id': 'p_' + alice, 'device': 'd_' + phone},
                'based_on': hs[-1], 'prev': hs[-1], 'roster_v': 1, 'auth': 'passphrase', 'from_seq': len(hs),
                'head': hs[-1], 'abandoned': None, 'abandoned_decisions': [], 'source': C.reference(source),
                'reason': 'rollback', 'revocations': [entry_of(r) for r in sorted(evidence, key=lambda r: (
                    r['o']['device_id'], r['o']['person_id']))]}
        line['sig'] = R.b64u(S.sign(keys['phone.sig'], C.event_bytes(S, line, ws, 'workspace')))
        line['host_sig'] = R.b64u(S.sign(keys['wsk_a.sig'], C.event_bytes(S, line, ws, 'workspace', True)))
        target = R.sign_object(S, keys['wsk_a.sig'], {**source['o'], 'n': source['o']['n'] + 1, 'at': at(NOW),
                                                      'workspace_log': entry(hs + [C.event_head(line)])})
        args = {'source': C.checkpoint_hash(source), 'target': C.checkpoint_hash(target)}
        run(c, state, {'op': 'manifest', 'body': {'pages': []}, **args})
        bundle = {'line': line, 'cert': certs['phone'], 'authz': {'delegation': delegation}, 'log': 'workspace'}
        body = {'checkpoint': target, 'source_hash': args['source'], 'restore': bundle}
        return run(c, state, {'op': 'publish', 'body': body}, error), body

    laptop_lost, laptop_comp = rev(laptop, alice, 'lost'), rev(laptop, alice, 'compromised', NOW - 500)
    bob_lost = rev(bob_phone, bob, 'lost')
    stranger = rev(laptop, intruder, 'compromised')
    ids = iter(f'01{c * 24}' for c in 'BCDEFGHJKMNPQRSTVWXYZ')

    def refs_match(result, page):
        got = {(r['device_id'], r['person_id']): (r['cursor'], r['digest']) for r in result['unpublished_refs']}
        assert got == {(i['device_id'], i['person_id']): (i['provenance']['cursor'], i['provenance']['digest'])
                       for i in page['items']}, (got, page)

    # 1. A restore omits a member's held pair: one item, and the publication's ref names exactly it.
    c, st = new('restore_omits_member_pair', held(base, laptop_lost))
    result, _ = restore(c, st, next(ids))
    assert result['unpublished'] == ['d_' + laptop]
    refs_match(result, get(c, st))

    # 2. The same evidence carried at its strength retires the item (a chain pair at equal strength).
    c, st = new('restore_carries_pair_retires', held(base, laptop_lost))
    assert len(get(c, st)['items']) == 1
    result, _ = restore(c, st, next(ids), [laptop_lost])
    assert 'unpublished' not in result
    assert get(c, st)['items'] == []

    # 3. Carried weaker than held: an item marked as a chain-pair upgrade (chain_reason).
    c, st = new('weaker_carriage_is_item', held(base, laptop_comp))
    result, _ = restore(c, st, next(ids), [laptop_lost])
    page = get(c, st)
    assert [i['chain_reason'] for i in page['items']] == ['lost']
    refs_match(result, page)

    # 4. A chain pair upgraded later through the §19.5 intake: the item appears at a new cursor; a resume
    # from the old position sees it once.
    c, st = new('chain_pair_upgraded_later', held(base, laptop_lost, chain=[laptop_lost]))
    old = get(c, st)
    assert old['items'] == [] and old['cursor'] == token(0)
    run(c, st, {'op': 'revoke', 'body': {'record': laptop_comp}})
    page = get(c, st, cursor=token(1))
    assert [(i['provenance']['cursor'], i['chain_reason']) for i in page['items']] == [(2, 'lost')]
    assert get(c, st, cursor=page['cursor']) == {'status': 200, 'items': [], 'cursor': token(2), 'more': False}

    # 5. Both arrival orders (global evidence before or after the restore) give the same final view.
    views = []
    for name, before in (('global_before_restore', True), ('global_after_restore', False)):
        c, st = new(name, held(base, laptop_lost) if before else base)
        restore(c, st, next(ids))
        if not before:
            run(c, st, {'op': 'revoke', 'body': {'record': laptop_lost}})
        views.append(get(c, st))
    assert views[0] == views[1]

    # 6. A stranger's self-certified pair for a listed device (from the stranger's own workspace's restore
    # evidence) is neither served nor reported; the registered person's pair beside it is.
    c, st = new('stranger_pair_never_served', held(base, stranger, laptop_lost))
    result, _ = restore(c, st, next(ids))
    page = get(c, st)
    assert [(i['device_id'], i['person_id']) for i in page['items']] == [(laptop, alice)]
    refs_match(result, page)

    # The chain is matched per pair: a stranger's chain pair for the device (pre-P3-D30 residue) never hides or
    # satisfies the registered person's pair.
    c, st = new('chain_matched_per_pair', held(base, stranger, laptop_lost, chain=[stranger]))
    assert [(i['person_id'], i['chain_reason']) for i in get(c, st)['items']] == [(alice, None)]

    # 7. A device known only through restore evidence (checkpoint ever-device, not a list member) is not served,
    # even when registered and held stronger than its chain pair.
    tomb = copy.deepcopy(base)
    tomb['registry'][primary] = alice
    tomb['certs'][primary] = certs['primary']
    tomb['ever_devices'] = sorted(tomb['ever_devices'] + [primary])
    prim_lost, prim_comp = rev(primary, alice, 'lost'), rev(primary, alice, 'compromised')
    c, st = new('tombstone_only_device_not_served', held(tomb, prim_comp, laptop_lost, chain=[prim_lost]))
    assert [i['device_id'] for i in get(c, st)['items']] == [laptop]

    # 8. A device the workspace never knew is not served, whatever the relay holds for it.
    unknown = copy.deepcopy(base)
    unknown['registry'][primary] = alice
    unknown['certs'][primary] = certs['primary']
    c, st = new('unknown_device_not_served', held(unknown, prim_comp, laptop_lost))
    assert [i['device_id'] for i in get(c, st)['items']] == [laptop]

    # 9. A former member (removed from the list, still an ever-device) is served.
    former = copy.deepcopy(base)
    del former['members'][laptop]
    c, st = new('former_member_served', held(former, laptop_lost))
    assert [i['device_id'] for i in get(c, st)['items']] == [laptop]

    # 10. The publication response is lost: the exact retry returns the stored result, refs included, and the
    # item is retrievable without a new restore.
    c, st = new('response_loss_recovers', held(base, laptop_lost))
    result, body = restore(c, st, next(ids))
    assert run(c, st, {'op': 'publish', 'body': body}) == result
    refs_match(result, get(c, st))

    # 11. A new relay process on the same database: the same view and the same cursors.
    c, st = new('restart_recovers', held(base, laptop_lost, bob_lost))
    first = get(c, st, limit='1')
    assert first['more'] and len(first['items']) == 1
    run(c, st, {'op': 'restart'})
    assert get(c, st, limit='1') == first
    rest = get(c, st, cursor=first['cursor'])
    assert [i['device_id'] for i in rest['items']] == [bob_phone] and not rest['more']

    # 12. An ack is not publication: the notice clears, a fetch from the start returns every item, and the next
    # intake raises the notice again.
    c, st = new('ack_is_not_publication', held(base, laptop_lost, bob_lost))
    before = get(c, st)
    assert run(c, st, {'op': 'notices'})['unpublished'] == token(2)
    assert run(c, st, {'op': 'unpublished_ack', 'body': {'cursor': before['cursor']}})['acked'] == token(2)
    assert run(c, st, {'op': 'notices'})['unpublished'] is None
    assert get(c, st) == before
    run(c, st, {'op': 'revoke', 'body': {'record': laptop_comp}})
    assert run(c, st, {'op': 'notices'})['unpublished'] == token(3)
    assert [i['device_id'] for i in get(c, st)['items']] == [bob_phone, laptop]

    # 13. The ack only moves up; an ack beyond the relay's state is refused.
    c, st = new('ack_lower_is_noop', held(base, laptop_lost, bob_lost))
    assert run(c, st, {'op': 'unpublished_ack', 'body': {'cursor': token(2)}})['acked'] == token(2)
    assert run(c, st, {'op': 'unpublished_ack', 'body': {'cursor': token(1)}})['acked'] == token(2)
    assert run(c, st, {'op': 'unpublished_ack', 'body': {'cursor': token(0)}})['acked'] == token(2)
    assert run(c, st, {'op': 'notices'})['unpublished'] is None
    c, st = new('ack_ahead_refused', held(base, laptop_lost))
    run(c, st, {'op': 'unpublished_ack', 'body': {'cursor': token(2)}}, 'cursor_ahead')
    run(c, st, {'op': 'unpublished_ack', 'body': {'cursor': token(1, ws_b)}}, 'malformed')
    run(c, st, {'op': 'unpublished_ack', 'body': {'cursor': token(1), 'published': []}}, 'malformed')
    assert run(c, st, {'op': 'notices'})['unpublished'] == token(1)

    # 14. Positions: ahead of the relay's state (409), another workspace's (400), malformed (400); behind is legal.
    c, st = new('cursor_ahead_fetch', held(base, laptop_lost))
    get(c, st, 'cursor_ahead', cursor=token(2))
    assert len(get(c, st, cursor=token(0))['items']) == 1
    c, st = new('cursor_other_workspace', held(base, laptop_lost))
    get(c, st, 'malformed', cursor=token(0, ws_b))
    c, st = new('query_malformed', held(base, laptop_lost))
    for query in ({'cursor': 'not a cursor'}, {'limit': '0'}, {'limit': '65'}, {'limit': '-1'}, {'after': '0'},
                  {'cursor': R.b64u(R.cj({'v': 2, 'ws': ws, 'c': 0}))},
                  {'cursor': R.b64u(R.cj({'v': 1, 'ws': ws, 'c': 0, 'x': 1}))},
                  {'cursor': R.b64u(R.cj({'v': 1, 'ws': ws, 'c': -1}))},
                  {'cursor': R.b64u(R.cj({'v': 1, 'ws': ws, 'c': '0'}))}):
        get(c, st, 'malformed', **query)
    assert len(get(c, st, limit='64')['items']) == 1

    # 15. Paging: a limit=1 walk; then a byte-bounded page cut exactly at 256 KiB of cj(response).
    c, st = new('paging_limit_walk', held(base, laptop_lost, bob_lost))
    page = get(c, st, limit='1')
    assert page['more'] and page['cursor'] == token(1)
    page = get(c, st, limit='1', cursor=page['cursor'])
    assert not page['more'] and page['cursor'] == token(2) and len(page['items']) == 1
    c, st = new('paging_bytes_cut', paging_state(S, v, base, rev, alice))
    page = get(c, st)
    assert page['more'] and len(R.cj({k: x for k, x in page.items() if k != 'status'})) == C.UNPUBLISHED_BYTES
    rest = get(c, st, cursor=page['cursor'])
    assert not rest['more'] and len(page['items']) + len(rest['items']) == 18

    # 16. A ticket restore neither carries nor retires anything: the view is unchanged.
    ticket = cs['ticket_restore']
    tstate = copy.deepcopy(ticket['state'])
    for k in ('members', 'registry', 'certs', 'list_devices', 'ever_devices', 'cursors'):
        tstate[k] = copy.deepcopy(base[k])
    c, st = new('ticket_restore_no_effect', held(tstate, laptop_lost))
    before = get(c, st)
    for s in ticket['steps']:
        run(c, st, s['input'])
    assert st['transitions'] and st['transitions'][-1]['log'] != 'workspace'
    assert get(c, st) == before

    # 17. Every served item verifies on its own under the person key it names (alice's and bob's).
    c, st = new('evidence_verifies', held(base, bob_lost, laptop_comp, chain=[laptop_lost]))
    page = get(c, st)
    assert [(i['person_id'], i['chain_reason']) for i in page['items']] == [(bob, None), (alice, 'lost')]

    for c in cases:
        c['expect'] = replay(S, c)
        assert c['expect']['results'] == [s['expect'] for s in c['steps']]
    v['unpublished'] = {'cases': cases}


def paging_state(S, v, base, rev, alice):
    """Eighteen more devices of alice, each held `lost`, with registry certificates near the 16 KiB request cap
    (label_sealed padding), sized so the first page's cj(response) is exactly UNPUBLISHED_BYTES and the next item
    does not fit."""
    state = copy.deepcopy(base)
    person = S.sig_key(bytes.fromhex(v['keys']['person_alice.sig']['seed']))
    template = v['certs']['signed']['laptop']['o']

    def build(i, pad):
        key = S.sig_key(R.fake(f'P3-D31 paging device {i}'))
        pub = S.sig_pub(key)
        o = {**template, 'device_id': R.device_id(S, pub).hex(), 'dk_sig_pub': R.b64u(pub),
             'label_sealed': 'A' * pad}
        return R.sign_object(S, person, o)

    def page_size(pads):
        trial = copy.deepcopy(state)
        for i, pad in enumerate(pads):
            cert = build(i, pad)
            d = cert['o']['device_id']
            trial['registry'][d] = alice
            trial['certs'][d] = cert
            trial['members'][d] = ['look']
            trial['list_devices'] = sorted(set(trial['list_devices']) | {d})
            trial['ever_devices'] = sorted(set(trial['ever_devices']) | {d})
            C.intake(trial, rev(d, alice, 'lost'))
        return trial

    pads = [15000] * 18
    trial = page_size(pads)
    first = C.unpublished_get(trial, {})
    n = len(first['items'])
    assert 1 < n < 18
    # Grow the last included certificate's padding until the page is exactly the bound (b64u lengths are never
    # 1 mod 4, so the two last included certificates share the difference).
    gap = C.UNPUBLISHED_BYTES - len(R.cj(first))
    a, b = pads[n - 2], pads[n - 1]
    for extra in range(4):
        x, y = a + extra, b + gap - extra
        if x % 4 != 1 and y % 4 != 1:
            pads[n - 2], pads[n - 1] = x, y
            break
    trial = page_size(pads)
    first = C.unpublished_get(trial, {})
    assert len(first['items']) == n and len(R.cj(first)) == C.UNPUBLISHED_BYTES, (len(R.cj(first)), n)
    return trial
