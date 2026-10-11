"""G4 additions to the checkpoint vectors (suite 2 only), kept apart from the G0b group.

Section `checkpoints_g4`: vector steps for the refusals the G0b HTTP fixtures left unbound
(transitions 404, baseline 404/410, staging page 429, checkpoint too_large/wrong_suite) and the
two workspace states the cross-workspace isolation fixtures run against (protocol-v2 §19.8
transport detail 6 (b)). Public FAKE seeds only. Built after ref/_checkpoint_vectors.py.
"""
import copy

from ref import checkpoints as C
from ref import orch_protocol_ref as R
from ref._checkpoint_vectors import NOW, replay


def add_checkpoints_g4(out):
    v = out['suites']['2']
    S = R.SUITES[2]
    keys = {n: S.sig_key(bytes.fromhex(k['seed'])) for n, k in v['keys'].items() if n.endswith('.sig')}
    cs = {c['name']: c for c in v['checkpoints']['cases']}
    accepted = cs['checkpoint_gone_all_endpoint_routes']['state']
    pinned = cs['first_checkpoint_full_proof']['state']
    root = pinned['genesis']['pin']['o']['genesis']
    base_h = C.checkpoint_hash(accepted['held'])
    unknown = C.digest(b'FAKE G4 unknown endpoint')
    cases = []

    def new(name, state):
        c = {'name': name, 'state': copy.deepcopy(state), 'steps': []}
        cases.append(c)
        return c, copy.deepcopy(state)

    def run(c, state, inp, error=None):
        inp = copy.deepcopy(inp)
        if inp['op'] == 'publish':
            inp.setdefault('generation', 1)
        result = C.dispatch(S, state, **copy.deepcopy(inp))
        assert result.get('error') == error, (c['name'], inp['op'], result, error)
        c['steps'].append({'input': inp, 'expect': result})
        return result

    c, st = new('transitions_unknown_endpoint_not_found', accepted)
    run(c, st, {'op': 'transitions', 'now_ms': NOW, 'to': unknown, 'after_n': 0}, 'not_found')

    c, st = new('baseline_unknown_hash_not_found', accepted)
    run(c, st, {'op': 'baseline', 'now_ms': NOW, 'body': {'hash': unknown, 'offer_id': 'ab' * 16}},
        'not_found')

    c, st = new('baseline_gone_hash', accepted)
    for s in cs['checkpoint_gone_all_endpoint_routes']['steps'][:2]:  # stage and publish n=2
        run(c, st, s['input'])
    run(c, st, {'op': 'baseline', 'now_ms': NOW + C.DAY, 'body': {'hash': base_h, 'offer_id': 'ab' * 16}},
        'checkpoint_gone')

    page = cs['staging_immutable_page_and_manifest']['steps'][0]['input']
    c, st = new('staging_page_third_open_set_quota', accepted)
    for i in range(3):
        run(c, st, {**page, 'target': C.digest(b'FAKE G4 set %d' % i)}, 'quota_exceeded' if i == 2 else None)

    restore = cs['workspace_restore_and_exact_retry']['steps']
    c, st = new('restore_line_over_cap_too_large', accepted)
    for s in restore[:2]:
        run(c, st, s['input'])
    big = copy.deepcopy(restore[2]['input'])
    line = big['body']['restore']['line']
    line['abandoned_decisions'] = [f'01{i:024d}' for i in range(C.LINE_CAP // 29 + 200)]
    assert len(R.cj(line)) + 1 > C.LINE_CAP and len(R.cj(big['body'])) <= C.REQUEST_CAP
    run(c, st, big, 'too_large')

    c, st = new('checkpoint_alternate_suite_object', pinned)
    alternate = out['suites']['1']['checkpoints']['objects']['checkpoint']
    run(c, st, {'op': 'publish', 'now_ms': NOW, 'body': {'checkpoint': alternate, 'source_hash': None}},
        'wrong_suite')

    # A staged page the final publication never uses is refused (no unused evidence, §19.8).
    missing = cs['staging_missing_page']['steps']
    target = missing[-1]['input']['body']['checkpoint']
    used = cs['staging_immutable_page_and_manifest']['steps'][0]['input']
    extra = {'kind': 'retained', 'log': 'workspace', 'after_seq': 0, 'from_acc': C.ZERO, 'heads': [root]}
    extra['digest'] = C.page_digest(extra)
    c, st = new('unused_staged_page_refused', accepted)
    run(c, st, used)
    run(c, st, {**used, 'i': 1, 'body': extra})
    manifest_input = {k: x for k, x in used.items() if k != 'i'}
    manifest_input.update(op='manifest', body={'pages': [C.descriptor(0, used['body']), C.descriptor(1, extra)]})
    run(c, st, manifest_input)
    run(c, st, {'op': 'publish', 'now_ms': NOW, 'body': {'checkpoint': target, 'source_hash': base_h}},
        'chain_diverged')

    # A proof source at the endpoint's height on another branch is not on E's branch (404),
    # even though no head separates them.
    restored = cs['historical_proof_abandoned_branch']['state']
    held = restored['held']
    other = next(n['acc'] for n in restored['nodes']['workspace'].values()
                 if n['seq'] == held['o']['workspace_log']['seq'] and n['acc'] != held['o']['workspace_log']['acc'])
    c, st = new('proof_source_other_branch_same_height', restored)
    run(c, st, {'op': 'proof', 'now_ms': NOW, 'to': C.checkpoint_hash(held), 'log': 'workspace', 'from': other},
        'not_found')

    # Cross-workspace isolation. Workspace A holds n=1, a pinned baseline and one staged page; B is
    # another workspace of the same owner whose only member is Bob's phone. A's hashes mean nothing
    # under B: reads are 404, a baseline cannot pin them, a DELETE is a no-op, and B's staging set
    # under A's key is its own (empty) set.
    c, st = new('isolation_workspace_a', accepted)
    run(c, st, {'op': 'baseline', 'now_ms': NOW, 'body': {'hash': base_h, 'offer_id': 'ab' * 16}})
    run(c, st, page)
    ws_b = v['ids']['workspace_b']
    wsk_b = R.b64u(bytes.fromhex(v['keys']['wsk_b.sig']['pub']))
    pk = accepted['owner_pk']
    owner = accepted['delegation']['o']['owner_person_id']
    delegation_b = R.sign_object(S, keys['person_alice.sig'], {
        'v': 2, 'suite': 2, 'kind': 'ws_delegation', 'workspace_id': ws_b, 'wsk_pub': wsk_b,
        'owner_person_id': owner, 'client_hosted': False, 'issued_ms': NOW - C.DAY})
    bob_phone = v['certs']['signed']['bob_phone']['o']
    blank_b = C.initial(ws_b, wsk_b, pk, delegation_b, {bob_phone['device_id']: ['look', 'decide', 'operate']},
                        {bob_phone['device_id']: bob_phone['person_id']}, accepted['person_keys'])
    c, st = new('isolation_workspace_b', blank_b)
    run(c, st, {'op': 'get', 'now_ms': NOW, 'hash': base_h}, 'not_found')
    run(c, st, {'op': 'proof', 'now_ms': NOW, 'to': base_h, 'log': 'workspace', 'from': C.ZERO}, 'not_found')
    run(c, st, {'op': 'transitions', 'now_ms': NOW, 'to': base_h, 'after_n': 0}, 'not_found')
    run(c, st, {'op': 'baseline', 'now_ms': NOW, 'body': {'hash': base_h, 'offer_id': 'ab' * 16}}, 'not_found')
    run(c, st, {'op': 'baseline_delete', 'now_ms': NOW, 'body': {'hash': base_h}, 'role': 'host'})
    manifest = {'pages': [C.descriptor(0, page['body'])]}
    run(c, st, {'op': 'manifest', 'now_ms': NOW, 'source': page['source'], 'target': page['target'],
                'body': manifest})
    assert c['steps'][-1]['expect'] == {'status': 200, 'complete': False, 'missing': [0]}

    for c in cases:
        c['expect'] = replay(S, c)
        assert c['expect']['results'] == [s['expect'] for s in c['steps']]
    v['checkpoints_g4'] = {'cases': cases}
