"""P3 checkpoint HTTP transcripts, using the executable state-machine scenarios."""
import copy

from ref import checkpoints as C
from ref import orch_protocol_ref as R

PREFIX = '/v2/workspaces/{ws}'
ROUTES = [
    ('genesis', 'PUT', PREFIX+'/genesis', 'host', 'W(g)', '401:bad_signature 409:genesis_mismatch,restore_not_owner'),
    ('staging_page', 'PUT', PREFIX+'/staging/{source_hash}/{target_hash}/pages/{i}', 'host', 'W(g)', '409:staging_conflict 429:quota_exceeded'),
    ('staging_manifest', 'PUT', PREFIX+'/staging/{source_hash}/{target_hash}/manifest', 'host', 'W(g)', '409:staging_conflict 429:quota_exceeded'),
    ('baseline_post', 'POST', PREFIX+'/baselines', 'host', 'W(g)', '404:not_found 410:checkpoint_gone 429:quota_exceeded'),
    ('baseline_delete', 'DELETE', PREFIX+'/baselines/{hash}', 'client', 'W(g)|D(m)', ''),
    ('checkpoint_put', 'PUT', PREFIX+'/checkpoint', 'host', 'W(g)', '400:wrong_suite,too_large 401:bad_signature 409:no_genesis,genesis_mismatch,chain_diverged,checkpoint_time,staging_incomplete,restore_invalid,restore_not_owner,restore_source_mismatch,restore_reused,restore_missing_revocation,fenced 429:quota_exceeded'),
    ('checkpoint_get', 'GET', PREFIX+'/checkpoint', 'client', 'D(m)|W', '404:not_found 410:checkpoint_gone'),
    ('transitions', 'GET', PREFIX+'/transitions', 'client', 'D(m)|W', '404:not_found 410:checkpoint_gone'),
    ('proof', 'GET', PREFIX+'/proof', 'client', 'D(m)|W', '404:not_found 410:checkpoint_gone'),
    # P3-D31: retrieval of unpublished revocation evidence; never 404 or 410 (no oracle).
    ('unpublished_get', 'GET', PREFIX+'/unpublished', 'host', 'W(g)', '409:cursor_ahead 429:rate_limited'),
    ('unpublished_ack', 'POST', PREFIX+'/unpublished/ack', 'host', 'W(g)', '409:cursor_ahead 429:rate_limited'),
]
CAPS = {'genesis': 65536, 'staging_page': C.PAGE_CAP, 'staging_manifest': C.PAGE_CAP,
        'baseline_post': 16384, 'checkpoint_put': C.REQUEST_CAP,
        'unpublished_ack': C.REQUEST_CAPS['unpublished_ack']}
CONDITIONS = {
    'genesis_mismatch': 'Pinned genesis or card WSK/workspace disagrees; established pins never change.',
    'no_genesis': 'Workspace has no accepted owner-device genesis pin.',
    'chain_diverged': 'Offered entries or staged ancestry do not extend the held checkpoint.',
    'checkpoint_time': 'Offered at regresses or exceeds relay time by more than 300 seconds.',
    'staging_incomplete': 'The source/target staging manifest or one of its pages is missing or expired.',
    'staging_conflict': 'This page index or manifest already has different canonical content.',
    'restore_invalid': 'The signed restore shape, signatures or target/prefix binding fails R0/R1/R3.',
    'restore_not_owner': 'The signer lacks the card owner device authority required by P3-D24.',
    'restore_source_mismatch': 'The signed source no longer equals the relay held checkpoint.',
    'restore_reused': 'This restore ID was applied by a prior accepted transition.',
    'restore_missing_revocation': 'The restore omits or weakens held revocations for ever-devices.',
    'checkpoint_gone': 'The requested immutable checkpoint endpoint expired after supersession.',
    'cursor_ahead': "The position names a §19.5 cursor above the relay's newest revocation; restart from the beginning.",
}


def shapes(v):
    o = v['checkpoints']['objects']
    cp = o['checkpoint']; h = C.checkpoint_hash(cp)
    target = o['target']; th = C.checkpoint_hash(target)
    bundle = {'restore_id': o['restore']['line']['id'], 'log': 'workspace', 'source_hash': h,
              'target_hash': th, 'target_n': target['o']['n'], **o['restore']}
    shapes = {
        'genesis': (o['pin'], {}),
        'staging_page': (o['page'], {}),
        'staging_manifest': ({'pages': [C.descriptor(0, o['page'])]}, {'complete': True, 'missing': []}),
        'baseline_post': ({'hash': h, 'offer_id': 'ab'*16}, {'until_ms': 1790000000000+7*C.DAY}),
        'baseline_delete': (None, {}),
        'checkpoint_put': ({'checkpoint': target, 'source_hash': h, 'restore': o['restore']}, {'result': 'accepted', 'n': 2, 'hash': th}),
        'checkpoint_get': (None, {'genesis': o['pin'], 'checkpoint': cp, 'transitions_head': 0}),
        'transitions': (None, {'transitions': [bundle], 'next': None}),
        'proof': (None, {'heads': o['page']['heads'], 'next': None}),
    }
    # P3-D31: placeholders, replaced by their bound vector steps in unpublished() below.
    shapes['unpublished_get'] = (None, {'items': [], 'cursor': '', 'more': False})
    shapes['unpublished_ack'] = ({'cursor': ''}, {'acked': ''})
    queries = {'checkpoint_get': {'hash': h}, 'transitions': {'after_n': '0', 'to': th, 'limit': '16'},
               'proof': {'log': 'workspace', 'from': C.ZERO, 'to': h, 'limit': '65536'}}
    paths = {'source_hash': 'null', 'target_hash': h, 'hash': h, 'i': '0'}
    return shapes, queries, paths


def enrich(output, v):
    """Bind business refusals/successes to reproducible vector inputs wherever available."""
    mapping = {'genesis': 'genesis', 'staging_page': 'page', 'staging_manifest': 'manifest',
               'baseline_post': 'baseline', 'baseline_delete': 'baseline_delete', 'checkpoint_put': 'publish',
               'checkpoint_get': 'get', 'transitions': 'transitions', 'proof': 'proof'}
    # Steps an HTTP fixture can never be: a missing Orch-Holder (bound to its own case below), a
    # role-less principal (HTTP always has one) and the two-workspace isolation states.
    unbindable = {'publish_generation_required', 'baseline_delete_requires_role',
                  'isolation_workspace_a', 'isolation_workspace_b'}
    sections = ['checkpoints'] + (['checkpoints_g4'] if 'checkpoints_g4' in v else [])
    for name, op in mapping.items():
        fixture = output[name]
        for case in fixture['cases']:
            error = case['response']['json'].get('error')
            if error == 'too_large' and name == 'checkpoint_put':
                continue  # the transport-cap recipe; the parsed line cap is bound below (G4)
            if error == 'fenced' and name == 'baseline_delete':
                case['request']['headers']['Authorization'] = 'Bearer FAKE-workspace'  # W(g) is fenced
            # G4: the alternate-suite object is itself a vector step now (precondition b).
            order = sections[::-1] if error == 'wrong_suite' else sections
            matches = [(sec, c, i, s) for sec in order for c in v[sec]['cases'] for i, s in enumerate(c['steps'])
                       if s['input']['op'] == op and s['expect'].get('error') == error
                       and c['name'] not in unbindable]
            if not matches:
                continue
            section, vector, index, step = matches[0]
            case['given']['vector'] = {'section': section, 'name': vector['name'], 'step': index}
            inp = step['input']
            req = case['request']
            if 'body' in inp:
                req['json'] = copy.deepcopy(inp['body'])
            ws = v['ids']['workspace_a']
            if op in ('page', 'manifest'):
                base = f"/v2/workspaces/{ws}/staging/{inp['source'] or 'null'}/{inp['target']}"
                req['path'] = base + (f"/pages/{inp['i']}" if op == 'page' else '/manifest')
            if op in ('get', 'proof', 'transitions'):
                req['query'] = {k: str(value) for k, value in inp.items() if k not in ('op', 'now_ms') and value is not None}
            if op == 'baseline_delete':
                req.pop('json', None)
                req['path'] = f"/v2/workspaces/{ws}/baselines/{inp['body']['hash']}"
                req['query'] = {}
                if inp.get('role') == 'member':
                    # D(m) names the pairing offer it releases (review 10); W(g) releases any pin.
                    req['query'] = {'offer_id': inp['body']['offer_id']}
                else:
                    req['headers']['Authorization'] = 'Bearer FAKE-workspace'
            case['given']['now_ms'] = inp['now_ms']
            if error == 'malformed':
                req['query'].pop('unexpected', None)  # the vector step is the malformed input
            case['response']['json'] = {k: value for k, value in step['expect'].items() if k != 'status'}
        # Additional executable success/refusal transcripts exercise all publication branches.
        for vector in v['checkpoints']['cases']:
            for i, step in enumerate(vector['steps']):
                if step['input']['op'] != op:
                    continue
                if name == 'baseline_delete' and vector['name'] == 'baseline_member_release_needs_offer_id' and i in (0, 3):
                    c = copy.deepcopy(fixture['cases'][0])
                    # i == 0: a member naming another offer_id is a no-op and the pin stays (review L5).
                    c['name'] = 'member_release_by_offer_id' if i == 3 else 'member_wrong_offer_id_is_a_noop'
                    c['request']['query'] = {'offer_id': step['input']['body']['offer_id']}
                    c['request']['headers']['Authorization'] = 'Bearer FAKE-device'
                    c['given'].update(vector={'section': 'checkpoints', 'name': vector['name'], 'step': i},
                                      now_ms=step['input']['now_ms'])
                    fixture['cases'].append(c)
                    continue
                if name == 'checkpoint_put' and vector['name'] == 'publish_generation_required':
                    c = copy.deepcopy(fixture['cases'][0])
                    c['name'] = 'missing_orch_holder'
                    c['request']['json'] = step['input']['body']
                    c['request']['headers'].pop('Orch-Holder', None)
                    c['given'].update(vector={'section': 'checkpoints', 'name': vector['name'], 'step': i},
                                      now_ms=step['input']['now_ms'], condition='The Orch-Holder header is absent.')
                    c['response']['status'] = step['expect']['status']
                    c['response']['json'] = {k: value for k, value in step['expect'].items() if k != 'status'}
                    fixture['cases'].append(c)
                    continue
                if name != 'checkpoint_put' or vector['name'] not in {
                    'workspace_restore_and_exact_retry', 'ticket_restore', 'bootstrap_null_source',
                    'restore_at_rewritten_within_window_accepted', 'B1_same_strength_other_bytes',
                    'B1_stronger', 'stale_checkpoint_ignored'}:
                    continue
                c = copy.deepcopy(fixture['cases'][0])
                c['name'] = vector['name'] + '_' + str(i)
                c['request']['json'] = step['input']['body']
                c['given'].update(vector={'section': 'checkpoints', 'name': vector['name'], 'step': i})
                c['response']['json'] = {k: value for k, value in step['expect'].items() if k != 'status'}
                fixture['cases'].append(c)
    unpublished(output, v)
    isolation(output, v)
    return output


def unpublished(output, v):
    """P3-D31: bind the unpublished route fixtures to the `unpublished` vector group's steps (states and exact
    responses replay in the reference and in production). Transport and authorization refusals keep the success
    case's state: 401 without a session, 403 for another workspace's host or a device session (never 404), 409
    fenced for a stale or missing Orch-Holder, 429 when the workspace's window is full."""
    if 'unpublished' not in v:
        return
    cases = {c['name']: c for c in v['unpublished']['cases']}

    def bind(fixture, label, vector, index, condition=None):
        step = cases[vector]['steps'][index]
        inp = step['input']
        if label in {c['name'] for c in fixture['cases']}:
            c = next(c for c in fixture['cases'] if c['name'] == label)
        else:
            c = copy.deepcopy(fixture['cases'][0])
            c['name'] = label
            fixture['cases'].append(c)
        c['given'] = {**({'scenario': c['given']['scenario']} if 'scenario' in c['given'] else {}),
                      'now_ms': inp['now_ms'], 'vector': {'section': 'unpublished', 'name': vector, 'step': index}}
        if condition:
            c['given']['condition'] = condition
        if inp['op'] == 'unpublished_get':
            c['request']['query'] = dict(inp.get('query', {}))
        else:
            c['request']['json'] = copy.deepcopy(inp['body'])
        c['response']['status'] = step['expect']['status']
        c['response']['json'] = {k: x for k, x in step['expect'].items() if k != 'status'}
        return c

    get, ack = output['unpublished_get'], output['unpublished_ack']
    bind(get, 'success', 'restore_omits_member_pair', 2,
         "A restore omitted the laptop's registered pair (held at cursor 1): one item, as its unpublished_refs named.")
    bind(get, 'empty', 'restore_carries_pair_retires', 3, 'A restore carried the only held pair: an empty view.')
    bind(get, 'paged_more', 'paging_limit_walk', 0, 'Two items, limit=1: the first page and more.')
    bind(get, 'resume_from_cursor', 'paging_limit_walk', 1, "Resumed from the first page's cursor.")
    bind(get, 'chain_upgrade_item', 'weaker_carriage_is_item', 2,
         'The chain holds the pair as lost, the relay as compromised: an upgrade item (chain_reason).')
    bind(get, 'refusal_409_cursor_ahead', 'cursor_ahead_fetch', 0)
    bind(get, 'refusal_400_malformed_other_workspace_cursor', 'cursor_other_workspace', 0,
         "Workspace B's position on workspace A's route.")
    for i, label in enumerate(('bad_cursor', 'limit_zero', 'limit_above_64')):
        bind(get, 'refusal_400_malformed_' + label, 'query_malformed', i)
    bind(ack, 'success', 'ack_lower_is_noop', 0, 'Two items held at cursors 1 and 2; nothing acknowledged yet.')
    # The publication whose response names the item that unpublished_get.json `success` serves (U10: hints).
    put = output['checkpoint_put']
    step = cases['restore_omits_member_pair']['steps'][1]
    c = copy.deepcopy(put['cases'][0])
    c['name'] = 'restore_with_unpublished_refs'
    c['request']['json'] = copy.deepcopy(step['input']['body'])
    c['given'] = {'now_ms': step['input']['now_ms'],
                  'vector': {'section': 'unpublished', 'name': 'restore_omits_member_pair', 'step': 1},
                  'condition': ("The relay holds the laptop's registered pair; the restore omits it. The refs are hints: "
                                'unpublished_get.json `success` serves the same item (cursor and digest).')}
    c['response']['json'] = {k: x for k, x in step['expect'].items() if k != 'status'}
    put['cases'].append(c)
    bind(ack, 'lower_noop', 'ack_lower_is_noop', 1, 'A lower position after an ack at 2 is a no-op.')
    bind(ack, 'refusal_409_cursor_ahead', 'ack_ahead_refused', 0)
    bind(ack, 'refusal_400_malformed_other_workspace_cursor', 'ack_ahead_refused', 1)
    bind(ack, 'refusal_400_malformed_unknown_field', 'ack_ahead_refused', 2)
    for fixture in (get, ack):
        for c in fixture['cases']:
            if c['name'] == 'refusal_409_fenced':
                c['given']['condition'] = 'The current holder generation is 1; the request names generation 0.'
                missing = copy.deepcopy(c)
                missing['name'] = 'refusal_409_fenced_missing_holder'
                missing['request']['headers'].pop('Orch-Holder')
                missing['given']['condition'] = 'The Orch-Holder header is absent (never malformed: fenced).'
            if c['name'] == 'refusal_403_not_eligible':
                device = copy.deepcopy(c)
                device['name'] = 'refusal_403_not_eligible_device_session'
                device['request']['headers'] = {**device['request']['headers'], 'Authorization': 'Bearer FAKE-device'}
                device['request']['headers'].pop('Orch-Holder')
                device['given'] = {'scenario': 'device_session', 'now_ms': c['given']['now_ms'],
                                   'condition': "A member device's session: the route is the fenced host's only."}
            if c['name'] == 'refusal_429_rate_limited':
                c['given']['condition'] = ("The workspace's " + ('fetch window (120 per minute)' if fixture is get
                                                                  else 'ack window (30 per minute)') + ' is full.')
        fixture['cases'] += [missing, device]


def isolation(output, v):
    """G4 precondition (b), protocol-v2 §19.8 detail 6: a second workspace B (token
    FAKE-workspace-b, member device token FAKE-device-b) against workspace A. B's principals on A's
    routes are 403 not_eligible; A's hashes under B are 404 (a DELETE is a no-op) and B's staging set
    under A's key is B's own. States: checkpoints_g4 isolation_workspace_a and _b."""
    if 'checkpoints_g4' not in v:
        return
    g4 = {c['name']: c for c in v['checkpoints_g4']['cases']}
    a, b = g4['isolation_workspace_a'], g4['isolation_workspace_b']
    states = {'a': {'section': 'checkpoints_g4', 'name': a['name']},
              'b': {'section': 'checkpoints_g4', 'name': b['name']}}
    ws_a, ws_b = v['ids']['workspace_a'], v['ids']['workspace_b']
    for name, fixture in output.items():
        if name not in {r[0] for r in ROUTES}:
            continue
        auth = next(r[4] for r in ROUTES if r[0] == name)
        for token in ('FAKE-workspace-b', 'FAKE-device-b'):
            if token == 'FAKE-device-b' and 'D(m)' not in auth:
                continue
            c = copy.deepcopy(fixture['cases'][0])
            c['name'] = 'cross_workspace_' + ('host' if token.endswith('workspace-b') else 'member') + '_b_on_a'
            c['request']['headers']['Authorization'] = 'Bearer ' + token
            if token == 'FAKE-device-b':
                c['request']['headers'].pop('Orch-Holder', None)
                if name == 'baseline_delete':
                    c['request']['query'] = {'offer_id': 'ab' * 16}
            c['given'] = {'scenario': 'cross_workspace', 'now_ms': 1790000000000, 'isolation': states,
                          'condition': "A principal of workspace B on workspace A's route."}
            c['response'] = {'status': 403, 'headers': {'Content-Type': 'application/json'},
                             'json': {'error': 'not_eligible'}}
            fixture['cases'].append(c)
    bound = {'get': 'checkpoint_get', 'proof': 'proof', 'transitions': 'transitions',
             'baseline': 'baseline_post', 'baseline_delete': 'baseline_delete', 'manifest': 'staging_manifest'}
    for index, step in enumerate(b['steps']):
        inp, name = step['input'], bound[step['input']['op']]
        c = copy.deepcopy(output[name]['cases'][0])
        c['name'] = 'workspace_b_names_a_' + {'manifest': 'staging_key'}.get(inp['op'], 'hash')
        req = c['request']
        req['headers']['Authorization'] = 'Bearer FAKE-workspace-b'
        prefix = f'/v2/workspaces/{ws_b}'
        if inp['op'] in ('get', 'proof', 'transitions'):
            req['path'] = prefix + {'get': '/checkpoint'}.get(inp['op'], '/' + inp['op'])
            req['query'] = {k: str(x) for k, x in inp.items() if k not in ('op', 'now_ms')}
        elif inp['op'] == 'baseline':
            req['path'], req['json'] = prefix + '/baselines', copy.deepcopy(inp['body'])
        elif inp['op'] == 'baseline_delete':
            req['path'], req['query'] = f"{prefix}/baselines/{inp['body']['hash']}", {}
        else:
            req['path'] = f"{prefix}/staging/{inp['source']}/{inp['target']}/manifest"
            req['json'] = copy.deepcopy(inp['body'])
        assert ws_a not in req['path']
        c['given'] = {'scenario': 'cross_workspace', 'now_ms': inp['now_ms'], 'isolation': states,
                      'vector': {'section': 'checkpoints_g4', 'name': b['name'], 'step': index},
                      'condition': "Workspace B's host names workspace A's checkpoint, baseline or staging key."}
        c['response'] = {'status': step['expect']['status'], 'headers': {'Content-Type': 'application/json'},
                         'json': {k: x for k, x in step['expect'].items() if k != 'status'}}
        output[name]['cases'].append(c)
    # The parsed restore-line cap (400 too_large) as a vector step, beside the transport recipe.
    vector = g4['restore_line_over_cap_too_large']
    step = vector['steps'][-1]
    c = copy.deepcopy(output['checkpoint_put']['cases'][0])
    c['name'] = 'restore_line_over_cap'
    c['request']['json'] = copy.deepcopy(step['input']['body'])
    c['given'] = {'scenario': 'too_large', 'now_ms': step['input']['now_ms'],
                  'vector': {'section': 'checkpoints_g4', 'name': vector['name'], 'step': len(vector['steps']) - 1},
                  'condition': 'The signed restore line exceeds 524,288 bytes including its LF.'}
    c['response'] = {'status': 400, 'headers': {'Content-Type': 'application/json'}, 'json': {'error': 'too_large'}}
    output['checkpoint_put']['cases'].append(c)
