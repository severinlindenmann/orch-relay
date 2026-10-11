"""Generated P3 checkpoint scenarios, dispatched by ref/_vectors.py. Public FAKE seeds only."""
import copy
from datetime import datetime, timezone

from ref import checkpoints as C
from ref import orch_protocol_ref as R

NOW = 1790000000000
UID = '01AAAAAAAAAAAAAAAAAAAAAAAA'


def at(ms):
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def replay(S, case):
    state = copy.deepcopy(case['state'])
    results = []
    for step in case['steps']:
        before = copy.deepcopy(state)
        result = C.dispatch(S, state, **step['input'])
        if result['status'] >= 400:
            assert C.contract(before) == C.contract(state), case['name']
        results.append(result)
    return {'results': results, 'state': state}


def add_checkpoints(out):
    for sid, v in out['suites'].items():
        S = R.SUITES[int(sid)]
        keys = {n: S.sig_key(bytes.fromhex(k['seed'])) for n, k in v['keys'].items() if n.endswith('.sig')}
        cert = v['certs']['signed']['phone']
        delegation = v['card']['card']['delegation']
        ws = v['ids']['workspace_a']
        pk = R.b64u(bytes.fromhex(v['keys']['person_alice.sig']['pub']))
        wsk = R.b64u(bytes.fromhex(v['keys']['wsk_a.sig']['pub']))
        device = cert['o']['device_id']
        root = C.digest(b'FAKE genesis')
        heads = [root] + [C.digest(f'FAKE original {i}'.encode()) for i in range(2, 5)]
        blank = C.initial(ws, wsk, pk, delegation, {device: ['look', 'decide', 'operate']})
        pin = R.sign_object(S, keys['phone.sig'], {'v': 2, 'suite': S.id, 'kind': 'genesis_pin',
                                                   'workspace_id': ws, 'wsk_pub': wsk, 'genesis': root})
        pin_body = {'pin': pin, 'cert': cert}
        cases = []

        def new(name, state=blank):
            c = {'name': name, 'state': copy.deepcopy(state), 'steps': []}
            cases.append(c)
            return c, copy.deepcopy(state)

        def run(c, state, op, body=None, error=None, now=NOW, **args):
            inp = {'op': op, 'now_ms': now, **args}
            if body is not None:
                inp['body'] = body
            before = copy.deepcopy(state)
            result = C.dispatch(S, state, **copy.deepcopy(inp))
            assert result.get('error') == error, (sid, c['name'], op, result, error)
            if error:
                assert C.contract(before) == C.contract(state)
            c['steps'].append({'input': copy.deepcopy(inp), 'expect': result})
            return result

        def entry(hs):
            acc = C.ZERO
            for h in hs:
                acc = C.log_acc(acc, h)
            return {'seq': len(hs), 'head': hs[-1], 'acc': acc}

        def cp(n, hs=heads, tickets=None, time=NOW):
            return R.sign_object(S, keys['wsk_a.sig'], {'v': 2, 'suite': S.id, 'kind': 'workspace_checkpoint',
                'workspace_id': ws, 'genesis': root, 'n': n, 'at': at(time), 'workspace_log': entry(hs), 'tickets': tickets or {}})

        def resign(obj, **changes):
            return R.sign_object(S, keys['wsk_a.sig'], {**obj['o'], **changes})

        def page(kind, log, start, hs):
            p = {'kind': kind, 'log': log, 'after_seq': start['seq'], 'from_acc': start['acc'], 'heads': hs}
            p['digest'] = C.page_digest(p)
            return p

        def staged(c, state, target, pages=(), source='held', manifest=True, now=NOW):
            src = C.checkpoint_hash(state['held']) if source == 'held' and state['held'] else None if source == 'held' else source
            args = {'source': src, 'target': C.checkpoint_hash(target)}
            ordered = sorted(pages, key=lambda p: (p['kind'], p['log'], p['after_seq']))
            for i, p in enumerate(ordered):
                run(c, state, 'page', p, i=i, now=now, **args)
            if manifest:
                run(c, state, 'manifest', {'pages': [C.descriptor(i, p) for i, p in enumerate(ordered)]}, now=now, **args)
            return {'checkpoint': target, 'source_hash': src}

        c, state = new('genesis_valid_and_historical_retry')
        run(c, state, 'genesis', pin_body)
        pinned = copy.deepcopy(state)
        state['revocations'][device] = v['revocations'][0]['signed']
        # Make revocation a scenario precondition, not an unexplained mutation mid-trace.
        c2, revoked_pin = new('genesis_revoked_certificate_keeps_pin', state)
        run(c2, revoked_pin, 'genesis', pin_body, now=NOW + 100 * C.DAY)
        for name, key, change in [('non_owner', 'bob_phone.sig', {}), ('other_wsk', 'phone.sig', {'wsk_pub': pk})]:
            c, state = new('genesis_' + name)
            altered = R.sign_object(S, keys[key], {**pin['o'], **change})
            run(c, state, 'genesis', {'pin': altered, 'cert': cert}, error='bad_signature' if name == 'non_owner' else 'genesis_mismatch')
        c, state = new('genesis_decide_only')
        decide = R.sign_object(S, keys['person_alice.sig'], {**cert['o'], 'scopes_max': ['look', 'decide']})
        run(c, state, 'genesis', {'pin': pin, 'cert': decide}, error='restore_not_owner')
        c, state = new('genesis_never_replaced', pinned)
        run(c, state, 'genesis', {'pin': {**pin, 'o': {**pin['o'], 'genesis': heads[1]}}, 'cert': cert}, error='genesis_mismatch')
        base = cp(1)
        c, state = new('first_checkpoint_full_proof', pinned)
        body = staged(c, state, base, [page('appended', 'workspace', C.EMPTY, heads)])
        run(c, state, 'publish', body)
        accepted = copy.deepcopy(state)
        run(c, state, 'publish', body)
        for name, start, target, error in [
            ('no_genesis', blank, base, 'no_genesis'),
            ('checkpoint_genesis_mismatch', pinned, resign(base, genesis=heads[1]), 'genesis_mismatch'),
            ('checkpoint_at_regression_refused', accepted, cp(2, time=NOW-1000), 'checkpoint_time'),
            ('checkpoint_at_future_refused_at_relay', accepted, cp(2, time=NOW+301000), 'checkpoint_time'),
            ('checkpoint_equal_n_conflict', accepted, resign(base, at=at(NOW+1000)), 'chain_diverged'),
        ]:
            c, state = new(name, start)
            run(c, state, 'publish', {'checkpoint': target, 'source_hash': C.checkpoint_hash(base) if start == accepted else None}, error=error)
        c, state = new('checkpoint_future_ceiling_inclusive', accepted)
        run(c, state, 'publish', staged(c, state, cp(2, time=NOW+300000)))
        c, state = new('stale_checkpoint_ignored', accepted)
        run(c, state, 'publish', staged(c, state, cp(2)))
        two = copy.deepcopy(state)
        # A fresh (never accepted) lower-n object whose entries are all older: ignored, H unchanged.
        run(c, state, 'publish', {'checkpoint': cp(1, heads[:3], time=NOW-1000), 'source_hash': None})
        assert state['held'] == two['held']
        for name, hs in [('stale_lower_n_higher_entry', heads + [C.digest(b'FAKE newer')]),
                         ('stale_lower_n_equal_height_conflict', heads[:3] + [C.digest(b'FAKE other')])]:
            c, state = new(name, two)
            run(c, state, 'publish', {'checkpoint': cp(1, hs, time=NOW-1000), 'source_hash': None}, error='chain_diverged')
        for name, page_heads, target in [
            ('withheld_restore_then_higher_heights', [C.digest(b'FAKE fork'), C.digest(b'FAKE fork tail')], cp(2, heads[:2] + [C.digest(b'FAKE branch ' + bytes([i])) for i in range(4)])),
            ('spliced_head_list', [heads[1], heads[2]], cp(2, heads + [heads[2], heads[1]])),
            ('wrong_head_count', [heads[1]], cp(2, heads + [heads[1], heads[2]])),
        ]:
            c, state = new(name, accepted)
            body = staged(c, state, target, [page('appended', 'workspace', entry(heads), page_heads)])
            run(c, state, 'publish', body, error='chain_diverged')
        c, state = new('equal_seq_other_acc', accepted)
        target = resign(cp(2), workspace_log={**entry(heads), 'acc': C.ZERO})
        run(c, state, 'publish', staged(c, state, target), error='chain_diverged')

        target = cp(2, heads + [heads[1]])
        pg = page('appended', 'workspace', entry(heads), [heads[1]])
        args = {'source': C.checkpoint_hash(base), 'target': C.checkpoint_hash(target)}
        for name, mode in [('staging_missing_manifest', 'none'), ('staging_missing_page', 'missing'), ('staging_expiry', 'expired')]:
            c, state = new(name, accepted)
            if mode == 'missing':
                run(c, state, 'manifest', {'pages': [C.descriptor(0, pg)]}, **args)
            else:
                staged(c, state, target, [pg], manifest=mode != 'none')
            run(c, state, 'publish', {'checkpoint': target, 'source_hash': args['source']}, error='staging_incomplete', now=NOW+C.HOUR if mode == 'expired' else NOW)
        c, state = new('staging_immutable_page_and_manifest', accepted)
        run(c, state, 'page', pg, i=0, **args)
        run(c, state, 'page', pg, i=0, **args)
        run(c, state, 'page', page('appended', 'workspace', entry(heads), [heads[2]]), i=0, error='staging_conflict', **args)
        run(c, state, 'manifest', {'pages': [C.descriptor(0, pg)]}, **args)
        run(c, state, 'manifest', {'pages': []}, error='staging_conflict', **args)
        c, state = new('staging_manifest_order_and_contiguity', accepted)
        p2 = page('appended', 'workspace', entry(heads + [heads[1]]), [heads[2]])
        ds = [C.descriptor(0, pg), C.descriptor(1, p2)]
        run(c, state, 'manifest', {'pages': ds[::-1]}, error='malformed', **args)
        run(c, state, 'manifest', {'pages': [ds[0], {**ds[1], 'after_seq': 99}]}, error='malformed', **args)
        run(c, state, 'manifest', {'pages': ds}, **args)
        run(c, state, 'page', pg, i=0, **args)
        run(c, state, 'page', p2, i=1, **args)
        run(c, state, 'manifest', {'pages': ds}, **args)
        c, state = new('staging_quota_two_open_sets', accepted)
        for i in range(3):
            run(c, state, 'manifest', {'pages': []}, source=args['source'], target=C.digest(bytes([i])), error='quota_exceeded' if i == 2 else None)
        c, state = new('staging_bound_to_target', accepted)
        staged(c, state, target, [pg])
        run(c, state, 'publish', {'checkpoint': cp(3), 'source_hash': args['source']}, error='staging_incomplete')

        def restore(target_n=2, source=base, log='workspace', prefix=heads[:2], ident='01BBBBBBBBBBBBBBBBBBBBBBBB', time=NOW, revocations=(), modifications=None, cert_=cert, key='phone.sig', omit=()):
            line = {'v': 2, 'hash_v': 1, 'id': ident, 'seq': len(prefix)+1, 'at': at(time), 'type': 'restore',
                    'actor': {'kind': 'person', 'id': 'p_'+cert_['o']['person_id'], 'device': 'd_'+cert_['o']['device_id']},
                    'based_on': prefix[-1], 'prev': prefix[-1], 'roster_v': 1, 'auth': 'passphrase',
                    'from_seq': len(prefix), 'head': prefix[-1], 'abandoned': {'seq': 4, 'head': heads[-1]} if len(prefix) < 4 else None,
                    'abandoned_decisions': [], 'source': C.reference(source), 'reason': 'rollback', 'revocations': list(revocations)}
            if log != 'workspace':
                line['ws_seq'] = 4
            line.update(modifications or {})
            for k in omit:
                del line[k]
            line['sig'] = R.b64u(S.sign(keys[key], C.event_bytes(S, line, ws, log)))
            line['host_sig'] = R.b64u(S.sign(keys['wsk_a.sig'], C.event_bytes(S, line, ws, log, True)))
            branch = prefix + [C.event_head(line)]
            tickets = dict(source['o']['tickets']) if source else {}
            if log != 'workspace':
                tickets[log] = entry(branch)
            target = R.sign_object(S, keys['wsk_a.sig'], {'v': 2, 'suite': S.id, 'kind': 'workspace_checkpoint',
                'workspace_id': ws, 'genesis': root, 'n': target_n, 'at': at(time), 'tickets': tickets,
                'workspace_log': entry(branch) if log == 'workspace' else source['o']['workspace_log'] if source else entry(heads)})
            return target, {'line': line, 'cert': cert_, 'authz': {'delegation': delegation}, 'log': log}

        def offer_restore(c, state, target, bundle, error=None, pages=None):
            line = bundle['line']
            log = UID if 'ws_seq' in line else 'workspace'
            if pages is None:
                pages = [page('abandoned', log, entry(heads[:2]), heads[2:])]
            body = staged(c, state, target, pages)
            body['restore'] = bundle
            run(c, state, 'publish', body, error=error)
            return body

        t, bundle = restore()
        c, state = new('workspace_restore_and_exact_retry', accepted)
        restore_body = offer_restore(c, state, t, bundle)
        restored_state = copy.deepcopy(state)
        run(c, state, 'publish', restore_body)
        c, state = new('historical_proof_abandoned_branch', restored_state)
        run(c, state, 'proof', to=C.checkpoint_hash(base), log='workspace', **{'from': C.ZERO, 'limit': 2})
        run(c, state, 'proof', to=C.checkpoint_hash(base), log='workspace', **{'from': entry(heads[:2])['acc']})
        run(c, state, 'get', hash=C.checkpoint_hash(base), now=NOW+30*C.DAY)
        # Review 6: both reach the person-signed source check (outer source_hash correct, staging complete).
        c, state = new('concurrent_restores_one_source', restored_state)
        t2, b2 = restore(3, ident='01CCCCCCCCCCCCCCCCCCCCCCCC')
        run(c, state, 'publish', {'checkpoint': t2, 'source_hash': C.checkpoint_hash(base), 'restore': b2}, error='restore_source_mismatch')
        loser = staged(c, state, t2, [])
        loser['restore'] = b2
        run(c, state, 'publish', loser, error='restore_source_mismatch')
        c, state = new('old_genuine_restore_after_chain_regrew', restored_state)
        new_heads = heads[:2] + [C.event_head(bundle['line'])] + [heads[1], heads[2], heads[3]]
        advanced = cp(3, new_heads)
        run(c, state, 'publish', staged(c, state, advanced, [page('appended', 'workspace', entry(new_heads[:3]), new_heads[3:])]))
        t4, b4 = restore(4, ident='01CCCCCCCCCCCCCCCCCCCCCCCC')
        replayed = staged(c, state, t4, [])
        replayed['restore'] = b4
        run(c, state, 'publish', replayed, error='restore_source_mismatch')
        c, state = new('restore_id_single_use', restored_state)
        reused_t, reused_b = restore(3, source=t, prefix=new_heads[:3])
        offer_restore(c, state, reused_t, reused_b, error='restore_reused', pages=[])
        for name, changes, error in [
            ('restore_at_before_source_at_refused', {'at': at(NOW-1000)}, 'restore_invalid'),
            ('restore_at_after_target_at_refused', {'at': at(NOW+1000)}, 'restore_invalid'),
            ('restore_retained_head_mismatch', {'head': heads[0], 'prev': heads[0]}, 'restore_invalid'),
            ('restore_abandoned_equal_height_conflict', {'abandoned': {'seq': 4, 'head': heads[0]}}, 'restore_invalid'),
            ('restore_wrong_sequence', {'seq': 7}, 'restore_invalid'),
            ('restore_unknown_field', {'unknown': True}, 'restore_invalid'),
            ('restore_null_source_initialized', {'source': None}, 'restore_source_mismatch'),
        ]:
            c, state = new(name, accepted)
            target, b = restore(modifications=changes)
            offer_restore(c, state, target, b, error)
        c, state = new('restore_at_rewritten_within_window_accepted', accepted)
        target, b = restore(time=NOW+1000)
        target = resign(target, at=at(NOW+2000))
        offer_restore(c, state, target, b)
        for name, kind, error in [('restore_missing_authorization', 'missing', 'restore_not_owner'),
                                  ('restore_signer_not_in_current_list_refused_at_relay', 'member', 'restore_not_owner'),
                                  ('restore_cert_decide_only_refused', 'decide', 'restore_not_owner'),
                                  ('restore_expired_cert_fresh_source', 'expired', 'restore_not_owner'),
                                  ('restore_delegation_other_person', 'delegation', 'restore_not_owner'),
                                  ('restore_bad_host_signature', 'host', 'restore_invalid')]:
            start = copy.deepcopy(accepted)
            b = copy.deepcopy(bundle)
            if kind == 'member':
                start['members'] = {}
            if kind == 'missing':
                b['authz'] = {}
            if kind == 'delegation':
                b['authz']['delegation'] = R.sign_object(S, keys['person_bob.sig'], {**delegation['o'], 'owner_person_id': v['ids']['person_bob']})
            if kind in ('decide', 'expired'):
                b['cert'] = R.sign_object(S, keys['person_alice.sig'], {**cert['o'], **({'scopes_max': ['look', 'decide']} if kind == 'decide' else {'expires_ms': NOW-1})})
            if kind == 'host':
                b['line']['host_sig'] = R.b64u(bytes(64))
            c, state = new(name, start)
            offer_restore(c, state, t, b, error)
        c, state = new('restore_forward_prefix', accepted)
        prefix = heads + [C.digest(b'FAKE forward')]
        target, b = restore(prefix=prefix)
        offer_restore(c, state, target, b, pages=[page('retained', 'workspace', entry(heads), prefix[4:])])
        c, state = new('restore_zero_length_retained_prefix', accepted)
        target, b = restore(prefix=heads)
        offer_restore(c, state, target, b, pages=[])
        c, state = new('bootstrap_null_source', pinned)
        target, b = restore(1, source=None)
        offer_restore(c, state, target, b, pages=[page('retained', 'workspace', C.EMPTY, heads[:2])])
        c, state = new('ticket_restore', pinned)
        ticket_base = cp(1, tickets={UID: entry(heads)})
        run(c, state, 'publish', staged(c, state, ticket_base, [page('appended', 'workspace', C.EMPTY, heads), page('appended', UID, C.EMPTY, heads)]))
        target, b = restore(source=ticket_base, log=UID)
        offer_restore(c, state, target, b)
        ticket_state = copy.deepcopy(state)
        c, state = new('ticket_entry_cannot_disappear', ticket_state)
        run(c, state, 'publish', staged(c, state, cp(3)), error='chain_diverged')

        other = v['certs']['signed']['laptop']
        other_id = other['o']['device_id']
        def rev(reason, time=NOW):
            return R.sign_object(S, keys['person_alice.sig'], {'v': 2, 'suite': S.id, 'kind': 'revocation',
                'person_id': v['ids']['person_alice'], 'device_id': other_id, 'revoked_ms': time, 'reason': reason})
        for name, known, offered in [('missing', 'lost', None), ('weaker', 'compromised', 'lost'),
                                     ('same_strength_other_bytes', 'lost', 'retired'), ('stronger', 'lost', 'compromised')]:
            start = copy.deepcopy(accepted)
            start['ever_devices'].append(other_id)
            start['revocations'][other_id] = rev(known)
            c, state = new('B1_' + name, start)
            evidence = [{'revocation': rev(offered, NOW-1000), 'device_cert': other, 'pk_pub': pk}] if offered else []
            target, b = restore(revocations=evidence)
            offer_restore(c, state, target, b, 'restore_missing_revocation' if name in ('missing', 'weaker') else None)
        c, state = new('B1_invalid_evidence_atomic', accepted)
        evidence = [{'revocation': rev('lost'), 'device_cert': other, 'pk_pub': wsk}]
        target, b = restore(revocations=evidence)
        offer_restore(c, state, target, b, 'restore_invalid')

        c, state = new('pagination_endpoint_while_relay_advances', restored_state)
        run(c, state, 'proof', to=C.checkpoint_hash(base), log='workspace', **{'from': C.ZERO, 'limit': 2})
        target = cp(3, heads[:2] + [C.event_head(bundle['line']), heads[3]])
        run(c, state, 'publish', staged(c, state, target, [page('appended', 'workspace', entries_of(t), [heads[3]])]))
        run(c, state, 'proof', to=C.checkpoint_hash(base), log='workspace', **{'from': entry(heads[:2])['acc']})
        run(c, state, 'transitions', to=C.checkpoint_hash(base), after_n=0)
        run(c, state, 'transitions', to=C.checkpoint_hash(t), after_n=0, limit=1)
        c, state = new('checkpoint_gone_all_endpoint_routes', accepted)
        target = cp(2)
        run(c, state, 'publish', staged(c, state, target))
        for op, kwargs in [('get', {'hash': C.checkpoint_hash(base)}), ('proof', {'to': C.checkpoint_hash(base), 'log': 'workspace', 'from': C.ZERO}), ('transitions', {'to': C.checkpoint_hash(base), 'after_n': 0})]:
            run(c, state, op, now=NOW+C.DAY, error='checkpoint_gone', **kwargs)
        c, state = new('baseline_retention_release_and_expiry', accepted)
        body = {'hash': C.checkpoint_hash(base), 'offer_id': 'ab'*16}
        run(c, state, 'baseline', body)
        run(c, state, 'baseline', body, now=NOW+1)
        run(c, state, 'publish', staged(c, state, cp(2)))
        run(c, state, 'get', hash=body['hash'], now=NOW+2*C.DAY)
        baseline_state = copy.deepcopy(state)
        run(c, state, 'baseline_delete', {'hash': body['hash']}, now=NOW+2*C.DAY)
        run(c, state, 'baseline_delete', {'hash': body['hash']}, now=NOW+2*C.DAY)
        run(c, state, 'get', hash=body['hash'], now=NOW+2*C.DAY, error='checkpoint_gone')
        c, state = new('baseline_seven_day_expiry', baseline_state)
        run(c, state, 'get', hash=body['hash'], now=NOW+7*C.DAY, error='checkpoint_gone')
        c, state = new('baseline_capacity_16', accepted)
        for n in range(1, 18):
            target = cp(n)
            if n > 1:
                run(c, state, 'publish', staged(c, state, target))
            run(c, state, 'baseline', {'hash': C.checkpoint_hash(target), 'offer_id': f'{n:032x}'}, error='quota_exceeded' if n == 17 else None)
        c, state = new('restore_owner_policy_removed_device_accepted_at_checkpoint_receiver',
                       {**accepted, 'members': {}})
        run(c, state, 'owner_policy', bundle, historical=True)
        run(c, state, 'owner_policy', bundle, error='restore_not_owner')
        c, state = new('historical_owner_policy_expiry_at_line_not_today', accepted)
        b = copy.deepcopy(bundle)
        b['cert'] = R.sign_object(S, keys['person_alice.sig'], {**cert['o'], 'expires_ms': NOW+1000})
        run(c, state, 'owner_policy', b, historical=True, now=NOW+100000)
        run(c, state, 'owner_policy', b, now=NOW+100000, error='restore_not_owner')
        b['line']['at'] = at(NOW+2000)
        run(c, state, 'owner_policy', b, historical=True, now=NOW+100000, error='restore_not_owner')
        c, state = new('restore_cert_other_person_refused', accepted)
        b = copy.deepcopy(bundle)
        b['cert'] = R.sign_object(S, keys['person_bob.sig'], {**cert['o'], 'person_id': v['ids']['person_bob']})
        offer_restore(c, state, t, b, 'restore_not_owner')
        c, state = new('B1_signer_self_revoked_in_payload', accepted)
        self_rev = R.sign_object(S, keys['person_alice.sig'], {'v': 2, 'suite': S.id, 'kind': 'revocation',
            'person_id': v['ids']['person_alice'], 'device_id': device, 'revoked_ms': NOW, 'reason': 'lost'})
        target, b = restore(revocations=[{'revocation': self_rev, 'device_cert': cert, 'pk_pub': pk}])
        offer_restore(c, state, target, b, 'restore_not_owner')
        c, state = new('retained_page_from_stored_branch_node', accepted)
        offer_restore(c, state, t, bundle, pages=[page('retained', 'workspace', entry(heads[:1]), heads[1:2]),
            page('abandoned', 'workspace', entry(heads[:2]), heads[2:])])
        c, state = new('restore_refusal_does_not_consume_id', accepted)
        bad = copy.deepcopy(bundle); bad['authz'] = {}
        body = offer_restore(c, state, t, bad, 'restore_not_owner')
        body['restore'] = bundle
        run(c, state, 'publish', body)
        c, state = new('transitions_position_cursor_endpoint_bound', restored_state)
        prefix = heads[:2] + [C.event_head(bundle['line'])]
        target, b = restore(3, source=t, prefix=prefix, ident='01DDDDDDDDDDDDDDDDDDDDDDDD')
        offer_restore(c, state, target, b, pages=[])
        run(c, state, 'transitions', to=C.checkpoint_hash(target), after_n=0, limit=1)
        run(c, state, 'transitions', to=C.checkpoint_hash(target), after_n=2, limit=1)
        run(c, state, 'transitions', to=C.checkpoint_hash(t), after_n=2, limit=1)
        c, state = new('proof_source_on_abandoned_branch_not_current_branch', restored_state)
        run(c, state, 'proof', to=C.checkpoint_hash(t), log='workspace',
            **{'from': entry(heads)['acc']}, error='not_found')
        c, state = new('read_missing_and_bad_limits', accepted)
        run(c, state, 'get', hash=C.digest(b'FAKE unknown'), error='not_found')
        run(c, state, 'proof', to=C.checkpoint_hash(base), log='workspace',
            **{'from': C.ZERO, 'limit': 65537}, error='malformed')
        run(c, state, 'transitions', to=C.checkpoint_hash(base), after_n=-1, error='malformed')
        c, state = new('staging_digest_tamper', accepted)
        bad = {**pg, 'digest': C.ZERO}
        run(c, state, 'page', bad, i=0, **args, error='malformed')
        c, state = new('manifest_page_metadata_mismatch', accepted)
        run(c, state, 'manifest', {'pages': [C.descriptor(0, pg)]}, **args)
        run(c, state, 'page', page('retained', 'workspace', entry(heads), [heads[1]]), i=0,
            **args, error='staging_conflict')
        c, state = new('checkpoint_drops_or_changes_unchanged_ticket', ticket_state)
        held_ticket = state['held']
        wrong = resign(cp(3), tickets={UID: {**held_ticket['o']['tickets'][UID], 'head': heads[0]}})
        run(c, state, 'publish', staged(c, state, wrong), error='chain_diverged')
        c, state = new('ticket_restore_ws_seq_above_target', ticket_state)
        prefix = heads[:2] + [C.event_head(ticket_state['transitions'][-1]['line'])]
        target, b = restore(3, source=held_ticket, log=UID, prefix=prefix,
                            ident='01EEEEEEEEEEEEEEEEEEEEEEEE', modifications={'ws_seq': 999})
        offer_restore(c, state, target, b, 'restore_invalid', pages=[])
        # Review 1: a receiver refuses a signer it already knows revoked, whatever the reason and
        # whatever revoked_ms says relative to the host-chosen line.at.
        for reason in ('lost', 'retired', 'compromised'):
            for when, offset in (('before', -30 * C.DAY), ('after', 1000)):
                local = copy.deepcopy(accepted)
                local['revocations'][device] = R.sign_object(S, keys['person_alice.sig'], {
                    **self_rev['o'], 'reason': reason, 'revoked_ms': NOW + offset})
                c, state = new(f'historical_signer_known_{reason}_{when}_line_at_refused', local)
                run(c, state, 'owner_policy', bundle, historical=True, now=NOW+2000, error='restore_not_owner')
        c, state = new('ticket_restore_revocations_forbidden', ticket_state)
        target, b = restore(3, source=ticket_state['held'], log=UID, ident='01FFFFFFFFFFFFFFFFFFFFFFFF',
                            prefix=heads[:2], revocations=[{'revocation': rev('lost'), 'device_cert': other, 'pk_pub': pk}])
        offer_restore(c, state, target, b, 'restore_invalid', pages=[])
        for name, change in [('source_forged_hash', {'source': {'n': 1, 'hash': C.ZERO}}),
                             ('prev_not_payload_head', {'prev': heads[0]}),
                             ('person_fields_on_host_actor', {'actor': {'kind': 'host'}})]:
            c, state = new(name, accepted)
            target, b = restore(modifications=change)
            offer_restore(c, state, target, b, 'restore_source_mismatch' if name == 'source_forged_hash' else 'restore_invalid')
        c, state = new('target_must_end_exactly_at_restore', accepted)
        target = cp(2, heads[:2] + [C.event_head(bundle['line']), heads[0]])
        offer_restore(c, state, target, bundle, 'restore_invalid')
        c, state = new('checkpoint_bad_signature', pinned)
        bad = copy.deepcopy(base); bad['sig'] = R.b64u(bytes(64))
        run(c, state, 'publish', {'checkpoint': bad, 'source_hash': None}, error='bad_signature')
        c, state = new('checkpoint_wrong_suite', pinned)
        bad = copy.deepcopy(base); bad['o']['suite'] = 3
        run(c, state, 'publish', {'checkpoint': bad, 'source_hash': None}, error='wrong_suite')
        # Review 5: a revoked device of a non-owner person, evidenced by its self-certifying pk_pub.
        bob_cert = v['certs']['signed']['bob_phone']
        bob_pk = R.b64u(bytes.fromhex(v['keys']['person_bob.sig']['pub']))
        bob_rev = R.sign_object(S, keys['person_bob.sig'], {'v': 2, 'suite': S.id, 'kind': 'revocation',
            'person_id': v['ids']['person_bob'], 'device_id': bob_cert['o']['device_id'], 'revoked_ms': NOW - 1000, 'reason': 'lost'})
        foreign = copy.deepcopy(accepted)
        foreign['ever_devices'] = sorted(foreign['ever_devices'] + [bob_cert['o']['device_id']])
        foreign['revocations'][bob_cert['o']['device_id']] = bob_rev
        for name, pk_pub, error in [('B1_foreign_person_self_certifying', bob_pk, None),
                                    ('B1_foreign_person_wrong_key', pk, 'restore_invalid')]:
            c, state = new(name, foreign)
            target, b = restore(revocations=[{'revocation': bob_rev, 'device_cert': bob_cert, 'pk_pub': pk_pub}])
            offer_restore(c, state, target, b, error)
        c, state = new('B1_foreign_person_missing', foreign)
        offer_restore(c, state, t, bundle, 'restore_missing_revocation')

        # Review 3: the final request names its log; only that signed context is verified.
        c, state = new('restore_log_missing', accepted)
        b = copy.deepcopy(bundle); del b['log']
        offer_restore(c, state, t, b, 'restore_invalid')
        # R0: ws_seq exactly for ticket logs, now that the log is named rather than searched.
        c, state = new('restore_ticket_context_without_ws_seq', ticket_state)
        target, b = restore(3, source=ticket_state['held'], log=UID, prefix=heads[:2],
                            ident='01GGGGGGGGGGGGGGGGGGGGGGGG', omit=('ws_seq',))
        offer_restore(c, state, target, b, 'restore_invalid', pages=[page('abandoned', UID, entry(heads[:2]), [C.event_head(ticket_state['transitions'][-1]['line'])])])
        # Review 8: T-level time (checkpoint_time) versus line.at position (restore_invalid).
        c, state = new('restore_target_at_future_is_checkpoint_time', accepted)
        target, b = restore(time=NOW + 400000)
        target = resign(target, at=at(NOW + 400000))
        offer_restore(c, state, target, b, 'checkpoint_time')

        # Review 3: failed final publications are charged; the 17th in an hour is refused before work.
        c, state = new('publish_failure_budget', accepted)
        bad = copy.deepcopy(bundle); bad['line']['host_sig'] = R.b64u(bytes(64))
        ab_pages = [page('abandoned', 'workspace', entry(heads[:2]), heads[2:])]
        body = staged(c, state, t, ab_pages)
        body['restore'] = bad
        for i in range(C.FAILURE_BUDGET):
            run(c, state, 'publish', body, error='restore_invalid', now=NOW + i)
        good = copy.deepcopy(body); good['restore'] = bundle
        run(c, state, 'publish', good, error='quota_exceeded', now=NOW + C.FAILURE_BUDGET)
        staged(c, state, t, ab_pages, now=NOW + C.HOUR + 1)
        run(c, state, 'publish', good, now=NOW + C.HOUR + 1)

        # Review 10: a member releases only the pin whose offer_id it names; the host releases any.
        c, state = new('baseline_member_release_needs_offer_id', baseline_state)
        h = body_hash = C.checkpoint_hash(base)
        run(c, state, 'baseline_delete', {'hash': h, 'offer_id': 'cd' * 16}, role='member', now=NOW+2*C.DAY)
        run(c, state, 'baseline_delete', {'hash': h}, role='member', now=NOW+2*C.DAY)
        run(c, state, 'get', hash=body_hash, now=NOW+2*C.DAY)
        run(c, state, 'baseline_delete', {'hash': h, 'offer_id': 'ab' * 16}, role='member', now=NOW+2*C.DAY)
        run(c, state, 'get', hash=body_hash, now=NOW+2*C.DAY, error='checkpoint_gone')

        add_walks(S, v, keys, cases, new, run, staged, page, restore, offer_restore, cp, resign, entry,
                  {'base': base, 'accepted': accepted, 'pinned': pinned, 'restored': restored_state,
                   'bundle': bundle, 't': t, 'heads': heads, 'root': root, 'ws': ws, 'wsk': wsk, 'pk': pk,
                   'cert': cert, 'delegation': delegation, 'other': other, 'rev': rev, 'self_rev': self_rev})
        for c in cases:
            c['expect'] = replay(S, c)
            assert c['expect']['results'] == [s['expect'] for s in c['steps']]
        v['checkpoints'] = {'objects': {'pin': pin_body, 'checkpoint': base, 'page': page('appended', 'workspace', C.EMPTY, heads),
                                       'restore': bundle, 'target': t}, 'cases': cases}


def entries_of(cp):
    return cp['o']['workspace_log']


def add_walks(S, v, keys, cases, new, run, staged, page, restore, offer_restore, cp, resign, entry, x):
    """§19.8 device synchronisation. States marked 'forged' are what a malicious relay (and WSK holder)
    serves; the device must refuse them with H unchanged."""
    base, accepted, pinned, restored, bundle, t, heads = (x[k] for k in ('base', 'accepted', 'pinned', 'restored', 'bundle', 't', 'heads'))
    laptop = x['other']
    laptop_id = laptop['o']['device_id']
    device = x['cert']['o']['device_id']

    def dev(held=None, revocations=None):
        d = C.device_initial(x['ws'], x['wsk'], x['pk'], x['root'], held)
        d['revocations'] = revocations or {}
        return d

    def apply(state, op, body=None, now=NOW, **args):
        result = C.dispatch(S, state, op, body, now_ms=now, **args)
        assert result['status'] == 200, result
        return result

    def stage(state, target, pages=()):
        src = C.checkpoint_hash(state['held']) if state['held'] else None
        args = {'source': src, 'target': C.checkpoint_hash(target)}
        ordered = sorted(pages, key=lambda p: (p['kind'], p['log'], p['after_seq']))
        for i, p in enumerate(ordered):
            apply(state, 'page', p, i=i, **args)
        apply(state, 'manifest', {'pages': [C.descriptor(i, p) for i, p in enumerate(ordered)]}, **args)
        return {'checkpoint': target, 'source_hash': src}

    def publish(state, target, pages=(), bundle_=None, now=NOW):
        body = stage(state, target, pages)
        if bundle_:
            body['restore'] = bundle_
        apply(state, 'publish', body, now=now)

    def forge(state, target, log, start, new_heads, bundle_=None, source=None):
        """Install a WSK-signed checkpoint as the relay's H without the relay's checks."""
        C.extend(state, log, start, new_heads)
        state['checkpoints'][C.checkpoint_hash(target)] = {'checkpoint': target, 'superseded_ms': None, 'permanent': True}
        state['held'] = target
        if bundle_:
            state['transitions'].append({'restore_id': bundle_['line']['id'], 'source_hash': C.checkpoint_hash(source),
                                         'target_hash': C.checkpoint_hash(target), 'target_n': target['o']['n'], **bundle_})

    def sync(name, state, device_state, error=None, result='ok', **args):
        c, st = new(name, state)
        out = run(c, st, 'device_sync', device_state, error=error, **args)
        if not error:
            assert out['result'] == result, (name, out['result'])
        return out

    ab = [page('abandoned', 'workspace', entry(heads[:2]), heads[2:])]
    extra = [C.digest(b'FAKE grown 5'), C.digest(b'FAKE grown 6')]
    grown = copy.deepcopy(accepted)
    publish(grown, cp(2, heads + extra), [page('appended', 'workspace', entry(heads), extra)])
    out = sync('walk_plain_growth', grown, dev(base))
    assert out['device']['held'] == grown['held']
    sync('walk_initial_device_full_proof', accepted, dev())
    # A source above the device's work state must still extend it (review 2, extension proof).
    regrown = copy.deepcopy(grown)
    tg, bg = restore(3, source=grown['held'], ident='01NNNNNNNNNNNNNNNNNNNNNNNN',
                     modifications={'abandoned': {'seq': 6, 'head': extra[1]}})
    publish(regrown, tg, [page('abandoned', 'workspace', entry(heads[:2]), heads[2:] + extra)], bg)
    sync('walk_source_must_extend_work', regrown, dev(cp(1, heads[:3] + [C.digest(b'FAKE local fork')])),
         error='sync_incomplete')
    sync('walk_lagging_relay_ignored', accepted, dev(cp(2)), result='ignored')
    sync('walk_endpoint_gone_keeps_held', grown, dev(base), error='checkpoint_gone',
         endpoint=C.checkpoint_hash(base), now=NOW + C.DAY)

    # Two restores the device missed, then ordinary growth after the last one.
    two = copy.deepcopy(restored)
    prefix = heads[:2] + [C.event_head(bundle['line'])]
    t3, b3 = restore(3, source=t, prefix=prefix, ident='01DDDDDDDDDDDDDDDDDDDDDDDD')
    publish(two, t3, [], b3)
    tail = [C.digest(b'FAKE after restore')]
    t4 = cp(4, prefix + [C.event_head(b3['line'])] + tail)
    publish(two, t4, [page('appended', 'workspace', entry(prefix + [C.event_head(b3['line'])]), tail)])
    out = sync('walk_two_restores_then_growth', two, dev(base))
    assert out['device']['applied'] == [bundle['line']['id'], b3['line']['id']]

    boot = copy.deepcopy(pinned)
    tb, bb = restore(1, source=None)
    publish(boot, tb, [page('retained', 'workspace', C.EMPTY, heads[:2])], bb)
    sync('walk_bootstrap_null_source', boot, dev())

    # Review 2, the device half of the old-restore defence: a withheld genuine restore R (source=base)
    # and a WSK-forged T at a higher n. Its source is not the device's work state.
    t_old, b_old = restore(3, ident='01CCCCCCCCCCCCCCCCCCCCCCCC')
    forged = copy.deepcopy(restored)
    forge(forged, t_old, 'workspace', entry(heads[:2]), [C.event_head(b_old['line'])], b_old, base)
    synced = dev(t)
    synced['applied'] = [bundle['line']['id']]
    sync('walk_replayed_old_restore_source_not_work', forged, synced, error='chain_diverged')
    sync('walk_replayed_old_restore_after_genuine_one', forged, dev(base), error='chain_diverged')

    nulled = copy.deepcopy(pinned)
    tn, bn = restore(2, source=None)
    publish(nulled, tn, [page('retained', 'workspace', C.EMPTY, heads[:2])], bn)
    sync('walk_initialized_device_refuses_null_source', nulled, dev(base), error='chain_diverged')

    relabel = copy.deepcopy(two)
    relabel['transitions'][1]['target_n'] = 4
    sync('walk_bundle_target_n_must_match_target', relabel, dev(t), error='chain_diverged')
    swapped = copy.deepcopy(restored)
    publish(swapped, cp(3, prefix, time=NOW + 2000), [])
    swapped['checkpoints'][C.checkpoint_hash(t)]['checkpoint'] = resign(t, at=at(NOW + 1000))
    sync('walk_fetched_target_bound_to_hash', swapped, dev(base), error='chain_diverged')

    older = copy.deepcopy(accepted)
    low = cp(3, time=NOW - 1000)
    forge(older, low, 'workspace', entry(heads), [])
    sync('walk_endpoint_higher_n_lower_at', older, dev(cp(2)), error='chain_diverged')
    higher = copy.deepcopy(accepted)
    lower = cp(1, heads + extra[:1], time=NOW + 1000)
    forge(higher, lower, 'workspace', entry(heads), extra[:1])
    sync('walk_endpoint_lower_n_higher_entry', higher, dev(cp(2)), error='chain_diverged')

    # The device's own checks, where an honest relay would already have refused.
    self_revoked = copy.deepcopy(accepted)
    ts, bs = restore(revocations=[{'revocation': x['self_rev'], 'device_cert': x['cert'], 'pk_pub': x['pk']}])
    forge(self_revoked, ts, 'workspace', entry(heads[:2]), [C.event_head(bs['line'])], bs, base)
    sync('walk_signer_revoked_in_own_bundle_refused', self_revoked, dev(base), error='chain_diverged')
    rootless = copy.deepcopy(pinned)
    wrong = [C.digest(b'FAKE other root')] + heads[1:]
    forge(rootless, cp(1, wrong), 'workspace', C.EMPTY, wrong)
    sync('walk_initial_device_refuses_wrong_root', rootless, dev(), error='sync_incomplete')

    spliced = copy.deepcopy(grown)
    acc5 = entry(heads + extra[:1])['acc']
    spliced['nodes']['workspace'][acc5]['head'] = extra[1]
    sync('walk_spliced_proof_page', spliced, dev(base), error='sync_incomplete')

    # Review 1 at the device: revocations it already knows refuse their signer, at any revoked_ms.
    ticket_base = cp(1, tickets={UID: entry(heads)})
    tickets = copy.deepcopy(pinned)
    publish(tickets, ticket_base, [page('appended', 'workspace', C.EMPTY, heads), page('appended', UID, C.EMPTY, heads)])
    ticket_held = copy.deepcopy(tickets)
    tt, bt = restore(source=ticket_base, log=UID)
    publish(tickets, tt, [page('abandoned', UID, entry(heads[:2]), heads[2:])], bt)
    for reason in ('lost', 'compromised'):
        known = {device: R.sign_object(S, keys['person_alice.sig'], {'v': 2, 'suite': S.id, 'kind': 'revocation',
                 'person_id': x['cert']['o']['person_id'], 'device_id': device, 'revoked_ms': NOW - 30 * C.DAY, 'reason': reason})}
        sync(f'walk_known_{reason}_signer_refused_workspace', restored, dev(base, known), error='chain_diverged')
        sync(f'walk_known_{reason}_signer_refused_ticket', tickets, dev(ticket_base, known), error='chain_diverged')

    # Revocations learned earlier in the same walk refuse later signers; learned later, they alarm.
    members = {device: ['look', 'decide', 'operate'], laptop_id: ['look', 'decide', 'operate']}
    laptop_lost = {'revocation': x['rev']('lost'), 'device_cert': laptop, 'pk_pub': x['pk']}
    early = copy.deepcopy(ticket_held)
    early['members'] = members
    ta, ba = restore(2, source=ticket_base, ident='01HHHHHHHHHHHHHHHHHHHHHHHH', revocations=[laptop_lost])
    publish(early, ta, ab, ba)
    hidden = early['revocations'].pop(laptop_id)
    tl, bl = restore(3, source=ta, log=UID, ident='01JJJJJJJJJJJJJJJJJJJJJJJJ', cert_=laptop, key='laptop.sig',
                     modifications={'ws_seq': 3})
    publish(early, tl, [page('abandoned', UID, entry(heads[:2]), heads[2:])], bl)
    early['revocations'][laptop_id] = hidden  # forged: the relay accepted a revoked signer
    sync('walk_signer_revoked_earlier_in_walk_refused', early, dev(ticket_base), error='chain_diverged')
    late = copy.deepcopy(ticket_held)
    late['members'] = members
    t1, b1 = restore(2, source=ticket_base, log=UID, ident='01KKKKKKKKKKKKKKKKKKKKKKKK', cert_=laptop, key='laptop.sig')
    publish(late, t1, [page('abandoned', UID, entry(heads[:2]), heads[2:])], b1)
    laptop_bad = {'revocation': x['rev']('compromised'), 'device_cert': laptop, 'pk_pub': x['pk']}
    t2, b2 = restore(3, source=t1, ident='01MMMMMMMMMMMMMMMMMMMMMMMM', revocations=[laptop_bad])
    publish(late, t2, ab, b2)
    out = sync('walk_later_compromised_revocation_alarms', late, dev(ticket_base))
    assert out['device']['alarms'] == [laptop_id]
