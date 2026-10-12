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
        bob_pk = R.b64u(bytes.fromhex(v['keys']['person_bob.sig']['pub']))
        registry = {device: cert['o']['person_id']}
        person_keys = {cert['o']['person_id']: pk, v['ids']['person_bob']: bob_pk}
        blank = C.initial(ws, wsk, pk, delegation, {device: ['look', 'decide', 'operate']}, registry, person_keys)
        pin = R.sign_object(S, keys['phone.sig'], {'v': 2, 'suite': S.id, 'kind': 'genesis_pin',
                                                   'workspace_id': ws, 'wsk_pub': wsk, 'genesis': root})
        pin_body = {'pin': pin, 'cert': cert}
        cases = []

        def new(name, state=blank):
            c = {'name': name, 'state': copy.deepcopy(state), 'steps': []}
            cases.append(c)
            return c, copy.deepcopy(state)

        def run(c, state, op, body=None, error=None, now=NOW, **args):
            if op == 'publish':
                args.setdefault('generation', 1)  # the Orch-Holder generation is required
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
        state['revocations'][rkey(v['revocations'][0]['signed'])] = v['revocations'][0]['signed']
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

        def restore(target_n=2, source=base, log='workspace', prefix=heads[:2], ident='01BBBBBBBBBBBBBBBBBBBBBBBB', time=NOW, revocations=(), modifications=None, cert_=cert, key='phone.sig', omit=(), person_sig=None, tip=None, delegation_=None, target_time=None):
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
            line['sig'] = person_sig or R.b64u(S.sign(keys[key], C.event_bytes(S, line, ws, log)))
            line['host_sig'] = R.b64u(S.sign(keys['wsk_a.sig'], C.event_bytes(S, line, ws, log, True)))
            branch = prefix + [tip or C.event_head(line)]
            tickets = dict(source['o']['tickets']) if source else {}
            if log != 'workspace':
                tickets[log] = entry(branch)
            target = R.sign_object(S, keys['wsk_a.sig'], {'v': 2, 'suite': S.id, 'kind': 'workspace_checkpoint',
                'workspace_id': ws, 'genesis': root, 'n': target_n, 'at': at(target_time or time), 'tickets': tickets,
                'workspace_log': entry(branch) if log == 'workspace' else source['o']['workspace_log'] if source else entry(heads)})
            return target, {'line': line, 'cert': cert_, 'authz': {'delegation': delegation_ or delegation}, 'log': log}

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
        ticket_base_state = copy.deepcopy(state)
        target, b = restore(source=ticket_base, log=UID)
        offer_restore(c, state, target, b)
        ticket_state = copy.deepcopy(state)
        # Review F4: a ticket restore has no coverage check; owner policy alone refuses a relay-revoked signer.
        revoked_signer = copy.deepcopy(ticket_base_state)
        signer_lost = R.sign_object(S, keys['person_alice.sig'], {'v': 2, 'suite': S.id,
            'kind': 'revocation', 'person_id': cert['o']['person_id'], 'device_id': device, 'revoked_ms': NOW - 1000,
            'reason': 'lost'})
        revoked_signer['revocations'][rkey(signer_lost)] = signer_lost
        c, state = new('ticket_restore_by_relay_revoked_signer_refused', revoked_signer)
        offer_restore(c, state, target, b, 'restore_not_owner')
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
            start['revocations'][rkey(rev(known))] = rev(known)
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
        run(c, state, 'baseline_delete', {'hash': body['hash']}, role='host', now=NOW+2*C.DAY)
        run(c, state, 'baseline_delete', {'hash': body['hash']}, role='host', now=NOW+2*C.DAY)
        c2, unrolled = new('baseline_delete_requires_role', baseline_state)
        run(c2, unrolled, 'baseline_delete', {'hash': body['hash']}, error='malformed', now=NOW+2*C.DAY)
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
        run(c, state, 'owner_policy', b, historical=True, error='restore_not_owner')
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
                own = R.sign_object(S, keys['person_alice.sig'], {
                    **self_rev['o'], 'reason': reason, 'revoked_ms': NOW + offset})
                local['revocations'][rkey(own)] = own
                c, state = new(f'historical_signer_known_{reason}_{when}_line_at_refused', local)
                run(c, state, 'owner_policy', bundle, historical=True, now=NOW+2000, error='restore_not_owner')
        c, state = new('ticket_restore_revocations_forbidden', ticket_state)
        target, b = restore(3, source=ticket_state['held'], log=UID, ident='01FFFFFFFFFFFFFFFFFFFFFFFF',
                            prefix=heads[:2], revocations=[{'revocation': rev('lost'), 'device_cert': other, 'pk_pub': pk}])
        # Review L1: stage the abandoned proof so the revocations rule is the only failure.
        offer_restore(c, state, target, b, 'restore_invalid',
                      pages=[page('abandoned', UID, entry(heads[:2]), [C.event_head(ticket_state['transitions'][-1]['line'])])])
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
        bob_rev = R.sign_object(S, keys['person_bob.sig'], {'v': 2, 'suite': S.id, 'kind': 'revocation',
            'person_id': v['ids']['person_bob'], 'device_id': bob_cert['o']['device_id'], 'revoked_ms': NOW - 1000, 'reason': 'lost'})
        foreign = copy.deepcopy(accepted)
        foreign['ever_devices'] = sorted(foreign['ever_devices'] + [bob_cert['o']['device_id']])
        foreign['revocations'][rkey(bob_rev)] = bob_rev
        foreign['registry'][bob_cert['o']['device_id']] = v['ids']['person_bob']
        for name, pk_pub, error in [('B1_foreign_person_self_certifying', bob_pk, None),
                                    ('B1_foreign_person_wrong_key', pk, 'restore_invalid')]:
            c, state = new(name, foreign)
            target, b = restore(revocations=[{'revocation': bob_rev, 'device_cert': bob_cert, 'pk_pub': pk_pub}])
            offer_restore(c, state, target, b, error)
        c, state = new('B1_foreign_person_missing', foreign)
        offer_restore(c, state, t, bundle, 'restore_missing_revocation')

        # Review N1: evidence for a device the relay binds to a person must come from that person.
        laptop_id = other['o']['device_id']
        with_laptop = copy.deepcopy(accepted)
        with_laptop['members'][laptop_id] = ['look', 'decide']
        with_laptop['registry'][laptop_id] = v['ids']['person_alice']  # registered after initial: read live
        with_laptop['ever_devices'] = sorted(with_laptop['ever_devices'] + [laptop_id])
        forged_cert = R.sign_object(S, keys['person_bob.sig'], {**other['o'], 'person_id': v['ids']['person_bob']})
        forged_rev = R.sign_object(S, keys['person_bob.sig'], {'v': 2, 'suite': S.id, 'kind': 'revocation',
            'person_id': v['ids']['person_bob'], 'device_id': laptop_id, 'revoked_ms': NOW - 1000, 'reason': 'compromised'})
        c, state = new('B1_cross_person_evidence_for_member_device', with_laptop)
        target, b = restore(revocations=[{'revocation': forged_rev, 'device_cert': forged_cert, 'pk_pub': bob_pk}])
        offer_restore(c, state, target, b, 'restore_invalid')
        alice_bob_cert = R.sign_object(S, keys['person_alice.sig'], {**bob_cert['o'], 'person_id': v['ids']['person_alice']})
        alice_bob_rev = R.sign_object(S, keys['person_alice.sig'], {'v': 2, 'suite': S.id, 'kind': 'revocation',
            'person_id': v['ids']['person_alice'], 'device_id': bob_cert['o']['device_id'], 'revoked_ms': NOW - 1000, 'reason': 'compromised'})
        # The registry association (bob) refuses alice's entry for bob's device; a held revocation does not bind.
        alice_bob = {'revocation': alice_bob_rev, 'device_cert': alice_bob_cert, 'pk_pub': pk}
        bob_lost = {'revocation': bob_rev, 'device_cert': bob_cert, 'pk_pub': bob_pk}
        both = sorted([alice_bob, bob_lost], key=C.pair_of)
        c, state = new('B1_cross_person_evidence_for_associated_device', foreign)
        target, b = restore(revocations=both)
        offer_restore(c, state, target, b, 'restore_invalid')
        # orch-core #397: a chain pair of a device without association (a tombstone) binds no identity: another
        # person's pair is carried beside it (the host does so), and completeness stays per pair.
        tombstone = copy.deepcopy(foreign)
        del tombstone['registry'][bob_cert['o']['device_id']]
        c, state = new('B1_other_person_pair_beside_a_chain_pair', tombstone)
        target, b = restore(revocations=both)
        offer_restore(c, state, target, b)
        c, state = new('B1_other_person_pair_never_stands_in_for_a_chain_pair', tombstone)
        target, b = restore(revocations=[alice_bob])
        offer_restore(c, state, target, b, 'restore_missing_revocation')
        c, state = new('B1_unknown_device_self_certifying', accepted)
        target, b = restore(revocations=[bob_lost])
        offer_restore(c, state, target, b)
        # orch-core #397 (relay review a205ec2 reverted): two persons' entries for one device without association are
        # two pairs in one restore; neither registers the device.
        c, state = new('B1_two_persons_for_one_unknown_device', accepted)
        target, b = restore(revocations=both)
        offer_restore(c, state, target, b)
        # Review L2, per pair since orch-core #397: evidence entries are unique and sorted by (device, person).
        laptop_lost = {'revocation': rev('lost'), 'device_cert': other, 'pk_pub': pk}
        pair = sorted([laptop_lost, bob_lost], key=C.pair_of)
        for name, evidence in [('B1_evidence_duplicate_device', [laptop_lost, laptop_lost]),
                               ('B1_evidence_unsorted', pair[::-1]),
                               ('B1_evidence_unsorted_persons_of_one_device', both[::-1]),
                               ('B1_evidence_sorted_pair', pair)]:
            c, state = new(name, accepted)
            target, b = restore(revocations=evidence)
            offer_restore(c, state, target, b, None if name.endswith('sorted_pair') else 'restore_invalid')
        c, state = new('bootstrap_restore_wrong_root', pinned)
        wrong_root = [C.digest(b'FAKE wrong root'), heads[1]]
        target, b = restore(1, source=None, prefix=wrong_root)
        offer_restore(c, state, target, b, 'restore_invalid', pages=[page('retained', 'workspace', C.EMPTY, wrong_root)])
        # Card binding: the bundle's delegation has the card's content (orch-52 24305776), not other content.
        c, state = new('restore_delegation_other_content_than_the_card', accepted)
        b = copy.deepcopy(bundle)
        b['authz']['delegation'] = R.sign_object(S, keys['person_alice.sig'], {**delegation['o'], 'issued_ms': delegation['o']['issued_ms'] + 1})
        offer_restore(c, state, t, b, 'restore_not_owner')
        c, state = new('restore_delegation_same_content_bad_signature', accepted)
        b = copy.deepcopy(bundle)
        b['authz']['delegation'] = {**delegation, 'sig': R.b64u(bytes(64))}
        offer_restore(c, state, t, b, 'restore_not_owner')
        if S.id == 2:
            # A re-signed (here: malleated ECDSA) delegation with the same content is the same delegation.
            raw = R.unb64u(delegation['sig'])
            n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
            twin = {**delegation, 'sig': R.b64u(raw[:32] + (n - int.from_bytes(raw[32:], 'big')).to_bytes(32, 'big'))}
            assert R.verify_delegation(S, twin, R.unb64u(pk)).get('ok') == delegation['o']
            c, state = new('restore_delegation_resigned_bytes_accepted', accepted)
            b = copy.deepcopy(bundle); b['authz']['delegation'] = twin
            offer_restore(c, state, t, b)

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
        # Review N5: an exact retry of the accepted publication is served even with the budget spent.
        for i in range(C.FAILURE_BUDGET):
            run(c, state, 'publish', body, error='restore_source_mismatch', now=NOW + C.HOUR + 2 + i)
        run(c, state, 'publish', good, now=NOW + C.HOUR + 100)
        c, state = new('publish_budget_per_holder_generation', accepted)
        body = staged(c, state, t, ab_pages)
        body['restore'] = bad
        for i in range(C.FAILURE_BUDGET):
            run(c, state, 'publish', body, error='restore_invalid', now=NOW + i)
        run(c, state, 'publish', good, error='quota_exceeded', now=NOW + 20)
        run(c, state, 'publish', good, error='fenced', generation=0, now=NOW + 21)
        run(c, state, 'publish', good, generation=2, now=NOW + 22)
        # Review F1: takeovers stay unlimited (P3-D10), but refusals are bounded per workspace-hour.
        c, state = new('publish_budget_workspace_ceiling_across_takeovers', accepted)
        body = staged(c, state, t, ab_pages)
        body['restore'] = bad
        per = C.WORKSPACE_FAILURE_CEILING // C.FAILURE_BUDGET
        for g in range(per):
            for i in range(C.FAILURE_BUDGET):
                run(c, state, 'publish', body, error='restore_invalid', generation=2 + g, now=NOW + 100 * g + i)
        run(c, state, 'publish', good, error='quota_exceeded', generation=2 + per, now=NOW + 1000)
        staged(c, state, t, ab_pages, now=NOW + C.HOUR + 1000)
        run(c, state, 'publish', good, generation=2 + per, now=NOW + C.HOUR + 1000)
        c, state = new('publish_generation_required', accepted)
        run(c, state, 'publish', good, error='malformed', generation=None)

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
                   'cert': cert, 'delegation': delegation, 'other': other, 'rev': rev, 'self_rev': self_rev,
                   'bob_id': v['ids']['person_bob'], 'bob_pk': bob_pk})
        for c in cases:
            c['expect'] = replay(S, c)
            assert c['expect']['results'] == [s['expect'] for s in c['steps']]
        v['checkpoints'] = {'objects': {'pin': pin_body, 'checkpoint': base, 'page': page('appended', 'workspace', C.EMPTY, heads),
                                       'restore': bundle, 'target': t}, 'cases': cases}


def rkey(rev):
    """The relay and device state key of a revocation's pair (orch-core #397): 'device_id:person_id'."""
    return rev['o']['device_id'] + ':' + rev['o']['person_id']


def entries_of(cp):
    return cp['o']['workspace_log']


def add_walks(S, v, keys, cases, new, run, staged, page, restore, offer_restore, cp, resign, entry, x):
    """§19.8 device synchronisation. States marked 'forged' are what a malicious relay (and WSK holder)
    serves; the device must refuse them with H unchanged."""
    base, accepted, pinned, restored, bundle, t, heads = (x[k] for k in ('base', 'accepted', 'pinned', 'restored', 'bundle', 't', 'heads'))
    laptop = x['other']
    laptop_id = laptop['o']['device_id']
    device = x['cert']['o']['device_id']
    alice_laptop = laptop_id + ':' + x['cert']['o']['person_id']  # the pair key of alice's laptop revocations
    bob_laptop_key = laptop_id + ':' + x['bob_id']

    def dev(held=None, revocations=(), local=(), devices=None):
        """revocations (chain-learned) and local are lists of entries, stored under their pair (orch-core #397)."""
        known = {device: {'person_id': x['cert']['o']['person_id'], 'pk_pub': x['pk']}, **(devices or {})}
        d = C.device_initial(x['ws'], x['wsk'], x['pk'], x['root'], x['delegation'], known, held)
        d['revocations'] = {C.pair_key(item): item for item in revocations}
        d['local'] = {C.pair_key(item): item for item in local}
        return d

    def apply(state, op, body=None, now=NOW, **args):
        if op == 'publish':
            args.setdefault('generation', 1)
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
        known = R.sign_object(S, keys['person_alice.sig'], {'v': 2, 'suite': S.id, 'kind': 'revocation',
                 'person_id': x['cert']['o']['person_id'], 'device_id': device, 'revoked_ms': NOW - 30 * C.DAY, 'reason': reason})
        sync(f'walk_known_{reason}_signer_refused_workspace', restored,
             dev(base, [{'revocation': known, 'pk_pub': x['pk']}]), error='chain_diverged')
        own = {'revocation': known, 'device_cert': x['cert'], 'pk_pub': x['pk']}
        sync(f'walk_local_{reason}_signer_refused_ticket', tickets, dev(ticket_base, local=[own]),
             error='chain_diverged')
    # Review N4: an out-of-band revocation of another device does not strand the device behind an older
    # genuine workspace restore that could not list it; a chain-learned one is demanded (F1 completeness).
    laptop_rev = x['rev']('lost')
    laptop_item = {'revocation': laptop_rev, 'device_cert': laptop, 'pk_pub': x['pk']}
    out = sync('walk_local_revocation_not_demanded_as_evidence', restored, dev(base, local=[laptop_item]))
    # revocation.unpublished for a device this workspace does not know: kept pending, never forwarded (F1 §5.10).
    assert out['device']['pending'] == [alice_laptop] and out['device']['forward'] == []
    sync('walk_chain_revocation_demanded_as_evidence', restored,
         dev(base, [{'revocation': laptop_rev, 'pk_pub': x['pk']}]), error='chain_diverged')

    # Revocations learned earlier in the same walk refuse later signers; learned later, they alarm.
    members = {device: ['look', 'decide', 'operate'], laptop_id: ['look', 'decide', 'operate']}
    laptop_lost = {'revocation': x['rev']('lost'), 'device_cert': laptop, 'pk_pub': x['pk']}
    early = copy.deepcopy(ticket_held)
    early['members'] = members
    ta, ba = restore(2, source=ticket_base, ident='01HHHHHHHHHHHHHHHHHHHHHHHH', revocations=[laptop_lost])
    publish(early, ta, ab, ba)
    hidden = early['revocations'].pop(alice_laptop)
    hidden_global = early['global_revocations'].pop(alice_laptop)
    tl, bl = restore(3, source=ta, log=UID, ident='01JJJJJJJJJJJJJJJJJJJJJJJJ', cert_=laptop, key='laptop.sig',
                     modifications={'ws_seq': 3})
    publish(early, tl, [page('abandoned', UID, entry(heads[:2]), heads[2:])], bl)
    early['revocations'][alice_laptop] = hidden  # forged: the relay accepted a revoked signer
    early['global_revocations'][alice_laptop] = hidden_global
    failed_early = sync('walk_signer_revoked_earlier_in_walk_refused', early, dev(ticket_base), error='chain_diverged')
    # F1 row 149: the failed walk commits nothing, but the evidence it verified (laptop lost) stays local.
    assert failed_early['device']['held'] == ticket_base and failed_early['device']['applied'] == []
    assert list(failed_early['device']['local']) == [alice_laptop] and failed_early['device']['revocations'] == {}
    late = copy.deepcopy(ticket_held)
    late['members'] = members
    t1, b1 = restore(2, source=ticket_base, log=UID, ident='01KKKKKKKKKKKKKKKKKKKKKKKK', cert_=laptop, key='laptop.sig')
    publish(late, t1, [page('abandoned', UID, entry(heads[:2]), heads[2:])], b1)
    after_t1 = copy.deepcopy(late)
    assert laptop_id not in pinned['registry'] and after_t1['bound'][laptop_id] == x['cert']['o']['person_id']
    laptop_bad = {'revocation': x['rev']('compromised'), 'device_cert': laptop, 'pk_pub': x['pk']}
    t2, b2 = restore(3, source=t1, ident='01MMMMMMMMMMMMMMMMMMMMMMMM', revocations=[laptop_bad])
    publish(late, t2, ab, b2)
    out = sync('walk_later_compromised_revocation_alarms', late, dev(ticket_base))
    assert out['device']['alarms'] == [laptop_id]
    # Review N3: the same history synced in two walks raises the same alarm.
    c, st = new('walk_alarm_independent_of_walk_split', late)
    first = run(c, st, 'device_sync', dev(ticket_base), endpoint=C.checkpoint_hash(t1))
    assert first['device']['alarms'] == []
    second = run(c, st, 'device_sync', first['device'])
    assert second['device']['alarms'] == [laptop_id]
    # An out-of-band compromised revocation of a device that signed an applied transition also alarms.
    c, st = new('walk_local_compromised_alarms_for_applied_signer', late)
    first = run(c, st, 'device_sync', dev(ticket_base), endpoint=C.checkpoint_hash(t1))
    told = copy.deepcopy(first['device'])
    told['local'] = {alice_laptop: laptop_bad}
    again = run(c, st, 'device_sync', told, endpoint=C.checkpoint_hash(t1))
    assert again['device']['alarms'] == [laptop_id]
    # Review F6: learning it out of band alarms at once, without any walk.
    c, st = new('device_learn_compromised_alarms_at_once', late)
    first = run(c, st, 'device_sync', dev(ticket_base), endpoint=C.checkpoint_hash(t1))
    learned = run(c, st, 'device_learn', {'device': first['device'], 'evidence': laptop_bad})
    assert learned['device']['alarms'] == [laptop_id]
    # Review F2: the device applied t1 signed by the laptop; a forged bundle then carries another person's
    # compromised revocation of the laptop.
    forged_late = copy.deepcopy(after_t1)
    bob_cert_l = R.sign_object(S, keys['person_bob.sig'], {**laptop['o'], 'person_id': x['bob_id']})
    bob_rev_l = R.sign_object(S, keys['person_bob.sig'], {'v': 2, 'suite': S.id, 'kind': 'revocation',
        'person_id': x['bob_id'], 'device_id': laptop_id, 'revoked_ms': NOW - 1000, 'reason': 'compromised'})
    tf, bf = restore(3, source=t1, ident='01SSSSSSSSSSSSSSSSSSSSSSSS',
                     revocations=[{'revocation': bob_rev_l, 'device_cert': bob_cert_l, 'pk_pub': x['bob_pk']}])
    forge(forged_late, tf, 'workspace', entry(heads[:2]), [C.event_head(bf['line'])], bf, t1)
    sync('walk_evidence_for_applied_signer_from_another_person', forged_late, dev(ticket_base),
         error='chain_diverged')
    # Review A/B, inverted by orch-core #397: self-certified evidence never registers its device (no first-come
    # association, no identity binding from held revocations); every pair is retained, at the relay and on devices.
    q_pub = R.b64u(bytes.fromhex(v['keys']['intruder.sig']['pub']))
    q_id = R.person_id(S, R.unb64u(q_pub)).hex()
    q_cert = R.sign_object(S, keys['intruder.sig'], {**laptop['o'], 'person_id': q_id})

    def q_rev(reason):
        return R.sign_object(S, keys['intruder.sig'], {'v': 2, 'suite': S.id, 'kind': 'revocation', 'person_id': q_id,
                             'device_id': laptop_id, 'revoked_ms': NOW - 1000, 'reason': reason})
    q_item = {'revocation': q_rev('compromised'), 'device_cert': q_cert, 'pk_pub': q_pub}
    q_key = laptop_id + ':' + q_id
    selfcert = copy.deepcopy(accepted)
    r1, rb1 = restore(2, ident='01TTTTTTTTTTTTTTTTTTTTTTTT', revocations=[q_item])
    publish(selfcert, r1, ab, rb1)
    assert laptop_id not in selfcert['registry'] and q_key in selfcert['global_revocations']
    after_r1 = heads[:2] + [C.event_head(rb1['line'])]
    alice_item = {'revocation': x['rev']('compromised'), 'device_cert': laptop, 'pk_pub': x['pk']}
    both_items = sorted([alice_item, q_item], key=C.pair_of)
    r2, rb2 = restore(3, source=r1, prefix=after_r1, ident='01VVVVVVVVVVVVVVVVVVVVVVVV', revocations=[alice_item])
    r3, rb3 = restore(3, source=r1, prefix=after_r1, ident='01XXXXXXXXXXXXXXXXXXXXXXXX', revocations=[q_item])
    r4, rb4 = restore(3, source=r1, prefix=after_r1, ident='01YYYYYYYYYYYYYYYYYYYYYYYY')
    r5, rb5 = restore(3, source=r1, prefix=after_r1, ident='01YYYYYYYYYYYYYYYYYYYYYYYZ', revocations=both_items)
    c, st = new('B1_self_certified_evidence_never_registers', selfcert)
    # The device id stays refused for registration (its chain-learned pair, P3-D30), but nothing binds its person.
    run(c, st, 'register_device', {'device_id': laptop_id, 'person_id': x['cert']['o']['person_id']}, error='revoked')
    run(c, st, 'register_device', {'device_id': device, 'person_id': x['bob_id']}, error='cert_conflict')
    run(c, st, 'register_device', {'device_id': device, 'person_id': x['cert']['o']['person_id']})
    # alice's pair is accepted as evidence, but never stands in for Q's chain pair (completeness per pair).
    offer_restore(c, st, r2, rb2, 'restore_missing_revocation', pages=[])
    offer_restore(c, st, r3, rb3, pages=[])
    assert list(st['revocations']) == [q_key]
    c, st = new('B1_other_person_pair_after_a_self_certified_pair', selfcert)
    offer_restore(c, st, r5, rb5, pages=[])
    assert sorted(st['revocations']) == sorted([q_key, alice_laptop]) and laptop_id not in st['registry']
    c, st = new('B1_self_certified_coverage_still_demanded', selfcert)
    offer_restore(c, st, r4, rb4, 'restore_missing_revocation', pages=[])
    # A registry association that contradicts the chain pair (unreachable: a new registration of a device id with a
    # chain-learned revocation of any person is refused on both routes, P3-D30 cases below) never discards the held revocation; it strands the workspace (F1 §5.10 accepted availability limit:
    # a conflicting association plus a completeness obligation). One that agrees keeps carrying it.
    # Each offer is its own case: refused offers keep their staging sets, and two open sets are the quota.
    for name, person, steps in [
            ('B1_registry_contradiction', x['cert']['o']['person_id'],
             [('keeps_revocation', r4, rb4, 'restore_missing_revocation'),
              ('associated_pair_alone_missing', r2, rb2, 'restore_missing_revocation'),
              ('strands_the_chain_pair', r3, rb3, 'restore_invalid'),
              ('strands_both_pairs', r5, rb5, 'restore_invalid')]),
            ('B1_registry_same_person', q_id,
             [('keeps_revocation', r4, rb4, 'restore_missing_revocation'),
              ('refuses_other_person', r2, rb2, 'restore_invalid'),
              ('refuses_other_person_beside', r5, rb5, 'restore_invalid'),
              ('accepts_its_pair', r3, rb3, None)])]:
        raced = copy.deepcopy(selfcert)
        raced['registry'][laptop_id] = person
        del raced['global_revocations'][q_key]
        for suffix, target_, bundle_, error_ in steps:
            c, st = new(name + '_' + suffix, raced)
            offer_restore(c, st, target_, bundle_, error_, pages=[])
    # P3-D30 (orch-52 rulings 2 and 4): the registration refusal that keeps the contradiction above unreachable, on
    # both routes (PUT /v2/devices = 'device_put', POST /v2/accounts = 'account'). A chain-learned pair of ANY person
    # refuses a new registration (bob's account attempt is refused before account_exists); out-of-band-only
    # evidence refuses only its own pair, never another person's registration.
    def account(person, pk):
        return {'device_id': laptop_id, 'person_id': person, 'route': 'account', 'pk_pub': pk}
    alice_id = x['cert']['o']['person_id']
    c, st = new('P3_D30_chain_learned_pair_refuses_registration', selfcert)
    run(c, st, 'register_device', {'device_id': laptop_id, 'person_id': alice_id}, error='revoked')
    run(c, st, 'register_device', account(x['bob_id'], x['bob_pk']), error='revoked')
    run(c, st, 'register_device', account(q_id, q_pub), error='revoked')
    # A registered device is cut off per registry pair only: another person's chain pair for its id (only reachable
    # through the contradiction above) never refuses the registry person's own certificate retry.
    registered = copy.deepcopy(selfcert)
    registered['registry'][laptop_id] = alice_id
    c, st = new('P3_D30_registered_device_cut_off_per_registry_pair', registered)
    run(c, st, 'register_device', {'device_id': laptop_id, 'person_id': alice_id})
    oob_q = copy.deepcopy(accepted)
    oob_q['global_revocations'][q_key] = q_rev('compromised')
    c, st = new('P3_D30_out_of_band_pair_refuses_only_its_person', oob_q)
    run(c, st, 'register_device', account(q_id, q_pub), error='revoked')
    run(c, st, 'register_device', {'device_id': laptop_id, 'person_id': alice_id})
    assert st['registry'][laptop_id] == alice_id
    oob_bob = copy.deepcopy(accepted)
    oob_bob['global_revocations'][laptop_id + ':' + x['bob_id']] = bob_rev_l
    c, st = new('P3_D30_out_of_band_other_person_never_refuses_account', oob_bob)
    run(c, st, 'register_device', account(q_id, q_pub))
    assert st['registry'][laptop_id] == q_id
    # The relay and devices agree: a device that walked r1 accepts r3 and r5 like the relay does, and refuses r2 (Q's
    # chain-learned pair missing) like the relay does.
    agreed = copy.deepcopy(selfcert)
    publish(agreed, r3, [], rb3)
    sync('walk_self_certified_pair_carried_again_like_relay', agreed, dev(base))
    beside = copy.deepcopy(selfcert)
    publish(beside, r5, [], rb5)
    out = sync('walk_other_person_pair_beside_a_chain_pair_like_relay', beside, dev(base))
    assert sorted(out['device']['revocations']) == sorted([q_key, alice_laptop])
    assert laptop_id not in out['device']['devices']
    alice_forged = copy.deepcopy(selfcert)
    forge(alice_forged, r2, 'workspace', entry(after_r1), [C.event_head(rb2['line'])], rb2, r1)
    sync('walk_other_person_pair_never_stands_in_like_relay', alice_forged, dev(base), error='chain_diverged')
    # Review N1 at the relay: a device the relay learned as a restore signer is bound to its person.
    signer_known = copy.deepcopy(ticket_held)
    signer_known['members'] = members
    forged_cert = R.sign_object(S, keys['person_bob.sig'], {**laptop['o'], 'person_id': x['bob_id']})
    forged_rev = R.sign_object(S, keys['person_bob.sig'], {'v': 2, 'suite': S.id, 'kind': 'revocation',
        'person_id': x['bob_id'], 'device_id': laptop_id, 'revoked_ms': NOW - 1000, 'reason': 'compromised'})
    c, st = new('B1_cross_person_evidence_for_earlier_signer', signer_known)
    offer_restore(c, st, t1, b1, pages=[page('abandoned', UID, entry(heads[:2]), heads[2:])])  # binds the signer
    tx, bx = restore(3, source=t1, ident='01QQQQQQQQQQQQQQQQQQQQQQQQ',
                     revocations=[{'revocation': forged_rev, 'device_cert': forged_cert, 'pk_pub': x['bob_pk']}])
    offer_restore(c, st, tx, bx, 'restore_invalid')

    # Review N2: device-only checks, each against a forged relay state where an honest relay would refuse.
    def forged_restore(name, error='chain_diverged', source=base, start=accepted, device_=None, **kw):
        state = copy.deepcopy(start)
        tf, bf = restore(ident='01PPPPPPPPPPPPPPPPPPPPPPPP', **kw)
        tip = kw.get('tip') or C.event_head(bf['line'])
        forge(state, tf, 'workspace', entry(heads[:2]), [tip], bf, source)
        sync(name, state, device_ or dev(base), error=error)
    junk = R.b64u(S.sign(keys['laptop.sig'], b'FAKE not the event'))
    forged_restore('walk_person_signature_required', person_sig=junk)
    forged_restore('walk_target_over_another_head', tip=C.digest(b'FAKE another event'))
    decide_cert = R.sign_object(S, keys['person_alice.sig'], {**x['cert']['o'], 'scopes_max': ['look', 'decide']})
    forged_restore('walk_signer_needs_operate', cert_=decide_cert)
    forged_restore('walk_actor_device_is_the_cert', modifications={'actor': {'kind': 'person', 'id': 'p_' + x['cert']['o']['person_id'], 'device': 'd_' + laptop_id}})
    forged_restore('walk_line_at_not_before_source', time=NOW - 1000, target_time=NOW)
    forged_restore('walk_abandoned_covers_source', modifications={'abandoned': {'seq': 3, 'head': heads[2]}})
    forged_restore('walk_restore_shape_required', modifications={'type': 'member.added'})
    other_card = R.sign_object(S, keys['person_alice.sig'], {**x['delegation']['o'], 'issued_ms': x['delegation']['o']['issued_ms'] + 1})
    forged_restore('walk_delegation_is_the_pinned_card', delegation_=other_card)
    # Review J26 as a vector: a line over the 524,288-byte cap (many abandoned decision ids).
    many = [f'01{i:024d}' for i in range(C.LINE_CAP // 29 + 200)]
    forged_restore('walk_line_over_cap_refused', modifications={'abandoned_decisions': many})
    # Review F2 / orch-52 #377: evidence for a device known only as active (pairing member list) must come
    # from its person.
    bob_cert_laptop = R.sign_object(S, keys['person_bob.sig'], {**laptop['o'], 'person_id': x['bob_id']})
    bob_rev_laptop = R.sign_object(S, keys['person_bob.sig'], {'v': 2, 'suite': S.id, 'kind': 'revocation',
        'person_id': x['bob_id'], 'device_id': laptop_id, 'revoked_ms': NOW - 1000, 'reason': 'compromised'})
    bob_laptop = {'revocation': bob_rev_laptop, 'device_cert': bob_cert_laptop, 'pk_pub': x['bob_pk']}
    paired = dev(base, devices={laptop_id: {'person_id': x['cert']['o']['person_id'], 'pk_pub': x['pk']}})
    forged_restore('walk_evidence_for_known_active_device_from_another_person', revocations=[bob_laptop],
                   device_=paired)
    forged_restore('walk_evidence_for_unknown_device_self_certifying', error=None, revocations=[bob_laptop])
    # orch-core #397: a held out-of-band revocation binds no identity; bob's pair is carried beside alice's held one.
    forged_restore('walk_local_revocation_never_binds_carried_identity', error=None, revocations=[bob_laptop],
                   device_=dev(base, local=[laptop_item]))
    # Review F5/J35: chain-held evidence binds to the stored key, not only the person.
    covered = copy.deepcopy(accepted)
    covered['ever_devices'] = sorted(covered['ever_devices'] + [laptop_id])
    covered['revocations'][alice_laptop] = x['rev']('lost')
    tcov, bcov = restore(2, ident='01WWWWWWWWWWWWWWWWWWWWWWWW',
                         revocations=[{'revocation': x['rev']('lost'), 'device_cert': laptop, 'pk_pub': x['pk']}])
    publish(covered, tcov, ab, bcov)
    for name, key, error in [('walk_chain_evidence_stored_key_matches', x['pk'], None),
                             ('walk_chain_evidence_under_another_stored_key', x['bob_pk'], 'chain_diverged')]:
        sync(name, covered, dev(base, [{'revocation': x['rev']('lost'), 'pk_pub': key}]), error=error)
    # Review W06 as a vector: a resumed endpoint must be exactly the requested hash.
    resumed = copy.deepcopy(grown)
    resumed['checkpoints'][C.checkpoint_hash(base)] = {'checkpoint': grown['held'], 'superseded_ms': None,
                                                      'permanent': True}
    sync('walk_resumed_endpoint_is_the_requested_hash', resumed, dev(base), error='chain_diverged',
         endpoint=C.checkpoint_hash(base))
    # Scripted relay pages (review F5): the device's own guards against a relay that pages badly.
    two_bundles = two['transitions']
    sync('walk_ignored_never_after_walking_beyond_endpoint', two, dev(base), error='chain_diverged',
         endpoint=C.checkpoint_hash(t), script={'transitions': [{'transitions': two_bundles, 'next': None}]})
    sync('walk_proof_empty_page_with_next_refused', grown, dev(base), error='sync_incomplete',
         script={'proof': [{'heads': [], 'next': entry(heads)['acc']}]})
    sync('walk_transitions_cursor_must_advance', two, dev(base), error='sync_incomplete',
         script={'transitions': [{'transitions': [], 'next': '1'}]})
    sync('walk_device_head_ceiling', grown, dev(base), error='sync_incomplete', max_heads=1)
    no_ws_seq = copy.deepcopy(ticket_held)
    tw, bw = restore(2, source=ticket_base, log=UID, ident='01RRRRRRRRRRRRRRRRRRRRRRRR', omit=('ws_seq',))
    forge(no_ws_seq, tw, UID, entry(heads[:2]), [C.event_head(bw['line'])], bw, ticket_base)
    sync('walk_ticket_context_needs_ws_seq', no_ws_seq, dev(ticket_base), error='chain_diverged')
    # Entries are exactly {seq, head, acc}: a signed entry whose head or seq disagrees with its proof.
    for name, change in [('walk_entry_head_must_be_last_proved_head', {'head': heads[0]}),
                         ('walk_entry_seq_must_match_proof_length', {'seq': 6})]:
        bad = copy.deepcopy(accepted)
        hs = heads + [C.digest(b'FAKE entry tail')]
        e5 = cp(2, hs)
        e5 = resign(e5, workspace_log={**e5['o']['workspace_log'], **change})
        forge(bad, e5, 'workspace', entry(heads), hs[4:])
        sync(name, bad, dev(base), error='sync_incomplete')
    # An unsigned endpoint invented by a relay without the WSK.
    invented = copy.deepcopy(accepted)
    fake_heads = heads + [C.digest(b'FAKE invented')]
    fake_e = {'o': {**cp(2, fake_heads)['o']}, 'sig': R.b64u(bytes(64))}
    forge(invented, fake_e, 'workspace', entry(heads), fake_heads[4:])
    sync('walk_endpoint_must_be_wsk_signed', invented, dev(base), error='chain_diverged')
    future = copy.deepcopy(accepted)
    ahead = cp(2, time=NOW + 400000)
    forge(future, ahead, 'workspace', entry(heads), [])
    sync('walk_endpoint_beyond_clock_ceiling', future, dev(base), error='checkpoint_time')

    # --- F1 §5.10 at orch-core 8a07c5ab (#387, per pair since #397): the receiver runtime's revocation rules -----
    # revocation.unpublished: an accepted workspace restore without a held out-of-band revocation (or carrying it
    # weaker) is accepted; the device forwards the evidence for a device this workspace knows and retries until an
    # accepted restore carries it at that strength (publication), never on an acknowledgement.
    laptop_known = {laptop_id: {'person_id': x['cert']['o']['person_id'], 'pk_pub': x['pk']}}
    out = sync('walk_unpublished_forwarded_for_known_device', restored,
               dev(base, local=[laptop_item], devices=laptop_known))
    assert out['device']['forward'] == [alice_laptop] and out['device']['pending'] == []
    # A device whose association names another person: reported by no judge, never forwarded (still enforced).
    bob_known = {laptop_id: {'person_id': x['bob_id'], 'pk_pub': x['bob_pk']}}
    out = sync('walk_unpublished_suppressed_for_another_persons_device', restored,
               dev(base, local=[laptop_item], devices=bob_known))
    assert out['device']['forward'] == [] and out['device']['pending'] == [] and list(out['device']['local']) == [alice_laptop]
    out = sync('walk_chain_lost_local_compromised_accepted_and_forwarded', covered,
               dev(base, local=[laptop_bad], devices=laptop_known))
    assert out['device']['revocations'][alice_laptop]['revocation']['o']['reason'] == 'lost'
    assert out['device']['forward'] == [alice_laptop]
    # A device known only through its tombstone (a chain-learned pair) counts as unknown for forwarding (#397).
    out = sync('walk_tombstone_only_device_stays_pending', covered, dev(base, local=[laptop_bad]))
    assert out['device']['forward'] == [] and out['device']['pending'] == [alice_laptop]
    assert laptop_id not in out['device']['devices']
    waiting = dev(base, local=[laptop_bad], devices=laptop_known)
    waiting['forward'] = [alice_laptop]
    out = sync('walk_growth_keeps_forwarding', grown, waiting)
    assert out['device']['forward'] == [alice_laptop]
    carried_bad = copy.deepcopy(accepted)
    rc, rbc = restore(2, ident='01GGGGGGGGGGGGGGGGGGGGGGGG', revocations=[laptop_bad])
    publish(carried_bad, rc, ab, rbc)
    out = sync('walk_carried_at_local_strength_is_published', carried_bad, waiting)
    assert out['device']['forward'] == [] and out['device']['revocations'][alice_laptop]['provenance']['event'] == rbc['line']['id']

    # Chain-learned provenance is monotonic: a later restore that abandons the restore carrying the revocation
    # neither erases it nor its completeness obligation; an equal-strength later occurrence keeps the first one.
    carrying = copy.deepcopy(accepted)
    rk, rbk = restore(2, ident='01EEEEEEEEEEEEEEEEEEEEEEEE', revocations=[laptop_lost])
    publish(carrying, rk, ab, rbk)
    learned_first = sync('walk_chain_learned_with_provenance', carrying, dev(base))
    prov = learned_first['device']['revocations'][alice_laptop]['provenance']
    assert prov == {'checkpoint': C.reference(rk), 'log': 'workspace', 'event': rbk['line']['id'], 'seq': 3,
                    'head': C.event_head(rbk['line']), 'acc': entry(heads[:2] + [C.event_head(rbk['line'])])['acc']}
    after_rk = heads[:2] + [C.event_head(rbk['line'])]
    abandoning = copy.deepcopy(carrying)
    ra, rba = restore(3, source=rk, ident='01FFFFFFFFFFFFFFFFFFFFFFFF')
    forge(abandoning, ra, 'workspace', entry(heads[:2]), [C.event_head(rba['line'])], rba, rk)
    sync('walk_chain_provenance_survives_abandoning_restore', abandoning, learned_first['device'],
         error='chain_diverged')
    honest = copy.deepcopy(carrying)
    rh, rbh = restore(3, source=rk, ident='01FFFFFFFFFFFFFFFFFFFFFFFG', revocations=[laptop_lost])
    publish(honest, rh, [page('abandoned', 'workspace', entry(heads[:2]), after_rk[2:])], rbh)
    out = sync('walk_chain_provenance_keeps_first_occurrence', honest, learned_first['device'])
    assert out['device']['revocations'][alice_laptop]['provenance'] == prov

    # F1 rows 149/150, failed walks: the laptop signed t1 (a ticket restore), t2 carries the laptop's compromised
    # revocation, and a forged t3 by the laptop makes the walk fail after t2 was judged.
    failing = copy.deepcopy(late)
    after_t2 = heads[:2] + [C.event_head(b2['line'])]
    t3, b3_ = restore(4, source=t2, prefix=after_t2, ident='01ZZZZZZZZZZZZZZZZZZZZZZZZ', cert_=laptop, key='laptop.sig')
    forge(failing, t3, 'workspace', entry(after_t2), [C.event_head(b3_['line'])], b3_, t2)
    # Committed t1 first: the failed walk keeps the compromise evidence and raises the alarm for t1's signer.
    c, st = new('walk_failed_walk_keeps_evidence_and_alarms_committed_signer', failing)
    first = run(c, st, 'device_sync', dev(ticket_base), endpoint=C.checkpoint_hash(t1))
    assert first['device']['alarms'] == [] and first['device']['applied'] == [b1['line']['id']]
    failed = run(c, st, 'device_sync', first['device'], error='chain_diverged')
    assert failed['device']['alarms'] == [laptop_id] and failed['device']['held'] == t1
    assert failed['device']['local'][alice_laptop]['revocation']['o']['reason'] == 'compromised'
    assert failed['device']['applied'] == [b1['line']['id']] and failed['device']['revocations'] == {}
    # t1 never committed: the alarm about it is dropped, the evidence stays local, and a retry refuses t1 (C3).
    dropped = sync('walk_failed_walk_drops_alarm_of_uncommitted_transition', failing, dev(ticket_base),
                   error='chain_diverged')
    assert dropped['device']['alarms'] == [] and dropped['device']['applied'] == []
    assert dropped['device']['held'] == ticket_base and list(dropped['device']['local']) == [alice_laptop]
    sync('walk_retry_after_failed_walk_refuses_former_alarm', late, dropped['device'], error='chain_diverged')
    # Local evidence kept from a failed walk is promoted when an accepted occurrence is established.
    early_ok = copy.deepcopy(ticket_held)
    early_ok['members'] = members
    publish(early_ok, ta, ab, ba)
    out = sync('walk_failed_walk_evidence_promoted_on_retry', early_ok, failed_early['device'])
    assert out['device']['revocations'][alice_laptop]['provenance']['event'] == ba['line']['id']
    assert list(out['device']['local']) == [alice_laptop]

    # Out-of-band intake verifies and retains every pair (orch-core #397): another person's evidence for a device
    # associated with its person is retained too (no binding filter), unverifiable evidence is refused.
    c, st = new('device_learn_admission', accepted)
    out = run(c, st, 'device_learn', {'device': paired, 'evidence': bob_laptop})
    assert out['admitted'] is True and list(out['device']['local']) == [bob_laptop_key]
    run(c, st, 'device_learn', {'device': dev(base), 'evidence': {**bob_laptop, 'pk_pub': x['pk']}}, error='malformed')
    taken = run(c, st, 'device_learn', {'device': dev(base), 'evidence': bob_laptop})
    assert taken['admitted'] is True and 'devices' in taken['device'] and laptop_id not in taken['device']['devices']
    told = run(c, st, 'device_learn', {'device': taken['device'], 'evidence': laptop_bad})
    assert told['admitted'] is True and list(told['device']['local']) == [bob_laptop_key, alice_laptop]
    # Security review (row-151 binding poisoning): bob's evidence first, then alice's own compromised revocation;
    # both pairs are held, and alice's still refuses her laptop as a restore signer (C3) ...
    poisoned = C.device_learn(S, dev(ticket_base), bob_laptop)['device']
    poisoned = C.device_learn(S, poisoned, laptop_bad)['device']
    sync('walk_poisoned_local_still_refuses_its_signer', late, poisoned, error='chain_diverged')
    # ... and alarms when the laptop signed a committed transition, whatever order the pairs arrived in.
    c, st = new('walk_genuine_pair_alarms_committed_signer_after_poison', late)
    committed_t1 = run(c, st, 'device_sync', dev(ticket_base), endpoint=C.checkpoint_hash(t1))
    bob_first = C.device_learn(S, committed_t1['device'], bob_laptop)['device']
    assert bob_first['alarms'] == []
    alarmed = run(c, st, 'device_learn', {'device': bob_first, 'evidence': laptop_bad})
    assert alarmed['admitted'] is True and alarmed['device']['alarms'] == [laptop_id]
    # PR #52 review F4, per pair: bob's compromised "revocation" of alice's known laptop is retained, but it never
    # refuses alice's laptop-signed restore and never alarms (a device-only key would refuse here).
    bobbed = C.device_learn(S, dev(ticket_base, devices=laptop_known), bob_laptop)
    assert bobbed['admitted'] is True and list(bobbed['device']['local']) == [bob_laptop_key]
    out = sync('walk_other_person_local_never_refuses_or_alarms', late, bobbed['device'],
               endpoint=C.checkpoint_hash(t1))
    assert out['device']['alarms'] == [] and out['device']['applied'] == [b1['line']['id']]
