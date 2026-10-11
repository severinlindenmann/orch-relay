"""Reproducible input sizes and local timing for P3-D20; python -m ref.checkpoint_capacity."""
import json
import platform
import time

from ref import checkpoints as C
from ref import orch_protocol_ref as R


def measure():
    v = json.loads(R.VECTORS.read_text())['suites']['2']
    base = v['checkpoints']['objects']['checkpoint']
    entry = base['o']['workspace_log']
    def encoded(n):
        # ULIDs in this range contain only decimal digits, all valid Crockford base32.
        return R.cj({**base, 'o': {**base['o'], 'tickets': {f'{i:026d}': entry for i in range(n)}}})
    def capacity(limit):
        lo, hi = 0, 20000
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if len(encoded(mid)) <= limit:
                lo = mid
            else:
                hi = mid - 1
        return lo
    count = 65536
    head = C.digest(b'FAKE capacity head')
    state = {'nodes': {}}
    start = time.perf_counter()
    C.extend(state, 'workspace', C.EMPTY, [head] * count)
    elapsed = time.perf_counter() - start
    return {'python': platform.python_version(), 'platform': platform.platform(),
            'checkpoint_bytes_5000_tickets': len(encoded(5000)),
            'ticket_entry_json_bytes': len(R.cj(entry)),
            'max_tickets_at_host_1_8_mib': capacity(int(1.8 * 1024 * 1024)),
            'max_tickets_at_object_2_mib': capacity(C.CP_CAP),
            'heads': count, 'fold_and_node_seconds': round(elapsed, 6),
            'log_nodes_canonical_json_bytes': len(R.cj(state['nodes'])),
            'note': 'Synthetic seq=4 entries; larger sequence numbers reduce capacity. Timing and JSON storage are reference measurements, not production DB or network benchmarks.'}


if __name__ == '__main__':
    print(json.dumps(measure(), indent=2))
