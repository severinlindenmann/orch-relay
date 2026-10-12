# P3-D20 reference capacity measurement

Run `uv run python -m ref.checkpoint_capacity` to repeat. Measured 2026-10-11 with
CPython 3.14.0 on macOS arm64. These are synthetic reference measurements, not a
production database, network or server capacity claim.

| Measurement | Result |
|---|---:|
| Canonical signed checkpoint with 5,000 tickets | 1,000,515 bytes |
| One `{seq:4, head, acc}` entry | 170 bytes |
| Maximum tickets below 1.8 MiB host admission threshold | 9,434 |
| Maximum tickets within 2 MiB checkpoint cap | 10,483 |
| Heads folded and immutable nodes inserted | 65,536 |
| Fold plus node insertion time | 0.147047 seconds |
| Canonical JSON representation of those nodes | 21,877,933 bytes |

Each ticket also needs its 26-character ULID key and JSON framing, making this
example about 200 bytes per ticket. Larger sequence numbers reduce the count.
The JSON node measurement includes accumulator map keys and field names; it is
not the size of a database row. Durable storage grows with all verified history,
including abandoned branches. Production G4 measurements must include indexes,
transactions, concurrency and persistence overhead.

The conservative advertised capacity remains about 5,000 tickets. The host
admission guard is 1.8 MiB, the signed checkpoint cap is 2 MiB, the full signed
restore line cap is 524,288 bytes including LF, and the final request cap is
2,686,976 bytes. Proof pagination must obey the common 4 MiB response limit even
when fewer than its nominal maximum 65,536 heads fit.

## G4 production measurement

Run `uv run python tests/bench_checkpoint_capacity.py` to repeat. Measured 2026-10-11, CPython 3.14.0 on
macOS arm64, the real app over HTTP (TestClient) against a SQLite file in WAL mode with `synchronous=FULL`,
one process, no network. Single runs, not a server capacity claim.

| Measurement | Result |
|---|---:|
| 5,000-ticket checkpoint (4 heads per log): staging 5,001 pages + 854,055-byte manifest | 5.2 s |
| Its final publication (verification, 20,004 nodes, commit) | 1.5 s |
| 200,000-head append in 4 pages of 56,672 heads: staging | 0.4 s |
| Its final publication (holds the directory write lock) | 4.2 s |
| Database bytes per stored node (after WAL checkpoint) | 293 |
| Heads per staging set at the 64 MiB quota / per 4 MiB page | ~906,876 / 56,672 |
| Proof page of 64 heads near the start / end of a 200,004-node history | 0.79 ms / 0.28 ms |
| Full proof walk from `acc_0` over 200,004 heads (limit 65,536) | 0.94 s |

The advertised capacity stays about 5,000 tickets. Publication time is linear in staged heads; since P3-D33
it is spent outside the global write transaction except for node inserts in 20,000-row chunks (below).

After review round 2 (R1, G2) a refused 10,000-ticket x 2-page first publication holds the lock 1.1 s
instead of 12.7 s, and megabyte stateless refusals hold it under a millisecond. Before P3-D33 a full 64 MiB /
~900,000-head publication held the global write lock about 21 s (peak RSS ~836 MB, review measurement), and
refused publications cost the same.

## P3-D33: publication outside the global write lock (G1)

Run `uv run python tests/bench_publication_lockhold.py` to repeat. Measured 2026-10-12, CPython 3.14.0 on
macOS arm64, the real app over HTTP (TestClient) against a SQLite file in WAL mode with `synchronous=FULL`;
staging is seeded with the production staging code and only the final `PUT checkpoint` is measured. Each
scenario runs in its own process; one run each before (develop at 63aa258) and after. Single runs on a laptop,
not a server capacity claim. "Holds" counts every outermost hold of `Directory.lock` during the request,
including the background sweeps (bridge every second).

| Scenario | Before: longest hold / total held / wall | After: longest hold / total held / wall | Peak RSS before → after |
|---|---:|---:|---:|
| Accepted 200,000-head append (4 pages of 56,672 heads) | 3.18 s / 3.18 s / 3.19 s | 0.22 s / 1.62 s / 2.81 s (14 holds: 10 node chunks, the commit, sweeps) | 408 → 484 MB |
| Refused 10,000-ticket x 2-page first publication (`chain_diverged` after every fold) | 0.40 s / 0.40 s / 0.57 s | 0.066 s / 0.066 s / 0.60 s | 326 → 341 MB |

Round 2 (review of PR #57; bench once, 2026-10-12): append_200k longest hold 0.26 s, 1.66 s held in total
(13 holds), wall 2.78 s, peak RSS 482 MB; tickets_10k_refused one hold of 0.083 s, wall 0.78 s, 340 MB. The
review's PoCs (phase A refuses before any fold, state changes before phase C) folded 40,000 heads under the
lock for a 20,000-head set before round 2 and fold none after (longest hold 0.08 s).

Memory: phase A needs about 1.3 KB of peak process memory per new node (a full set ~1.2 GB). The gate admits
at most `ORCH_RELAY_PUBLISH_WIDTH` (2) publications whose reserved heads stay under
`ORCH_RELAY_PUBLISH_HEADS` (1.5 million, about 2 GB); a larger one runs alone. Set the width to 1 on small
hosts.

No head is folded and no staged page is read while the lock is held (pinned by
`tests/test_publication_phases.py`). A node chunk of 20,000 rows holds the lock about 0.1–0.2 s on a
200,000-node table (it grows slowly with the table); a full 64 MiB set is about 45 such holds, between which
every other writer runs. Peak RSS rose because phase A keeps the new rows until phase B; phase A still holds
every new node of the publication (as before), and the gate bounds the publications in phases A to C. The
per-account staging cap and the per-workspace storage quota remain pre-public-deploy gates (G3, G4 in
docs/p3-relay-design.md §10); `checkpoint_node_usage` now counts stored and orphaned nodes for the latter.
