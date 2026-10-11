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

The advertised capacity stays about 5,000 tickets. Publication time is linear in staged heads and is spent
inside the global write transaction; see "Open after G4" in docs/p3-relay-design.md §10.
