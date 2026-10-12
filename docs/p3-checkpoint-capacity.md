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

Memory: phase A needs about 1.3 KB of peak process memory per new node (a full 64 MiB set ~1.2 GB). The gate
admits at most `ORCH_RELAY_PUBLISH_WIDTH` (2) publications whose reserved heads stay under
`ORCH_RELAY_PUBLISH_HEADS`; a larger one runs alone, so the gate alone never bounded one publication. Since
P3-D37 (below) the heads cap defaults to the heads of one maximal set (226,719; was 1.5 million, about 2 GB).

No head is folded and no staged page is read while the lock is held (pinned by
`tests/test_publication_phases.py`). A node chunk of 20,000 rows holds the lock about 0.1–0.2 s on a
200,000-node table (it grows slowly with the table); a full 64 MiB set is about 45 such holds, between which
every other writer runs. Peak RSS rose because phase A keeps the new rows until phase B; phase A still holds
every new node of the publication (as before), and the gate bounds the publications in phases A to C. The
per-account staging cap and the per-workspace storage quota are in place since P3-D34 (below);
`checkpoint_node_usage` counts stored and orphaned nodes and is the quota's input.

## P3-D34: per-account and per-workspace caps (G3, G4)

Defaults, each overridable from the environment (read once at start-up); every cap answers 429
`quota_exceeded` after authorization. 293 B per stored node and ~906,876 heads per full 64 MiB staging set
are the G4 measurements above.

| Cap | Default | Variable | Arithmetic |
|---|---:|---|---|
| Staged bytes per owner person (all its workspaces) | 512 MiB | `ORCH_RELAY_ACCOUNT_STAGE_BYTES` | 4 GiB ceiling / 8: eight full 64 MiB workspace quotas; at least 8 accounts to fill the ceiling (was 1) |
| Workspaces per account (first card) | 32 | `ORCH_RELAY_ACCOUNT_WORKSPACES` | reached in 3.2 h at 10 cards/hour (was unbounded); lifetime (no workspace deletion) |
| Per-account override of the above (P3-D36) | none | `orch-relay account-cap set` (audited; 1..10,000) | replaces the global cap for that account only; disk: each extra workspace can add up to 1.17 GB of nodes |
| Stored nodes per workspace (orphans included) | 4,000,000 | `ORCH_RELAY_WORKSPACE_NODES` | 4,000,000 x 293 B ≈ 1.17 GB ≈ 4.4 full sets; ~11 years at 1,000 events a day |
| Of which reserved for owner-signed restores (P3-D36) | 5 % (200,000) | `ORCH_RELAY_WORKSPACE_NODES_RESERVE` | ordinary publications stop at 3,800,000; a recovery restore adds 1 node, one carrying a full set ~906,877 |
| Receipts kept per workspace (newest) | 256 | constant `RECEIPTS_KEPT` | ~100 B each (a restore's up to ~0.8 MB with 4,096 refs) |
| `checkpoint_gone` kept per workspace (newest) | 4,096 | constant `GONE_KEPT` | ~100 B each; one per purged checkpoint |
| New self-certified evidence pairs per owner person | 50,000 | `ORCH_RELAY_ACCOUNT_EVIDENCE` | ~1 KB per entry (`cj`), ~500 per 512 KiB line: ~100 restores, ~75 MB of global and chain rows |

The staging bucket (P3-D35, weighted by P3-D36: one token per started 64 KiB, burst 28,801, refill 600/min per
workspace) bounds staging writes, not storage; the staging bytes are bounded by the caps above.

Worst cases with the defaults: one account stores at most 32 x 1.17 GB ≈ 37.5 GB of nodes (by accepted
publications, each refused one costing the refused-heads budget instead) and stages at most 512 MiB. A
publication over the node quota is refused at phase A's commit point, after its folds (whose work is recorded as
refused heads: about two full sets per workspace-hour), and inserts nothing. Sizing the knobs to a VPS (memory
for the publication gate, disk for the node quota): docs/p3-relay-design.md §10, "Pre-public-deploy checklist".

## P3-D37: hard maximum publication size

`ORCH_RELAY_MAX_PUBLICATION_BYTES` bounds one staging set (manifest plus pages, as `checkpoint_staging.bytes`
counts them); `too_large` at the staging manifest (from the size it implies, before any page) and pages (413) and
at the final publication before any fold (400). Phase A memory per instance ≈ heads x 1.3 KB (macOS arm64,
CPython 3.14; not measured on the VPS Python, so +25 %) plus a ~250 MB baseline; the heads cap defaults to
`max // 74`, so at most one maximal set is in phase A per instance. systemd `M` is MiB.

| Maximum | Heads (bytes / 74) | Phase A (1.3 KB) | +25 % | + 250 MB baseline | Fits |
|---:|---:|---:|---:|---:|---|
| 4 MiB | 56,679 | 74 MB | 92 MB | 342 MB | internal `MemoryMax=450M` (472 MB), 28 % headroom: **recommended internal** |
| 6 MiB | 85,019 | 111 MB | 138 MB | 388 MB | internal, 18 % headroom: only with a measured baseline ≤ 200 MB |
| 8 MiB | 113,359 | 147 MB | 184 MB | 434 MB | internal, 8 % headroom: too tight |
| 16 MiB (default) | 226,719 | 295 MB | 368 MB | 618 MB | public `MemoryMax=900M` (944 MB), 34 % headroom: **public** |
| 32 MiB | 453,438 | 589 MB | 737 MB | 987 MB | a 4 GB VPS |
| 64 MiB (the staging quota) | 906,876 | 1,179 MB | 1,474 MB | 1,724 MB | an 8 GB VPS |

The dev VPS (1,961 MB, no swap) with one maximal publication in flight on each instance: 618 + 342 + Caddy ~100 +
OS ~250 ≈ 1,310 MB (67 %). Honest sets for scale: a 5,000-ticket first publication (4 heads per log) stages
3.56 MB (fits 4 MiB); the 200,000-head append above stages ~14.8 MB (fits 16 MiB, not 4 MiB: an internal host
publishes it as several checkpoints). A restore cannot be split: one whose set exceeds the maximum cannot be
published (docs/p3-relay-design.md §10, P3-D37). The follow-up that lifts the limit is the streaming verify
(compact rows ~4–5x less, or a temporary table at O(chunk) memory).
