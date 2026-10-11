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
