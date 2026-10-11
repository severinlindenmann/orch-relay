# G2 members integration for G3/G4

G2 implements protocol §19.2's five routes in `members.py`, using G1's
`Directory.handle` process lock and `BEGIN IMMEDIATE` transaction. Both writes
require a current workspace session and `Directory.fence`; reads reauthorize
membership on each request. No host acquisition route is added. Tests can seed
an existing lease with `tests/members_support.py::holder`.

Migration 0003 adds only `membership_receipts` and its expiry index. Receipts
are keyed by workspace and SHA-256 of the exact HTTP body, with acceptance time,
sequence and epoch. They authorize no request: session/workspace/holder gates
always run first. Receipts are valid for seven days, without refreshing on
retry; expired rows are collected on the next successful publication in that
workspace. Inactive workspaces can retain expired rows, but cannot use them.
GET members returns the latest signed object for stale-list recovery.

Publication commits the signed list, exploded members, grants, wraps, historical
sets and obligation clearing together. The first accepted list must contain a
certificate-bound owner device (`other_person` otherwise). Later lists may
remove the owner; historical authority remains. Proposed-list persons authorize
new people's certificates without requiring prior historical authority.

`Directory.revoke` remains the single verified-intake hook, including for G4.
It calls `members.prune_device` inside its transaction and records obligations
with the current epoch and revocation cursor. Publication clears an obligation
only when its epoch is strictly higher and the obligated device is absent.
Exact retries do not reinsert pruned data or clear obligations.

`prune_device(con, device_id, workspace_id=None)` deletes grants, wraps and rows
in existing `bridge_msgs`, `request_mailboxes`, `sk_grants`, and
`push_subscriptions` tables. G3 queues must expose `device_id` and `workspace_id`;
workspace departure uses both columns, revocation deletes across workspaces.
The helper intentionally does not delete `rid_seen`/`rid_chunks` replay metadata.
G3 must add any differently named queue to this hook, release queue accounting,
and wake affected pollers after commit. G4 must validate restore evidence before
calling `Directory.revoke` in its own write transaction. Historical authorization
sets grow only through accepted membership publication, as §19.1 requires.

Contract clarifications in this group:

- (G2b, P3-D26; supersedes the G2 adjacency note) Epoch violations return 409
  `bad_epoch`: a first list outside epochs `1..2^16`, a later epoch that falls or
  skips by more than `2^16`. Any first `list_seq >= 1` is accepted, so a refused
  first publication can retry at `(2, 2)`. A removal needs a higher epoch
  (`rotation_required`); the same epoch with another `wk_commit` is 409
  `wk_commit_changed`. The `member_lists` vectors `first_list_not_epoch_1` and
  `epoch_skips` were replaced; the `bad_epoch` fixture now uses a falling epoch.
- `other_person` covers an ownerless first list; no new refusal code is needed.
- Membership refusal fixtures now use appropriate signed vector artifacts:
  other-workspace, grant-device/epoch mismatch, invalid first-list sequence, and
  removal without rotation. A stale-epoch fixture was added. Copy the updated shared corpus downstream.
- Identical card-key submissions return the number of submitted unique wraps,
  including no-ops. Existing older-sequence wraps remain addressable; a newer
  sequence can coexist, and departure/revocation prunes all sequences.
- The abstract retry vector advances time beyond seven days but has no receipt
  timestamps. Its adapter seeds live receipts at that vector's clock. A separate
  restart test exercises actual acceptance timestamps at seven days minus one
  millisecond and exactly seven days.
