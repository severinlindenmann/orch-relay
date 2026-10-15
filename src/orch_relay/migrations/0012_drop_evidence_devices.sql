-- P3-D30 round 2 (review R1, orch-52 rulings 1 and 4): device rows written by restore evidence
-- before migration 0010 (their person is in evidence_persons, P3-D29) are no association, but
-- redeeming an invite made them one, which could contradict another workspace's chain pair for
-- the same id and strand it. Restores create no association, so the rows go. Each such device is
-- cut off by its own revoked pair, and its chain pair refuses any re-registration. No session,
-- member row, grant or wrap can reference it (all need a usable account); sessions are cleared
-- anyway. Account and evidence_persons rows and every revocation stay. The runner applies this
-- file once, in its own transaction; on a database without such rows it changes nothing.
DELETE FROM sessions WHERE kind = 'device' AND subject_id IN (
    SELECT device_id FROM devices WHERE person_id IN (SELECT person_id FROM evidence_persons));
DELETE FROM devices WHERE person_id IN (SELECT person_id FROM evidence_persons);
