from fastapi.testclient import TestClient

from orch_relay.app import create_app
from orch_relay import db


def test_challenge_single_use_and_logout(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        r = c.post('/v2/session/challenge', json={})
        assert r.status_code == 200
        challenge = r.json()['challenge']
        body = dict(challenge=challenge, kind='device', id='00'*16, sig='AA'*43)
        assert c.post('/v2/session/login', json=body).json() == {'error': 'bad_signature'}
        assert c.post('/v2/session/login', json=body).json() == {'error': 'unknown_challenge'}
        assert c.post('/v2/session/logout', json={}).json() == {}


def test_challenge_cap_never_evicts(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        issued = [c.post('/v2/session/challenge', json={}) for _ in range(16)]
        assert all(r.status_code == 200 for r in issued)
        assert c.post('/v2/session/challenge', json={}).status_code == 429
        assert len(c.app.state.directory.challenges) == 16


def test_full_durability(tmp_path):
    con = db.connect(tmp_path / 'test.sqlite3')
    assert con.execute('PRAGMA synchronous').fetchone()[0] == 2
    con.close()
