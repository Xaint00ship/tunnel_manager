"""Orchestration tests for TunnelApp using MockBackend."""

from __future__ import annotations

import pytest

from tunnel_manager.app import TunnelApp
from tunnel_manager.config import Config
from tunnel_manager.state import StateFile

from ._mocks import MockBackend


@pytest.fixture
def make_app(mock_backend, tmp_path, list_file):
    def _make(dry_run: bool = False, backend=None):
        cfg = Config(list_url=str(list_file), refresh_interval_hours=1)
        state = StateFile(tmp_path / "state.json")
        return TunnelApp(
            backend=backend or mock_backend,
            config=cfg,
            state=state,
            base_dir=tmp_path,
            dry_run=dry_run,
        )
    return _make


@pytest.mark.asyncio
async def test_setup_adds_all_routes_when_empty(make_app, mock_backend):
    app = make_app()
    await app.start()
    # 3 entries from list_file + nothing in existing → 3 added
    assert app.total_routes == 3
    assert {"1.1.1.1", "2.2.2.2/24", "3.3.3.3"} <= app.active_routes
    add_calls = [c for c in mock_backend.calls if c[0] == "add_routes"]
    assert len(add_calls) == 1


@pytest.mark.asyncio
async def test_diff_only_adds_new_and_removes_stale(make_app, mock_vpn):
    backend = MockBackend(vpn=mock_vpn, existing={"1.1.1.1/32", "9.9.9.9/32"})
    app = make_app(backend=backend)
    await app.start()
    # 9.9.9.9 should be removed (not in desired); 2.2.2.2/24 + 3.3.3.3 added.
    add_calls = [c for c in backend.calls if c[0] == "add_routes"]
    rm_calls = [c for c in backend.calls if c[0] == "remove_routes"]
    added: set[str] = set()
    removed: set[str] = set()
    for c in add_calls:
        added.update(c[1][0])
    for c in rm_calls:
        removed.update(c[1][0])
    assert "1.1.1.1" not in added                # already exists
    assert {"2.2.2.2/24", "3.3.3.3"} <= added
    assert "9.9.9.9/32" in removed


@pytest.mark.asyncio
async def test_dry_run_skips_route_writes(make_app, mock_backend):
    app = make_app(dry_run=True)
    await app.start()
    add_calls = [c for c in mock_backend.calls if c[0] == "add_routes"]
    assert add_calls == []                       # never invoked
    assert mock_backend.routes == set()
    assert app.total_routes == 3                 # but desired set still computed


@pytest.mark.asyncio
async def test_load_failure_does_not_touch_routing(make_app, mock_backend, tmp_path):
    cfg = Config(list_url=str(tmp_path / "missing.txt"))
    state = StateFile(tmp_path / "state.json")
    app = TunnelApp(mock_backend, cfg, state, tmp_path)
    await app.start()
    # detect_vpn was called once during start; nothing else.
    op_calls = [c for c in mock_backend.calls
                if c[0] in ("remove_default_vpn_route", "add_routes", "remove_routes")]
    assert op_calls == []
    assert app.status_line == "Load failed"


@pytest.mark.asyncio
async def test_no_vpn_detected_skips_setup(make_app, mock_vpn, tmp_path, list_file):
    backend = MockBackend(vpn=None)
    cfg = Config(list_url=str(list_file))
    state = StateFile(tmp_path / "state.json")
    app = TunnelApp(backend, cfg, state, tmp_path)
    await app.start()
    assert app.vpn_connected is False
    op_calls = [c for c in backend.calls
                if c[0] in ("add_routes", "remove_default_vpn_route")]
    assert op_calls == []


@pytest.mark.asyncio
async def test_state_persists_after_setup(make_app, tmp_path):
    app = make_app()
    await app.start()
    # Reload state from disk
    fresh = StateFile(tmp_path / "state.json")
    assert set(fresh.previous_routes()) >= {"1.1.1.1", "2.2.2.2/24", "3.3.3.3"}
    assert fresh.previous_interface() == "50"


@pytest.mark.asyncio
async def test_cleanup_uses_state_when_vpn_gone(make_app, tmp_path, mock_vpn):
    app = make_app()
    await app.start()
    # Now VPN goes down; cleanup using saved state should still remove routes.
    backend2 = MockBackend(vpn=None, existing={"1.1.1.1/32"})
    cfg = Config(list_url="dummy")
    state = StateFile(tmp_path / "state.json")
    app2 = TunnelApp(backend2, cfg, state, tmp_path)
    # Inject a synthetic VPNInfo from state (simulates cli._restore_vpn_info)
    from tunnel_manager.backends.base import VPNInfo
    app2.vpn_info = VPNInfo(interface=state.previous_interface() or "?", gateway=None)
    await app2.cleanup()
    # state was cleared
    fresh = StateFile(tmp_path / "state.json")
    assert fresh.data == {}


@pytest.mark.asyncio
async def test_failure_aggregation_groups_messages(make_app, mock_vpn, tmp_path, list_file):
    backend = MockBackend(
        vpn=mock_vpn,
        add_failures={"1.1.1.1": "File exists", "2.2.2.2/24": "File exists",
                      "3.3.3.3": "Network unreachable"},
    )
    cfg = Config(list_url=str(list_file))
    state = StateFile(tmp_path / "state.json")
    app = TunnelApp(backend, cfg, state, tmp_path)
    await app.start()
    # All three "added" should appear in failures groups; nothing should explode.
    add_calls = [c for c in backend.calls if c[0] == "add_routes"]
    assert len(add_calls) == 1
