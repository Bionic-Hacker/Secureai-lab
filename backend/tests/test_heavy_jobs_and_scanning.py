"""Heavy-job lock and scanner invocation. No scanners actually run."""

import asyncio
import types

from app.services import code_scan_service
from app.services.heavy_jobs import heavy_job


def test_heavy_jobs_never_overlap():
    events = []

    async def job(name):
        async with heavy_job():
            events.append(f"{name}:start")
            await asyncio.sleep(0.01)
            events.append(f"{name}:end")

    async def main():
        await asyncio.gather(job("index"), job("scan"))

    asyncio.run(main())
    # each job finishes before the other starts
    assert events in (
        ["index:start", "index:end", "scan:start", "scan:end"],
        ["scan:start", "scan:end", "index:start", "index:end"],
    )


def _capture_run(monkeypatch):
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return types.SimpleNamespace(stdout='{"results": []}', stderr="")

    monkeypatch.setattr(code_scan_service.subprocess, "run", fake_run)
    return calls


def test_semgrep_runs_with_memory_limits_and_no_telemetry(monkeypatch, tmp_path):
    calls = _capture_run(monkeypatch)
    assert code_scan_service._run_semgrep(tmp_path / "x.py") == []
    args = calls[0]
    assert "shell" not in args  # list form, never a shell string
    for flag, value in [("--metrics", "off"), ("--max-memory", "200"), ("-j", "1")]:
        assert args[args.index(flag) + 1] == value
    assert "--disable-version-check" in args
    assert args[args.index("--max-target-bytes") + 1] == str(code_scan_service.MAX_SCAN_BYTES)


def test_scan_size_limit_is_sane():
    assert 100_000 <= code_scan_service.MAX_SCAN_BYTES <= 2_000_000
