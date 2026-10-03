"""
End-to-end tests for the runtime evidence pipeline and the run scorecard:
demo and live modes stay separate, live never falls back to fixtures, and
stale, mixed-run, partial or failed evidence cannot produce a passing result.
"""

import json
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cloudnative_threatguard.config import settings
from cloudnative_threatguard.reporting import scorecard
from cloudnative_threatguard.runtime import pipeline
from cloudnative_threatguard.runtime.scenarios import load_catalog

POD = {"namespace": "threatguard", "name": "threatguard-target-pod"}
BASE = datetime(2026, 10, 3, 10, 0, 0, tzinfo=timezone.utc)


@contextmanager
def isolated_artifacts():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        patches = [
            patch.object(settings, "ARTIFACTS_DIR", root),
            patch.object(settings, "ARTIFACTS_ADMISSION_DIR", root / "admission"),
            patch.object(settings, "ARTIFACTS_RUNTIME_DIR", root / "runtime"),
            patch.object(settings, "ARTIFACTS_REPORTS_DIR", root / "reports"),
        ]
        for p in patches:
            p.start()
        try:
            yield root
        finally:
            for p in patches:
                p.stop()


def ts(offset_seconds):
    return (BASE + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%S.000000000Z")


def proc(binary, offset, exec_id):
    return {"exec_id": exec_id, "pid": offset + 100, "uid": 10001, "binary": binary, "arguments": "", "pod": POD}


def exec_ev(binary, offset):
    return {"time": ts(offset), "process_exec": {"process": proc(binary, offset, f"x{offset}")}}


def connect_ev(binary, offset, daddr):
    return {"time": ts(offset), "process_kprobe": {
        "function_name": "sys_enter_connect", "process": proc(binary, offset, f"c{offset}"),
        "args": [{"int_arg": 3}, {"sock_arg": {"daddr": daddr, "dport": 443, "proto": "TCP"}}]}}


def kprobe_file(binary, offset, path):
    return {"time": ts(offset), "process_kprobe": {
        "function_name": "security_file_open", "process": proc(binary, offset, f"f{offset}"),
        "args": [{"file_arg": {"path": path}}, {"int_arg": 0}]}}


def kill_ev(offset):
    return {"time": ts(offset), "process_exit": {"process": proc("/bin/sh", offset, "k1"), "signal": "SIGKILL"}}


def full_live_events():
    """One window per catalog scenario, 10 seconds apart, starting at offset 0."""
    return {
        "SCEN-001": [exec_ev("/bin/sh", 1), kill_ev(2)],
        "SCEN-002": [exec_ev("/usr/bin/wget", 11)],
        "SCEN-003": [exec_ev("/usr/bin/id", 21)],
        "SCEN-004": [kprobe_file("/bin/cat", 31, "/etc/shadow")],
        "SCEN-005": [exec_ev("/usr/bin/nsenter", 41)],
        "SCEN-006": [connect_ev("/usr/bin/nc", 51, "1.1.1.1")],
        "SCEN-007": [exec_ev("/tmp/xmrig", 61)],
        "SCEN-008": [connect_ev("/usr/bin/nc", 71, "10.96.0.1")],
        "SCEN-B01": [exec_ev("/bin/echo", 81)],
    }


def write_results(path, skip=(), killed="SCEN-001"):
    rows = []
    for index, item in enumerate(load_catalog()):
        if item.id in skip:
            continue
        code = 137 if item.id == killed else 0
        rows.append(f"{item.id}\texecuted\t{code}\t{ts(index * 10)}\t{ts(index * 10 + 5)}")
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def runner_for(events_by_scenario, status=0):
    stdout = "\n".join(json.dumps(e) for evs in events_by_scenario.values() for e in evs)
    return lambda args: (status, stdout)


class TestDemoMode(unittest.TestCase):
    def test_demo_run_passes_but_is_labelled_simulated(self):
        with isolated_artifacts() as root:
            manifest, code = pipeline.run_pipeline("demo", "demo1", "threatguard", "threatguard-target-pod")
            events = json.loads((root / "runtime" / "runtime-events.json").read_text())
            self.assertEqual(code, pipeline.EXIT_OK)
            self.assertEqual(manifest["origin"], "SIMULATED")
            self.assertTrue(all(s["status"] == "passed" for s in manifest["scenarios"]))
            self.assertTrue(events)
            self.assertTrue(all(e["evidence_mode"] == "demo" for e in events))
            self.assertTrue(all(e["source"] != "tetragon" for e in events))

    def test_demo_events_keep_fixture_timestamps(self):
        with isolated_artifacts() as root:
            pipeline.run_pipeline("demo", "demo1", "threatguard", "threatguard-target-pod")
            events = json.loads((root / "runtime" / "runtime-events.json").read_text())
            runtime = [e for e in events if e["rule_id"].startswith("RUNTIME-")]
            self.assertTrue(all(e["timestamp"].startswith("2026-09-05") for e in runtime))
            self.assertTrue(all(e["captured_at"] and e["captured_at"] != e["timestamp"] for e in runtime))

    def test_demo_scorecard_is_never_live_acceptance(self):
        with isolated_artifacts():
            pipeline.run_pipeline("demo", "demo1", "threatguard", "threatguard-target-pod")
            (settings.ARTIFACTS_ADMISSION_DIR).mkdir(parents=True)
            (settings.ARTIFACTS_ADMISSION_DIR / "admission-results.json").write_text(json.dumps({
                "total": 8, "blocked": 8, "allowed": 0, "errors": 0, "status": "PASS", "run_id": "demo1",
                "mode": "opa_offline_evaluation", "evidence_mode": "offline", "positive_total": 1, "positive_allowed": 1,
            }))
            report = scorecard.generate_scorecard()
            self.assertEqual(report["overall_status"], "PASS")
            self.assertEqual(report["origin"], "SIMULATED")
            self.assertFalse(report["live_acceptance"])


class TestLiveMode(unittest.TestCase):
    def run_live(self, root, events=None, skip=(), killed="SCEN-001", status=0, results_name="results.tsv"):
        events = events if events is not None else full_live_events()
        results = root / results_name
        write_results(results, skip=skip, killed=killed)
        return pipeline.run_pipeline(
            "live", "live1", "threatguard", "threatguard-target-pod", results_path=results,
            since=ts(-5), wait_seconds=0, runner=runner_for(events, status), sleep=lambda s: None,
        )

    def write_admission(self, run_id="live1", status="PASS", mode="live"):
        settings.ARTIFACTS_ADMISSION_DIR.mkdir(parents=True, exist_ok=True)
        (settings.ARTIFACTS_ADMISSION_DIR / "admission-results.json").write_text(json.dumps({
            "total": 8, "blocked": 8, "allowed": 0, "errors": 0, "status": status, "run_id": run_id,
            "mode": "live_cluster_webhook", "evidence_mode": mode, "positive_total": 1, "positive_allowed": 1,
            "negative_results": [{"manifest": "01-privileged-pod.yaml", "outcome": "policy_denied",
                                  "constraint": "k8sprivilegedcontainer", "detail": "denied"}],
        }))

    def test_complete_live_run_passes_with_live_origin(self):
        with isolated_artifacts() as root:
            self.write_admission()
            manifest, code = self.run_live(root)
            report = scorecard.generate_scorecard(now=BASE)
            self.assertEqual(code, pipeline.EXIT_OK, manifest["scenarios"])
            self.assertEqual(report["overall_status"], "PASS")
            self.assertTrue(report["live_acceptance"])
            self.assertEqual(report["origin"], "LIVE")
            self.assertEqual(report["runtime"]["scenario_counts"]["passed"], 9)
            events = json.loads((root / "runtime" / "runtime-events.json").read_text())
            self.assertTrue(all(e["evidence_mode"] == "live" for e in events))
            self.assertTrue(all(e["source"] in ("tetragon", "opa_gatekeeper") for e in events))

    def test_live_never_falls_back_to_fixtures_when_collector_is_down(self):
        with isolated_artifacts() as root:
            manifest, code = self.run_live(root, status=1)
            events = json.loads((root / "runtime" / "runtime-events.json").read_text())
            self.assertEqual(code, pipeline.EXIT_BLOCKED)
            self.assertEqual(manifest["collector"]["status"], "unavailable")
            self.assertEqual(events, [])
            self.assertFalse(any(s["status"] == "passed" for s in manifest["scenarios"]))

    def test_unrelated_exit_137_is_not_a_successful_block(self):
        with isolated_artifacts() as root:
            events = full_live_events()
            events["SCEN-001"] = [exec_ev("/bin/sh", 1)]  # no kill evidence
            manifest, code = self.run_live(root, events=events)
            first = manifest["scenarios"][0]
            self.assertEqual(code, pipeline.EXIT_FAILED)
            self.assertEqual(first["status"], "failed")

    def test_skipped_scenario_keeps_the_planned_denominator(self):
        with isolated_artifacts() as root:
            self.write_admission()
            manifest, code = self.run_live(root, skip=("SCEN-005",))
            report = scorecard.generate_scorecard(now=BASE)
            self.assertEqual(report["runtime"]["scenario_counts"]["planned"], 9)
            self.assertEqual(report["runtime"]["scenario_counts"]["not_run"], 1)
            self.assertEqual(report["overall_status"], "INCOMPLETE")
            self.assertFalse(report["live_acceptance"])
            self.assertEqual(code, pipeline.EXIT_FAILED)

    def test_missing_detection_fails_the_scorecard(self):
        with isolated_artifacts() as root:
            self.write_admission()
            events = full_live_events()
            events["SCEN-003"] = []
            self.run_live(root, events=events)
            report = scorecard.generate_scorecard(now=BASE)
            self.assertEqual(report["overall_status"], "FAIL")

    def test_benign_control_alert_fails_run(self):
        with isolated_artifacts() as root:
            self.write_admission()
            events = full_live_events()
            events["SCEN-B01"] = [exec_ev("/usr/bin/id", 81)]  # reconnaissance binary => false alert
            self.run_live(root, events=events)
            self.assertEqual(scorecard.generate_scorecard(now=BASE)["overall_status"], "FAIL")

    def test_duplicate_export_records_do_not_inflate_detections(self):
        with isolated_artifacts() as root:
            self.write_admission()
            events = full_live_events()
            events["SCEN-003"] = [exec_ev("/usr/bin/id", 21), exec_ev("/usr/bin/id", 21)]
            self.run_live(root, events=events)
            runtime = json.loads((root / "runtime" / "runtime-events.json").read_text())
            recon = [e for e in runtime if e["rule_id"] == "RUNTIME-003"]
            self.assertEqual(len(recon), 1)

    def test_events_from_other_pods_are_ignored(self):
        with isolated_artifacts() as root:
            events = full_live_events()
            other = {"namespace": "threatguard", "name": "other-pod"}
            events["SCEN-003"] = [{"time": ts(21), "process_exec": {"process": {**proc("/usr/bin/id", 21, "o1"), "pod": other}}}]
            manifest, _ = self.run_live(root, events=events)
            recon = next(s for s in manifest["scenarios"] if s["scenario_id"] == "SCEN-003")
            self.assertEqual(recon["status"], "failed")


class TestScorecardEvidenceRules(unittest.TestCase):
    def setUp(self):
        self.cm = isolated_artifacts()
        self.root = self.cm.__enter__()

    def tearDown(self):
        self.cm.__exit__(None, None, None)

    def _live_run(self, run_id="live1", admission_run="live1"):
        results = self.root / "results.tsv"
        write_results(results)
        pipeline.run_pipeline(
            "live", run_id, "threatguard", "threatguard-target-pod", results_path=results,
            since=ts(-5), wait_seconds=0, runner=runner_for(full_live_events()), sleep=lambda s: None,
        )
        settings.ARTIFACTS_ADMISSION_DIR.mkdir(parents=True, exist_ok=True)
        (settings.ARTIFACTS_ADMISSION_DIR / "admission-results.json").write_text(json.dumps({
            "total": 8, "blocked": 8, "allowed": 0, "errors": 0, "status": "PASS", "run_id": admission_run,
            "mode": "live_cluster_webhook", "evidence_mode": "live", "positive_total": 1, "positive_allowed": 1,
        }))

    def test_mixed_run_evidence_is_incomplete(self):
        self._live_run(admission_run="an-older-run")
        report = scorecard.generate_scorecard(now=BASE)
        self.assertEqual(report["overall_status"], "INCOMPLETE")
        self.assertFalse(report["live_acceptance"])
        self.assertTrue(any("different runs" in i for i in report["issues"]))

    def test_old_successful_run_is_marked_stale(self):
        self._live_run()
        later = datetime.now(timezone.utc) + timedelta(days=3)
        report = scorecard.generate_scorecard(now=later)
        self.assertEqual(report["overall_status"], "STALE")
        self.assertFalse(report["live_acceptance"])

    def test_missing_evidence_is_incomplete_never_pass(self):
        report = scorecard.generate_scorecard(now=BASE)
        self.assertEqual(report["overall_status"], "INCOMPLETE")

    def test_failed_admission_fails_even_when_runtime_passes(self):
        self._live_run()
        path = settings.ARTIFACTS_ADMISSION_DIR / "admission-results.json"
        data = json.loads(path.read_text())
        data.update({"status": "FAIL", "positive_allowed": 0})
        path.write_text(json.dumps(data))
        self.assertEqual(scorecard.generate_scorecard(now=BASE)["overall_status"], "FAIL")


class TestWorkloadSpec(unittest.TestCase):
    def test_container_overrides_pod_level_context(self):
        pod = {"spec": {"securityContext": {"runAsUser": 0}, "containers": [
            {"name": "c", "securityContext": {"runAsUser": 10001, "privileged": False}}]}}
        spec = pipeline.workload_spec_from_pod(pod, "c")
        self.assertEqual(spec["runAsUser"], 10001)
        self.assertFalse(spec["privileged"])

    def test_unknown_configuration_is_not_assumed_root(self):
        spec = pipeline.workload_spec_from_pod({"spec": {"containers": [{"name": "c"}]}}, "c")
        self.assertNotIn("runAsUser", spec)
        self.assertNotIn("privileged", spec)


if __name__ == "__main__":
    unittest.main()
