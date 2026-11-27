"""Guarded internal DNS retirement never replays ambiguous deletion."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cloudflare_api import CloudflareError
from cloudflare_internal_cleanup import (
    JOURNAL,
    MAX_GAP,
    candidates,
    disabled,
    load_state,
    observe,
    run_cleanup,
    save_state,
    scope_for,
)
from cloudflare_internal_ownership import internal_scope, load_registry, save_registry

BOUND = internal_scope("a" * 32, "b" * 32, "example.net", "192.0.2.0/24")
EXTERNAL = "e" * 32
SCOPE = scope_for(BOUND, EXTERNAL)
ENTRY = {
    "id": "c" * 32,
    "hostname": "demo.example.net",
    "address": "192.0.2.42",
    "fingerprint": "d" * 64,
}
ID = ENTRY["id"]
GRACE = 24 * 3600
NOW = 1000000


def context(status="candidate_review_only", *, owned=True, count=1):
    return (
        {
            "rows": [
                {
                    "hostname": ENTRY["hostname"],
                    "address": ENTRY["address"],
                    "record_id": ID,
                    "ownership": "docker" if owned else "unmanaged",
                    "status": status,
                }
            ],
            "selected_dns_record_count": count,
        },
        BOUND,
        EXTERNAL,
        {ID: ("docker", ENTRY)} if owned else {},
    )


class InternalCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data = Path(self.temp.name)
        save_registry(
            self.data,
            {"version": 1, "scope": BOUND, "records": {ID: ENTRY}},
        )
        self.client = Mock()
        self.client.delete_dns_record.return_value = {"id": ID}
        self.review = self.enterContext(
            patch("cloudflare_internal_cleanup.fresh_review", return_value=context())
        )
        self.notice = self.enterContext(patch("cloudflare_internal_cleanup.notice"))

    def run_cycle(self, now=NOW, notify=False):
        return run_cleanup(
            self.client,
            self.data,
            {},
            GRACE,
            1,
            notify=notify,
            clock=lambda: now,
        )

    def ready(self):
        state = load_state(self.data, SCOPE)
        state["observations"] = {
            ID: {"entry": ENTRY, "first": NOW - GRACE, "last": NOW - 3600}
        }
        save_state(self.data, state)

    def test_grace_and_continuity(self):
        previous = {}
        for hour in (0, 6, 12, 18, 24):
            previous, eligible = observe(
                previous, {ID: ENTRY}, NOW + hour * 3600, GRACE
            )
            self.assertEqual(eligible, [ID] if hour == 24 else [])
        fresh, eligible = observe(
            previous, {ID: ENTRY}, NOW + GRACE + MAX_GAP + 1, GRACE
        )
        self.assertEqual(eligible, [])
        self.assertEqual(fresh[ID]["first"], fresh[ID]["last"])
        self.assertEqual(observe(previous, {}, NOW + GRACE, GRACE), ({}, []))
        changed = {**ENTRY, "fingerprint": "f" * 64}
        _, eligible = observe(previous, {ID: changed}, NOW + GRACE, GRACE)
        self.assertEqual(eligible, [])
        _, eligible = observe(previous, {ID: ENTRY}, NOW - 1, GRACE)
        self.assertEqual(eligible, [])

    def test_unmanaged_and_static_never_candidates(self):
        report, _, _, owned = context(owned=False)
        self.assertEqual(candidates(report, owned), {})
        report, _, _, owned = context()
        report["rows"][0]["ownership"] = "static"
        self.assertEqual(candidates(report, owned), {})
        self.review.return_value = context(owned=False)
        self.ready()
        self.assertEqual(self.run_cycle(), 0)
        self.client.delete_dns_record.assert_not_called()
        self.assertEqual(load_state(self.data)["observations"], {})

    def test_wait_then_verified_delete_and_notice(self):
        self.assertEqual(self.run_cycle(), 0)
        self.client.delete_dns_record.assert_not_called()
        self.ready()
        self.review.side_effect = [
            context(),
            context(),
            context("missing_record", count=0),
        ]

        def delete(zone, identifier):
            self.assertEqual((zone, identifier), (BOUND["zone"], ID))
            self.assertEqual(load_state(self.data)["pending"]["phase"], "intent")
            return {"id": ID}

        self.client.delete_dns_record.side_effect = delete
        self.assertEqual(self.run_cycle(notify=True), 1)
        self.client.delete_dns_record.assert_called_once_with(BOUND["zone"], ID)
        self.assertEqual(load_registry(self.data)["records"], {})
        self.assertIsNone(load_state(self.data)["pending"])
        self.notice.assert_called_once_with(ENTRY)

    def test_reappearance_blocks_and_resets_grace(self):
        self.ready()
        self.review.side_effect = [context(), context("runtime_present")]
        with self.assertRaisesRegex(ValueError, "candidate changed"):
            self.run_cycle()
        self.client.delete_dns_record.assert_not_called()
        self.assertEqual(load_state(self.data)["observations"], {})

    def test_lost_acknowledgement_never_replayed(self):
        self.ready()
        self.client.delete_dns_record.side_effect = CloudflareError("timeout")
        with self.assertRaises(CloudflareError):
            self.run_cycle()
        self.assertEqual(load_state(self.data)["pending"]["phase"], "intent")
        with self.assertRaisesRegex(ValueError, "Unknown"):
            self.run_cycle()
        self.client.delete_dns_record.assert_called_once()
        self.assertEqual(load_registry(self.data)["records"], {ID: ENTRY})
        self.notice.assert_not_called()

    def test_acknowledged_but_unverified_recovers_without_delete(self):
        self.ready()
        self.review.side_effect = [context(), context(), context()]
        with self.assertRaisesRegex(ValueError, "absence not verified"):
            self.run_cycle(notify=True)
        self.assertEqual(load_state(self.data)["pending"]["phase"], "acknowledged")
        self.assertEqual(load_registry(self.data)["records"], {ID: ENTRY})
        self.notice.assert_not_called()
        self.review.side_effect = None
        self.review.return_value = context("missing_record", count=0)
        self.assertEqual(self.run_cycle(notify=True), 0)
        self.client.delete_dns_record.assert_called_once()
        self.notice.assert_called_once_with(ENTRY)
        self.assertEqual(load_registry(self.data)["records"], {})

    def test_verified_recovery_after_ledger_release(self):
        state = load_state(self.data, SCOPE)
        state["pending"] = {"entry": ENTRY, "phase": "verified"}
        save_state(self.data, state)
        save_registry(self.data, {"version": 1, "scope": BOUND, "records": {}})
        self.review.return_value = (
            {"rows": [], "selected_dns_record_count": 0},
            BOUND,
            EXTERNAL,
            {},
        )
        self.assertEqual(self.run_cycle(), 0)
        self.assertIsNone(load_state(self.data)["pending"])
        self.client.delete_dns_record.assert_not_called()

    def test_failed_review_and_disabled_mode_reset_observations(self):
        self.ready()
        self.review.side_effect = ValueError("invalid evidence")
        with self.assertRaises(ValueError):
            self.run_cycle()
        self.assertEqual(load_state(self.data)["observations"], {})
        self.ready()
        disabled(self.data)
        self.assertEqual(load_state(self.data)["observations"], {})
        state = load_state(self.data)
        state["pending"] = {"entry": ENTRY, "phase": "intent"}
        save_state(self.data, state)
        disabled(self.data)
        self.assertEqual(load_state(self.data)["pending"], state["pending"])
        self.client.delete_dns_record.assert_not_called()

    def test_corrupt_state_blocks_before_review(self):
        (self.data / JOURNAL).write_text("{}")
        with self.assertRaises(ValueError):
            self.run_cycle()
        self.review.assert_not_called()
        self.client.delete_dns_record.assert_not_called()
