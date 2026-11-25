"""Read-only tests for batch scheduling of verified automatic orphan cleanup."""

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).with_name("cloudflare-auto-cleanup.py")
SPEC = importlib.util.spec_from_file_location("cloudflare_auto_cleanup_cli", SOURCE)
if SPEC is None or SPEC.loader is None:
    raise ImportError("Cannot import automatic cleanup")
cleanup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cleanup)


class OrphanCleanupBatchTests(unittest.TestCase):
    def test_limits_are_explicit_and_never_silently_fall_back(self):
        self.assertEqual(cleanup.cleanup_batch(["a", "b", "c"], 1), ["a"])
        self.assertEqual(cleanup.cleanup_batch(["a", "b", "c"], 2), ["a", "b"])
        self.assertEqual(cleanup.cleanup_batch(["a", "b", "c"], 0), ["a", "b", "c"])
        for invalid in (-1, True, "5"):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                cleanup.cleanup_batch(["a", "b"], invalid)

    def test_each_selected_orphan_is_planned_and_revalidated_independently(self):
        settings = {
            "account_id": "a" * 32,
            "external_zone_id": "b" * 32,
            "tunnel_id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
        }
        hosts = ["host1.ebi.nu", "host2.ebi.nu", "host3.ebi.nu"]
        for limit, count in (("1", 1), ("2", 2), ("0", 3)):
            with (
                patch.dict(
                    "os.environ",
                    {
                        "YGGFLARE_CLOUDFLARE_AUTO_APPLY": "true",
                        "YGGFLARE_CLOUDFLARE_AUTO_CLEANUP": "true",
                        "YGGFLARE_CLOUDFLARE_AUTO_CLEANUP_BATCH_SIZE": limit,
                    },
                    clear=True,
                ),
                patch.object(cleanup, "api_token", return_value="token"),
                patch.object(cleanup, "CloudflareWriter"),
                patch.object(cleanup, "cloudflare_settings", return_value=settings),
                patch.object(cleanup, "scope", return_value={}),
                patch.object(cleanup.Path, "is_dir", return_value=True),
                patch.object(cleanup, "desired_hosts", return_value={}),
                patch.object(cleanup, "observe_orphans", return_value=hosts),
                patch.object(
                    cleanup,
                    "review_orphan",
                    side_effect=lambda *args: ({}, "fingerprint"),
                ) as review,
                patch.object(
                    cleanup,
                    "retire",
                    return_value=["delete_dns_cname", "remove_tunnel_ingress"],
                ) as retire,
                patch.object(cleanup, "notify_retirement") as notify,
                patch("builtins.print"),
            ):
                self.assertEqual(cleanup.main(), 0)
            self.assertEqual(review.call_count, count)
            self.assertEqual(retire.call_count, count)
            self.assertEqual(
                [call.args[4] for call in retire.call_args_list],
                hosts[:count],
            )
            self.assertEqual(
                [call.args[0] for call in notify.call_args_list], hosts[:count]
            )

    def test_invalid_cleanup_budget_blocks_before_network_access(self):
        for budget in ("-1", "invalid"):
            with (
                patch.dict(
                    "os.environ",
                    {
                        "YGGFLARE_CLOUDFLARE_AUTO_APPLY": "true",
                        "YGGFLARE_CLOUDFLARE_AUTO_CLEANUP": "true",
                        "YGGFLARE_CLOUDFLARE_AUTO_CLEANUP_BATCH_SIZE": budget,
                    },
                    clear=True,
                ),
                patch.object(cleanup, "CloudflareWriter") as writer,
                self.assertRaises(cleanup.OwnershipError),
            ):
                cleanup.main()
            writer.assert_not_called()


if __name__ == "__main__":
    unittest.main()
