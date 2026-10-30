"""Resource collection must discard exit races without hiding live failures."""

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import psutil

import native_resources as resources

MACH_FAILURE = "mach_vm_region(VM_REGION_TOP_INFO) syscall failed"


class MemoryExitTests(unittest.TestCase):
    def process(self):
        return Mock(
            spec=[
                "pid",
                "create_time",
                "memory_full_info",
                "num_fds",
                "is_running",
                "status",
                "children",
            ],
            pid=42,
        )

    def inspect_failure(self, process, message=MACH_FAILURE, platform="darwin"):
        process.create_time.return_value = 1
        process.memory_full_info.side_effect = RuntimeError(message)
        with (
            patch.object(resources.sys, "platform", platform),
            patch.object(resources, "redacted", side_effect=lambda value: value),
            patch.object(resources.time, "sleep") as sleep,
        ):
            try:
                return resources.inspect(process)
            finally:
                self.assertLessEqual(sleep.call_count, 10)

    def test_disappeared_process_discards_sample(self):
        process = self.process()
        process.is_running.return_value = False
        with self.assertRaises(psutil.NoSuchProcess):
            self.inspect_failure(process)

    def test_zombie_and_dead_processes_discard_sample(self):
        for state in [psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD]:
            with self.subTest(state=state):
                process = self.process()
                process.is_running.return_value = True
                process.status.return_value = state
                with self.assertRaises(psutil.NoSuchProcess):
                    self.inspect_failure(process)

    def test_exit_between_identity_and_status_checks_discards_sample(self):
        process = self.process()
        process.is_running.return_value = True
        process.status.side_effect = psutil.NoSuchProcess(process.pid)
        with self.assertRaises(psutil.NoSuchProcess):
            self.inspect_failure(process)

    def test_delayed_exit_discards_sample(self):
        process = self.process()
        process.is_running.side_effect = [True, True, False]
        process.status.return_value = psutil.STATUS_RUNNING
        with self.assertRaises(psutil.NoSuchProcess):
            self.inspect_failure(process)
        self.assertEqual(process.is_running.call_count, 3)

    def test_live_memory_failure_is_not_hidden(self):
        process = self.process()
        process.is_running.return_value = True
        process.status.return_value = psutil.STATUS_RUNNING
        with self.assertRaisesRegex(RuntimeError, "mach_vm_region"):
            self.inspect_failure(process)
        self.assertEqual(process.is_running.call_count, 10)

    def test_unknown_errors_and_other_platforms_are_not_reclassified(self):
        for message, platform in [
            ("other memory failure", "darwin"),
            (MACH_FAILURE, "linux"),
        ]:
            with self.subTest(message=message, platform=platform):
                process = self.process()
                with self.assertRaises(RuntimeError):
                    self.inspect_failure(process, message, platform)
                process.is_running.assert_not_called()

    def test_denied_exit_verification_is_not_treated_as_exit(self):
        process = self.process()
        process.is_running.return_value = True
        process.status.side_effect = psutil.AccessDenied(process.pid)
        with self.assertRaises(psutil.AccessDenied):
            self.inspect_failure(process)

    def test_partial_cohort_is_not_returned(self):
        root = self.process()
        root.children.return_value = [SimpleNamespace(pid=43, create_time=lambda: 2)]
        child = self.process()
        child.pid = 43
        child.create_time.return_value = 2
        complete = {
            "same_identity": True,
            "pid": 42,
            "memory": {"uss": 1, "rss": 2, "vms": 3},
            "handles": 4,
            "regions": [{"bytes": 3, "state": 0x1000}],
        }
        with (
            patch.object(resources.psutil, "Process", return_value=child),
            patch.object(resources, "redacted", side_effect=lambda value: value),
            patch.object(
                resources, "inspect", side_effect=[complete, psutil.NoSuchProcess(43)]
            ),
            self.assertRaises(psutil.NoSuchProcess),
        ):
            resources.sample(root)


if __name__ == "__main__":
    unittest.main()
