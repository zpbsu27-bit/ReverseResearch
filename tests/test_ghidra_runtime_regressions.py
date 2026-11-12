import asyncio
import os
import re
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from mcp.types import CallToolResult
from re_mcp.exceptions import BackendError

from re_mcp.worker_provider import Worker, WorkerPoolProvider, WorkerState
from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.session import Session, _project_storage


class DummyBackend:
    @staticmethod
    def canonical_path(file_path: str, **kwargs):
        return os.path.realpath(os.path.expanduser(file_path))


class GhidraProjectStorageTests(unittest.TestCase):
    def test_unicode_source_uses_ascii_content_addressed_project_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_dir = root / "中文（测试）"
            source_dir.mkdir()
            source = source_dir / "游戏（测试）.exe"
            source.write_bytes(b"MZ" + b"\x00" * 30)
            project_root = root / "projects"
            previous = os.environ.get("RE_MCP_GHIDRA_PROJECT_ROOT")
            os.environ["RE_MCP_GHIDRA_PROJECT_ROOT"] = str(project_root)
            try:
                project_dir, project_name, project_file = _project_storage(str(source))
            finally:
                if previous is None:
                    os.environ.pop("RE_MCP_GHIDRA_PROJECT_ROOT", None)
                else:
                    os.environ["RE_MCP_GHIDRA_PROJECT_ROOT"] = previous

            self.assertEqual(os.path.realpath(project_dir), os.path.realpath(project_root))
            self.assertRegex(project_name, r"^rr_[0-9a-f]{24}$")
            self.assertTrue(project_file.endswith(project_name + ".gpr"))
            self.assertNotIn("（", project_name)
            self.assertNotIn("）", project_name)


class WorkerPoolStaleIdTests(unittest.IsolatedAsyncioTestCase):
    async def test_dead_worker_id_can_be_reused_for_new_path(self):
        provider = object.__new__(WorkerPoolProvider)
        provider._backend = DummyBackend()
        provider._workers = {}
        provider._id_to_path = {}
        provider._lock = asyncio.Lock()
        provider._max_workers = None

        old_path = os.path.realpath("old-failed.exe")
        new_path = os.path.realpath("new-retry.exe")
        dead = Worker(database_id="retrydb", file_path=old_path)
        dead.state = WorkerState.DEAD
        dead._spawn_error = "previous import failed"
        provider._workers[old_path] = dead
        provider._id_to_path["retrydb"] = old_path

        async def fake_background_spawn(worker, *args, **kwargs):
            worker.state = WorkerState.IDLE
            worker._ready_event.set()

        provider._background_spawn = fake_background_spawn

        result = await provider.spawn_worker(
            new_path,
            run_auto_analysis=False,
            database_id="retrydb",
            force_new=False,
        )
        await asyncio.sleep(0)

        self.assertEqual(result["database"], "retrydb")
        self.assertEqual(provider._id_to_path["retrydb"], new_path)
        self.assertNotIn(old_path, provider._workers)


class ExistingGhidraProjectTests(unittest.TestCase):
    """Exercise Session.open against the Java project API's exception contract."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.source = root / "Heroes3.exe"
        self.source.write_bytes(b"MZ" + b"\x00" * 30)
        self.path = os.path.realpath(self.source)
        env = patch.dict(os.environ, {"RE_MCP_GHIDRA_PROJECT_ROOT": str(root / "projects")})
        env.start()
        self.addCleanup(env.stop)
        project_dir, _, project_file = _project_storage(self.path)
        Path(project_dir).mkdir()
        Path(project_file).write_bytes(b"existing-project-sentinel")
        self.marker = Path(project_file)
        self.program = Mock()
        self.program.getExecutablePath.return_value = self.path
        self.program.getName.return_value = self.source.name
        self.folder = Mock()
        self.folder.getFile.return_value = None
        self.folder.getFiles.return_value = []
        self.folder.getFolders.return_value = []
        self.project = Mock()
        self.project.getRootFolder.return_value = self.folder
        # The real API throws, rather than returning None, for a missing item.
        self.project.openProgram.side_effect = FileNotFoundError("//Heroes3.exe")
        self.project.importProgram.return_value = self.program
        self.api = Mock()
        self.api.openProject.return_value = self.project
        self.flat = Mock(return_value=object())
        modules = {
            "ghidra.base.project": {"GhidraProject": self.api},
            "ghidra.program.flatapi": {"FlatProgramAPI": self.flat},
            "ghidra.program.model.lang": {"CompilerSpecID": str, "LanguageID": str},
            "ghidra.util.task": {"TaskMonitor": types.SimpleNamespace(DUMMY=object())},
            "java.io": {"File": str},
        }
        imported = {}
        for name, attributes in modules.items():
            module = types.ModuleType(name)
            module.__dict__.update(attributes)
            imported[name] = module
        imports = patch.dict(sys.modules, imported)
        imports.start()
        self.addCleanup(imports.stop)
        self.session = Session()

    def open(self):
        return self.session.open(self.path, run_auto_analysis=False, force_new=False)

    def assert_preserved_failure(self, error_type):
        with self.assertRaises(GhidraError) as caught:
            self.open()
        self.assertEqual(caught.exception.error_type, error_type)
        self.assertFalse(self.session.is_open())
        self.assertIsNone(self.session.program)
        self.assertEqual(self.marker.read_bytes(), b"existing-project-sentinel")
        self.api.createProject.assert_not_called()
        self.project.close.assert_called_once_with()

    def test_empty_existing_project_imports_without_calling_missing_open_program(self):
        result = self.open()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["database_name"], "Heroes3.exe")
        self.assertIs(self.session.program, self.program)
        self.project.openProgram.assert_not_called()
        self.project.importProgram.assert_called_once_with(self.path)
        self.api.createProject.assert_not_called()
        self.api.analyze.assert_not_called()
        self.assertEqual(self.marker.read_bytes(), b"existing-project-sentinel")
        self.session.close(save=False)
        self.project.close.assert_called_once_with()

    def test_existing_program_is_opened_without_reimport_or_enumeration(self):
        self.folder.getFile.return_value = object()
        self.project.openProgram.side_effect = None
        self.project.openProgram.return_value = self.program
        self.assertEqual(self.open()["status"], "ok")
        self.project.openProgram.assert_called_once_with("/", "Heroes3.exe", False)
        self.project.importProgram.assert_not_called()
        self.folder.getFiles.assert_not_called()
        self.folder.getFolders.assert_not_called()
        self.session.close(save=False)

    def test_different_existing_program_is_preserved_and_rejected(self):
        self.folder.getFiles.return_value = [object()]
        self.assert_preserved_failure("ProjectConflict")
        self.project.openProgram.assert_not_called()
        self.project.importProgram.assert_not_called()

    def test_existing_subfolder_is_preserved_and_rejected(self):
        self.folder.getFolders.return_value = [object()]
        self.assert_preserved_failure("ProjectConflict")
        self.project.importProgram.assert_not_called()

    def test_existing_program_read_error_is_not_reclassified_as_missing(self):
        self.folder.getFile.return_value = object()
        self.project.openProgram.side_effect = OSError("program database is damaged")
        self.assert_preserved_failure("RuntimeError")
        self.project.importProgram.assert_not_called()

    def test_root_enumeration_error_does_not_attempt_import(self):
        self.folder.getFiles.side_effect = OSError("cannot enumerate project")
        self.assert_preserved_failure("RuntimeError")
        self.project.importProgram.assert_not_called()

    def test_lock_conflict_does_not_create_or_close_someone_elses_project(self):
        self.api.openProject.side_effect = OSError("project lock held")
        with self.assertRaises(GhidraError) as caught:
            self.open()
        self.assertEqual(caught.exception.error_type, "RuntimeError")
        self.assertFalse(self.session.is_open())
        self.api.createProject.assert_not_called()
        self.project.importProgram.assert_not_called()
        self.project.close.assert_not_called()
        self.assertEqual(self.marker.read_bytes(), b"existing-project-sentinel")

    def test_import_returning_none_closes_project_without_publishing_session(self):
        self.project.importProgram.return_value = None
        self.assert_preserved_failure("ImportFailed")

    def test_import_exception_closes_project_without_rebuilding_it(self):
        self.project.importProgram.side_effect = OSError("loader failed")
        self.assert_preserved_failure("RuntimeError")

    def test_source_metadata_failure_closes_project(self):
        self.program.getExecutablePath.return_value = "wrong-path.exe"
        self.program.startTransaction.side_effect = OSError("metadata transaction failed")
        self.assert_preserved_failure("RuntimeError")

    def test_flat_api_failure_closes_project_without_publishing_session(self):
        self.flat.side_effect = OSError("flat API initialization failed")
        self.assert_preserved_failure("RuntimeError")

    def test_cleanup_failure_keeps_the_primary_open_error(self):
        self.folder.getFile.return_value = object()
        self.project.openProgram.side_effect = OSError("primary program error")
        self.project.close.side_effect = OSError("secondary cleanup error")
        with self.assertRaises(GhidraError) as caught:
            self.open()
        self.assertIn("primary program error", str(caught.exception))
        self.assertNotIn("secondary cleanup error", str(caught.exception))
        self.project.close.assert_called_once_with()
        self.project.importProgram.assert_not_called()
        self.assertFalse(self.session.is_open())


class GhidraPersistenceOwnerTests(unittest.TestCase):
    """Persistence must use the project that owns its batch transaction."""

    setUp = ExistingGhidraProjectTests.setUp
    open = ExistingGhidraProjectTests.open

    def test_persisted_program_saves_through_project_owner(self):
        self.open()
        self.program.getDomainFile.return_value.getParent.return_value = object()
        self.program.getCurrentTransactionInfo.side_effect = AssertionError("foreign transaction ID")
        self.session.save()
        self.project.save.assert_called_once_with(self.program)
        self.program.getCurrentTransactionInfo.assert_not_called()
        self.program.endTransaction.assert_not_called()
        self.program.getDomainFile.return_value.save.assert_not_called()
        self.project.saveAs.assert_not_called()

    def test_repeated_save_leaves_the_project_as_transaction_owner(self):
        self.open()
        self.program.getDomainFile.return_value.getParent.return_value = object()
        self.program.getCurrentTransactionInfo.return_value = None
        self.session.save()
        self.session.save()
        self.assertEqual(self.project.save.call_count, 2)
        self.program.endTransaction.assert_not_called()
        self.assertTrue(self.session.is_open())

    def test_imported_unsaved_program_never_overwrites_a_collision(self):
        self.open()
        self.program.getDomainFile.return_value.getParent.return_value = None
        self.program.getCurrentTransactionInfo.return_value = None
        self.project.saveAs.side_effect = FileExistsError("different program already exists")
        with self.assertRaises(FileExistsError):
            self.session.save()
        self.project.saveAs.assert_called_once_with(self.program, "/", "Heroes3.exe", False)
        self.assertTrue(self.session.is_open())
        self.project.close.assert_not_called()

    def test_import_with_no_domain_file_uses_non_overwriting_save_as(self):
        self.open()
        self.program.getDomainFile.return_value = None
        self.program.getCurrentTransactionInfo.return_value = None
        self.session.save()
        self.project.saveAs.assert_called_once_with(self.program, "/", "Heroes3.exe", False)
        self.project.save.assert_not_called()

    def test_failed_save_during_close_preserves_the_open_session(self):
        self.open()
        self.program.getCurrentTransactionInfo.return_value = None
        self.program.getDomainFile.return_value.getParent.return_value = object()
        self.project.save.side_effect = OSError("disk refused save")
        self.program.getDomainFile.return_value.save.side_effect = OSError("disk refused save")
        with self.assertRaises(GhidraError) as caught:
            self.session.close(save=True)
        self.assertEqual(caught.exception.error_type, "CloseFailed")
        self.assertTrue(self.session.is_open())
        self.assertIs(self.session.program, self.program)
        self.assertEqual(self.session.current_path, self.path)
        self.project.close.assert_not_called()

    def test_project_close_error_does_not_report_a_cleared_session(self):
        self.open()
        self.project.close.side_effect = OSError("project release failed")
        with self.assertRaises(GhidraError):
            self.session.close(save=False)
        self.assertTrue(self.session.is_open())
        self.assertIs(self.session.program, self.program)

    def test_open_new_input_stops_when_previous_save_fails(self):
        self.open()
        self.program.getCurrentTransactionInfo.return_value = None
        self.project.save.side_effect = OSError("disk refused save")
        self.program.getDomainFile.return_value.save.side_effect = OSError("disk refused save")
        self.api.openProject.reset_mock()
        with self.assertRaises(GhidraError):
            self.open()
        self.api.openProject.assert_not_called()
        self.assertTrue(self.session.is_open())


class WorkerCloseOwnershipTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.provider = object.__new__(WorkerPoolProvider)
        self.provider._backend = DummyBackend()
        self.provider._workers = {}
        self.provider._id_to_path = {}
        self.provider._lock = asyncio.Lock()
        self.provider._max_workers = None
        self.provider._close_client = AsyncMock()
        self.worker = self.add_worker("complete", "complete.exe")

    def add_worker(self, identity, path):
        worker = Worker(database_id=identity, file_path=os.path.realpath(path))
        worker.state = WorkerState.IDLE
        worker._ready_event.set()
        worker.attach("owner")
        worker.client = Mock()
        worker.client.call_tool_mcp = AsyncMock(return_value=self.result("closed"))
        self.provider._workers[worker.file_path] = worker
        self.provider._id_to_path[identity] = worker.file_path
        return worker

    @staticmethod
    def result(status, *, is_error=False):
        data = {"status": status, "saved": True}
        if is_error:
            data = {"error": "disk refused save", "error_type": "CloseFailed"}
        return CallToolResult(content=[], structuredContent=data, isError=is_error)

    def assert_retained(self, worker=None):
        worker = worker or self.worker
        self.assertIs(self.provider._workers[worker.file_path], worker)
        self.assertEqual(self.provider._id_to_path[worker.database_id], worker.file_path)
        self.assertTrue(worker.is_attached("owner"))

    async def test_explicit_save_failure_keeps_index_session_and_process(self):
        self.worker.client.call_tool_mcp.return_value = self.result("error", is_error=True)
        with self.assertRaises(BackendError) as caught:
            await self.provider.close_for_session(self.worker, "owner")
        self.assertEqual(caught.exception.error_type, "CloseFailed")
        self.assert_retained()
        self.assertIs(self.provider.resolve_worker("complete"), self.worker)
        self.provider._close_client.assert_not_awaited()

    async def test_terminate_worker_has_the_same_save_failure_contract(self):
        self.worker.client.call_tool_mcp.return_value = self.result("error", is_error=True)
        with self.assertRaises(BackendError):
            await self.provider.terminate_worker(self.worker.file_path)
        self.assert_retained()
        self.provider._close_client.assert_not_awaited()

    async def test_transport_failure_reserves_unknown_outcome(self):
        self.worker.client.call_tool_mcp.side_effect = OSError("connection ended")
        with self.assertRaises(BackendError) as caught:
            await self.provider.close_for_session(self.worker, "owner")
        self.assertEqual(caught.exception.error_type, "CloseOutcomeUnknown")
        self.assert_retained()
        self.assertEqual(self.worker.state.name, "CLOSING")
        self.provider._close_client.assert_not_awaited()
        with self.assertRaises(BackendError):
            self.provider.resolve_worker("complete")
        with self.assertRaises(BackendError):
            await self.provider.close_for_session(self.worker, "owner", force=True, save=False)
        self.worker.client.call_tool_mcp.assert_awaited_once()

    async def test_unexpected_success_payload_is_not_closed(self):
        self.worker.client.call_tool_mcp.return_value = self.result("still_open")
        with self.assertRaises(BackendError) as caught:
            await self.provider.close_for_session(self.worker, "owner")
        self.assertEqual(caught.exception.error_type, "CloseOutcomeUnknown")
        self.assert_retained()
        self.provider._close_client.assert_not_awaited()

    async def test_missing_response_is_unknown_instead_of_a_known_rejection(self):
        self.worker.client.call_tool_mcp.return_value = CallToolResult(content=[], isError=False)
        with self.assertRaises(BackendError) as caught:
            await self.provider.close_for_session(self.worker, "owner")
        self.assertEqual(caught.exception.error_type, "CloseOutcomeUnknown")
        self.assert_retained()
        self.assertEqual(self.worker.state.name, "CLOSING")
        self.provider._close_client.assert_not_awaited()

    async def test_close_without_confirmed_save_cannot_claim_requested_success(self):
        self.worker.client.call_tool_mcp.return_value = CallToolResult(
            content=[], structuredContent={"status": "closed", "saved": False})
        with self.assertRaises(BackendError) as caught:
            await self.provider.close_for_session(self.worker, "owner")
        self.assertEqual(caught.exception.error_type, "CloseOutcomeUnknown")
        self.assert_retained()
        self.provider._close_client.assert_not_awaited()

    async def test_already_closed_response_does_not_invent_a_save(self):
        self.worker.client.call_tool_mcp.return_value = CallToolResult(
            content=[], structuredContent={"status": "no_database_open"})
        result = await self.provider.close_for_session(self.worker, "owner")
        self.assertFalse(result["saved"])
        self.assertNotIn("complete", self.provider._id_to_path)

    async def test_closed_response_without_save_fact_keeps_unknown_reservation(self):
        self.worker.client.call_tool_mcp.return_value = CallToolResult(
            content=[], structuredContent={"status": "closed"})
        with self.assertRaises(BackendError) as caught:
            await self.provider.close_for_session(self.worker, "owner")
        self.assertEqual(caught.exception.error_type, "CloseOutcomeUnknown")
        self.assert_retained()
        self.provider._close_client.assert_not_awaited()

    async def test_busy_command_cannot_be_cancelled_to_make_close_succeed(self):
        self.worker._active_calls = 1
        with self.assertRaises(BackendError) as caught:
            await self.provider.close_for_session(self.worker, "owner", force=True)
        self.assertEqual(caught.exception.error_type, "Busy")
        self.assert_retained()
        self.worker.client.call_tool_mcp.assert_not_awaited()
        self.provider._close_client.assert_not_awaited()

    async def test_opening_worker_is_preserved(self):
        self.worker.state = WorkerState.STARTING
        self.worker._ready_event.clear()
        with self.assertRaises(BackendError):
            await self.provider.close_for_session(self.worker, "owner")
        self.assert_retained()
        self.worker.client.call_tool_mcp.assert_not_awaited()

    async def test_background_analysis_is_not_cancelled_by_close(self):
        gate = asyncio.Event()
        task = asyncio.create_task(gate.wait())
        self.worker._analysis_task = task
        try:
            with self.assertRaises(BackendError):
                await self.provider.close_for_session(self.worker, "owner")
            self.assertFalse(task.cancelled())
            self.assertFalse(task.done())
            self.assert_retained()
            self.worker.client.call_tool_mcp.assert_not_awaited()
        finally:
            gate.set()
            await task

    async def test_other_session_detaches_without_closing_database(self):
        self.worker.attach("peer")
        result = await self.provider.close_for_session(self.worker, "peer")
        self.assertEqual(result["status"], "detached")
        self.assertEqual(result["remaining_sessions"], 1)
        self.assert_retained()
        self.worker.client.call_tool_mcp.assert_not_awaited()

    async def test_force_does_not_override_save_failure(self):
        self.worker.attach("peer")
        self.worker.client.call_tool_mcp.return_value = self.result("error", is_error=True)
        with self.assertRaises(BackendError):
            await self.provider.close_for_session(self.worker, "owner", force=True)
        self.assert_retained()
        self.assertTrue(self.worker.is_attached("peer"))
        self.provider._close_client.assert_not_awaited()

    async def test_explicit_discard_is_forwarded_only_as_requested(self):
        result = await self.provider.close_for_session(self.worker, "owner", save=False)
        self.assertEqual(result["status"], "closed")
        self.worker.client.call_tool_mcp.assert_awaited_once_with("close_database", {"save": False})
        self.provider._close_client.assert_awaited_once_with(self.worker)
        self.assertNotIn(self.worker.file_path, self.provider._workers)
        self.assertNotIn("complete", self.provider._id_to_path)

    async def test_closing_reservation_blocks_attach_open_dispatch_and_second_close(self):
        entered, release = asyncio.Event(), asyncio.Event()

        async def close_call(*args):
            entered.set()
            await release.wait()
            return self.result("closed")

        self.worker.client.call_tool_mcp.side_effect = close_call
        task = asyncio.create_task(self.provider.close_for_session(self.worker, "owner"))
        try:
            await entered.wait()
            self.assert_retained()
            with self.assertRaises(BackendError):
                self.worker.attach("late")
            with self.assertRaises(BackendError):
                self.provider.resolve_worker("complete")
            with self.assertRaises(BackendError):
                await self.provider.spawn_worker(self.worker.file_path, session_id="late")
            with self.assertRaises(BackendError):
                await self.provider.spawn_worker("different.exe", database_id="complete")
            with self.assertRaises(BackendError):
                await self.provider.proxy_to_worker(self.worker, "get_database_info", {})
            with self.assertRaises(BackendError):
                await self.provider.close_for_session(self.worker, "owner")
        finally:
            release.set()
            await task
        self.worker.client.call_tool_mcp.assert_awaited_once()

    async def test_external_cancellation_keeps_unknown_reservation(self):
        entered, release = asyncio.Event(), asyncio.Event()

        async def close_call(*args):
            entered.set()
            await release.wait()
            return self.result("closed")

        self.worker.client.call_tool_mcp.side_effect = close_call
        task = asyncio.create_task(self.provider.close_for_session(self.worker, "owner"))
        await entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assert_retained()
        self.assertEqual(self.worker.state.name, "CLOSING")
        self.provider._close_client.assert_not_awaited()

    async def test_client_cleanup_failure_does_not_report_normal_close(self):
        self.provider._close_client.side_effect = OSError("transport cleanup failed")
        with self.assertRaises(BackendError) as caught:
            await self.provider.close_for_session(self.worker, "owner")
        self.assertEqual(caught.exception.error_type, "CloseOutcomeUnknown")
        self.assert_retained()

    async def test_surviving_pid_does_not_make_best_effort_cleanup_success(self):
        self.worker.pid = 123456
        self.provider._close_client = WorkerPoolProvider._close_client.__get__(self.provider)
        with patch("re_mcp.worker_provider._kill_pid", new_callable=AsyncMock), \
                patch("re_mcp.worker_provider.pid_alive", return_value=True):
            with self.assertRaises(BackendError) as caught:
                await self.provider.close_for_session(self.worker, "owner")
        self.assertEqual(caught.exception.error_type, "CloseOutcomeUnknown")
        self.assert_retained()
        self.assertEqual(self.worker.state.name, "CLOSING")

    async def test_process_cleanup_wait_keeps_the_same_identity_reserved(self):
        entered, release = asyncio.Event(), asyncio.Event()
        self.provider._close_client = WorkerPoolProvider._close_client.__get__(self.provider)
        self.worker._exit_stack = Mock()

        async def cleanup():
            entered.set()
            await release.wait()

        self.worker._exit_stack.aclose = AsyncMock(side_effect=cleanup)
        with patch("re_mcp.worker_provider._kill_pid", new_callable=AsyncMock):
            task = asyncio.create_task(self.provider.close_for_session(self.worker, "owner"))
            try:
                await entered.wait()
                self.assertEqual(self.worker.state.name, "CLOSING")
                self.assert_retained()
                with self.assertRaises(BackendError):
                    await self.provider.spawn_worker(self.worker.file_path, session_id="late")
            finally:
                release.set()
                await task
        self.assertNotIn("complete", self.provider._id_to_path)

    async def test_stale_worker_cannot_close_or_remove_new_identity_owner(self):
        fresh = self.add_worker("complete", "complete.exe")
        with self.assertRaises(BackendError):
            await self.provider.close_for_session(self.worker, "owner", force=True)
        self.assert_retained(fresh)
        self.worker.client.call_tool_mcp.assert_not_awaited()
        self.provider._close_client.assert_not_awaited()

    async def test_detach_all_propagates_save_failure_and_keeps_owner(self):
        self.worker.client.call_tool_mcp.return_value = self.result("error", is_error=True)
        with self.assertRaises(BackendError):
            await self.provider.detach_all("owner")
        self.assert_retained()
        self.provider._close_client.assert_not_awaited()

    async def test_disconnect_bookkeeping_does_not_close_or_discard(self):
        await self.provider.detach_all("owner", terminate=False)
        self.assertFalse(self.worker.is_attached("owner"))
        self.assertIs(self.provider._workers[self.worker.file_path], self.worker)
        self.worker.client.call_tool_mcp.assert_not_awaited()
        self.provider._close_client.assert_not_awaited()

    async def test_batch_shutdown_finishes_good_worker_and_preserves_failed_worker(self):
        good = self.add_worker("other", "other.exe")
        self.worker.client.call_tool_mcp.return_value = self.result("error", is_error=True)
        with self.assertRaises(BackendError):
            await self.provider.shutdown_all()
        self.assert_retained()
        self.assertNotIn(good.file_path, self.provider._workers)
        self.assertNotIn(good.database_id, self.provider._id_to_path)
        self.provider._close_client.assert_awaited_once_with(good)

    async def test_closing_list_and_wait_do_not_advertise_ready(self):
        self.worker.state = WorkerState.CLOSING
        self.worker._close_error = "unknown after transport loss"
        result = self.provider.build_database_list(include_state=True)
        self.assertEqual(result["databases"][0]["state"], "closing")
        self.assertEqual(result["databases"][0]["close_error"], self.worker._close_error)
        with self.assertRaises(BackendError):
            await self.provider.wait_for_ready("complete")


if __name__ == "__main__":
    unittest.main()
