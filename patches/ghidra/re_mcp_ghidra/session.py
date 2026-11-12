# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Database session manager for Ghidra via pyghidra.

Tracks whether a program is currently open and provides guards
for tools that require an open database.
"""

from __future__ import annotations

import functools
import hashlib
import inspect
import logging
import os
import shutil
import signal
import tempfile
from contextlib import contextmanager

from re_mcp_ghidra.exceptions import GhidraError

log = logging.getLogger(__name__)

_PROJECT_SUBDIR = "ghidra_projects"
_PROJECT_ROOT_ENV = "RE_MCP_GHIDRA_PROJECT_ROOT"
_GHIDRA_INVALID_NAME_CHARS = frozenset("/\\\\'`\"*:<>?|")


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ghidra_item_name_valid(name: str) -> bool:
    """Mirror Ghidra LocalFileSystem.isValidNameCharacter for item names."""
    return bool(name) and all(
        32 <= ord(char) <= 0xFF and char not in _GHIDRA_INVALID_NAME_CHARS
        for char in name
    )


def _ghidra_program_name(path: str) -> str:
    """Return the stable project item name used for an external binary path."""
    original = os.path.basename(path)
    if _ghidra_item_name_valid(original):
        return original
    suffix = os.path.splitext(original)[1]
    if not _ghidra_item_name_valid(suffix) or any(ord(char) > 0x7F for char in suffix):
        suffix = ""
    return f"rr_{_sha256_file(path)[:24]}{suffix}"


@contextmanager
def _ghidra_import_path(path: str, program_name: str):
    """Expose an ASCII/Latin-1-safe basename without changing source identity."""
    if os.path.basename(path) == program_name:
        yield path
        return

    alias_dir = tempfile.mkdtemp(prefix="rr-ghidra-import-")
    alias_path = os.path.join(alias_dir, program_name)
    try:
        try:
            os.link(path, alias_path)
        except OSError:
            shutil.copy2(path, alias_path)
        yield alias_path
    finally:
        shutil.rmtree(alias_dir, ignore_errors=True)


def _restore_program_source_path(program, path: str) -> None:
    """Keep executable metadata pointed at the caller-visible source path."""
    current = str(program.getExecutablePath() or "")
    if current == path:
        return

    tx_id = program.startTransaction("ReverseResearch source path")
    commit = False
    try:
        program.setExecutablePath(path)
        commit = True
    finally:
        program.endTransaction(tx_id, commit)


def _project_storage(path: str) -> tuple[str, str, str]:
    """Return a filesystem-safe, content-addressed Ghidra project location."""
    configured_root = os.environ.get(_PROJECT_ROOT_ENV, "").strip()
    if configured_root:
        project_dir = os.path.realpath(os.path.expanduser(configured_root))
    else:
        project_dir = os.path.join(os.path.dirname(path), _PROJECT_SUBDIR)
    project_name = f"rr_{_sha256_file(path)[:24]}"
    project_file = os.path.join(project_dir, project_name + ".gpr")
    return project_dir, project_name, project_file


class Session:
    """Singleton managing the Ghidra program session."""

    def __init__(self):
        self._program = None
        self._project = None
        self._project_location = None
        self._current_path: str | None = None
        self._flat_api = None
        self.capabilities: dict[str, bool] = {}

    def is_open(self) -> bool:
        return self._current_path is not None and self._program is not None

    @property
    def current_path(self) -> str | None:
        return self._current_path

    @property
    def program(self):
        return self._program

    @property
    def flat_api(self):
        return self._flat_api

    def open(
        self,
        file_path: str,
        run_auto_analysis: bool = False,
        force_new: bool = False,
        language: str = "",
        compiler_spec: str = "",
    ) -> dict:
        """Open a binary for analysis.

        Returns a status dict on success.  Raises :class:`GhidraError` on failure.
        """
        from ghidra.base.project import GhidraProject  # noqa: PLC0415
        from ghidra.program.flatapi import FlatProgramAPI  # noqa: PLC0415
        from ghidra.program.model.lang import (  # noqa: PLC0415
            CompilerSpecID,
            LanguageID,
        )
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415
        from java.io import File  # noqa: PLC0415

        path = os.path.realpath(os.path.expanduser(file_path))

        if not os.path.isfile(path):
            raise GhidraError(f"File not found: {path}", error_type="FileNotFoundError")

        if self.is_open():
            self.close(save=True)

        # Keep Ghidra project metadata out of the target directory when a
        # project root is configured, and never use the original filename as
        # a Ghidra project name (Unicode punctuation can be rejected by Ghidra).
        original_name = os.path.basename(path)
        binary_name = _ghidra_program_name(path)
        project_dir, project_name, project_file = _project_storage(path)

        os.makedirs(project_dir, exist_ok=True)
        project_location = project_dir

        warnings: list[str] = []
        if binary_name != original_name:
            warnings.append(
                "source filename cannot be represented by Ghidra LocalFileSystem; "
                f"using internal database name {binary_name!r} while preserving the original source path"
            )

        project = None
        try:
            if force_new and os.path.exists(project_file):
                gpr_path = project_file
                rep_path = os.path.join(project_dir, project_name + ".rep")
                if os.path.isfile(gpr_path):
                    os.remove(gpr_path)
                if os.path.isdir(rep_path):
                    shutil.rmtree(rep_path)
                log.info("force_new: removed existing project files")

            if os.path.exists(project_file):
                project = GhidraProject.openProject(project_location, project_name)
                root_folder = project.getRootFolder()
                if root_folder.getFile(binary_name) is not None:
                    program = project.openProgram("/", binary_name, False)
                else:
                    # openProgram throws FileNotFoundException for missing
                    # items. Resume an interrupted import only into a truly
                    # empty project; never replace unrelated analysis data.
                    if root_folder.getFiles() or root_folder.getFolders():
                        raise GhidraError(
                            f"Existing project has no {binary_name!r} and is not empty",
                            error_type="ProjectConflict",
                        )
                    with _ghidra_import_path(path, binary_name) as import_path:
                        program = project.importProgram(File(import_path))
                    if program is None:
                        raise GhidraError(
                            f"Failed to import {path} into existing project",
                            error_type="ImportFailed",
                        )
            else:
                project = GhidraProject.createProject(project_location, project_name, False)
                lang_svc = None
                lang = None
                cspec = None

                if language:
                    lang_svc = _get_language_service()
                    try:
                        lang = lang_svc.getLanguage(LanguageID(language))
                    except Exception as e:
                        raise GhidraError(
                            f"Unknown language: {language!r}. Use list_targets to see available languages.",
                            error_type="InvalidArgument",
                        ) from e

                    if compiler_spec:
                        try:
                            cspec = lang.getCompilerSpecByID(CompilerSpecID(compiler_spec))
                        except Exception as e:
                            raise GhidraError(
                                f"Unknown compiler spec: {compiler_spec!r} for language {language!r}",
                                error_type="InvalidArgument",
                            ) from e

                with _ghidra_import_path(path, binary_name) as import_path:
                    if lang is not None:
                        if cspec is not None:
                            program = project.importProgram(File(import_path), lang, cspec)
                        else:
                            program = project.importProgramFast(File(import_path), lang)
                    else:
                        program = project.importProgram(File(import_path))

                if program is None:
                    raise GhidraError(
                        f"Failed to import binary: {path}",
                        error_type="ImportFailed",
                    )

            _restore_program_source_path(program, path)

            if run_auto_analysis:
                from ghidra.program.util import GhidraProgramUtilities  # noqa: PLC0415

                try:
                    GhidraProgramUtilities.resetAnalysisFlags(program)
                except AttributeError:
                    # Compatibility with older Ghidra releases that exposed
                    # the previous boolean setter instead.
                    GhidraProgramUtilities.setAnalyzedFlag(program, False)
                GhidraProject.analyze(program)

            flat_api = FlatProgramAPI(program, TaskMonitor.DUMMY)
        except Exception as exc:
            if project is not None:
                try:
                    project.close()
                except Exception:
                    log.exception("Failed to close project after open failure: %s", path)
            if isinstance(exc, GhidraError):
                raise
            log.exception("Failed to open database: %s", path)
            raise GhidraError(f"Failed to open database: {exc}", error_type="RuntimeError") from exc

        self._program = program
        self._project = project
        self._project_location = project_location
        self._current_path = path
        self._flat_api = flat_api
        self.capabilities = self._probe_capabilities()
        log.info("Opened database: %s (capabilities: %s)", path, self.capabilities)
        return {
            "status": "ok",
            "path": path,
            "database_name": binary_name,
            "warnings": warnings,
        }

    def _probe_capabilities(self) -> dict[str, bool]:
        """Detect which optional features are available."""
        return {
            "decompiler": True,
        }

    def _end_open_transactions(self) -> None:
        """End any active transactions so save/undo can proceed.

        Ghidra cannot save or undo while a transaction is active.  The
        pyghidra environment (or tool calls whose endTransaction was
        swallowed by the JVM) may leave a transaction open.

        Strategy: commit first (preserving data from tool operations),
        then abort any cascading listener transactions that the commit
        triggers.  Aborting listener-opened transactions is safe because
        they only contain bookkeeping that will be regenerated on next
        analysis.
        """
        import contextlib  # noqa: PLC0415

        tx_info = self._program.getCurrentTransactionInfo()
        if tx_info is None:
            return
        # Commit to preserve tool data.
        with contextlib.suppress(Exception):
            self._program.endTransaction(int(tx_info.getID()), True)
        # Abort cascading listener transactions to break the cycle.
        for _ in range(10):
            tx_info = self._program.getCurrentTransactionInfo()
            if tx_info is None:
                return
            with contextlib.suppress(Exception):
                self._program.endTransaction(int(tx_info.getID()), False)

    def save(self) -> None:
        """Persist the current program to disk."""
        if self._program is None or self._project is None:
            raise GhidraError("No database is open.", error_type="NoDatabase")

        df = self._program.getDomainFile()
        # GhidraProject owns a Batch Processing transaction for each program.
        # Its save API ends and renews that exact transaction. A TransactionInfo
        # ID is not permission to end arbitrary subtransactions here.
        if df is not None and df.getParent() is not None:
            self._project.save(self._program)
        else:
            self._project.saveAs(self._program, "/", self._program.getName(), False)

    def close(self, save: bool = True) -> dict:
        """Close the current database.

        Raises :class:`GhidraError` on failure.
        """
        if not self.is_open():
            return {"status": "no_database_open"}

        path = self._current_path
        try:
            if save and self._program is not None and self._project is not None:
                self.save()
            if self._project is not None:
                self._project.close()
        except Exception as exc:
            log.exception("Error closing database %s", path)
            raise GhidraError(f"Error closing database {path}", error_type="CloseFailed") from exc

        self._program = None
        self._project = None
        self._project_location = None
        self._current_path = None
        self._flat_api = None

        log.info("Closed database: %s (saved=%s)", path, save)
        return {"status": "closed", "path": path, "saved": save}

    def require_open(self, fn):
        """Decorator that raises :class:`GhidraError` if no database is open."""

        def _check():
            if not self.is_open():
                raise GhidraError(
                    "No database is open. Use open_database first.",
                    error_type="NoDatabase",
                )

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                from re_mcp_ghidra.helpers import call_ghidra  # noqa: PLC0415

                await call_ghidra(_check)
                return await fn(*args, **kwargs)

            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            _check()
            return fn(*args, **kwargs)

        return wrapper


# Module-level singleton
session = Session()


def _get_language_service():
    """Get Ghidra's default language service."""

    try:
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager  # noqa: PLC0415

        return AutoAnalysisManager.getLanguageService()
    except Exception:
        from ghidra.program.util import DefaultLanguageService  # noqa: PLC0415

        return DefaultLanguageService.getLanguageService()


def _terminate_handler(signum, frame):
    """SIGTERM — shut down immediately."""
    raise SystemExit(0)


# SIGTERM — hard shutdown
if hasattr(signal, "SIGTERM"):
    signal.signal(signal.SIGTERM, _terminate_handler)
