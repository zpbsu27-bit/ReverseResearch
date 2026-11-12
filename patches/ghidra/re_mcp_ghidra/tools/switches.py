# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Static computed-jump targets; case labels and defaults remain unavailable."""

from __future__ import annotations

from typing import Literal

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_READ_ONLY,
    Address,
    Limit,
    Offset,
    format_address,
    paginate_iter,
    resolve_address,
)
from re_mcp_ghidra.session import session


# Bound both work and retained output, including duplicate/non-jump references.
# Exhaustion is an error, never a successful partial switch observation.
_MAX_REFERENCES = 8192
_MAX_TARGETS = 512
_PROVENANCE = "ghidra-reference-manager"


class SwitchCase(BaseModel):
    """One observed jump destination, with no recovered case labels."""

    case_values: None = Field(default=None, description="Unavailable; never target ordinals.")
    target: str = Field(description="Observed memory jump destination offset (hex).")
    address_space: str = Field(description="Destination address-space name.")


class SwitchFacts(BaseModel):
    """Reference observations do not establish a complete source-level switch."""

    num_cases: None = Field(default=None, description="Unavailable source-level case count.")
    num_targets: int = Field(description="Unique typed memory jump destinations observed.")
    default_targets: None = Field(default=None, description="Unavailable; no default is inferred.")
    labels_status: Literal["unavailable"] = "unavailable"
    default_status: Literal["unavailable"] = "unavailable"
    provenance: Literal["ghidra-reference-manager"] = _PROVENANCE
    references_examined: int = Field(description="All references enumerated at this instruction.")
    references_ignored: int = Field(description="References not typed as memory jump destinations.")
    references_complete: Literal[True] = Field(
        default=True, description="Reference enumeration completed within the hard budgets."
    )
    coverage_complete: Literal[False] = Field(
        default=False, description="Labels, default, table layout and runtime reachability remain unknown."
    )


class GetSwitchInfoResult(SwitchFacts):
    """Static reference targets at one computed jump, not recovered case mappings."""

    address: str = Field(description="Computed-jump instruction address (hex).")
    cases: list[SwitchCase] = Field(description="Observed targets; case_values is unavailable for each.")


class SwitchSummary(SwitchFacts):
    """Computed-jump summary using the same target semantics as get_switch_info."""

    address: str = Field(description="Computed-jump instruction address (hex).")
    function: str = Field(description="Containing function name.")


def _collect_jump_targets(program, addr) -> tuple[list[SwitchCase], dict]:
    """Collect only typed memory jump references, preserving address-space identity."""
    targets: set[tuple[str, int]] = set()
    examined = 0
    ignored = 0
    for ref in program.getReferenceManager().getReferencesFrom(addr):
        examined += 1
        if examined > _MAX_REFERENCES:
            raise GhidraError(
                "Computed-jump reference budget exceeded; no partial result returned",
                error_type="ResourceLimit",
                address=format_address(addr.getOffset()),
                reference_limit=_MAX_REFERENCES,
                references_examined=examined,
                coverage_complete=False,
            )
        if not ref.isMemoryReference() or not ref.getReferenceType().isJump():
            ignored += 1
            continue
        target = ref.getToAddress()
        if not target.isMemoryAddress():
            ignored += 1
            continue
        key = (str(target.getAddressSpace().getName()), int(target.getOffset()))
        targets.add(key)
        if len(targets) > _MAX_TARGETS:
            raise GhidraError(
                "Computed-jump target budget exceeded; no partial result returned",
                error_type="ResourceLimit",
                address=format_address(addr.getOffset()),
                target_limit=_MAX_TARGETS,
                targets_observed=len(targets),
                coverage_complete=False,
            )
    cases = [
        SwitchCase(target=format_address(offset), address_space=space)
        for space, offset in sorted(targets)
    ]
    return cases, {
        "num_targets": len(cases),
        "references_examined": examined,
        "references_ignored": ignored,
    }


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"analysis"})
    @session.require_open
    def get_switch_info(address: Address) -> GetSwitchInfoResult:
        """Inspect static memory jump targets at one computed-jump instruction.

        Only ReferenceManager references typed as jumps to memory are targets.
        They do not recover case values, case count, default, table layout or
        runtime reachability, including when no targets are observed. Those
        facts remain explicitly unavailable. Non-instructions and other flow
        types are rejected. More than 8192 references or 512 unique targets
        fails with ResourceLimit; no truncated success is returned.
        """
        program = session.program
        addr = resolve_address(address)
        insn = program.getListing().getInstructionAt(addr)
        if insn is None:
            raise GhidraError(
                f"No instruction at {format_address(addr.getOffset())}",
                error_type="NotFound",
            )
        flow = insn.getFlowType()
        if not flow.isComputed() or not flow.isJump():
            raise GhidraError(
                f"Instruction at {format_address(addr.getOffset())} is not a computed jump",
                error_type="NotFound",
            )
        cases, facts = _collect_jump_targets(program, addr)
        return GetSwitchInfoResult(address=format_address(addr.getOffset()), cases=cases, **facts)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"analysis"})
    @session.require_open
    def list_switches(offset: Offset = 0, limit: Limit = 100) -> dict:
        """Page computed-jump observations from the database's function bodies.

        Uses the same typed memory-jump collection and hard per-instruction
        budgets as get_switch_info. num_targets counts observed destinations;
        num_cases/default_targets are null and labels/default are unavailable.
        An empty page or target set proves neither absence nor switch coverage.
        Pagination retains the existing bounded-prefix total/has_more semantics.
        """
        program = session.program
        listing = program.getListing()

        def _gen():
            func_iter = program.getFunctionManager().getFunctions(True)
            while func_iter.hasNext():
                func = func_iter.next()
                insn_iter = listing.getInstructions(func.getBody(), True)
                while insn_iter.hasNext():
                    insn = insn_iter.next()
                    flow = insn.getFlowType()
                    if flow.isComputed() and flow.isJump():
                        addr = insn.getAddress()
                        _, facts = _collect_jump_targets(program, addr)
                        yield SwitchSummary(
                            address=format_address(addr.getOffset()),
                            function=func.getName(),
                            **facts,
                        ).model_dump()

        page = paginate_iter(_gen(), offset, limit)
        page.update(
            coverage_complete=False,
            labels_status="unavailable",
            default_status="unavailable",
            provenance=_PROVENANCE,
        )
        return page
