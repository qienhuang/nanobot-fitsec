"""Secure Tool Registry with FIT-Sec integration.

This module wraps the standard ToolRegistry with FIT-Sec runtime checks,
implementing the Omega taxonomy, Monitorability Gate, and Emptiness Window.
"""

from pathlib import Path
from typing import Any, Callable

from nanobot.agent.tools.base import Tool
from nanobot.agent.tools.registry import ToolRegistry
from nanobot.fitsec import (
    FitSecRuntime,
    ToolManifest,
    ToolCall,
    OmegaLevel,
    Decision,
    GateStatus,
    PolicyDeniedError,
    EmptinessActiveError,
    GateFailedError,
    ToolNotRegisteredError,
)


# Default Omega level mappings for nanoBot tools
DEFAULT_OMEGA_MAPPINGS: dict[str, OmegaLevel] = {
    # O0 - Safe, read-only operations
    "read_file": OmegaLevel.OMEGA_0,
    "list_dir": OmegaLevel.OMEGA_0,
    "web_search": OmegaLevel.OMEGA_0,
    "web_fetch": OmegaLevel.OMEGA_0,
    "message": OmegaLevel.OMEGA_0,

    # O1 - Medium risk, reversible writes
    "write_file": OmegaLevel.OMEGA_1,
    "edit_file": OmegaLevel.OMEGA_1,

    # O2 - High risk, irreversible operations
    "exec": OmegaLevel.OMEGA_2,
    "spawn": OmegaLevel.OMEGA_2,
    "cron": OmegaLevel.OMEGA_2,
}


class SecureToolRegistry:
    """
    Secure wrapper around ToolRegistry with FIT-Sec integration.

    This class intercepts all tool executions and routes them through
    the FIT-Sec runtime for policy checks, gate validation, and audit logging.
    """

    def __init__(
        self,
        workspace: Path | None = None,
        strict_mode: bool = True,
        omega_mappings: dict[str, OmegaLevel] | None = None,
        audit_path: Path | None = None,
    ):
        """
        Initialize the secure registry.

        Args:
            workspace: Working directory for file restrictions.
            strict_mode: If True, unknown tools are denied by default.
            omega_mappings: Custom tool->OmegaLevel mappings.
            audit_path: Path for audit log file.
        """
        self._registry = ToolRegistry()
        self._runtime = FitSecRuntime(
            strict_mode=strict_mode,
            audit_path=audit_path,
        )
        self._omega_mappings = {**DEFAULT_OMEGA_MAPPINGS, **(omega_mappings or {})}
        self._workspace = workspace
        self._tool_executors: dict[str, Callable] = {}

    def register(self, tool: Tool, omega_level: OmegaLevel | None = None) -> None:
        """
        Register a tool with both registries.

        Args:
            tool: The nanoBot tool to register.
            omega_level: Override Omega level (uses default mapping if None).
        """
        # Register with nanoBot registry
        self._registry.register(tool)

        # Determine Omega level
        level = omega_level or self._omega_mappings.get(tool.name, OmegaLevel.OMEGA_1)

        # Build manifest for FIT-Sec
        manifest = ToolManifest(
            tool_id=tool.name,
            omega_level=level,
            description=tool.description,
            requires_approval=(level == OmegaLevel.OMEGA_2),
        )

        # Create async executor wrapper
        async def make_executor(t: Tool):
            async def executor(action: str, args: dict[str, Any]) -> str:
                return await t.execute(**args)
            return executor

        # Store executor for later use
        self._tool_executors[tool.name] = tool.execute

        # Register with FIT-Sec runtime (sync wrapper for manifest only)
        self._runtime.register_tool(
            manifest,
            executor=lambda action, args, name=tool.name: f"[ASYNC:{name}]",
        )

    def unregister(self, name: str) -> None:
        """Unregister a tool by name."""
        self._registry.unregister(name)
        # Note: FitSecRuntime registry doesn't support unregistration
        # The manifest remains for audit purposes
        self._tool_executors.pop(name, None)

    def get(self, name: str) -> Tool | None:
        """Get a tool by name."""
        return self._registry.get(name)

    def has(self, name: str) -> bool:
        """Check if a tool is registered."""
        return self._registry.has(name)

    def get_definitions(self) -> list[dict[str, Any]]:
        """Get all tool definitions in OpenAI format."""
        return self._registry.get_definitions()

    async def execute(self, name: str, params: dict[str, Any]) -> str:
        """
        Execute a tool with FIT-Sec policy checks.

        This is the main integration point. All tool calls flow through here
        and are validated against the FIT-Sec runtime before execution.

        Args:
            name: Tool name.
            params: Tool parameters.

        Returns:
            Tool execution result as string.

        Raises:
            PolicyDeniedError: If policy denies the action.
            EmptinessActiveError: If Emptiness Window blocks the action.
            GateFailedError: If Monitorability Gate fails.
        """
        # Build ToolCall for FIT-Sec
        call = ToolCall(
            tool_id=name,
            action="execute",
            args=params,
        )

        # Get manifest from registry
        manifest = self._runtime.registry.get_manifest(name)

        # Check Emptiness Window first
        if self._runtime.emptiness.is_active:
            if manifest and not self._runtime.emptiness.check_allowed(manifest.omega_level):
                self._runtime.emptiness.record_blocked_call(call)
                raise EmptinessActiveError(
                    f"Emptiness Window active: {name} (O{manifest.omega_level.value}) blocked"
                )

        # Check Monitorability Gate for O2 tools
        gate_status = GateStatus.PASS
        if manifest and manifest.omega_level == OmegaLevel.OMEGA_2:
            gate_status = self._runtime.gate.check()
            if gate_status not in (GateStatus.PASS, GateStatus.UNKNOWN):
                raise GateFailedError(
                    f"Monitorability Gate failed: {self._runtime.gate.get_failure_reason()}"
                )

        # Evaluate policy
        decision = self._runtime.policy.evaluate(call, manifest, gate_status)

        # Policy check
        if decision.decision == Decision.DENY:
            raise PolicyDeniedError(decision.rationale or f"Policy denied: {name}")

        try:
            # Execute via nanoBot registry (preserves original behavior)
            result = await self._registry.execute(name, params)

            # Audit success
            self._runtime.audit.log(
                tool_call=call,
                manifest=manifest,
                policy_decision=decision,
                executed=True,
                result=result,
            )

            return result

        except (PolicyDeniedError, EmptinessActiveError, GateFailedError):
            # Re-raise FIT-Sec exceptions
            raise
        except Exception as e:
            # Audit failure
            self._runtime.audit.log(
                tool_call=call,
                manifest=manifest,
                policy_decision=decision,
                executed=True,
                error=str(e),
            )
            raise

    @property
    def tool_names(self) -> list[str]:
        """Get list of registered tool names."""
        return self._registry.tool_names

    @property
    def runtime(self) -> FitSecRuntime:
        """Access the underlying FIT-Sec runtime."""
        return self._runtime

    def grant_approval(self, tool_id: str, duration_seconds: int = 300) -> None:
        """Grant temporary O2 approval for a tool."""
        self._runtime.policy.grant_omega2_approval(tool_id, duration_seconds)

    def revoke_approval(self, tool_id: str) -> None:
        """Revoke O2 approval for a tool."""
        self._runtime.policy.revoke_omega2_approval(tool_id)

    def enter_emptiness(self, reason: str) -> None:
        """Enter Emptiness Window (safety mode)."""
        self._runtime.enter_emptiness(reason)

    def exit_emptiness(self):
        """Exit Emptiness Window."""
        return self._runtime.exit_emptiness()

    def emergency_stop(self, reason: str) -> None:
        """Trigger emergency stop."""
        self._runtime.emergency_stop(reason)

    def __len__(self) -> int:
        return len(self._registry)

    def __contains__(self, name: str) -> bool:
        return name in self._registry
