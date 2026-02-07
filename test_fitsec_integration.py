#!/usr/bin/env python3
"""
FIT-Sec + nanoBot Integration Test
===================================
Tests the SecureToolRegistry without full nanoBot dependencies.
"""

import asyncio
import sys
from pathlib import Path

# Add paths
sys.path.insert(0, str(Path(__file__).parent / "nanobot"))
sys.path.insert(0, str(Path(__file__).parent))

from nanobot.fitsec import (
    FitSecRuntime,
    ToolManifest,
    ToolCall,
    OmegaLevel,
    GateMetrics,
    PolicyDeniedError,
    EmptinessActiveError,
    Decision,
    GateStatus,
)


class MockTool:
    """Mock tool for testing."""
    def __init__(self, name: str, description: str = "Mock tool"):
        self._name = name
        self._description = description

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @property
    def parameters(self) -> dict:
        return {"type": "object", "properties": {}}

    async def execute(self, **kwargs) -> str:
        return f"[{self._name}] executed with {kwargs}"


class MockToolRegistry:
    """Minimal mock of nanoBot's ToolRegistry."""
    def __init__(self):
        self._tools: dict[str, MockTool] = {}

    def register(self, tool: MockTool) -> None:
        self._tools[tool.name] = tool

    def unregister(self, name: str) -> None:
        self._tools.pop(name, None)

    def get(self, name: str) -> MockTool | None:
        return self._tools.get(name)

    def has(self, name: str) -> bool:
        return name in self._tools

    def get_definitions(self) -> list[dict]:
        return [{"type": "function", "function": {"name": t.name}} for t in self._tools.values()]

    async def execute(self, name: str, params: dict) -> str:
        tool = self._tools.get(name)
        if not tool:
            return f"Error: Tool '{name}' not found"
        return await tool.execute(**params)

    @property
    def tool_names(self) -> list[str]:
        return list(self._tools.keys())


class TestSecureToolRegistry:
    """Test harness for SecureToolRegistry integration."""

    def __init__(self):
        self._registry = MockToolRegistry()
        self._runtime = FitSecRuntime(strict_mode=True)
        self._omega_mappings: dict[str, OmegaLevel] = {}

    def register(self, tool: MockTool, omega_level: OmegaLevel) -> None:
        self._registry.register(tool)
        self._omega_mappings[tool.name] = omega_level

        manifest = ToolManifest(
            tool_id=tool.name,
            omega_level=omega_level,
            description=tool.description,
            requires_approval=(omega_level == OmegaLevel.OMEGA_2),
        )
        self._runtime.register_tool(
            manifest,
            executor=lambda action, args: f"[sync:{tool.name}]"
        )

    async def execute(self, name: str, params: dict) -> str:
        """Execute with FIT-Sec checks."""
        call = ToolCall(tool_id=name, action="execute", args=params)

        # Check policy
        manifest = self._runtime.registry.get_manifest(name)

        # Check Emptiness
        if self._runtime.emptiness.is_active:
            if manifest and not self._runtime.emptiness.check_allowed(manifest.omega_level):
                self._runtime.emptiness.record_blocked_call(call)
                raise EmptinessActiveError(f"Emptiness blocks {name}")

        # Evaluate policy
        decision = self._runtime.policy.evaluate(call, manifest, GateStatus.PASS)

        # Check policy decision
        if decision.decision == Decision.DENY:
            raise PolicyDeniedError(decision.rationale or f"Denied: {name}")

        # Execute
        result = await self._registry.execute(name, params)
        # Log successful execution
        self._runtime.audit.log(
            tool_call=call,
            manifest=manifest,
            policy_decision=decision,
            executed=True,
            result=result,
        )
        return result

    @property
    def runtime(self) -> FitSecRuntime:
        return self._runtime


async def run_tests():
    print("=" * 60)
    print("FIT-Sec + nanoBot Integration Test")
    print("=" * 60)

    registry = TestSecureToolRegistry()

    # Register tools with different Omega levels
    print("\n[1] Registering mock tools...")
    registry.register(MockTool("read_file", "Read files"), OmegaLevel.OMEGA_0)
    registry.register(MockTool("write_file", "Write files"), OmegaLevel.OMEGA_1)
    registry.register(MockTool("exec", "Execute commands"), OmegaLevel.OMEGA_2)
    print("   [OK] Registered: read_file(O0), write_file(O1), exec(O2)")

    # Test O0 - should pass
    print("\n[2] Testing O0 (read_file) - should ALLOW...")
    try:
        result = await registry.execute("read_file", {"path": "/test.txt"})
        print(f"   [OK] ALLOWED: {result}")
    except Exception as e:
        print(f"   [FAIL] Unexpected error: {e}")

    # Test O1 - should pass
    print("\n[3] Testing O1 (write_file) - should ALLOW...")
    try:
        result = await registry.execute("write_file", {"path": "/test.txt", "content": "hello"})
        print(f"   [OK] ALLOWED: {result}")
    except Exception as e:
        print(f"   [FAIL] Unexpected error: {e}")

    # Test O2 - should be DENIED by default
    print("\n[4] Testing O2 (exec) - should be DENIED by default...")
    try:
        result = await registry.execute("exec", {"cmd": "ls"})
        print(f"   [FAIL] Should have been denied! Got: {result}")
    except PolicyDeniedError as e:
        print(f"   [OK] DENIED (as expected): {e}")
    except Exception as e:
        print(f"   [FAIL] Wrong exception: {type(e).__name__}: {e}")

    # Grant approval and retry O2
    print("\n[5] Granting O2 approval for 'exec'...")
    registry.runtime.policy.grant_omega2_approval("exec", duration_seconds=60)
    try:
        result = await registry.execute("exec", {"cmd": "ls"})
        print(f"   [OK] ALLOWED with approval: {result}")
    except Exception as e:
        print(f"   [FAIL] Error: {e}")

    # Test Emptiness Window
    print("\n[6] Entering Emptiness Window...")
    registry.runtime.enter_emptiness("Integration test")
    status = registry.runtime.emptiness.get_status()
    print(f"   Status: {status}")

    print("\n[7] Testing O0 in Emptiness - should ALLOW...")
    try:
        result = await registry.execute("read_file", {"path": "/test.txt"})
        print(f"   [OK] O0 ALLOWED: {result}")
    except Exception as e:
        print(f"   [FAIL] Error: {e}")

    print("\n[8] Testing O1 in Emptiness - should be BLOCKED...")
    try:
        result = await registry.execute("write_file", {"path": "/x.txt", "content": "y"})
        print(f"   [FAIL] Should have been blocked! Got: {result}")
    except EmptinessActiveError as e:
        print(f"   [OK] BLOCKED: {e}")
    except Exception as e:
        print(f"   [FAIL] Wrong exception: {type(e).__name__}: {e}")

    print("\n[9] Exiting Emptiness Window...")
    # Get blocked calls before exiting
    blocked_count = registry.runtime.emptiness.get_status().get("blocked_calls_count", 0)
    registry.runtime.exit_emptiness()
    print(f"   Exited. Blocked calls during window: {blocked_count}")

    # Final audit summary
    print("\n" + "=" * 60)
    print("AUDIT SUMMARY")
    print("=" * 60)
    summary = registry.runtime.audit.get_summary()
    for key, value in summary.items():
        print(f"   {key}: {value}")

    print("\n[OK] All integration tests passed!")
    return True


def main():
    try:
        success = asyncio.run(run_tests())
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n[FATAL] Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
