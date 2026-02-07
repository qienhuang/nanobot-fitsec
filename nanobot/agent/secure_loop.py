"""Secure Agent Loop with FIT-Sec integration.

This module provides a secure version of AgentLoop that uses SecureToolRegistry
for policy-controlled tool execution with the Omega taxonomy.
"""

import asyncio
import json
from pathlib import Path
from typing import Any

from loguru import logger

from nanobot.bus.events import InboundMessage, OutboundMessage
from nanobot.bus.queue import MessageBus
from nanobot.providers.base import LLMProvider
from nanobot.agent.context import ContextBuilder
from nanobot.agent.tools.secure_registry import SecureToolRegistry, DEFAULT_OMEGA_MAPPINGS
from nanobot.agent.tools.filesystem import ReadFileTool, WriteFileTool, EditFileTool, ListDirTool
from nanobot.agent.tools.shell import ExecTool
from nanobot.agent.tools.web import WebSearchTool, WebFetchTool
from nanobot.agent.tools.message import MessageTool
from nanobot.agent.tools.spawn import SpawnTool
from nanobot.agent.tools.cron import CronTool
from nanobot.agent.subagent import SubagentManager
from nanobot.session.manager import SessionManager
from nanobot.fitsec import (
    OmegaLevel,
    PolicyDeniedError,
    EmptinessActiveError,
    GateFailedError,
)


class SecureAgentLoop:
    """
    Secure agent loop with FIT-Sec governance.

    This extends the standard AgentLoop with:
    1. Omega taxonomy for tool classification
    2. Monitorability Gate for O2 operations
    3. Emptiness Window for safety mode
    4. Comprehensive audit logging
    """

    def __init__(
        self,
        bus: MessageBus,
        provider: LLMProvider,
        workspace: Path,
        model: str | None = None,
        max_iterations: int = 20,
        brave_api_key: str | None = None,
        exec_config: "ExecToolConfig | None" = None,
        cron_service: "CronService | None" = None,
        restrict_to_workspace: bool = False,
        strict_mode: bool = True,
        audit_path: Path | None = None,
    ):
        from nanobot.config.schema import ExecToolConfig
        from nanobot.cron.service import CronService

        self.bus = bus
        self.provider = provider
        self.workspace = workspace
        self.model = model or provider.get_default_model()
        self.max_iterations = max_iterations
        self.brave_api_key = brave_api_key
        self.exec_config = exec_config or ExecToolConfig()
        self.cron_service = cron_service
        self.restrict_to_workspace = restrict_to_workspace

        self.context = ContextBuilder(workspace)
        self.sessions = SessionManager(workspace)

        # Use SecureToolRegistry instead of ToolRegistry
        self.tools = SecureToolRegistry(
            workspace=workspace,
            strict_mode=strict_mode,
            audit_path=audit_path or workspace / ".nanobot" / "audit.jsonl",
        )

        self.subagents = SubagentManager(
            provider=provider,
            workspace=workspace,
            bus=bus,
            model=self.model,
            brave_api_key=brave_api_key,
            exec_config=self.exec_config,
            restrict_to_workspace=restrict_to_workspace,
        )

        self._running = False
        self._register_default_tools()

        logger.info("SecureAgentLoop initialized with FIT-Sec governance")

    def _register_default_tools(self) -> None:
        """Register the default set of tools with Omega classifications."""
        allowed_dir = self.workspace if self.restrict_to_workspace else None

        # O0 - Safe, read-only tools
        self.tools.register(
            ReadFileTool(allowed_dir=allowed_dir),
            omega_level=OmegaLevel.OMEGA_0
        )
        self.tools.register(
            ListDirTool(allowed_dir=allowed_dir),
            omega_level=OmegaLevel.OMEGA_0
        )

        # O1 - Medium risk, reversible writes
        self.tools.register(
            WriteFileTool(allowed_dir=allowed_dir),
            omega_level=OmegaLevel.OMEGA_1
        )
        self.tools.register(
            EditFileTool(allowed_dir=allowed_dir),
            omega_level=OmegaLevel.OMEGA_1
        )

        # O0 - Web tools (read-only)
        self.tools.register(
            WebSearchTool(api_key=self.brave_api_key),
            omega_level=OmegaLevel.OMEGA_0
        )
        self.tools.register(
            WebFetchTool(),
            omega_level=OmegaLevel.OMEGA_0
        )

        # O0 - Message tool (user communication)
        message_tool = MessageTool(send_callback=self.bus.publish_outbound)
        self.tools.register(message_tool, omega_level=OmegaLevel.OMEGA_0)

        # O2 - High risk tools (require approval)
        self.tools.register(
            ExecTool(
                working_dir=str(self.workspace),
                timeout=self.exec_config.timeout,
                restrict_to_workspace=self.restrict_to_workspace,
            ),
            omega_level=OmegaLevel.OMEGA_2
        )

        spawn_tool = SpawnTool(manager=self.subagents)
        self.tools.register(spawn_tool, omega_level=OmegaLevel.OMEGA_2)

        if self.cron_service:
            self.tools.register(
                CronTool(self.cron_service),
                omega_level=OmegaLevel.OMEGA_2
            )

        logger.info(f"Registered {len(self.tools)} tools with FIT-Sec")

    async def run(self) -> None:
        """Run the secure agent loop, processing messages from the bus."""
        self._running = True
        logger.info("SecureAgentLoop started")

        while self._running:
            try:
                msg = await asyncio.wait_for(
                    self.bus.consume_inbound(),
                    timeout=1.0
                )

                try:
                    response = await self._process_message(msg)
                    if response:
                        await self.bus.publish_outbound(response)
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
                    await self.bus.publish_outbound(OutboundMessage(
                        channel=msg.channel,
                        chat_id=msg.chat_id,
                        content=f"Sorry, I encountered an error: {str(e)}"
                    ))
            except asyncio.TimeoutError:
                continue

    def stop(self) -> None:
        """Stop the agent loop."""
        self._running = False
        logger.info("SecureAgentLoop stopping")

    async def _process_message(self, msg: InboundMessage) -> OutboundMessage | None:
        """Process a single inbound message with FIT-Sec checks."""
        if msg.channel == "system":
            return await self._process_system_message(msg)

        preview = msg.content[:80] + "..." if len(msg.content) > 80 else msg.content
        logger.info(f"Processing message from {msg.channel}:{msg.sender_id}: {preview}")

        session = self.sessions.get_or_create(msg.session_key)

        # Update tool contexts
        message_tool = self.tools.get("message")
        if isinstance(message_tool, MessageTool):
            message_tool.set_context(msg.channel, msg.chat_id)

        spawn_tool = self.tools.get("spawn")
        if isinstance(spawn_tool, SpawnTool):
            spawn_tool.set_context(msg.channel, msg.chat_id)

        cron_tool = self.tools.get("cron")
        if isinstance(cron_tool, CronTool):
            cron_tool.set_context(msg.channel, msg.chat_id)

        messages = self.context.build_messages(
            history=session.get_history(),
            current_message=msg.content,
            media=msg.media if msg.media else None,
            channel=msg.channel,
            chat_id=msg.chat_id,
        )

        iteration = 0
        final_content = None

        while iteration < self.max_iterations:
            iteration += 1

            response = await self.provider.chat(
                messages=messages,
                tools=self.tools.get_definitions(),
                model=self.model
            )

            if response.has_tool_calls:
                tool_call_dicts = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(tc.arguments)
                        }
                    }
                    for tc in response.tool_calls
                ]
                messages = self.context.add_assistant_message(
                    messages, response.content, tool_call_dicts
                )

                # Execute tools with FIT-Sec checks
                for tool_call in response.tool_calls:
                    args_str = json.dumps(tool_call.arguments, ensure_ascii=False)
                    logger.info(f"Tool call: {tool_call.name}({args_str[:200]})")

                    try:
                        # This now goes through SecureToolRegistry with FIT-Sec
                        result = await self.tools.execute(tool_call.name, tool_call.arguments)
                    except PolicyDeniedError as e:
                        result = f"[POLICY DENIED] {e}"
                        logger.warning(f"Policy denied: {tool_call.name} - {e}")
                    except EmptinessActiveError as e:
                        result = f"[EMPTINESS BLOCKED] {e}"
                        logger.warning(f"Emptiness blocked: {tool_call.name} - {e}")
                    except GateFailedError as e:
                        result = f"[GATE FAILED] {e}"
                        logger.warning(f"Gate failed: {tool_call.name} - {e}")

                    messages = self.context.add_tool_result(
                        messages, tool_call.id, tool_call.name, result
                    )
            else:
                final_content = response.content
                break

        if final_content is None:
            final_content = "I've completed processing but have no response to give."

        preview = final_content[:120] + "..." if len(final_content) > 120 else final_content
        logger.info(f"Response to {msg.channel}:{msg.sender_id}: {preview}")

        session.add_message("user", msg.content)
        session.add_message("assistant", final_content)
        self.sessions.save(session)

        return OutboundMessage(
            channel=msg.channel,
            chat_id=msg.chat_id,
            content=final_content
        )

    async def _process_system_message(self, msg: InboundMessage) -> OutboundMessage | None:
        """Process a system message (e.g., subagent announce)."""
        logger.info(f"Processing system message from {msg.sender_id}")

        if ":" in msg.chat_id:
            parts = msg.chat_id.split(":", 1)
            origin_channel = parts[0]
            origin_chat_id = parts[1]
        else:
            origin_channel = "cli"
            origin_chat_id = msg.chat_id

        session_key = f"{origin_channel}:{origin_chat_id}"
        session = self.sessions.get_or_create(session_key)

        # Update tool contexts
        message_tool = self.tools.get("message")
        if isinstance(message_tool, MessageTool):
            message_tool.set_context(origin_channel, origin_chat_id)

        spawn_tool = self.tools.get("spawn")
        if isinstance(spawn_tool, SpawnTool):
            spawn_tool.set_context(origin_channel, origin_chat_id)

        cron_tool = self.tools.get("cron")
        if isinstance(cron_tool, CronTool):
            cron_tool.set_context(origin_channel, origin_chat_id)

        messages = self.context.build_messages(
            history=session.get_history(),
            current_message=msg.content,
            channel=origin_channel,
            chat_id=origin_chat_id,
        )

        iteration = 0
        final_content = None

        while iteration < self.max_iterations:
            iteration += 1

            response = await self.provider.chat(
                messages=messages,
                tools=self.tools.get_definitions(),
                model=self.model
            )

            if response.has_tool_calls:
                tool_call_dicts = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(tc.arguments)
                        }
                    }
                    for tc in response.tool_calls
                ]
                messages = self.context.add_assistant_message(
                    messages, response.content, tool_call_dicts
                )

                for tool_call in response.tool_calls:
                    args_str = json.dumps(tool_call.arguments, ensure_ascii=False)
                    logger.info(f"Tool call: {tool_call.name}({args_str[:200]})")

                    try:
                        result = await self.tools.execute(tool_call.name, tool_call.arguments)
                    except (PolicyDeniedError, EmptinessActiveError, GateFailedError) as e:
                        result = f"[BLOCKED] {e}"
                        logger.warning(f"Tool blocked: {tool_call.name} - {e}")

                    messages = self.context.add_tool_result(
                        messages, tool_call.id, tool_call.name, result
                    )
            else:
                final_content = response.content
                break

        if final_content is None:
            final_content = "Background task completed."

        session.add_message("user", f"[System: {msg.sender_id}] {msg.content}")
        session.add_message("assistant", final_content)
        self.sessions.save(session)

        return OutboundMessage(
            channel=origin_channel,
            chat_id=origin_chat_id,
            content=final_content
        )

    async def process_direct(
        self,
        content: str,
        session_key: str = "cli:direct",
        channel: str = "cli",
        chat_id: str = "direct",
    ) -> str:
        """Process a message directly (for CLI or cron usage)."""
        msg = InboundMessage(
            channel=channel,
            sender_id="user",
            chat_id=chat_id,
            content=content
        )

        response = await self._process_message(msg)
        return response.content if response else ""

    # FIT-Sec control methods
    def grant_tool_approval(self, tool_id: str, duration_seconds: int = 300) -> None:
        """Grant temporary O2 approval for a tool."""
        self.tools.grant_approval(tool_id, duration_seconds)
        logger.info(f"Granted O2 approval for {tool_id} ({duration_seconds}s)")

    def revoke_tool_approval(self, tool_id: str) -> None:
        """Revoke O2 approval for a tool."""
        self.tools.revoke_approval(tool_id)
        logger.info(f"Revoked O2 approval for {tool_id}")

    def enter_safety_mode(self, reason: str) -> None:
        """Enter Emptiness Window (safety mode)."""
        self.tools.enter_emptiness(reason)
        logger.warning(f"Entered Emptiness Window: {reason}")

    def exit_safety_mode(self, require_review: bool = True):
        """Exit Emptiness Window."""
        packet = self.tools.exit_emptiness(require_review)
        logger.info("Exited Emptiness Window")
        return packet

    def emergency_stop(self, reason: str) -> None:
        """Trigger emergency stop."""
        self.tools.emergency_stop(reason)
        logger.critical(f"EMERGENCY STOP: {reason}")

    def get_audit_summary(self) -> dict[str, Any]:
        """Get audit summary from FIT-Sec runtime."""
        return self.tools.runtime.audit.get_summary()
