"""Agent layer package (ARCHITECTURE layer 2): the agent-under-test.

Re-exports the tool surface (:mod:`.tools`) and the naive loop (:mod:`.loop`).
"""

from artil.agent.loop import NAIVE_SYSTEM_PROMPT, AgentLoop, RunResult
from artil.agent.tools import ToolBox, ToolResult

__all__ = [
    "NAIVE_SYSTEM_PROMPT",
    "AgentLoop",
    "RunResult",
    "ToolBox",
    "ToolResult",
]
