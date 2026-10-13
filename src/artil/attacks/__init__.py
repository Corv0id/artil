"""Attack catalog (ARCHITECTURE layer 5: "Attack catalog", `attacks/`).

Each attack is a frozen :class:`Attack` entry: an id, a category, a channel, a
plain-language description, and a deterministic ``render`` that produces the text
of the poisoned document written to disk inside the sandbox. Channels: user-turn,
tool-return, retrieved-doc, on-disk file, MCP descriptor. Phase 1 ships exactly
one end-to-end entry plus its clean control document.
"""

from artil.attacks.inj_file_exfil_01 import (
    CATALOG,
    INJ_FILE_EXFIL_01,
    NOTES_PLAIN,
    Attack,
    control_document,
)

__all__ = [
    "Attack",
    "CATALOG",
    "INJ_FILE_EXFIL_01",
    "NOTES_PLAIN",
    "control_document",
]
