"""Terminal Hex Viewer with color highlights and offset navigation."""

from pathlib import Path
from rich.console import Console
from rich.table import Table


def render_hexdump(filepath: str | Path, offset: int = 0, length: int = 256) -> Table:
    """Render a hex dump table with address, hex bytes, and ASCII."""
    target = Path(filepath).resolve()
    with open(target, "rb") as f:
        f.seek(offset)
        data = f.read(length)

    table = Table(title=f"Hex View: {target.name} (Offset 0x{offset:x})", border_style="cyan")
    table.add_column("Offset", style="bold yellow", width=10)
    table.add_column("Hex Bytes", style="bold white", width=50)
    table.add_column("ASCII", style="green", width=18)

    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        cur_offset = f"{offset + i:08x}"
        table.add_row(cur_offset, hex_str, ascii_str)

    return table
