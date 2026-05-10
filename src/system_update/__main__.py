"""Enable ``python -m system_update`` by delegating to the Typer app."""

import io
import sys

# Force UTF-8 on stdout/stderr so emoji-rich help renders on Windows cp1252
# consoles. ``reconfigure`` is only on the concrete TextIOWrapper subclass —
# narrow with isinstance so pyright accepts the call.
for _stream in (sys.stdout, sys.stderr):
	if isinstance(_stream, io.TextIOWrapper):
		try:
			_stream.reconfigure(encoding='utf-8', errors='replace')
		except Exception:
			pass

from system_update.cli import _main_entry  # noqa: E402

if __name__ == '__main__':
	_main_entry()
