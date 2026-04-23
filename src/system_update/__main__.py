"""Enable ``python -m system_update`` by delegating to the Typer app."""

from system_update.cli import app

if __name__ == '__main__':
	app()
