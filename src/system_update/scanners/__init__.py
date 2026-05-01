"""Per-source package scanners.

Each submodule exposes a ``scan() -> List[AppInfo]`` function for one package
source. The :class:`PackageScanner` facade re-exports them as ``scan_<source>``
static methods so legacy call sites (and ``@patch('system_update.PackageScanner.scan_*')``
test mocks) keep working unchanged.
"""

from __future__ import annotations

from system_update.scanners import (
	appx,
	bun,
	chocolatey,
	dotnet,
	msix,
	npm,
	path,
	pip,
	pnpm,
	registry,
	rust,
	scoop,
	winget,
	yarn,
)


class PackageScanner:
	"""Static-method facade over the per-source scanner modules."""

	scan_winget = staticmethod(winget.scan)
	scan_chocolatey = staticmethod(chocolatey.scan)
	scan_npm = staticmethod(npm.scan)
	scan_pnpm = staticmethod(pnpm.scan)
	scan_bun = staticmethod(bun.scan)
	scan_yarn = staticmethod(yarn.scan)
	scan_pip = staticmethod(pip.scan)
	scan_path = staticmethod(path.scan)
	scan_rust = staticmethod(rust.scan)
	scan_dotnet = staticmethod(dotnet.scan)
	scan_scoop = staticmethod(scoop.scan)
	scan_registry = staticmethod(registry.scan)
	scan_appx = staticmethod(appx.scan)
	scan_msix = staticmethod(msix.scan)

	_parse_pip_list = staticmethod(pip._parse_pip_list)


__all__ = ['PackageScanner']
