"""Per-source package scanners.

Each submodule exposes a ``scan() -> List[AppInfo]`` function for one package
source. The :class:`PackageScanner` facade re-exports them as ``scan_<source>``
static methods so legacy call sites (and ``@patch('system_update.PackageScanner.scan_*')``
test mocks) keep working unchanged. Built-in scanners register once via
``@scanner('<source>')`` wrappers that call the facade, so app dispatch and
legacy mocks stay in sync.
"""

from __future__ import annotations

from typing import Callable, Dict, List

from system_update.models import AppInfo

ScannerFunc = Callable[[], List[AppInfo]]

_SCANNERS: Dict[str, ScannerFunc] = {}


def scanner(name: str) -> Callable[[ScannerFunc], ScannerFunc]:
	"""Register ``func`` as the scanner for ``name`` and return it unchanged."""

	def deco(func: ScannerFunc) -> ScannerFunc:
		_SCANNERS[name] = func
		return func

	return deco


def get_scanner_map() -> Dict[str, ScannerFunc]:
	"""Return a defensive copy of the registered built-in scanners."""
	return dict(_SCANNERS)


from system_update.scanners import (  # noqa: E402
	appx,
	bun,
	chocolatey,
	dotnet,
	drivers,
	msix,
	npm,
	path,
	pip,
	pnpm,
	registry,
	rust,
	scoop,
	services,
	psmodules,
	vsextensions,
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
	scan_drivers = staticmethod(drivers.scan)
	scan_services = staticmethod(services.scan)
	scan_psmodules = staticmethod(psmodules.scan)
	scan_vsextensions = staticmethod(vsextensions.scan)

	_parse_pip_list = staticmethod(pip._parse_pip_list)


@scanner('winget')
def _scan_winget() -> List[AppInfo]:
	return PackageScanner.scan_winget()


@scanner('chocolatey')
def _scan_chocolatey() -> List[AppInfo]:
	return PackageScanner.scan_chocolatey()


@scanner('npm')
def _scan_npm() -> List[AppInfo]:
	return PackageScanner.scan_npm()


@scanner('pnpm')
def _scan_pnpm() -> List[AppInfo]:
	return PackageScanner.scan_pnpm()


@scanner('bun')
def _scan_bun() -> List[AppInfo]:
	return PackageScanner.scan_bun()


@scanner('yarn')
def _scan_yarn() -> List[AppInfo]:
	return PackageScanner.scan_yarn()


@scanner('pip')
def _scan_pip() -> List[AppInfo]:
	return PackageScanner.scan_pip()


@scanner('path')
def _scan_path() -> List[AppInfo]:
	return PackageScanner.scan_path()


@scanner('registry')
def _scan_registry() -> List[AppInfo]:
	return PackageScanner.scan_registry()


@scanner('rust')
def _scan_rust() -> List[AppInfo]:
	return PackageScanner.scan_rust()


@scanner('scoop')
def _scan_scoop() -> List[AppInfo]:
	return PackageScanner.scan_scoop()


@scanner('dotnet')
def _scan_dotnet() -> List[AppInfo]:
	return PackageScanner.scan_dotnet()


@scanner('appx')
def _scan_appx() -> List[AppInfo]:
	return PackageScanner.scan_appx()


@scanner('msix')
def _scan_msix() -> List[AppInfo]:
	return PackageScanner.scan_msix()


@scanner('drivers')
def _scan_drivers() -> List[AppInfo]:
	return PackageScanner.scan_drivers()


@scanner('services')
def _scan_services() -> List[AppInfo]:
	return PackageScanner.scan_services()


@scanner('psmodules')
def _scan_psmodules() -> List[AppInfo]:
	return PackageScanner.scan_psmodules()


@scanner('vsextensions')
def _scan_vsextensions() -> List[AppInfo]:
	return PackageScanner.scan_vsextensions()


__all__ = ['PackageScanner', 'get_scanner_map', 'scanner']
