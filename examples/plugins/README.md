# Example plugins

Reference plugins demonstrating the public extension API. Copy any file
in this directory to `~/.system_update/plugins/` to use it.

| File | What it shows |
|------|---------------|
| [`demo_plugin.py`](demo_plugin.py) | All five extension points (scanner, checker, updater, security checker, notifier) using the standardized contract — typed `AppInfo`, source filtering, `UpdateStatus` enum, `context.data_dir` for I/O, and structured `logging`. |

See the **🧩 Plugins** section of the project [README](../../README.md) for
the full plugin development guide, including the security model
(`plugins.enabled=true`, `allowed.sha256` allowlist, `--no-plugins`).
