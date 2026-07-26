#!/usr/bin/env python3
"""Install the ledger-integrity lint into this checkout's existing pre-commit chain.

The repository's Agent Mail hook is a chain runner under ``.git/hooks``. This
installer adds a numbered plugin instead of replacing that runner or any peer
hook. The plugin is deliberately tiny and delegates all policy to the tracked
``scripts/check_perf_ledger_integrity.py`` implementation.
"""

from __future__ import annotations

import stat
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PLUGIN = "40-perf-ledger.py"


def main() -> int:
    try:
        git_dir = Path(
            subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"cannot locate git directory: {exc}", file=sys.stderr)
        return 1
    if not git_dir.is_absolute():
        git_dir = ROOT / git_dir

    hooks_dir = git_dir / "hooks"
    chain = hooks_dir / "pre-commit"
    if not chain.exists():
        print(f"refusing to install: expected pre-commit chain is missing: {chain}", file=sys.stderr)
        return 1
    chain_text = chain.read_text(encoding="utf-8", errors="replace")
    if "hooks.d" not in chain_text:
        print(
            f"refusing to install: existing hook is not the hooks.d chain runner: {chain}",
            file=sys.stderr,
        )
        return 1

    plugin_dir = hooks_dir / "hooks.d" / "pre-commit"
    plugin_dir.mkdir(parents=True, exist_ok=True)
    plugin = plugin_dir / PLUGIN
    plugin.write_text(
        "#!/usr/bin/env python3\n"
        "import subprocess\n"
        "import sys\n"
        "from pathlib import Path\n"
        "\n"
        "root = Path(__file__).resolve().parents[4]\n"
        "gate = root / 'scripts' / 'check_perf_ledger_integrity.py'\n"
        "raise SystemExit(subprocess.call([sys.executable, str(gate), 'lint', '--staged']))\n",
        encoding="utf-8",
    )
    plugin.chmod(plugin.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"installed {plugin}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
