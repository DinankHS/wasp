# scanner/plugins/__init__.py
"""
WASP Plugin System — Phase 2
Automatically discovers and loads vulnerability scanner plugins
from this directory.

To create a new plugin:
  1. Create a new .py file in scanner/plugins/
  2. Define a class that inherits from BasePlugin
  3. Implement the scan() method
  4. WASP will auto-discover and run it

Example:
  scanner/plugins/lfi_plugin.py   — Local File Inclusion scanner
  scanner/plugins/csrf_plugin.py  — CSRF detection
  scanner/plugins/xxe_plugin.py   — XML External Entity scanner
"""

import os
import importlib
import inspect
from core.logger import get_logger

log = get_logger(__name__)


def load_plugins() -> list:
    """
    Auto-discover and load all plugin classes from this directory.
    Returns a list of instantiated plugin objects ready to run.

    Skips:
      - __init__.py itself
      - Files starting with underscore
      - base_plugin.py (abstract base, not a real plugin)
      - Files without a class inheriting BasePlugin
    """
    # ── Import BasePlugin first so subclasses can find it ─────────────────────
    from scanner.plugins.base_plugin import BasePlugin

    plugins      = []
    plugins_dir  = os.path.dirname(os.path.abspath(__file__))

    for filename in sorted(os.listdir(plugins_dir)):
        # Only process Python files
        if not filename.endswith(".py"):
            continue
        # Skip special files
        if filename.startswith("_"):
            continue
        # Skip the base class itself — it's not a real plugin
        if filename == "base_plugin.py":
            continue

        module_name = filename[:-3]  # strip .py

        try:
            # Import as scanner.plugins.module_name
            module = importlib.import_module(
                f"scanner.plugins.{module_name}"
            )

            # Find all classes in the module that extend BasePlugin
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, BasePlugin)
                    and obj is not BasePlugin
                    and obj.__module__ == module.__name__
                ):
                    instance = obj()
                    plugins.append(instance)
                    log.info(
                        f"Plugin loaded: {instance.name} "
                        f"(v{instance.version}) — {instance.description}"
                    )

        except Exception as e:
            log.warning(f"Failed to load plugin '{module_name}': {e}")

    log.info(f"Plugin system ready. {len(plugins)} plugin(s) loaded.")
    return plugins