"""PyInstaller entry point. A frozen script cannot use package-relative
imports as `__main__`, so this imports the real entry point by absolute name."""

import sys

from qavach_agent.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
