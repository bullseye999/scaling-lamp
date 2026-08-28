#!/usr/bin/env python3
# run_ciph.py - CIPH 3.0 Sovereign Autonomous Intelligence Launcher

import os
import sys

# Enable ANSI escape sequences on Windows
if sys.platform == "win32":
    os.system("")

from ciph_core import CiphCore

def main():
    try:
        ciph = CiphCore()
        ciph.run_ssh_session()
    except KeyboardInterrupt:
        print("\n\n⚠️  Session interrupted by user.")
    except Exception as e:
        print(f"\n💥 Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()