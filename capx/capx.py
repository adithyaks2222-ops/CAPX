#!/usr/bin/env python3
import sys
from capx.cli import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] CAPX execution interrupted by user.")
        sys.exit(130)