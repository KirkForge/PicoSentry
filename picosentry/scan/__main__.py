"""Allow running PicoSentry CLI as: python -m picosentry"""

from picosentry.scan.cli import main

if __name__ == "__main__":
    import sys

    sys.exit(main())
