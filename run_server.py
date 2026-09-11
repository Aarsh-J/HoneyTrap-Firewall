#!/usr/bin/env python
"""Entry point for the HoneyTrap Firewall server."""
from honeytrap.logging_setup import configure_logging

configure_logging()

from honeytrap.server import main

if __name__ == "__main__":
    main()
