#!/usr/bin/env python
"""Entry point for the HoneyTrap Firewall client GUI."""
from honeytrap.logging_setup import configure_logging

configure_logging()

from honeytrap.gui.app import App

if __name__ == "__main__":
    app = App()
    app.mainloop()
