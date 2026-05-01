"""
main.py — Firewall agent entry point.

Run with sudo (iptables requires root):
  sudo python3 ~/sfw/agent/main.py
"""

import os
import sys

from gui import FirewallAgentUI


def main():
    if os.geteuid() != 0:
        print("ERROR: Firewall agent requires root for iptables.")
        print("Run with: sudo python3 ~/sfw/agent/main.py")
        sys.exit(1)

    app = FirewallAgentUI()
    app.run()


if __name__ == "__main__":
    main()
