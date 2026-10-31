"""
run.py - Entry point for launching the PCAP Investigator web server.
"""

import sys
import os

# Add project root directory to path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import app
import config

if __name__ == "__main__":
    print("=" * 70)
    print("  Intelligent PCAP Investigation & Attack Timeline System")
    print(f"  Running on: http://{config.HOST}:{config.PORT}")
    print(f"  AI Mode   : {config.AI_PROVIDER.upper()} (Fallback Enabled: True)")
    print(f"  Database  : {config.DATABASE_PATH}")
    print("=" * 70)
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
