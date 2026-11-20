#!/usr/bin/env python3
"""Standalone entry point for proof-gate."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proof_gate.cli import main

if __name__ == "__main__":
    sys.exit(main())
