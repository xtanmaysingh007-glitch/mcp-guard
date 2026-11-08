"""`python -m mcp_guard init tools.json -o policy.yaml` (see init_policy.py)."""
import sys

from .init_policy import main

sys.exit(main())
