"""`python -m mcp_guard ...` = the `mcp-guard` command (cli.py): `init` and `proxy`."""
import sys

from .cli import main

sys.exit(main())
