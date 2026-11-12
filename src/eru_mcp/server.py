"""smith_mcp.server by its old name (see __init__.py): the same module, so the same server."""

import sys

from smith_mcp import server as _server

if __name__ == "__main__":
    sys.exit(_server.main())
else:
    sys.modules[__name__] = _server
