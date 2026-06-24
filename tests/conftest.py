"""Make the src/ layout importable when running tests from a clean clone
without an editable install (CI also installs the package, but this keeps
`pytest` working out of the box)."""

import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.dirname(__file__)), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
