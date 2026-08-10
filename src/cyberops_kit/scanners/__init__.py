"""Scanner plugins — one module per external tool.

We orchestrate; we do not reimplement. Each module maps a tool's native output into
the canonical ``Finding`` model and nothing more. See
``docs/contributing/add-a-scanner.md`` to add one.
"""
