"""Resource-oriented API mixins for the Phoenix Security client.

Each module maps one Phoenix API resource group to plain-Python methods:
inputs are simple values/dicts, outputs are decoded JSON. No internal
platform details (token handling, retries, payload quirks) leak out.
"""
