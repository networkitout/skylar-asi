"""Exposure Analysis module.

Answers "which internet-facing sites run an affected technology, who hosts
them, and who can patch them?" for a critical-vulnerability fire drill.

See docs/exposure-analysis/CONTEXT.md for the lessons behind each rule and
docs/exposure-analysis/SPEC.md for the build spec. Everything in this package
is network-free and unit-testable; main.py wires it to Cloudflare, the
database, and the HTTP probes.
"""
