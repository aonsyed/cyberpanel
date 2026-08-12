# CyberPanel Greenfield Platform

This directory is a standalone Go module for the secure CyberPanel replacement.
It must not import or execute the legacy Django, Python, or shell application.

All builds and tests run inside disposable QEMU guests. Host execution is limited
to the reviewed VM harness and fixed virtualization utilities.

This foundation is not a usable hosting panel and does not claim feature parity.
