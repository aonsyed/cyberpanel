# Native QEMU diagnostics

Never run a bare `openlitespeed -t` or `lshttpd -t`, even as a supposedly
read-only diagnostic. The native parser performs recursive configuration
ownership/permission repair, including CyberPanel's sealed state, and can make
the executor correctly refuse startup.

Use the existing `webactivation.FixedRunner.ValidateInitial` or the confined
QEMU webactivation tests. These execute the parser through `systemd-run` with
`ReadOnlyPaths=/usr/local/lsws/conf /etc` and
`CapabilityBoundingSet=~CAP_SYS_ADMIN`. Do not relax the private configuration
store checks to accommodate diagnostic-induced metadata changes.
