"""Windows VM worker dynamic analysis provider.

Triggers sample execution in an isolated Windows VM, collects Sysmon
event logs and process telemetry, then reverts the VM to a clean snapshot.
Optional backend — requires VM infrastructure to be pre-configured.
"""
