# Log Source Onboarding

The former “Agent Development” label was inaccurate: this project deploys and configures agents; it does not develop Elastic Agent source code.

## Windows

Collect Security events, PowerShell operational logs, and Sysmon where installed. Initial use cases include Event ID 4625 bursts, privilege changes, and suspicious process creation.

## Linux

Collect authentication, sudo, account-management, process, and service events. Confirm parsing into Elastic Common Schema fields.

## Web server

Collect access and error logs. Validate client IP handling, response codes, request paths, user agents, and proxy headers without ingesting secrets.

## Acceptance test

For every source, generate one authorized benign event, locate it in Discover, record the data stream and ECS fields, then capture sanitized evidence.
