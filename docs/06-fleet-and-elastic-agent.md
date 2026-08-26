# Fleet and Elastic Agent

This document merges the former empty `06-Fleet.md` and `06-Elastic-Agent.md` placeholders because Fleet management and agent enrollment form one operational workflow.

## Status

Planned after Kibana validation.

## Deployment sequence

1. Configure Fleet settings and outputs.
2. Create separate policies for Windows, Linux, and web-server workloads.
3. Add only the integrations required by each policy.
4. Deploy Fleet Server if the chosen topology requires it.
5. Enroll agents using short-lived credentials.
6. Confirm agent health and expected data streams.
7. Revoke or rotate exposed enrollment tokens.

## Validation

- Agent status is Healthy.
- Host identity and policy assignment are correct.
- Expected data streams contain recent events.
- Timestamps and time zones are correct.
- Integration errors are investigated before detection testing.
