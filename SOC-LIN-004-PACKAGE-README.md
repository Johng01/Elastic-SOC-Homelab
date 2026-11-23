# SOC-LIN-004 publication package (updated November 23, 2026)

This archive contains the updated investigation report, TIG (Markdown and PDF), and experimental Sigma rule. It **does not include screenshot image files**, which the operator confirmed saved in their physical Ubuntu host repository.

Destination: `/home/cybersafe/Elastic-SOC-Homelab/`.

Copy the `reports/`, `implementation-guides/`, and `detection-rules/` files to the corresponding folders in the repository **after reviewing existing files for conflicts**. Do not treat the Sigma YAML as converted/validated native Elastic threshold logic.

Operator-confirmed screenshot inventory:

- `screenshots/05-detection/SOC-LIN-004-sudo-positive-alert.png`
- `screenshots/05-detection/SOC-LIN-004-sudo-positive-source-events.png`
- `screenshots/05-detection/SOC-LIN-004-negative-test-source-events.png`
- `screenshots/05-detection/SOC-LIN-004-negative-test-zero-alerts.png`
- `screenshots/06-investigations/SOC-LIN-004-sudo-alert-closed.png`

Confirmed: the final alert was investigated and closed; `soctest004`, its sudo membership and its home directory were removed. Pending: formal Sigma backend parity and testing of non-covered scenarios. No GitHub files have been modified by preparing this archive.
