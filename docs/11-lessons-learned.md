# Lessons Learned

- HTTPS connectivity and certificate trust are separate tests.
- A 401 response can confirm network/TLS reachability while exposing an authentication problem.
- Certificate SANs—not the common name alone—control modern hostname validation.
- Binding to all interfaces requires compensating firewall and segmentation controls.
- An encrypted CA key is valuable only if its password and backups are protected.
- Evidence quality depends on consistent naming, sanitization, and linkage to the relevant procedure.
- Empty repository scaffolds create a false impression of completeness; status must be explicit.
