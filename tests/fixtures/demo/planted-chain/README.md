# Planted certificate chain (T-120, OQ-20)

Two **synthetic** certificates, generated once and committed so the demo is
reproducible (fresh random keys would change every identity on every run). Both
are RSA-2048: an offline root CA valid 20 years and a TLS leaf valid 90 days.
They exist to demonstrate invariant I2 - same algorithm, opposite urgency - and
are labelled as planted wherever the demo shows them. No private key is kept.
