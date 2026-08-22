# ai_analysis (placeholder)

Reserved for a future plugin that summarizes and triages findings across a
pipeline's runs (e.g. de-duplicating open ports/services across steps,
flagging headers of interest, drafting a first-pass narrative for the
Markdown report). Not implemented in this starter. Any future
implementation must still call `AssessmentPlugin.authorize()` before
touching a target, and must not add capability to bypass the
approved_targets allowlist.
