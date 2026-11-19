# Prompts

Versioned prompt + JSON Schema for the analysis engine. Read
[`docs/architecture.md` → "¿Dónde vive el prompt?"](../docs/architecture.md) for the
full reasoning; the short version:

| Question | Answer |
|---|---|
| Where does it live? | Files here, versioned in git. Not in code, not in a DB, never in the client. |
| Why? | It is security policy: it must be reviewed by diff, auditable after the fact, testable, and adjustable without a release. |
| How is it versioned? | `prompt_version = <stem>@<12 hex of sha256(prompt + schema)>`. Content-addressed, so it cannot be forgotten or faked. |
| What can break it? | `validate_prompt()` runs at startup and in CI: it fails if a required block disappears, if the prompt is truncated, or if the schema allows a category the prompt never briefs the model on. |
| How is it kept separate from the code under review? | The prompt is the *system* message and is byte-identical to this file. Reviewed code only ever appears inside a delimited `<UNTRUSTED_CODE>` block in the user message. |

## Files

| File | Role |
|---|---|
| `analyze.v1.md` | The system prompt: categories, decision procedure, evidence rule, and the "untrusted data" framing. |
| `analysis.schema.json` | Closed JSON Schema for the answer. Enums for category/severity; `additionalProperties: false`. |

## Changing the prompt safely

1. Edit the file. `prompt_version` changes automatically — cached verdicts are
   invalidated by design.
2. Run `uv run pytest tests/test_engine.py -k prompt` (consistency checks).
3. Re-run `aegis analyze examples/vulnerable/app.py --local` and
   `examples/clean/*` — the six examples are the regression suite for prompt
   quality, and `examples/vulnerable/injected.py` is the injection canary.
4. Bump the file name (`analyze.v2.md`) only for a change that should *not* share
   the cache and should be visibly different in the audit log.
