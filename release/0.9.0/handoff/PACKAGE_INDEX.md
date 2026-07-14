# Galadriel 1.0 standalone implementation handoff

## Use

Give this extracted directory to the agent assigned to `https://github.com/sepahead/galadriel`. It is independent of the pid-rs handoff and of the other two repository handoffs.

The agent must execute tasks in dependency order from `T000` through `T119`. Cross-repository changes are permitted only under the limits in the blueprint and migration document.

## Files

- `GALADRIEL_V1_0_RELEASE_BLUEPRINT.md`
- `GALADRIEL_V1_0_AGENT_TASK_LEDGER.yaml`
- `GALADRIEL_V1_0_ARCHITECTURE.md`
- `GALADRIEL_V1_0_CORE_CONTRACT_SCHEMA.json`
- `GALADRIEL_V1_0_MIGRATION_AND_ECOSYSTEM.md`
- `GALADRIEL_V1_0_GO_NO_GO_CHECKLIST.md`
- `GALADRIEL_V1_0_RELEASE_MANIFEST_TEMPLATE.json`
- `GALADRIEL_V1_0_ARTIFACT_VALIDATION_REPORT.md`
- `GALADRIEL_V1_0_ARTIFACT_SHA256SUMS.txt`

## Precedence

1. Normative repository contract produced by executing the tasks.
2. This architecture and schema design target.
3. Blueprint task requirements.
4. Machine-readable ledger.
5. Current pre-1.0 behavior.

Unsafe or ambiguous legacy behavior never outranks the 1.0 design.

## Immediate first actions

1. Extract into a clean review directory.
2. Read every file before coding.
3. Clone the repository and record the exact initial commit.
4. Run the unmodified test suite and preserve logs.
5. Create `audit-inputs.json`, requirements ledger and release branch.
6. Start at T000.
7. Do not publish until the entire checklist and independent evidence pass.
