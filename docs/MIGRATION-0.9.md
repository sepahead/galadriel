# Migration from the 0.1 research API to 0.9.0

Galadriel 0.9.0 deliberately breaks ambiguous pre-1.0 behavior. Callers must make
identity, lifecycle, configuration, and failure semantics explicit; compatibility
adapters may translate only when the source meaning is known.

## Domain values

Raw `u64` values are no longer sufficient evidence of semantic identity. Convert
at the boundary with `TrackId`, `ProjectionFrameId`, `ProjectionContextId`,
`FrozenPriorId`, `Sequence`, `StateGeneration`, and `TimestampMillis`. Values above
the exact JSON integer ceiling are rejected rather than rounded. Zero remains valid
for ordinals and timestamps, but not for semantic numeric identifiers.

Session, epoch, stream, and producer labels now use separate validated types. The
accepted grammar is bounded ASCII. A legacy Unicode NCP identifier cannot be
normalized safely because normalization could merge identities; start a fresh
epoch with a conforming identifier or retain the capture as unqualified evidence.

`ClockDomain` is a closed enum. Existing millisecond timestamps must be labeled as
`unix_utc`, `monotonic_process`, `simulation_time`, or `tai`; callers may not invent
an open string or infer a clock from magnitude.

## Lifecycle

Large sequence/time gaps, context changes, and track removal formerly cleared
history implicitly. The 0.9 target requires an explicit reset receipt or epoch
rollover. `StreamPosition::checked_successor`, `checked_reset`, and
`checked_epoch_rollover` provide the bounded coordinate rules; the detector event
machine and adapter migration are specified in `STATE-MACHINE.md` and completed by
T014–T015.

## Result handling

Do not collapse every non-nominal condition into an error or Boolean alarm.
`AssessmentOutcome::InsufficientEvidence` is a successful fail-closed assessment;
positive anomaly evidence is also a successful assessment. `AssessmentFailure`
is reserved for typed invalid, authentication/authorization, compatibility,
temporal/identity, resource, backend, or internal failures.

The unversioned `Verdict`/`MirrorReport` serde representation and the causal aliases
`spoof`, `jam`, and `anomaly` are pre-0.9 migration inputs only. Normal 0.9 report
decoding will reject them; any historical conversion must be an explicit offline
migration that retains the original bytes and digest.

