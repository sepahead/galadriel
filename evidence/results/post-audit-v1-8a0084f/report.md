# Galadriel post-audit evidence

Study: `post_audit_v1`

Git commit: `8a0084f56d41a1e09f1c3959750bbf6dff47a662`

Dirty worktree at invocation: `false`

Only holdout rows below support reported results. Calibration tracks are retained in `summary.json` as separate diagnostics and are never pooled. Proportions use Wilson intervals, alert-episode rates use labeled Garwood Poisson intervals, and other intervals use whole-track bootstrap; eligible bootstrap envelopes never replace the boundary-safe analytic interval.

Alert episodes reset only on an explicit nominal assessment. Insufficient or rejected-input outcomes preserve any active episode; rejected inputs count toward abstention.

| condition | detector | exposure h | false alerts/hour | mission P(any) | restricted ARL0 | ARL0 censored | abstention | provenance P(any alert) | pre-onset P | conditional detection | conditional delay | attribution |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| attack_broad_degradation | nis_baseline | 2.3993 | not_applicable | not_applicable | not_applicable | not_applicable | 0.0000 [0.0000, 0.2772] | not_applicable | 0.5833 [0.3750, 0.7917] | 1.0000 [0.7225, 1.0000] | 9.0000 [9.0000, 9.0000] | not_applicable |
| attack_broad_degradation | default_correlation_fusion | 2.3993 | not_applicable | not_applicable | not_applicable | not_applicable | 0.0000 [0.0000, 0.2772] | not_applicable | 0.5833 [0.3750, 0.7553] | 1.0000 [0.7225, 1.0000] | 9.0000 [9.0000, 9.0000] | not_applicable |
| attack_loud_acoustic | nis_baseline | 2.3993 | not_applicable | not_applicable | not_applicable | not_applicable | 0.0000 [0.0000, 0.2772] | not_applicable | 0.6667 [0.4583, 0.8333] | 1.0000 [0.6756, 1.0000] | 9.0000 [9.0000, 9.0000] | 1.0000 [0.6756, 1.0000] |
| attack_loud_acoustic | default_correlation_fusion | 2.3993 | not_applicable | not_applicable | not_applicable | not_applicable | 0.0000 [0.0000, 0.2772] | not_applicable | 0.6667 [0.4583, 0.8333] | 1.0000 [0.6756, 1.0000] | 9.0000 [9.0000, 9.0000] | 1.0000 [0.6756, 1.0000] |
| attack_stealthy_acoustic | nis_baseline | 2.3993 | not_applicable | not_applicable | not_applicable | not_applicable | 0.0000 [0.0000, 0.2772] | not_applicable | 0.7500 [0.5510, 0.9167] | 1.0000 [0.6097, 1.0000] | 414.0000 (descriptive_sparse/not_estimable_sparse) | 0.6667 [0.2500, 1.0000] |
| attack_stealthy_acoustic | default_correlation_fusion | 2.3993 | not_applicable | not_applicable | not_applicable | not_applicable | 0.0032 [0.0000, 0.2804] | not_applicable | 0.7500 [0.5417, 0.9167] | 1.0000 [0.6097, 1.0000] | 74.0000 (descriptive_sparse/not_estimable_sparse) | 0.1667 [0.0000, 0.5714] |
| clean_autocorrelation_phi_0p000000_0000000000000000 | nis_baseline | 2.3993 | 26.2573 [20.0056, 33.5945] | 0.9167 [0.7415, 1.0000] | 126.0417 [26.2420, 225.8413] | 0.0833 [0.0000, 0.2585] | 0.0000 [0.0000, 0.2772] | not_applicable | not_applicable | not_applicable | not_applicable | not_applicable |
| clean_autocorrelation_phi_0p000000_0000000000000000 | default_correlation_fusion | 2.3993 | 26.2573 [19.5888, 34.1762] | 0.9167 [0.7415, 1.0000] | 126.0417 [26.2420, 225.8413] | 0.0833 [0.0000, 0.2585] | 0.0000 [0.0000, 0.2772] | not_applicable | not_applicable | not_applicable | not_applicable | not_applicable |
| clean_autocorrelation_phi_0p500000_3fe0000000000000 | nis_baseline | 2.3993 | 102.9453 [90.5062, 116.6164] | 1.0000 [0.8620, 1.0000] | 38.8750 [0.0000, 138.6747] | 0.0000 [0.0000, 0.1380] | 0.0000 [0.0000, 0.2772] | not_applicable | not_applicable | not_applicable | not_applicable | not_applicable |
| clean_autocorrelation_phi_0p500000_3fe0000000000000 | default_correlation_fusion | 2.3993 | 102.9453 [90.5062, 116.6164] | 1.0000 [0.8620, 1.0000] | 38.8750 [0.0000, 138.6747] | 0.0000 [0.0000, 0.1380] | 0.0000 [0.0000, 0.2772] | not_applicable | not_applicable | not_applicable | not_applicable | not_applicable |
| clean_autocorrelation_phi_0p850000_3feb333333333333 | nis_baseline | 2.3993 | 262.5729 [242.4670, 283.9013] | 1.0000 [0.8620, 1.0000] | 12.5417 [0.0000, 112.3413] | 0.0000 [0.0000, 0.1380] | 0.0000 [0.0000, 0.2772] | not_applicable | not_applicable | not_applicable | not_applicable | not_applicable |
| clean_autocorrelation_phi_0p850000_3feb333333333333 | default_correlation_fusion | 2.3993 | 262.5729 [242.4670, 283.9013] | 1.0000 [0.8620, 1.0000] | 10.9167 [0.0000, 110.7163] | 0.0000 [0.0000, 0.1380] | 0.0192 [0.0000, 0.2964] | not_applicable | not_applicable | not_applicable | not_applicable | not_applicable |
| clean_covariance_scale_0p700000_3fe6666666666666 | nis_baseline | 2.3993 | 81.6894 [70.6528, 93.9611] | 1.0000 [0.8620, 1.0000] | 4.5000 [0.0000, 104.2997] | 0.0000 [0.0000, 0.1380] | 0.0000 [0.0000, 0.2772] | not_applicable | not_applicable | not_applicable | not_applicable | not_applicable |
| clean_covariance_scale_0p700000_3fe6666666666666 | default_correlation_fusion | 2.3993 | 81.2726 [70.2652, 93.5152] | 1.0000 [0.8620, 1.0000] | 4.5000 [0.0000, 104.2997] | 0.0000 [0.0000, 0.1380] | 0.0000 [0.0000, 0.2772] | not_applicable | not_applicable | not_applicable | not_applicable | not_applicable |
| clean_covariance_scale_1p300000_3ff4cccccccccccd | nis_baseline | 2.3993 | 0.0000 [0.0000, 1.5375] | 0.0000 [0.0000, 0.1380] | 360.0000 [260.2003, 360.0000] | 1.0000 [0.8620, 1.0000] | 0.0000 [0.0000, 0.2772] | not_applicable | not_applicable | not_applicable | not_applicable | not_applicable |
| clean_covariance_scale_1p300000_3ff4cccccccccccd | default_correlation_fusion | 2.3993 | 0.0000 [0.0000, 1.5375] | 0.0000 [0.0000, 0.1380] | 360.0000 [260.2003, 360.0000] | 1.0000 [0.8620, 1.0000] | 0.0000 [0.0000, 0.2772] | not_applicable | not_applicable | not_applicable | not_applicable | not_applicable |
| clean_ordinary_missingness | nis_baseline | 2.3993 | 9.1692 [5.7463, 13.8823] | 0.6667 [0.4583, 0.8333] | 193.4167 [93.6170, 293.2163] | 0.3333 [0.1667, 0.5417] | 0.9863 [0.7091, 1.0000] | not_applicable | not_applicable | not_applicable | not_applicable | not_applicable |
| clean_ordinary_missingness | default_correlation_fusion | 2.3993 | 6.6685 [3.8116, 10.8293] | 0.6667 [0.4671, 0.8750] | 193.4167 [93.6170, 293.2163] | 0.3333 [0.1667, 0.5417] | 0.9935 [0.7163, 1.0000] | not_applicable | not_applicable | not_applicable | not_applicable | not_applicable |
| provenance_invalid_prior | nis_baseline | 2.3993 | not_applicable | not_applicable | not_applicable | not_applicable | 0.0000 [0.0000, 0.2772] | not_applicable | not_applicable | not_applicable | not_applicable | not_applicable |
| provenance_invalid_prior | default_correlation_fusion | 2.3993 | not_applicable | not_applicable | not_applicable | not_applicable | 1.0000 [0.7228, 1.0000] | 0.0000 [0.0000, 0.1380] | not_applicable | not_applicable | not_applicable | not_applicable |
| provenance_missing_projection | nis_baseline | 2.3993 | not_applicable | not_applicable | not_applicable | not_applicable | 0.0000 [0.0000, 0.2772] | not_applicable | not_applicable | not_applicable | not_applicable | not_applicable |
| provenance_missing_projection | default_correlation_fusion | 2.3993 | not_applicable | not_applicable | not_applicable | not_applicable | 0.9932 [0.7160, 1.0000] | 0.5833 [0.3883, 0.7553] | not_applicable | not_applicable | not_applicable | not_applicable |

## Recorded fixture

Status: `not_estimable`; 476 observations across 1 track(s), 15800 ms total observed duration, 0 observations with a consistency projection.

Reasons:

- insufficient_duration: 15800 ms is below configured minimum 3600000 ms
- missing_consistency_projection

The checked-in capture is therefore a parser/provenance/abstention smoke test. The runner does not extrapolate its short duration into an operational false-alert rate or detection claim.

## Interpretation limits

- Synthetic observations are controlled stress tests, not a deployed residual population or operational accuracy claim.
- Configured family_alpha is a per-assessment family-wise bound under the detector model; it is not a stream false-alert-rate guarantee.
- Garwood episode-rate intervals assume a homogeneous Poisson count process; whole-track bootstrap envelopes are reported when sufficiently estimable, but neither turns the controlled stream into an operational FAR claim.
- ARL0 is a finite-horizon restricted mean and must be read with its censoring fraction.
- Attack delay and attribution are conditional on no pre-onset alert; delay is also conditional on detection.
- Alert episodes use the configured nominal_only reset policy: abstention preserves an active episode, and only a nominal assessment clears it.
- The default runner evaluates streaming NIS and signed correlation only; PID has no product streaming cadence in this revision.
