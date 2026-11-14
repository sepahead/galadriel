# Recorded CREBAIN NCP 2 loop runs

`tests/ncp_loop.rs` assesses these runs. Each directory holds what `crebain-ncp-loop run` wrote, without its summary and trajectory: `manifest.json`, one transcript for each world, and one for each controller. `config.json` is the loop configuration of the run, with program names instead of their local paths.

The runs come from CREBAIN commit `a1df34c7d9f409e929a138ed5c7ac810e7a82931`, whose native simulation pins the NCP 2 core at `2e24ef5b89feb3f1e4f4972e290201d93e2d0a8d` (revision 4 of the NCP 2 specification). Their transcripts are of version 2, and `crebain-ncp-loop verify` accepts each run.

| Run | Worlds and drones | Steps | Inputs |
| --- | --- | --- | --- |
| `loop-1x1` | one world, one drone, one controller | 20 | none |
| `loop-1x1-faults` | one world, one drone, one controller | 40 | a sensor offset of 0.2 m east at steps 11 to 20; no sensor measurement at step 30 |
| `loop-2x3` | two worlds with three and two drones, three controllers | 10 | none |

Each opening draws a new nonce, so a new run of the same configuration gives other transcript bytes. The tests read these files; they do not run CREBAIN.
