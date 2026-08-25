# A2A to SMESH Protocol Mapping

| A2A v1 | SMESH gateway |
|---|---|
| Agent Card | Aggregate swarm capability and gateway interfaces |
| Agent skill | Supported task family; not internal role inventory |
| Message | Validated external request |
| Task ID | Stable gateway ID copied into the mesh task envelope |
| Context ID | Stable conversation/workflow grouping |
| `Submitted` | Durable task created by the A2A handler |
| `Working` | Mesh dispatch accepted or progress observed |
| Artifact update | Candidate/accepted mesh output exposed to the client |
| `Completed` | Completion policy accepted the output |
| `Failed` | Dispatcher or worker produced a terminal error |
| `Canceled` | Cancellation reached the dispatcher |
| Task history | Durable A2A conversation record |
| SMESH signal decay | Internal coordination only; never deletes the A2A task |
| SMESH reinforcement | Internal confidence signal; not directly exposed as truth |
| SMESH attestation | Optional provenance extension after independent verification |

## Completion policy

The demo completes when the loopback worker produces one artifact. A production SMESH adapter must make completion explicit. Recommended policy inputs are required reviewer/test signals, a consensus threshold, zero blocking contradictions, and human ratification when policy requires it.

## Non-mappings

- A2A authentication does not become SMESH reputation.
- A client-supplied tenant does not become a trusted internal identity.
- Agent Card skills do not grant capabilities.
- A high-intensity SMESH signal does not automatically become an external artifact.
