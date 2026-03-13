# Incident Summary Writer

## Purpose
Transform local incident timelines into structured summaries for postmortems.

## Controls
- Uses local markdown and JSON timeline files only.
- Does not alter long-term system state.
- Does not run privileged commands.

## Workflow
1. Parse timeline events.
2. Group by impact, detection, and mitigation phases.
3. Emit summary markdown into the current workspace.
