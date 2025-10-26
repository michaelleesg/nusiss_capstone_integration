# nusiss_capstone_integration
integration for capstone

## Eval symlink
This repo has a symlink `eval_external/` pointing to the separate documentation/evaluation repo
(`/mnt/c/Users/mike/Downloads/cybersage_eval`). Treat it as **read-only** from here.
To export artefacts for reports:

```bash
make export-eval
# or copy a specific path
make export-eval FROM=observability/dashboard-heva.json
```
