# Rust vs. Python agent — deviations

Intentional differences from the reference Python agent. Behaviour is otherwise wire-compatible.

| Area | Python | Rust |
|------|--------|------|
| Command execution | `shell=True` (globbing, `$VAR`, quote handling) | explicit argv, no shell expansion — server strings are split on whitespace only |
| Preprocessor windowing (no native skip/limit) | `\| head -n (skip+length) \| tail -n length` | in-process line window (`spawn_line_window`); also works on Windows |
| Task file provisioning | `check_files` every loop iteration (supports mid-task multicast) | `ensure_files` once per task pickup; no multicast, avoids trailing `getFile` after completion |
| Configuration reload | Global config reread between outer-loop iterations, but long-lived components retain independent snapshots | supervisor prepares and atomically swaps a complete generation between ticks/chunks |
| Keyspace overflow cutoff | `> 9.0e18` | `> i64::MAX` (~9.22e18) |
| Keyspace parse | `int(last_nonempty)` (throws on garbage) | last line that parses |
