# TODO

- [ ] Consider signature check for archive
- [x] Honour piping: `enforcePipe` runs a hashcat self-pipe, and `allow_piping`/`piping_threshold` drive the reactive slow-hash auto-pipe (a starved direct run restarts as a self-pipe). Note: a self-pipe consumer carries no attack command, so the hash type `-m` must live in `cmd_parameters`, not the attack string (a long-standing server contract, mirrored from the Python agent).
- [ ] Single-instance guard (lock.pid): nothing stops two agents running in the same directory and clobbering each other's files
