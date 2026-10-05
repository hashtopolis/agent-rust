# TODO

- [ ] Consider signature check for archive
- [ ] Honour piping: `enforcePipe` task flag and the `allow_piping`/`piping_threshold` slow-hash auto-pipe are parsed but never drive the chunk run
- [ ] Single-instance guard (lock.pid): nothing stops two agents running in the same directory and clobbering each other's files
