# Firewall

Firewall is built to enable app level filtering of packets.
It is designed for work on linux operating system.

## Overview

The basic flow of the application is as follows:

- Capture outgoing packets using `netfilter`.
- For Captured packets figure out the process name.
- Check rules to either allow or disallow packet.

### DNS Capture

- Capture incoming dns packets (port == 53).
- Parse the packet to get dns queries.
- Use the same (store it) to make rules more readable.

### Process name identification [[1]]

- search for socket inode by parsing `/proc/net/{protocol}6?`.
- search for files in `/proc/{pids}/fd/{fds}` for link to `socket[{inode}]`.
- use pid from above step to get link to executable link using `/proc/{pid}/exe`.

## TODO

- [x] Add logging to enable debugging.
- [ ] Use multi-threading or async[2] approach.
- [ ] Add rules interface and expose it to user.
  - [ ] allow to add new rules.
  - [ ] modifying existing rules.
  - [ ] save and restore rules.
- [ ] Add tests to enable maintainability.
  - [ ] for parsing of basic packets.
  - [ ] for checking for finding pid/process names.
- [X] Do reverse lookup if needed

[1]: https://superuser.com/a/34784 "so: how to get pid for socket"
[2]: https://web.archive.org/web/20210205020030/https://www.zupzup.org/epoll-with-rust/index.html "Epoll in rust"
