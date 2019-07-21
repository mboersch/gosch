# gosch
A simple IRC server in golang  (GOsch`S a CHat server).
Currently only supports SSL sockets (see -selfsigned option for getting started quickly)
Work In Progress -- contains a lot of debugging code and not a lot of features.

## TODO

- [x] move to github from private repo
- [x] Nick name changing doesnt work yet (?)
- [ ] usermodes: +m on channels, +v, +o for users,
- [ ] CAP parsing
- [x] refactor into more standard go project
- [ ] rate limiting
- [ ] add unittests
- [ ] make sure BAN works with hashed client addr/hostnames
- [ ] implement POSIX getopt, flags sucks 
- [x] daemonize
- [ ] log to folder
- [ ] web frontend for roaming users (need some sort of bouncer?)
