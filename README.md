# gosch
A simple IRC server in golang  (GOsch`S a CHat server).
Currently only supports SSL sockets (see -selfsigned option for getting started quickly)
Work In Progress -- contains a lot of debugging code and not a lot of features.

## TODO

- [x] move to github from private repo
- [ ] CAP parsing
- [ ] refactor into more standard go project
- [ ] rate limiting
- [ ] add unittests
- [ ] usermodes: +m on channels, +v, +o for users,
- [ ] make sure BAN works with hashed client addr/hostnames
- [x] the nick roster in pidgin is broken, works fine in konversation and irssi
- [x] refactor and clean up
- [x] remove ssl-shellout, can be done in native go code
- [ ] implement POSIX getopt, flags sucks 
- [ ] daemonize, log to folder
- [ ] web frontend for roaming users (need some sort of bouncer?)
