# gosch
A simple chat server in golang  (GOsch`S a CHat server).
Currently only supports SSL sockets (see -selfsigned option for getting started quickly)
Work In Progress -- contains a lot of debugging code and not a lot of features.

## Usage
Creating a self-signed TLS certificate `foo.pem` and starting the server in foreground mode:
> ./gosch -selfsigned -certfile foo.pem

## TODO

- [ ] usermodes: +m on channels, +v, +o for users,
- [ ] CAP parsing
- [ ] rate limiting
- [ ] make sure BAN works with hashed client addr/hostnames
- [ ] implement POSIX getopt, flags sucks 
- [ ] web frontend for roaming users (need some sort of bouncer?)
- [ ] matrix protocol?
