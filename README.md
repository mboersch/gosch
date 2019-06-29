# gosch
A simple IRC server in golang. 
Currently only supports SSL sockets (see -selfsigned option for getting started quickly)
Work In Progress -- contains a lot of debugging code

## TODO
[x] - move to github from private repo
[ ] - refactor into more standard go project
[ ] - rate limiting
[ ] - add unittests
[ ] - usermodes: +m on channels, +v, +o for users,
[ ] - make sure BAN works with hashed client addr/hostnames
[ ] - the nick roster in pidgin is broken, works fine in konversation and irssi
[ ] - refactor and clean up
[ ] - remove ssl-shellout, can be done in native go code
[ ] - implement POSIX getopt, flags sucks 
[ ] - daemonize, log to folder

