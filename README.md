# gosch
A simple chat server in golang  (GOsch`S a CHat server).
Currently only supports SSL sockets (see -selfsigned option for getting started quickly)
Work In Progress -- contains a lot of debugging code and not a lot of features.

## Usage
Creating a self-signed TLS certificate `foo.pem` and starting the server in foreground mode:
> ./gosch -selfsigned -certfile foo.pem

