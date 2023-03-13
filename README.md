This software was just a proof of concept and not developed further or maintained in any way. Will be archived.

# gosch
A simple chat server experiment in golang  (GOsch`S a CHat server).
Currently only supports SSL sockets (see -selfsigned option for getting started quickly)
Work In Progress -- contains a lot of debugging code and not a lot of features.

## Usage
Creating a self-signed TLS certificate `foo.pem` and starting the server in foreground mode:
> ./gosch -selfsigned -certfile foo.pem

