# OpenPGP Long Key ID Collider

Uses hash chains to find pairs of keys that have "long" 64-bit key ID
collisions. Overview: [**The Long Key ID Collider**][long]

## Installation

    $ go get -u github.com/skeeto/pgpcollider

## Usage:

(*Quickstart*) This command will find and output two ASCII-armored
secret keys whose long key IDs collide:

    $ pgpcollider --verbose

It will use all your CPU cores (see `GOMAXPROCS`) and, on a modern
computer, can take up to a day to find a collision. A collision is
expected after around 4 billion keys (try `--verbose`), but could happen
sooner or later.

Additional computers can work together to search for a collision. To
enable, pass additional arguments just for `--collide` (`-X`). One
instance is a server that distributes tasks, but does none of its own
work. Client instances join and compute hash chains on behalf of the
server. Clients are free to come and go at any time.

Start a server with `--server` (`-S`) listening on port 1234:

    $ pgpcollider -S :1234 -v

Start one or more clients with `--client` (`-C`):

    $ pgpcollider -C hostname:1234


[long]: https://nullprogram.com/blog/2019/07/22/
