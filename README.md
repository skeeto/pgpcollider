# OpenPGP Long Key ID Collider

Uses hash chains to find pairs of keys that have "long" 64-bit key ID
collisions.

Overview: [**The Long Key ID Collider**][long]

## Installation

    $ go get -u github.com/skeeto/pgpcollider

## Usage

*Quickstart*: This command will find and output two ASCII-armored
private keys whose long key IDs collide:

    $ pgpcollider --verbose | tee keys.asc

It will use all your CPU cores (see `GOMAXPROCS`) and, on a modern
computer, can take up to a day to find a collision. A collision is
expected after around 4 billion keys (monitor with `--verbose`), but
could happen sooner or later.

Additional computers can work together to search for a collision. One
instance is a server that distributes tasks, but does none of its own
work. Client instances join and compute hash chains on behalf of the
server. These clients are free to come and go at any time without
disrupting overall progress.

Start a server with `--server` (`-S`) listening on port 1234:

    $ pgpcollider -S :1234 -v

Start one or more clients with `--client` (`-C`):

    $ pgpcollider -C hostname:1234

### Options listing

Use `--help` (`-h`) to get an option listing:

```
Usage:
   pgpcollider [-pv] [-t CREATED] [-u USERID]
   pgpcollider -C HOSTNAME [-v]
   pgpcollider -S BINDADDR [-pv] [-t CREATED] [-u USERID]
Commands (distributed computation):
   -C, --server BINDADDR  generate hash chains for a server
   -S, --client HOSTNAME  listen for worker clients
Options:
   -h, --help             print this help message
   -p, --public           only output the public key
   -t, --time SECONDS     key creation date (unix epoch seconds)
   -u, --uid USERID       user ID for the keys
   -v, --verbose          print progress information
```

## See Also

* [passphrase2pgp][p2p]


[long]: https://nullprogram.com/blog/2019/07/22/
[p2p]: https://github.com/skeeto/passphrase2pgp
