ping
====

[![Build Status][build_status]][build]

This is a rather basic implementation of the `ping` command in C. It was
created for learning more about raw sockets and how ping works (and for fun).

Features:

* Cross-platform: can compile and run on Windows (MSVC, Cygwin), Linux, macOS
* Supports IPv6
* Displays time with microsecond precision

Example usage:

```sh
$ ./ping google.com
PING google.com (142.250.74.206)
Received reply from 142.250.74.206: seq=0, time=103.307 ms
Received reply from 142.250.74.206: seq=1, time=91.200 ms
Received reply from 142.250.74.206: seq=2, time=103.080 ms
Received reply from 142.250.74.206: seq=3, time=94.531 ms
Received reply from 142.250.74.206: seq=4, time=92.204 ms
^C
```

`ping` accepts only one argument - the name of the host to ping.

Building
--------

To build ping you'll need a C89 compiler and CMake. Supported platforms include
Linux, Mac OS X and Cygwin.

After you cloned this repo run the following commands to build an executable:

```sh
cd ping
mkdir build && cd build
cmake ../ -G "Unix Makefiles"
make
```

Running
-------

Use of raw sockets usually requires administrative privileges, therefore you
will need to run `ping` as root:

```sh
sudo ./ping google.com
```

There is also a way to make it run without typing `sudo` every time: set the
`suid` bit on the executable and change its owner to `root`:

```sh
sudo chmod +s ./ping
sudo chown root ./ping
```

After starting `ping`, it will run indefinitely until you interrupt it, e.g.
by doing `Ctrl-C` in the terminal.

Scripts
-------

The `scripts` directory contains a couple of scripts to aid debugging:

* `capture.sh` - captures ICMP traffic with `tcpdump` and saves it to
  `ping.pcap` (needs to be run as root)
* `dump.sh` - prints the contents of `ping.pcap` in a nice form (`tcpdump`
   may actually display helpful errors there, like a miscalculated checksum)

[build]: https://travis-ci.com/sryze/ping
[build_status]: https://travis-ci.com/sryze/ping.svg?branch=master
