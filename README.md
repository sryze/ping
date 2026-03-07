ping
====

> [!WARNING]
> This project is unmaintained and considered deprecated. No new features or bug fixes will be provided. Users are advised to seek alternative solutions.

This is a rather basic implementation of the `ping` command in C. It was
created for learning more about raw sockets and how ping works (and for fun).

Features:

* Cross-platform: can compile and run on Windows, Linux, macOS, *BSD
* Supports IPv6
* Displays time with microsecond precision

Building
--------

To build ping you will need a C89 compiler and CMake.

After you cloned this repo run the following commands to build an executable:

```sh
cd ping
mkdir build && cd build
cmake ../ -G "Unix Makefiles"
make
```

Running
-------

Example usage:

```sh
$ ./ping google.com
PING google.com (XXX.XXX.XXX.XXX)
Received reply from XXX.XXX.XXX.XXX: seq=0, time=103.307 ms
Received reply from XXX.XXX.XXX.XXX: seq=1, time=91.200 ms
Received reply from XXX.XXX.XXX.XXX: seq=2, time=103.080 ms
Received reply from XXX.XXX.XXX.XXX: seq=3, time=94.531 ms
Received reply from XXX.XXX.XXX.XXX: seq=4, time=92.204 ms
^C
```

The program will run indefinitely until you interrupt it.

Note: the use of raw sockets usually requires administrative privileges. One
of the ways to overcome this is to use `sudo`. However, running programs as
root is very dangerous and can potentially damage your system! Also:
**DO NOT** run random code from the internet as root! You should look into
other options instead, such as Capabilities on Linux or using a Docker
container or a VM.

Scripts
-------

The `scripts` directory contains a couple of scripts to aid debugging:

* `capture.sh` - captures ICMP traffic with `tcpdump` and saves it to
  `ping.pcap`
* `dump.sh` - prints the contents of `ping.pcap` in a nice form (`tcpdump`
   may actually display helpful errors there, like a miscalculated checksum)
