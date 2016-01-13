ping
====

This is a simple implementation of the `ping` command in C. It was created for learning more
about raw sockets and how ping works.

Example usage:

```sh
$./ping google.com
Sent ICMP echo request to 212.188.10.88
Received ICMP echo reply from 212.188.10.88: seq=0, time=14.438 ms
Sent ICMP echo request to 212.188.10.88
Received ICMP echo reply from 212.188.10.88: seq=1, time=14.125 ms
Sent ICMP echo request to 212.188.10.88
Received ICMP echo reply from 212.188.10.88: seq=2, time=13.850 ms
^C
```

`ping` accepts only one argument - the name of the host to ping.

Building
--------

To build ping you'll need a C89 compiler and CMake. It is known to build successfully on
Linux and Mac OS X.

After you cloned this repo run the following commands to build an executable:

```sh
cd ping
mkdir build && cd build
cmake ../ -G "Unix Makefiles"
make
```

Running
-------

Use of raw sockets usually requires administrative priviliges, therefore you'll need to
run `ping` as root:

```sh
sudo ./ping google.com
```

There are way to make it runnable without root privileges but depends on your system. 
In particular, that can be achieved by setting the `suid` bit on the executable file and
changing its owner to `root`:

```sh
sudo chmod +s ./ping
sudo chown root ./ping
```

After starting `ping`, it will run indefinitely until you interrupt it, e.g. by doing
`Ctrl-C` in the terminal.
