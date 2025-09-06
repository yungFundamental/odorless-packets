# Odorless Packets

## Introduction
This project dives into network captures, and how to override them.

The name "Odorless Packets" comes from the "network sniffing" term - This project makes packets that can't be "sniffed".

## System Requirements
It is important to note that this project was developed on Ubuntu 24.04, and is meant for Linux systems.


## Contents
### Network Sniffer
In order to play around with the concept, I built a basic TCP sniffer. 

It utilizes the [libpcap](https://github.com/the-tcpdump-group/libpcap) library. This is the same library that is used in common sniffing tools.

### Overrider
A basic thought of how do hide network traffic is to utilize the `LD_PRELOAD` environment variable.
`LD_PRELOAD` can help us influence the linkage process and symbol resolution of compiled programs. 
In short, we can make a compiled program use our version of standard library functions instead of the standard ones **without recompiling the program**.

Personally, I was familiar of this "trick" for observabillity purposes, for example wrapping the `malloc` function to add metrics and logs to each call. 
Theoretically, the `LD_PRELOAD` variable can act as a strategy to cause unexpected behavior for less experienced Linux users. That is why I wanted to put the idea to practice. 

For more information about the `LD_PRELOAD` trick - see this [Baeldung article](https://www.baeldung.com/linux/ld_preload-trick-what-is).

