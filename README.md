# Odorless Packets

## Introduction
This project dives into network captures, and how to override them.

The name "Odorless Packets" comes from the "network sniffing" term - This project makes packets that can't be "sniffed".

## Demonstration

The following video demonstrates how to override the sniffing process to hide certain packets:

![Demo](assets/demo/demo-2.gif)

The top left terminal contains a process of the sniffer program. The bottom left terminal runs the same program but with the `LD_PRELOAD` environment variable set to our specific `override` code.
On the right we have a connected TCP session.

As we can see in the demo, every packet that reaches the sniffer in the top left reaches the sniffer in the bottom left as well. The only exception is the message with the "DON'T LOOK" prefix and its acknowledgement.

Thus demonstrating how we can hide packets from a network capture tool **without changing the binary**.

## System Requirements
It is important to note that this project was developed on Ubuntu 24.04, and is meant for Linux systems.


## Project Contents
### Network Sniffer
In order to play around with the concept, I built a basic TCP sniffer. 

It utilizes the [libpcap](https://github.com/the-tcpdump-group/libpcap) library. This is the same library that is used in common sniffing tools.

### Overrider
A basic thought of how do hide network traffic is to utilize the `LD_PRELOAD` environment variable.
`LD_PRELOAD` can help us influence the linkage process and symbol resolution of compiled programs. 
In short, we can make a compiled program use our version of standard library functions instead of the standard ones **without recompiling the program**.

Personally, I was familiar of this "trick" for observabillity purposes, for example wrapping the `malloc` function to add metrics and logs to each call. 
Theoretically, the `LD_PRELOAD` variable can act as a strategy to cause unexpected behavior for less experienced Linux users. That is why I wanted to put the idea to practice. 

I chose to override the `libpcap` library, since it is the same library used by common tools like `tcpdump` and `npcap`.

For more information about the `LD_PRELOAD` trick - see this [Baeldung article](https://www.baeldung.com/linux/ld_preload-trick-what-is).

#### Hiding Acknowledgements
In order to hide the acknowledgements, I had to keep track which messages I hid so when I got to the ack of those messages I'd hide them.

I considered multiple datastructures to solve this problem. HashMap the theoretically the "optimal" choice - $O(1)$ lookup/delete/insertion time is tough to deny.
But looking closer into the decision, there is more to be considered than just time complexity:
- Implementation complexity - Time complexity isn't the most important part of this educational project. Perhaps HashMaps are optimal but should they be implemented in the MVP?
- Space complexity
- Collision management

All in all, I realised that the more fitting implementation may be starting with a simple linked list, but writing the code in a way so that switching datastructures would be very simple.
I wrote the [ack_ds.h](override/ack_ds.h) with inspiration from the Interface type in OOP (this whole implementation is taken from [DIP](https://www.baeldung.com/cs/dip)).
The overriding code will reference only the functions written in the `ack_ds.h` file and only use the `ack_ds` type. The `ack_ds` typedef will point to us which implementation to use.

The linked list does a good job supporting our use-case, since we haven't reached the scale where the amount of acks to hide at a single point of time is above 2.

