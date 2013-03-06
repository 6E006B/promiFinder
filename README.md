promiFinder
===========

Discover network interfaces that are in promiscuous mode. For further information see https://hack0r.net/?p=24.

It currently checks for all your network interfaces and scans all subnets for promiscuous devices.

Requirements
------------

In order to use this you need the python packages *netifaces* and *scapy*.

Run
---

To run the tool simply execute the following command as root or sudo it.

    scapy -c promiFinder.py
