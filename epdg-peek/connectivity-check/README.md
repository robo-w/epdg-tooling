# epdg-peek connectivity check

The utilities can be used to test the connectivity between two servers, covering following scenarios:

* `f01-dns-canary.sh`: Using DNS canary domain to check whether DNS requests are sent to the internet.
* `f01-ping-external.sh`: Check whether ICMP ping to an external server is possible. 
    The DNS resolution of the Google server happens in the default network namespace, to be independent of DNS functionality in the network.
* `f02-client.sh` and `f02-server.sh`: The server part opens ports to check from the client part the direct IP connection.
* `icmpv6_mdns_ra.py`: Sends router-advertisement messages to the network, in order to check whether multicast packets are received on another device.
* `ping-all-pcscf-servers.sh`: Checks whether all P-CSCF servers are reachable via ICMP ping, which were announced before in the IPsec configuration.
