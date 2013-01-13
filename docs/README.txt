Design NAT machanism of TCP layer to SOCKS protocol transforming.
Project home: https://socksnat.googlecode.com/
Description:
  This project is to convert a SOCKS proxy service to an IP gateway which is more compatible, e.g., some mobile devices like iPhone do not support SOCKS proxy, so an IP gateway is better and convenient for them.
  Since SSH SOCKS tunnel only supports TCP proxy, so we only let TCP packets pass through the proxy tunnel, while UDP and other L4 protocols go through the gateway's local network.

Designing principles:

This project includes tiny kernel modification and a user-space daemon.

1. Solution of retrieving target address:
   Provide a kernel module, which allows querying the original target address with 'ioctl' by the translated address (got by 'getsockname', 'getpeername'), so that the TCP proxy program knows where it should connect to via SOCKS tunnel.
   For example, the gateway's IP is 192.168.1.1, it's to provide proxying service for 192.168.1.0/24 subnet, and use port 7070 for accepting all TCP connections, the port forwarding rules can be simply issued like this:
     iptables -t nat -A PREROUTING -s 192.168.1.0/24 -p tcp -j DNAT --to 192.168.1.1:7070

2. User-space program 'socksnatd':
   Listens a TCP port and a UDP port (unimplemented yet), e.g., 7070 in the above. When it receives a new TCP connection, first it gets the requsted target IP/port by 'ioctl(/proc/socksnat_query,<translated_addresses>)', and then connects to the real server through SOCKS protocol.

3. Solution of SOCKS5 implementation:
    Simply wrapp the program with 'tsock', so do not have to write a new one.

