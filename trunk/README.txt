Design NAT mechanism of TCP layer to SOCKS protocol transforming.

Description:
  I've launched a very small but very useful project. I name it "SOCKS NAT".
  The goal is to convert a SOCKS proxy service to an IP gateway which is more compatible, e.g., some mobile devices like iPhone do not support SOCKS proxy, so an IP gateway is better and convenient for them.

  Currently only myself is in. The first available version has been finished. It can work well now for TCP traffic. The DNS resolving over tunnel is not implemented yet. This is important since in some countries DNS is either hijack or polluted, and I already have a couple of solutions and will continue later.

  Since SSH SOCKS tunnel only supports TCP proxy, so we only let TCP packets pass through the proxy tunnel, while UDP and other L4 protocols go through the gateway's local network.

  Welcome everybody to download or review the code, and looking forward to more discussions on this. Maybe some better ideas and more powerful solutions can be carried out.

Project home: https://socksnat.googlecode.com/

Designing principles:
  Forward all TCP requests with 'iptables' rules to a single TCP port on the gateway host, and a user-space program listens on this port. Each time it accepts a new connection, it tries to get the original target IP/port by a 'conntrack' query mechanism provided by a kernel module.

This project includes a kernel module and a user-space daemon.

1. Solution of retrieving target address:
   Provide a kernel module, which allows querying the original target address with 'ioctl' by the translated address (got by 'getsockname', 'getpeername'), so that the TCP proxy program knows where it should connect to via SOCKS tunnel.
   For example, the gateway's IP is 192.168.1.1, it's to provide proxy service for 192.168.1.0/24 subnet, and use port 7070 for accepting all TCP connections, the port forwarding rules can be simply issued like this:
     iptables -t nat -A PREROUTING -s 192.168.1.0/24 -p tcp -j DNAT --to 192.168.1.1:7070

2. User-space program 'socksnatd':
   Listens a TCP port and a UDP port (unimplemented yet), e.g., 7070 in the above. When it receives a new TCP connection, first it gets the requested target IP/port by 'ioctl(/proc/socksnat_query,<translated_addresses>)', and then connects to the real server through SOCKS protocol.

3. Solution of SOCKS5 implementation:
    Simply wrap the program with 'tsock', so do not have to write a new one.
