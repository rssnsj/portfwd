NAT mechanism of IP packet to SOCKS protocol transforming.

Description:
  A small but useful project. I name it "SOCKS NAT".
  It's like 'redsocks'. The goal is to convert a SOCKS proxy service to an IP gateway which is more compatible, e.g., some mobile devices like iPhone do not support SOCKS proxy, so an IP gateway is better and convenient for them.

  The first available version has been finished. It can work well now for TCP traffic. Yet DNS resolving over tunnel is not implemented. This is important since in some countries (like China) DNS is either hijack or polluted, and I already have a couple of solutions and will continue later.

  Since SSH SOCKS tunnel only supports TCP proxy, so we only let TCP packets pass through the proxy tunnel, while UDP and other L4 protocols go through the gateway's local network.

  Welcome everybody to download or review the code, and looking forward to more discussions on this. Maybe some better ideas and more powerful solutions can be carried out.

Project home: https://socksnat.googlecode.com/

Designing principles:
  Forward all TCP requests with 'iptables' rules to a single TCP port on the gateway host, and a user-space program listens on this port. Each time a connection is in, it gets the original target IP/port by "getsockopt(..., SOL_IP, SO_ORIGINAL_DST, ...);".

1. Redirect TCP packets to local socket:
   For example, your gateway's IP is 192.168.1.1, and it's to provide proxy service for 192.168.1.0/24 subnet, and uses port 7070 for accepting TCP, the rules can be issued like this:
     iptables -t nat -A PREROUTING -s 192.168.1.0/24 -p tcp -j DNAT --to 192.168.1.1:7070

2. User-space program 'socksnatd':
   Listens a TCP port and a UDP port (unimplemented yet), e.g., 7070 in the above. When it receives a new TCP connection, first it gets the requested target IP/port by "getsockopt(..., SOL_IP, SO_ORIGINAL_DST, ...)", and then connects to the real server through specified SOCKS tunnel.

---------------------------------------------------
How to use:

1. Compile kernel module and the application, and install:
    cd src
    make
    make install
   Note: 'socksnatd' is saved at /usr/local/bin/.

3. Add filewall rules for forwarding TCP connections to 'socksnatd':
   e.g., the gateway IP is 10.255.0.1, and you with it to provide proxy service for subnet 10.255.0.0/24, the rules can be issued by: 
    iptables -t nat -A PREROUTING -s 10.255.0.0/24 -p tcp -j DNAT --to 10.255.0.1:7070
   Note: 7070 is the TCP proxy port that 'socksnatd' listens.

4. Start the service:
    /usr/local/bin/socksnatd -s <socks_server_ip:socks_server_port> -d

5. Set networking for other devices:
   e.g., the gateway IP is 10.255.0.1/24, you may set your mobile phone like this:
    IP address: 10.255.0.x
    Netmask: 255.255.255.0
    Gateway: 10.255.0.1
    DNS: <Unhijacked_DNS>
   Note: since DNS resolving over tunnel has not been implemented, please use an unhijacked DNS address, or you still cannot visit Facebook, YouTube, Twitter in China.
