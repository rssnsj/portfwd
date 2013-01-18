Design NAT mechanism of IP packet to SOCKS protocol transforming.

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

---------------------------------------------------
How to use:

1. Compile kernel module and the application, and install:
    cd src
    make
    make install
   Note:
    (1) Before compiling the kernel module, you should install packages of your Linux distribution that contain kernel header files.
    (2) 'socksnat.ko' is saved at /lib/modules/<kernel_version>/kernel/misc/, 'socksnatd' is saved at /usr/local/bin/.

2. Load the kernel module:
    modprobe socksnat
   You may confirm the kernel module is correctly loaded by this:
    root@lenny-r50:~# lsmod | grep socksnat
    socksnat                2112  0
    nf_conntrack           55540  5 socksnat,iptable_nat,nf_nat,nf_conntrack_ipv4
    root@lenny-r50:~#

   For being automatically loaded at system startup, you may add 'socksnat' to /etc/modules.

3. Add filewall rules for forwarding TCP connections to 'socksnatd':
   e.g., the gateway IP is 10.255.0.1, and you with it to provide proxy service for subnet 10.255.0.0/24, the rules can be issued by: 
    iptables -t nat -A PREROUTING -s 10.255.0.0/24 -p tcp -j DNAT --to 10.255.0.1:7070
   Note: 7070 is the TCP proxy port that 'socksnatd' listens.

4. Install and setup 'tsocks':
   'tsocks' helps 'socksnatd' to proxy connections to SOCKS tunnel.
   In Ubuntu, Debian, install by:
    apt-get install tsocks
   In RedHat, Fedora or CentOS, install by:
    yum install tsocks
   Then edit /etc/tsocks.conf, set your SOCKS service address there, and fix the 'local' fields.

5. Start the service:
    /usr/local/bin/socksnatd -d

6. Set networking for other devices:
   e.g., the gateway IP is 10.255.0.1/24, you may set your mobile phone like this:
    IP address: 10.255.0.x
    Netmask: 255.255.255.0
    Gateway: 10.255.0.1
    DNS: <unhijacked_DNS>
   Note: since DNS resolving over tunnel has not been implemented, please use an unhijacked DNS address, or you still cannot visit Facebook, YouTube, Twitter in China.

