portfwd
=======

User-space TCP/UDP port forwarding services

## Summary ##
 This project contains two applications: tcpfwd, udpfwd, which are for TCP and UDP port forwarding literally.
 Written in pure C, with libevent2 library.
 
## Usage ##

    rssnsj@precise-aaa:~$ tcpfwd
    Userspace TCP proxy.
    Usage:
      tcpfwd <local_ip:local_port> <dest_ip:dest_port> [-d] [-o] [-f6.4]
    Options:
      -d              run in background
      -o              accept IPv6 connections only for IPv6 listener
      -f X.Y          allow address families for source|destination
      -p <pidfile>    write PID to file
      
    rssnsj@precise-aaa:~$ udpfwd
    User space UDP proxy.
    Usage:
      udpfwd <local_ip:local_port> <dest_ip:dest_port> [-d] [-o] [-f6.4]
    Options:
      -d              run in background
      -o              accept IPv6 connections only for IPv6 listener
      -f X.Y          allow address families for source|destination
      -p <pidfile>    write PID to file
    rssnsj@precise-aaa:~$
