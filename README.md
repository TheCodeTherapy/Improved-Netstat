# Improved Netstat

This is a netstat + whois that I wrote to replace the Linux's netstat as it better fits my needs. Besides showing all the current IPv4 connections, it shows some extra information that can't be obtained using Linux's netstat.

![](http://mgz.me//blog/wp-content/uploads/2017/11/inetstat_working_2.gif)

* Both netstat and whois features are self implemented through reading the proc filesystem and sockets (respectively), so the code does not need to execute none of those Linux command line tools;
* Local IP address is also obtained by establishing a socket connection with a fast response DNS server and getting it's own connection name, to prevent undesired local IP address as 127.0.0.1;
* My whois implementation checks "whois.cymru.com" through sockets, passing the requested remote hosts's IPs as a query parameter and requesting a verbose information, thus, the queries return [Autonomous System][1] information as BGP prefixes and AS names, so I can identify to which company that remote host belongs;
* All the AS information is written / cached to disk through \_pickle (Python 3.5 implementation of cPickle), so new queries looking for information previously obtained does not spend time unnecessarily;
* The queries to check for AS information are executed through multiprocessing to save time once they're required, and all the necessary IPs to be checked are evenly divided through separate lists taking in consideration an optimize number of simultaneous threads to be used;
* UPDATED: now inetstat also retrieves detailed information about each PID with a connection established, as the processes's umask, state (running, sleeping), number of threads spawned by them and ammount of memory occupied by each process.

**#TODO**:
1. Implement the methods required to merge information concerning IPv6 and open UDP connections as well
2. Document it properly and implement tests to make sure unexpected behavior break some stuff, considering I plan to use this code to further applications (as important as some fancy Desktop conky showoff :P
3. Detect 256 colors terminal emulation capabilities (using another project I'm working on - available on GitHub: [color_ansi_rgb][2]) to make colorized output available (as per future Python argparse implementation) to improve readability
4. Improve some methods that by now feel _a little bit hackish_ to me  

[1]: https://en.wikipedia.org/wiki/Autonomous_system_(Internet)
[2]: https://github.com/mgzme/color_ansi_rgb
