#!/usr/bin/ruby

require "rnids"

n = NIDS.new

n.pcap_filter("ip host 192.168.100.1")

n.use_ip(true)
n.use_tcp(false)
print "use_ip is " + n.use_ip.to_s + "\n"
print "use_tcp is " + n.use_tcp.to_s + "\n"
print "use_udp is " + n.use_udp.to_s + "\n"

def n.callback(iph)
  printf "%s -> %s (ttl==%d)\n", iph.ip_saddr, iph.ip_daddr,  iph.ip_ttl
end

n.run
