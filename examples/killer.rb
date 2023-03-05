#!/usr/bin/ruby

require "rnids"

n = NIDS.new

def n.kill(tcph)
  if tcph.tcp_daddr == "192.168.100.20"
    print "killed\n"
    return true;
  else
    return false;
  end
end

n.use_tcp(true)
n.use_ip(false)
n.use_udp(false)

n.run
