#!/usr/bin/ruby

#
# Copyright (c) 2000 Yasuhiro ABE
#

require "rnids"

n = NIDS.new

n.use_tcp(false)
n.use_udp(true)
n.use_ip(false)

def n.callback(udph)
  printf "receive udp packet\n"
  printf "%s:%d -> %s:%d\n", udph.udp_saddr, udph.udp_sport, udph.udp_daddr, udph.udp_dport
  printf "udp_data -> %s\n", udph.udp_data.dump

  iph = udph.get_ippkt
  printf "iph (%s) belongs to NIDS_Packet class\n",iph if iph.kind_of?(NIDS_Packet)
  printf "iph (%s) belongs to NIDS_IP class\n",iph if iph.kind_of?(NIDS_IP)
end

n.run
