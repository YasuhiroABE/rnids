#!/usr/bin/ruby

require "rnids"

n = NIDS.new

n.promisc(false)

n.use_tcp(true)

def n.callback(struct)
  if struct.kind_of?(NIDS_TCP)
    if struct.tcp_state == NIDS::NIDS_DATA
      printf "%s:%d -> %s:%d %s\n", struct.tcp_saddr, struct.tcp_sport, struct.tcp_daddr, struct.tcp_sport, struct.tcp_data[0,20].dump
    end
  end
end

n.run
