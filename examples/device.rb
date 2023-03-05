#!/usr/bin/ruby

require "rnids"

n = NIDS.new

p n.device
n.device("all")
p n.device

n.use_tcp(true)
n.each { |struct|
  if struct.state == NIDS::NIDS_DATA
    printf "%s:%d -> %s:%d %s\n", struct.saddr,struct.sport,struct.daddr,struct.sport,struct.data[0,25]
  end
}
