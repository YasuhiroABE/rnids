#!/usr/bin/ruby

#
# Copyright (c) 2000 Yasuhiro ABE
#

require "rnids"

n = NIDS.new

print "public_methods..\n"
for i in n.public_methods.reverse
  printf "  %s\n", i
end

def n.callback(tcph)
  printf "to_s -> %s\n", tcph.to_s
  printf "tcp_data -> %s\n", tcph.tcp_data
  printf "tcp_data_len -> %d\n", tcph.tcp_data_len
  printf "tcp_dport -> %d\n", tcph.tcp_dport
  printf "tcp_sport -> %d\n", tcph.tcp_sport
  printf "tcp_ack -> %d\n", tcph.tcp_ack
  printf "tcp_win -> %d\n", tcph.tcp_win
end

n.run
