#!/usr/bin/ruby

#
# Copyright (c) 2000 Yasuhiro ABE
#

require "rnids"

n = NIDS.new

n.use_tcp(false)
n.use_ip(true)
n.each { |iph|
   p iph
}
