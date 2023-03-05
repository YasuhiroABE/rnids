#!/usr/bin/ruby

#
# Copyright (c) 2000 Yasuhiro ABE
#

require "rnids"

n = NIDS.new

n.each { |tcph|
   p tcph
}
