#!/usr/bin/ruby

require "rnids"

class MAIN
  def initialize
    n = NIDS.new
    @n = n

    def n.kill(tcph)
      if tcph.tcp_daddr == "192.168.100.20"
	print "killing connection to 192.168.100.20\n"
	return true;
      end

      if tcph.tcp_sport == 8888
	print "killing connection to 8888\n"
	return true;
      end

      return false;
    end

    n.use_tcp(true)
    n.use_ip(true)
    n.use_udp(false)

    def n.callback(tcph)
      if tcph.kind_of?(NIDS_TCP)
	if tcph.tcp_state == NIDS::NIDS_CLOSE
	  print "connection closed\n"
	elsif tcph.tcp_state == NIDS::NIDS_RESET
	  print "connection reset\n"
	elsif tcph.tcp_state == NIDS::NIDS_TIMED_OUT
	  print "connection timed out\n"
	else
	  printf "tcp: %s:%d -> %s:%d\n", tcph.tcp_saddr, tcph.tcp_sport, 
	    tcph.tcp_daddr, tcph.tcp_dport
	end
      end

      if tcph.kind_of?(NIDS_IP)
	printf "ip: ...\n"
      end
    end
  end

  def start
    @n.run
  end
end

require "socket"
# start process

fork do
  m = MAIN.new
  m.start
end

gs = TCPServer.open(8888)
addr = gs.addr
addr.shift
printf("server is on %d\n", addr.join(":"))

while TRUE
  ns = gs.accept
  print(ns, " is accepted\n")
  Thread.start do
    s = ns                      # save to dynamic variable
    while s.gets
      s.write($_)
    end
    print(s, " is gone\n")
    s.close
  end
end
