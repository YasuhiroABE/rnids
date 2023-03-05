#!/usr/bin/ruby

require "rnids"

class MAIN < NIDS
  def initialize
    use_tcp(true)
    use_ip(true)
    use_udp(false)
    
    @daddr = "192.168.100.20"
  end

  def set_daddr(daddr)
    p daddr.dump
    printf "set daddr as %s\n",daddr
    @addr = daddr
  end

  def kill(tcph)
    if tcph.tcp_daddr == "192.168.100.20"
      print "killing connection to 192.168.100.20\n"
      return true
    end

    if tcph.tcp_daddr == @daddr
      return true
    end

    return false
  end

  def callback(tcph)
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

  def start
    Thread.start do
      run
    end
  end
end

require "socket"
# start process

@m = MAIN.new
$CURRENT = @m
@m.start

gs = TCPServer.open(8888)
addr = gs.addr
addr.shift
printf("server is on %d\n", addr.join(":"))

while TRUE
  ns = gs.accept
  print(ns, " is accepted\n")
  line = ""
  Thread.start do
    s = ns                      # save to dynamic variable
    line = s.gets
    s.close
    line.chomp!("\r\n")
    p line
  end
  @m.set_daddr(line)
end
