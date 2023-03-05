#!/usr/bin/ruby

require "rnids"

n = NIDS.new

def n.kill(tcph)
  if tcph.tcp_daddr == "192.168.100.20"
    print "killing connection to 192.168.100.20\n"
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
      printf "%s", tcph.tcp_new_data
    end
  end

  #if tcph.kind_of?(NIDS_IP)
  #  printf "ip: ...\n"
  #end
end

n.run
