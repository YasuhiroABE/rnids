#!/usr/bin/ruby
#
# Copyright (c) 2000 Yasuhiro ABE <yasu@dengaku.org>
#

require "rnids"

class Logger
  def initialize(manager=nil)
    raise if manager == nil
    @manager = manager
    @alert_files = Hash.new
    @dir_entries = Array.new
    @log_files = Hash.new
  end

  def logit?(packet)
    if @dir_entries != Dir::entries("log_files")
      @dir_entries = Dir::entries("log_files")
      @alert_files = Hash.new
      @dir_entries.each { |file|
	next if file =~ /^\./
	if @alert_files[file] == nil
	  @alert_files[file] = open("log_files/"+file).read
	end
      }
    end

    @alert_files.each_value {|alerts|
      result = eval(alerts)
      return true if result == true
      return false
    }
  end

  # NOTE: The high frequency of 'open' function call will cause 
  # a performance problem, so it should be kept low.
  def log_connection(packet)
    return if ! packet.kind_of?(NIDS_TCP)
    if packet.tcp_state == NIDS::NIDS_CLOSE or
	packet.tcp_state == NIDS::NIDS_RESET or
	packet.tcp_state == NIDS::NIDS_TIMED_OUT
      key = format "%s:%d-%s:%d", packet.tcp_saddr,packet.tcp_sport,
	packet.tcp_daddr,packet.tcp_dport
      @log_files[key].close if @log_files[key]
      @log_files.delete(key)
    elsif packet.tcp_state == NIDS::NIDS_DATA
      # unless the filestream has been opened already
      key = format "%s:%d-%s:%d", packet.tcp_saddr,packet.tcp_sport,
	packet.tcp_daddr,packet.tcp_dport
      if @log_files[key] == nil
	@log_files[key] = open("logs/#{packet.tcp_saddr}-#{packet.tcp_daddr}."+Time.now.to_i.to_s,"w")
	@log_files[key].sync = true
      end
      begin
	return if packet.tcp_new_data_len <= 0
	@log_files[key].print packet.tcp_new_data.dump + "\n"
      end
    end
  end
end

class Disconnector
  def initialize(manager=nil)
    raise if manager == nil
    @manager = manager
    @alertIDs = Array.new
    @alert_files = Hash.new
  end

  def kill_connection(tcph)
    @tcph = tcph

    Dir::foreach("kill_files") { |file|
      next if file =~ /^\./
      if @alert_files[file] == nil
	@alert_files[file] = open("kill_files/"+file).read
      end
    }

    @alert_files.each_value { |file|
      result = eval(file)
      next if result == false
      return true if result == true
    }
    return false
  end
end

class IDMEFManager < NIDS
  @@disconnector = Disconnector.new(self)
  @@logger = Logger.new(self)

  def initialize
    super()
    use_tcp(true)
    use_ip (false)
    use_udp(false)
  end

  def kill(tcph)
    @@disconnector.kill_connection(tcph)
  end
  
  def callback(packet)
    if @@logger.logit?(packet)
      @@logger.log_connection(packet)
    end
  end
end

def main
  consumer = IDMEFManager.new
  consumer.run
end
main
