#!/usr/bin/ruby
#
# Copyright (c) 2000 Yasuhiro ABE <yasu@dengaku.org>
#

require "rnids"

class Logger
  def initialize(manager=nil)
    raise if manager == nil
    @manager = manager
    @alertIDs = Array.new
    @alert_files = Hash.new
    @dir_entries = Array.new
    @alerts = ""
  end

  def logit(packet)
    if @dir_entries != Dir::entries("log_files")
      @dir_entries = Dir::entries("log_files")
      @dir_entries.each { |file|
	next if file =~ /^\./
	if @alert_files[file] == nil
	  @alert_files[file] = open("log_files/"+file).read
	  @alerts += @alert_files[file]
	end
      }
    end

    @alert_files.each_value{|val|
      #result = eval(val)
      result = eval(@alerts)
      next if result == false
      return true if result == true
    }
    return false
  end

  def log_connection(packet)
    return if ! packet.kind_of?(NIDS_TCP)
    return if packet.tcp_data_len <= 0
    begin
      file = open("logs/#{packet.tcp_saddr}-#{packet.tcp_daddr}."+Time.now.to_i.to_s,"w")
      file.print packet.tcp_new_data
    ensure
      file.close
    end
  end

  def add_alertID(alertID=nil)
    raise if alertID == nil
    @alertIDs << alertID
  end
end

class Disconnector
  def initialize(manager=nil)
    raise if manager == nil
    @manager = manager
    @alertIDs = Array.new
    @alert_files = Hash.new
  end

  def add_alertID(alertID=nil)
    raise if alertID == nil
    @alertIDs << alertID
  end

  def kill_connection(tcph)
    @tcph = tcph

    Dir::foreach("kill_files") {|file|
      next if file =~ /^\./
      if @alert_files[file] == nil
	@alert_files[file] = open("kill_files/"+file).read
      end
      contents = @alert_files[file]
      result = eval(contents)
      next if result == false
      return true if result == true
    }
    return false
  end
end

class IDMEFManager
  def initialize
    @nids = NIDS.new
    @nids.use_tcp(true)
    @nids.use_ip (false)
    @nids.use_udp(false)
    

    def @nids.kill(tcph)
      @disconnector = Disconnector.new(self)
      return if @disconnector == nil
      @disconnector.kill_connection(tcph)
    end

    def @nids.callback(packet)
      if packet.tcp_state == NIDS::NIDS_DATA
	# @logger.log_connection(packet)
	return if ! packet.kind_of?(NIDS_TCP) or packet.tcp_data_len <= 0
	Thread.start {
	  file = open("logs/#{packet.tcp_saddr}-#{packet.tcp_daddr}."+Time.now.to_i.to_s,"w")
	  file.print packet.tcp_new_data
	  file.close
	}
      end
    end
  end

  def start
    @nids.run
  end

  def get_nids
    return @nids
  end
end


def main
  consumer = IDMEFManager.new
  consumer.start
end
main
