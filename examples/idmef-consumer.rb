#!/usr/bin/ruby
#
# Copyright (c) 2000 Yasuhiro ABE <yasu@dengaku.org>
#

require "socket"
require "xmlparser"
require "xmltree"
require "postgres"

require "net/smtp"

require "examples/idmef"

class Messenger
  def initialize(consumer=nil)
    raise if consumer == nil
    @consumer = consumer
    @mailaddresses = Array.new
  end

  def send_alert(idmef_data=nil)
    return if @mailaddresses.size == 0

    message_body = ""
    message_body += "NIDS reports intrusion on the network.\n"
    message_body += "from #{idmef_data.saddr} port #{idmef_data.sport}\n"
    message_body += "to #{idmef_data.daddr} port #{idmef_data.dport}\n"
    message_body += "\n"
    message_body += "the level of impact is #{idmef_data.impact}\n"

    Net::SMTP.start("localhost",25){|smtp|
      smtp.send_mail(message_body,"yasu@dengaku.org",@mailaddresses.join(" "))
    }
  end

  def add_mailaddress(mail_address=nil)
    return if mail_address == nil or mail_address == ""
    @mailaddresses << mail_address
  end
end

class Scripter
  def initialize(consumer=nil)
    raise if consumer == nil
    @consumer = consumer
  end

  def write_killsession_script(idmef_struct)
    begin
      file = open("kill_files/consumer.#{idmef_struct.saddr}:#{idmef_struct.sport}-#{idmef_struct.daddr}:#{idmef_struct.dport}"+Time.now.to_i.to_s,"w")
      file.sync = true
      file.print "true if @tcph.tcp_daddr == '#{idmef_struct.daddr}'" +
      " and @tcph.tcp_saddr ==' #{idmef_struct.saddr}'" +
      " and @tcph.tcp_sport == #{idmef_struct.sport}" +
      " and @tcph.tcp_dport == #{idmef_struct.dport}\n"
    ensure
      file.close
    end
  end

  def write_killconnection_script(idmef_struct)
    begin
      file = open("kill_files/consumer.#{idmef_struct.saddr}-#{idmef_struct.daddr}"+Time.now.to_i.to_s,"w")
      file.sync = true
      file.print "true if @tcph.tcp_daddr == '#{idmef_struct.daddr}'" +
      " and @tcph.tcp_saddr == '#{idmef_struct.saddr}'\n"
    ensure
      file.close
    end
  end

  def write_killincoming_script(idmef_struct)
    begin
      file = open("kill_files/consumer.#{idmef_struct.saddr}-"+Time.now.to_i.to_s,"w")
      file.print "true if @tcph.tcp_saddr == '#{idmef_struct.saddr}'\n"
    ensure
      file.close
    end
  end
    
  def write_killoutgoing_script(idmef_struct)
    begin
      file = open("kill_files/consumer.-#{idmef_struct.daddr}"+Time.now.to_i.to_s,"w")
      file.sync = true
      file.print "true if @tcph.tcp_daddr == '#{idmef_struct.daddr}'\n"
    ensure
      file.close
    end
  end
  
  def write_logsession_script(idmef_struct)
    begin
      file = open("log_files/consumer.#{idmef_struct.saddr}:#{idmef_struct.sport}-#{idmef_struct.daddr}:#{idmef_struct.dport}"+Time.now.to_i.to_s,"w")
      file.print "true if packet.tcp_saddr == '#{idmef_struct.saddr}'" +
      " and packet.tcp_daddr == '#{idmef_struct.daddr}'" +
      " and packet.tcp_sport == #{idmef_struct.sport}" +
      " and packet.tcp_dport == #{idmef_struct.dport}\n"
    ensure
      file.close
    end
  end

  def write_logconnection_script(idmef_struct)
    begin
      file = open("log_files/consumer.#{idmef_struct.saddr}-#{idmef_struct.daddr}"+Time.now.to_i.to_s,"w")
      file.print "true if packet.tcp_saddr == '#{idmef_struct.saddr}'" +
      " and packet.tcp_daddr == '#{idmef_struct.daddr}'\n"
    ensure
      file.close
    end
  end

  def write_logincoming_script(idmef_struct)
    begin
      file = open("log_files/consumer.#{idmef_struct.saddr}-"+Time.now.to_i.to_s,"w")
      file.print "true if packet.tcp_saddr == '#{idmef_struct.saddr}'\n"
    ensure
      file.close
    end
  end

  def write_logoutgoing_script(idmef_struct)
    begin
      file = open("log_files/consumer.-#{idmef_struct.daddr}"+Time.now.to_i.to_s,"w")
      file.print "true if packet.tcp_daddr == '#{idmef_struct.daddr}'\n"
    ensure
      file.close
    end
  end
end

class IDMEFConsumer
  def initialize
    @messenger = Messenger.new(self)
    begin
      addressfile = open("admin_address","r")
      addressfile.each { |addr|
	@messenger.add_mailaddress(addr)
      }
    ensure
      addressfile.close
    end
    
    @scripter = Scripter.new(self)
    @data = Struct.new("IDMEFData",:impact,:saddr,:sport,:daddr,:dport)

    open_port
  end

  def create_data
    return @data.new("","",0,"",0)
  end

  def open_port
    gs = TCPServer.open(8989)
    while true
      ns = gs.accept
      Thread.start do
	s = ns	# save to dynamic variable
	idmef= ""
	while line = s.gets
	  break if line == 0
	  idmef += line
	end

	# parse IDMEF message
	data = parse_idmef(idmef)
	# decide action
	decide_action(data)
      end
    end
  end

  def parse_idmef(idmef)
    #output = $stdout
    idmef_data = create_data

    tag_list = Array.new
    tag_name = ""
    parser = XMLParser.new
    parser.parse(idmef) { |type,name,data|
      case type
      when XMLParser::START_ELEM
	tag_name = name
	tag_list << tag_name

	#output.print "<#{tag_name}"
	data.each { |key,val|
	  if tag_name =~ /alert/i && key =~ /impact/i
	    idmef_data.impact = val.to_s
	  end
	}
      when XMLParser::END_ELEM
	tag_name = ""
	tag_list.delete_at(tag_list.size-1)
      when XMLParser::CDATA
	if tag_name =~ /sport/i  && tag_list[tag_list.size-2] =~ /service/i
	  idmef_data.sport = data.to_i
	elsif tag_name =~ /dport/i  && tag_list[tag_list.size-2] =~ /service/i
	  idmef_data.dport = data.to_i
	elsif tag_name =~ /address/i  && tag_list[tag_list.size-4] =~ /source/i
	  idmef_data.saddr = data.to_s
	elsif tag_name =~ /address/i  && tag_list[tag_list.size-4] =~ /target/i
	  idmef_data.daddr = data.to_s
	end
      end
    }

    print "parse finished\n"
    return idmef_data
  end

  def decide_action(idmef_data)
    impact = idmef_data.impact
    printf "DEBUG: impact == %s\n", impact
    printf IDMEF::LEVEL[4] + "\n"

    begin
      conn = PGconn.connect("localhost", 5432, "", "", "idmefproxy")
      res = conn.exec("select killsession,killconnection,killincoming,killoutgoing,logsession,logconnection,logincoming,logoutgoing,sendmail from decide_action,rule_impact where decide_action.idmef_impact = rule_impact.impactid and rule_impact.newimpact = '#{impact}'")
      
      action = res.result[0]
      @scripter.write_killsession_script(idmef_data)    if action[0] == "t"
      @scripter.write_killconnection_script(idmef_data) if action[1] == "t"
      @scripter.write_killincoming_script(idmef_data)   if action[2] == "t"
      @scripter.write_killoutgoing_script(idmef_data)   if action[3] == "t"
      @scripter.write_logsession_script(idmef_data)     if action[4] == "t"
      @scripter.write_logconnection_script(idmef_data)  if action[5] == "t"
      @scripter.write_logincoming_script(idmef_data)    if action[6] == "t"
      @scripter.write_logoutgoing_script(idmef_data)    if action[7] == "t"
      @messenger.send_alert(idmef_data)                 if action[8] == "t"
    ensure
      res.clear
      conn.close
    end
  end
end

#
# MAIN Statements: Trigger of this function
#
def main
  consumer = IDMEFConsumer.new
end
main
