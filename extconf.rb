require 'mkmf'

=begin
Options: --with-libpcap-{dir,include,lib}
         --with-libnet-{dir,include,lib}
         --with-libnids-{dir,include,lib}
=end

dir_config("libpcap")
dir_config("libnet")
dir_config("libnids")

if have_library("pcap","pcap_lookupnet") and
   have_library("net","libnet_init_packet") and
   have_library("nids","raw_init")
     $CFLAGS  += %x{libnet-config --defines}
     $CFLAGS  += %x{libnet-config --cflags}
     $LDFLAGS += %x{libnet-config --libs}

     create_makefile("rnids")
else
     print "error: libnet must be necessary\n"
end


