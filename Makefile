SHELL = /bin/sh

#### Start of system configuration section. ####

srcdir = /home/akira/rpm.vineseed/BUILD/ruby-1.6.1/ruby-1.6.1
topdir = /usr/lib/ruby/1.6/i386-linux-gnu
hdrdir = /usr/lib/ruby/1.6/i386-linux-gnu

CC = gcc

CFLAGS   = -fPIC -g -O2 -fPIC -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H -DLIBNET_LIL_ENDIAN


CPPFLAGS = -I$(hdrdir) -I/usr/include  
CXXFLAGS = $(CFLAGS)
DLDFLAGS =  -L/usr/lib -lnet

LDSHARED = gcc -shared 

RUBY_INSTALL_NAME = ruby
RUBY_SO_NAME = 

prefix = $(DESTDIR)/usr
exec_prefix = $(DESTDIR)/usr
libdir = $(DESTDIR)/usr/lib/ruby/1.6
archdir = $(DESTDIR)/usr/lib/ruby/1.6/i386-linux-gnu
sitelibdir = $(DESTDIR)/usr/lib/ruby/site_ruby/1.6
sitearchdir = $(DESTDIR)/usr/lib/ruby/site_ruby/1.6/i386-linux-gnu

#### End of system configuration section. ####

LOCAL_LIBS =  
LIBS = -L. -l$(RUBY_INSTALL_NAME) -lnids -lnet -lpcap -lc
OBJS = nids.o ipaddr.o ippkt.o tcppkt.o udppkt.o packet.o

TARGET = rnids
DLLIB = $(TARGET).so

RUBY = ruby
RM = $(RUBY) -r ftools -e 'File::rm_f(*Dir[ARGV.join(" ")])'

EXEEXT = 

all:		$(DLLIB)

clean:;		@$(RM) *.o *.so *.sl *.a $(DLLIB)
		@$(RM) $(TARGET).lib $(TARGET).exp $(TARGET).ilk *.pdb

distclean:	clean
		@$(RM) Makefile extconf.h conftest.*
		@$(RM) core ruby$(EXEEXT) *~

realclean:	distclean

install:	$(archdir)/$(DLLIB)

site-install:	$(sitearchdir)/$(DLLIB)

$(archdir)/$(DLLIB): $(DLLIB)
	@$(RUBY) -r ftools -e 'File::makedirs(*ARGV)' $(libdir) $(archdir)
	@$(RUBY) -r ftools -e 'File::install(ARGV[0], ARGV[1], 0555, true)' $(DLLIB) $(archdir)/$(DLLIB)

$(sitearchdir)/$(DLLIB): $(DLLIB)
	@$(RUBY) -r ftools -e 'File::makedirs(*ARGV)' $(libdir) $(sitearchdir)
	@$(RUBY) -r ftools -e 'File::install(ARGV[0], ARGV[1], 0555, true)' $(DLLIB) $(sitearchdir)/$(DLLIB)


.c.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<
$(DLLIB): $(OBJS)
	$(LDSHARED) $(DLDFLAGS) -o $(DLLIB) $(OBJS) $(LIBS) $(LOCAL_LIBS)
###
