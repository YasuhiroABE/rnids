/**
 * Copyright (c) 2000 Yasuhiro ABE <yasu@yasundial.org>. All rights reserved.
 * See the file COPYING for license details.
 *
 * If you have any comments, please send e-mail to yasu@yasundial.org.
 **/

#include"rnids.h"

VALUE cUDPPacket;

struct udp_object {
  struct tuple4 *addr;
  char *buf;
  int len;
  struct ip *iph;
};

#define GetUDP(obj, udph) \
    Data_Get_Struct(obj, struct udp_object, udph)

VALUE
rnids_udppkt_new(addr, buf, len, iph)
     struct tuple4 *addr;
     char *buf;
     int len;
     struct ip *iph;
{
  VALUE object;
  struct udp_object *udph;
  
  object = Data_Make_Struct(cUDPPacket, struct udp_object, 0, free, (void *)udph);
  udph->addr = addr;
  udph->buf = buf;
  udph->len = len;
  udph->iph = iph;

  return object;
}

static VALUE
udppkt_s_new(self,val)
     VALUE self, val;
{
  VALUE object;
  struct udp_object* udph;

  switch(TYPE(val)) {
  case T_DATA:
    GetUDP(val, udph);
    break;
  default:
    rb_raise(rb_eTypeError, "UDP object is required");
  }

  object = Data_Wrap_Struct(cUDPPacket, 0, free, (void *)udph);
  return object;
}

static VALUE
udppkt_to_s(self)
     VALUE self;
{
  struct udp_object *udph;
  
  GetUDP(self,udph);
  
  return rb_str_new2(int_ntoa(udph->iph->ip_src.s_addr));
}

#define UDP_METHOD(func, val) \
static VALUE\
(func)(self)\
     VALUE self;\
{\
    struct udp_object *udph;\
\
    GetUDP(self, udph);\
    return (val);\
}

UDP_METHOD(udppkt_data, rb_tainted_str_new(udph->buf, udph->len))
UDP_METHOD(udppkt_data_len, INT2FIX(udph->len))
UDP_METHOD(udppkt_get_ippkt, rnids_ippkt_new(udph->iph))
UDP_METHOD(udppkt_dport, INT2FIX(udph->addr->dest))
UDP_METHOD(udppkt_sport, INT2FIX(udph->addr->source))
UDP_METHOD(udppkt_daddr, rb_str_new2(int_ntoa(udph->addr->daddr)))
UDP_METHOD(udppkt_saddr, rb_str_new2(int_ntoa(udph->addr->saddr)))

/* rb_str_new2(int_ntoa(tcph->a_tcp->addr.saddr))
IP_METHOD(ippkt_ip_tos, INT2FIX(iph->ip_tos));
IP_METHOD(ippkt_ip_ttl, INT2FIX(iph->ip_ttl));
IP_METHOD(ippkt_ip_len, INT2FIX(iph->ip_len));
IP_METHOD(ippkt_ip_id,  INT2FIX(iph->ip_id));
IP_METHOD(ippkt_ip_off, INT2FIX(iph->ip_off));
IP_METHOD(ippkt_ip_sum, INT2FIX(iph->ip_sum));
IP_METHOD(ippkt_ip_p,   INT2FIX(iph->ip_p));
*/

void
Init_udppkt() {
  cUDPPacket = rb_define_class("NIDS_UDP", cNIDSPacket);
  rb_define_singleton_method(cUDPPacket, "new", udppkt_s_new, 1);

  rb_define_method(cUDPPacket, "to_s", udppkt_to_s, 0);
  rb_define_method(cUDPPacket, "udp_data", udppkt_data, 0);
  rb_define_method(cUDPPacket, "udp_data_len", udppkt_data_len, 0);
  rb_define_method(cUDPPacket, "get_ippkt", udppkt_get_ippkt, 0);
  rb_define_method(cUDPPacket, "udp_dport", udppkt_dport, 0);
  rb_define_method(cUDPPacket, "udp_sport", udppkt_sport, 0);
  rb_define_method(cUDPPacket, "udp_daddr", udppkt_daddr, 0);
  rb_define_method(cUDPPacket, "udp_saddr", udppkt_saddr, 0);
}
