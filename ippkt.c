/**
 * Copyright (c) 2000 Yasuhiro ABE <yasu@yasundial.org>. All rights reserved.
 * See the file COPYING for license details.
 *
 * If you have any comments, please send e-mail to yasu@yasundial.org.
 **/

#include"rnids.h"

VALUE cIPPacket;

struct ip_object {
  struct ip *iph;
};

#define GetIP(obj, iph) \
    Data_Get_Struct(obj, struct ip, iph)

VALUE
rnids_ippkt_new(iph)
     struct ip *iph;
{
  VALUE object;
  
  object = Data_Wrap_Struct(cIPPacket, 0, 0, (void *)iph);
  return object;
}

static VALUE
ippkt_s_new(self,val)
     VALUE self, val;
{
  VALUE object;
  struct ip* iph;

  switch(TYPE(val)) {
  case T_DATA:
    GetIP(val, iph);
    break;
  default:
    rb_raise(rb_eTypeError, "IP object is required");
  }

  object = Data_Wrap_Struct(cIPPacket, 0, 0, (void *)iph);
  return object;
}

static VALUE
ippkt_to_s(self)
     VALUE self;
{
  struct ip *iph;
  
  GetIP(self,iph);

  return rb_str_new2(int_ntoa(iph->ip_src.s_addr));
}

#define IP_METHOD(func, val) \
static VALUE\
(func)(self)\
     VALUE self;\
{\
    struct ip *iph;\
\
    GetIP(self, iph);\
    return (val);\
}

IP_METHOD(ippkt_ip_tos, INT2FIX(iph->ip_tos));
IP_METHOD(ippkt_ip_ttl, INT2FIX(iph->ip_ttl));
IP_METHOD(ippkt_ip_len, INT2FIX(iph->ip_len));
IP_METHOD(ippkt_ip_id,  INT2FIX(iph->ip_id));
IP_METHOD(ippkt_ip_off, INT2FIX(iph->ip_off));
IP_METHOD(ippkt_ip_sum, INT2FIX(iph->ip_sum));
IP_METHOD(ippkt_ip_p,   INT2FIX(iph->ip_p));
IP_METHOD(ippkt_ip_saddr, rb_str_new2(int_ntoa(iph->ip_src.s_addr)))
IP_METHOD(ippkt_ip_daddr, rb_str_new2(int_ntoa(iph->ip_dst.s_addr)))

     
void
Init_ippkt() {
  cIPPacket = rb_define_class("NIDS_IP", cNIDSPacket);
  rb_define_singleton_method(cIPPacket, "new", ippkt_s_new, 1);

  rb_define_method(cIPPacket, "to_s", ippkt_to_s, 0);
  rb_define_method(cIPPacket, "ip_tos", ippkt_ip_tos, 0);
  rb_define_method(cIPPacket, "ip_ttl", ippkt_ip_ttl, 0);
  rb_define_method(cIPPacket, "ip_len", ippkt_ip_len, 0);
  rb_define_method(cIPPacket, "ip_id", ippkt_ip_id, 0);
  rb_define_method(cIPPacket, "ip_off", ippkt_ip_off, 0);
  rb_define_method(cIPPacket, "ip_sum", ippkt_ip_sum, 0);
  rb_define_method(cIPPacket, "ip_p", ippkt_ip_p, 0);
  rb_define_method(cIPPacket, "ip_daddr", ippkt_ip_daddr, 0);
  rb_define_method(cIPPacket, "ip_saddr", ippkt_ip_saddr, 0);
}
