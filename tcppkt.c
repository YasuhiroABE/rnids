/**
 * Copyright (c) 2000 Yasuhiro ABE <yasu@yasundial.org>. All rights reserved.
 * See the file COPYING for license details.
 *
 * If you have any comments, please send e-mail to yasu@yasundial.org.
 **/

#include"rnids.h"

VALUE cTCPPacket;

struct tcp_object {
  struct tcp_stream *a_tcp;
  struct half_stream *hlf;
};

#define GetTCP(obj, tcph) \
    Data_Get_Struct(obj, struct tcp_object, tcph)

VALUE
rnids_tcppkt_new(a_tcp, hlf)  
     struct tcp_stream *a_tcp;
     struct half_stream *hlf;
{
  VALUE object;
  struct tcp_object *tcph;

  object = Data_Make_Struct(cTCPPacket, struct tcp_object, 0, free, (void *)tcph);
  tcph->a_tcp = a_tcp;
  tcph->hlf = hlf;
  return object;
}

static VALUE
tcppkt_s_new(self,val)
     VALUE self, val;
{
  VALUE object;
  struct tcp_object *tcph;

  switch(TYPE(val)) {
  case T_DATA:
    GetTCP(val, tcph);
    break;
  default:
    rb_raise(rb_eTypeError, "TCP object is required");
  }

  object = Data_Wrap_Struct(cTCPPacket, 0, 0, (void *)tcph);
  return object;
}

static VALUE
tcppkt_to_s(self)
     VALUE self;
{
  struct tcp_object *tcph;
  
  GetTCP(self,tcph);
  
  return rb_str_new2(int_ntoa(tcph->a_tcp->addr.daddr));
}

static VALUE
tcppkt_tcp_data(self)
     VALUE self;
{
  struct tcp_object *tcph;
  
  GetTCP(self,tcph);

  if(tcph->hlf)
    return rb_tainted_str_new(tcph->hlf->data, tcph->hlf->count);
  else
    return rb_str_new2("");
}
/*
static VALUE
tcppkt_tcp_data_len(self)
     VALUE self;
{
  struct tcp_object *tcph;
  
  GetTCP(self,tcph);
  
  if(tcph->hlf)
    return INT2FIX(tcph->hlf->count);
  else
    return INT2FIX(0);
}

static VALUE
tcppkt_tcp_dport(self)
     VALUE self;
{
  struct tcp_object *tcph;
  
  GetTCP(self,tcph);
  
  if(tcph->hlf)
    return INT2FIX(tcph->a_tcp->addr.dest);
  else
    return INT2FIX(0);
}


static VALUE
tcppkt_tcp_sport(self)
     VALUE self;
{
  struct tcp_object *tcph;
  
  GetTCP(self,tcph);
  
  if(tcph->hlf)
    return INT2FIX(tcph->a_tcp->addr.source);
  else
    return INT2FIX(0);
}
*/

#define TCPP_METHOD(func, hlf_val, val) \
static VALUE\
(func)(self)\
     VALUE self;\
{\
    struct tcp_object *tcph;\
\
    GetTCP(self, tcph);\
    if(tcph->hlf) \
      return (hlf_val); \
    return (val);\
}

TCPP_METHOD(tcppkt_tcp_ack, INT2FIX(tcph->hlf->acked), INT2FIX(0))
TCPP_METHOD(tcppkt_tcp_seq, INT2FIX(tcph->hlf->seq), INT2FIX(0))
TCPP_METHOD(tcppkt_tcp_sport, INT2FIX(tcph->a_tcp->addr.source), INT2FIX(0))
TCPP_METHOD(tcppkt_tcp_dport, INT2FIX(tcph->a_tcp->addr.dest), INT2FIX(0))
TCPP_METHOD(tcppkt_tcp_new_data, rb_tainted_str_new(tcph->hlf->data, tcph->hlf->count_new), rb_str_new2(""))
TCPP_METHOD(tcppkt_tcp_data_len, INT2FIX(tcph->hlf->count), INT2FIX(0))
TCPP_METHOD(tcppkt_tcp_new_data_len, INT2FIX(tcph->hlf->count_new), INT2FIX(0))
TCPP_METHOD(tcppkt_tcp_win, INT2FIX(tcph->hlf->window), INT2FIX(0))
TCPP_METHOD(tcppkt_tcp_saddr, rb_str_new2(int_ntoa(tcph->a_tcp->addr.saddr)), rb_str_new2(""))
TCPP_METHOD(tcppkt_tcp_daddr, rb_str_new2(int_ntoa(tcph->a_tcp->addr.daddr)), rb_str_new2(""))
TCPP_METHOD(tcppkt_tcp_state, INT2FIX(tcph->a_tcp->nids_state), INT2FIX(0))

void 
Init_tcppkt() {
  cTCPPacket = rb_define_class("NIDS_TCP", cNIDSPacket);
  rb_define_singleton_method(cTCPPacket, "new", tcppkt_s_new, 1);

  rb_define_method(cTCPPacket, "to_s", tcppkt_to_s, 0);
  rb_define_method(cTCPPacket, "tcp_data", tcppkt_tcp_data, 0);
  rb_define_method(cTCPPacket, "tcp_new_data", tcppkt_tcp_new_data, 0);
  rb_define_method(cTCPPacket, "tcp_data_len", tcppkt_tcp_data_len, 0);
  rb_define_method(cTCPPacket, "tcp_new_data_len", tcppkt_tcp_new_data_len, 0);
  rb_define_method(cTCPPacket, "tcp_dport", tcppkt_tcp_dport, 0);
  rb_define_method(cTCPPacket, "tcp_sport", tcppkt_tcp_sport, 0);
  rb_define_method(cTCPPacket, "tcp_ack", tcppkt_tcp_ack, 0);
  rb_define_method(cTCPPacket, "tcp_seq", tcppkt_tcp_seq, 0);
  rb_define_method(cTCPPacket, "tcp_win", tcppkt_tcp_win, 0);
  rb_define_method(cTCPPacket, "tcp_daddr", tcppkt_tcp_daddr, 0);
  rb_define_method(cTCPPacket, "tcp_saddr", tcppkt_tcp_saddr, 0);
  rb_define_method(cTCPPacket, "tcp_state", tcppkt_tcp_state, 0);
}
