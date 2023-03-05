/**
 * Copyright (c) 2000 Yasuhiro ABE <yasu@yasundial.org>. All rights reserved.
 * See the file COPYING for license details.
 *
 * If you have any comments, please send e-mail to yasu@yasundial.org.
 **/

#include"rnids.h"

static VALUE cIPAddress;

#define GetIPAddress(obj, addr) {\
    Check_Type(obj, T_DATA);\
    addr = (struct in_addr *)&(DATA_PTR(obj));\
}

static VALUE
ipaddr_s_new(self,val)
     VALUE self, val;
{
  struct in_addr addr;
  struct hostent *hent;
  char *hname;
  VALUE object;

  switch(TYPE(val)) {
  case T_STRING:
    hname = RSTRING(val)->ptr;
    hent = (struct hostent *)gethostbyname(hname);
    if (hent == NULL) {
      rb_raise(eNidsError, "host not found: %s", hname);
    }
    addr = *(struct in_addr *)hent->h_addr;
    break;
  case T_FIXNUM:
  case T_BIGNUM:
    addr.s_addr = htonl(NUM2ULONG(val));
    break;
  default:
    rb_raise(rb_eTypeError, "String or Integer required");
  }

  object = Data_Wrap_Struct(cIPAddress, 0, 0, (void *)&addr.s_addr);
  return object;
}

static VALUE
ipaddr_to_i(self)
     VALUE self;
{
  struct in_addr *addr;
  
  GetIPAddress(self, addr);
  return UINT32_2_NUM(ntohl(addr->s_addr));
}

static VALUE
ipaddr_num_s(self)
    VALUE self;
{
    struct in_addr *addr;

    GetIPAddress(self, addr);
    return rb_str_new2(inet_ntoa(*addr));
}

Init_ipaddr() {
  cIPAddress = rb_define_class("NIDS_IPAddress", rb_cObject);
  rb_define_singleton_method(cIPAddress, "new", ipaddr_s_new, 1);
  rb_define_method(cIPAddress, "to_i", ipaddr_to_i, 0);
  rb_define_method(cIPAddress, "to_num_s", ipaddr_num_s, 0);
}
