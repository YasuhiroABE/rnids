/**
 * Copyright (c) 2000 Yasuhiro ABE <yasu@yasundial.org>. All rights reserved.
 * See the file COPYING for license details.
 *
 * If you have any comments, please send e-mail to yasu@yasundial.org.
 **/

#include"rnids.h"

VALUE cNIDS; // define class
VALUE cuNIDS; // current reference to object 
VALUE eNidsError;

struct stream_object {
  int is_ipfilter; /*boolean*/
  int is_ip; /*boolean*/
  int is_udp; /*boolean*/
  int is_tcp; /*boolean*/
};

#define GetStream(obj, stream) \
    Data_Get_Struct(obj, struct stream_object, stream)

static void
free_stream(stream)
     struct stream_object *stream;
{
  free(stream);
}

/**
 * create struct

VALUE
create_tcp_struct(a_tcp, hlf)
     struct tcp_stream *a_tcp;
     struct half_stream *hlf;
{
  if(hlf == NULL)
    return rb_struct_new(sTCPStruct,
			 rb_tainted_str_new2("tcp"),
			 INT2FIX(a_tcp->nids_state),
			 rb_tainted_str_new2(""),
			 INT2FIX(a_tcp->addr.source),
			 INT2FIX(a_tcp->addr.dest),
			 rb_str_new2(int_ntoa(a_tcp->addr.saddr)),
			 rb_str_new2(int_ntoa(a_tcp->addr.daddr)),
			 INT2FIX(0),
			 INT2FIX(0),
			 INT2FIX(0));
  else 
    return rb_struct_new(sTCPStruct,
			 rb_tainted_str_new2("tcp"),
			 INT2FIX(a_tcp->nids_state),
			 rb_tainted_str_new(hlf->data, hlf->count_new),
			 INT2FIX(a_tcp->addr.source),
			 INT2FIX(a_tcp->addr.dest),
			 rb_str_new2(int_ntoa(a_tcp->addr.saddr)),
			 rb_str_new2(int_ntoa(a_tcp->addr.daddr)),
			 INT2FIX(hlf->acked),
			 INT2FIX(hlf->seq),
			 INT2FIX(hlf->ack_seq));
}
VALUE
create_ip_struct(iph)
     struct ip *iph;
{
  return rb_struct_new(sIPStruct,
		       rb_tainted_str_new2("ip"),
		       rb_str_new2(int_ntoa(iph->ip_src.s_addr)),
		       rb_str_new2(int_ntoa(iph->ip_dst.s_addr)),
		       INT2FIX(iph->ip_tos),
		       INT2FIX(iph->ip_ttl),
		       INT2FIX(iph->ip_len),
		       INT2FIX(iph->ip_id),
		       INT2FIX(iph->ip_off),
		       INT2FIX(iph->ip_sum),
		       INT2FIX(iph->ip_p)
		       );
}
VALUE
create_udp_struct(addr, buf, len, iph)
     struct tuple4 *addr;
     char *buf;
     int len;
     struct ip *iph;
{
  return rb_struct_new(sUDPStruct,
		       rb_tainted_str_new2("udp"),
		       create_ip_struct(iph),
		       INT2FIX(addr->source),
		       INT2FIX(addr->dest),
		       rb_tainted_str_new(buf,len),
		       INT2FIX(len));
}
 **/

static int
nids_ip_filter(x, len)
     struct ip *x;
     int len;
{
  return 1;
}

static int
rnids_ip_filter(iph)
     struct ip *iph;
{
  VALUE ret;
  ret = rb_funcall(cuNIDS, rb_intern("ipfilter"), 1,
		   rnids_ippkt_new(iph));

  if(ret == Qtrue)
    {
      return 1;
    }
  return 0;
}

void
ip_callback(iph)
     struct ip *iph;
{
  VALUE ret;
  ret = rb_funcall(cuNIDS, rb_intern("callback"), 1,
		   rnids_ippkt_new(iph));
}


void
udp_callback(addr, buf, len, iph)
     struct tuple4 *addr;
     char *buf;
     int len;
     struct ip *iph;
{
  VALUE ret;
  ret = rb_funcall(cuNIDS, rb_intern("callback"), 1,
		   rnids_udppkt_new(addr, buf, len, iph));
}

void
tcp_callback (a_tcp, conn_opt) /* aka. new_tcp_callback() */
     struct tcp_stream *a_tcp;
     void ** conn_opt;
{
  char buf[1024];
  VALUE state, data;
  VALUE ret;

  if (a_tcp->nids_state == NIDS_JUST_EST)
    {
      a_tcp->client.collect++;
      a_tcp->server.collect++;
      //a_tcp->server.collect_urg++;
      //a_tcp->client.collect_urg++;
      return;
    }
  if (a_tcp->nids_state == NIDS_DATA)
    {
      struct half_stream *hlf;
      if (a_tcp->client.count_new)
	{
	  hlf = &a_tcp->client;
	}
      else
	{
	  hlf = &a_tcp->server;
	}
      // killing the connection
      ret = rb_funcall(cuNIDS, rb_intern("kill"), 1,
		       rnids_tcppkt_new(a_tcp, hlf));
      if(ret == Qtrue)
	{
	  nids_killtcp(a_tcp);
	}
      // for yield processing
      //rb_yield(create_tcp_struct(a_tcp, hlf));
      ret = rb_funcall(cuNIDS, rb_intern("callback"), 1,
		       rnids_tcppkt_new(a_tcp, hlf));
    }
  else
    {
      ret = rb_funcall(cuNIDS, rb_intern("callback"), 1,
		       rnids_tcppkt_new(a_tcp, NULL));
    }
}

static VALUE
rnids_s_new(argc, argv, klass)
     int argc;
     VALUE argv[];
     VALUE klass;
{
  struct stream_object *stream;
  VALUE obj;
  //obj = rb_class_new_instance(argc, argv, klass);

  obj = Data_Make_Struct(klass, struct stream_object, 0, free_stream, stream);
  stream->is_tcp = 1;
  stream->is_udp = 0;
  stream->is_ip = 0;
  stream->is_ipfilter = 0;

  return obj;
}

static VALUE
rnids_run(self)
     VALUE self;
{
  struct stream_object *stream;
  int ret;
  int fd;
  int time = 0;
  fd_set rset;
  struct timeval tv;

  GetStream(self, stream);

  if (!nids_init ())
    {
      fprintf(stderr,"%s\n", nids_errbuf);
      exit(1);
    }
  cuNIDS = self; // tell current object as global variable 
  if(stream->is_tcp) {
    nids_register_tcp(tcp_callback);
  }
  if(stream->is_udp) {
    nids_register_udp(udp_callback);
  }
  if(stream->is_ip) {
    nids_register_ip(ip_callback);
  }
  fd = nids_getfd();

  tv.tv_sec = 0;
  tv.tv_usec = 0;
  FD_ZERO (&rset);
  for(;;)
    {
      do {
	FD_SET (fd, &rset);
	// add any other fd we need to take care of
	if (select(fd+1, &rset, NULL, NULL, &tv) == 0)
	  {
	    rb_thread_wait_fd(fd);
	  }
	if (FD_ISSET(fd,&rset))  // need to test it if there are other
	  {
	    cuNIDS = self;
	    TRAP_BEG;
	    ret = nids_next();
	    TRAP_END;
	  }
      } while(ret); // 'ret == 1' means success 
      if (ret == 0) // when error
	break;
    }
  return self;
}

static VALUE
rnids_kill(self, state)
     VALUE self, state;
{
  return Qfalse;
}

static VALUE
rnids_ipfilter(self, ip)
     VALUE self, ip;
{
  return Qtrue;
}

static VALUE
rnids_tcp_stream(argc, argv, obj)
     int argc;
     VALUE argv[];
     VALUE obj;
{
  struct stream_object *stream;
  VALUE val;

  GetStream(obj, stream);
  
  if(argc == 0)
    return stream->is_tcp ? Qtrue : Qfalse;
  else
    val = argv[0];

  switch(TYPE(val))
    {
    case T_TRUE:
      stream->is_tcp = 1;
      break;
    case T_FALSE:
      stream->is_tcp = 0;
      break;
    }
  return obj;
}

static VALUE
rnids_udp_stream(argc, argv, obj)
     int argc;
     VALUE argv[];
     VALUE obj;
{
  struct stream_object *stream;
  VALUE val;

  GetStream(obj, stream);
  
  if(argc == 0)
    return stream->is_udp ? Qtrue : Qfalse;

  val = argv[0];

  switch(TYPE(val))
    {
    case T_TRUE:
      stream->is_udp = 1;
      return obj;
      break;
    case T_FALSE:
      stream->is_udp = 0;
      return obj;
      break;
    }
  return stream->is_udp ? Qtrue : Qfalse;
}

static VALUE
rnids_ip_stream(argc, argv, obj)
     int argc;
     VALUE argv[];
     VALUE obj;
{
  struct stream_object *stream;
  VALUE val;

  GetStream(obj, stream);
  
  if(argc == 0)
    return stream->is_ip ? Qtrue : Qfalse;

  val = argv[0];

  switch(TYPE(val))
    {
    case T_TRUE:
      stream->is_ip = 1;
      return obj;
    case T_FALSE:
      stream->is_ip = 0;
      return obj;
    }
  return stream->is_ip ? Qtrue : Qfalse;
}

static VALUE
rnids_use_ipfilter(argc, argv, obj)
     int argc;
     VALUE argv[];
     VALUE obj;
{
  struct stream_object *stream;
  VALUE val;

  GetStream(obj, stream);
  
  if(argc == 0)
    return stream->is_ipfilter ? Qtrue : Qfalse;

  val = argv[0];

  switch(TYPE(val))
    {
    case T_TRUE:
      stream->is_ipfilter = 1;
      nids_params.ip_filter = rnids_ip_filter;
      return obj;
      break;
    case T_FALSE:
      stream->is_ipfilter = 0;
      nids_params.ip_filter = nids_ip_filter;
      return obj;
      break;
    }
  return stream->is_ipfilter ? Qtrue : Qfalse;
}


/**
 * variable reference methods *
 **/
/* char *device */
static VALUE
rnids_device(argc, argv, obj)
     int argc;
     VALUE argv[];
     VALUE obj;
{
  VALUE val;

  if(argc == 0)
    if(nids_params.device==NULL)
      return rb_str_new2("");
    else
      return rb_str_new2(nids_params.device);

  val = argv[0];
  if(TYPE(val) == T_STRING)
    if(RSTRING(val)->len == 0)
      nids_params.device = NULL;
    else
      nids_params.device = STR2CSTR(val);
  return obj;
}
/* char *pcap_filter
   Note: pcap_filter only supports the link-layer level processing.
*/
static VALUE
rnids_pcap_filter(argc, argv, obj)
     int argc;
     VALUE argv[];
     VALUE obj;
{
  VALUE value;

  if(argc == 0)
    if(nids_params.pcap_filter == NULL)
      return rb_str_new2("");
    else
      return rb_str_new2(nids_params.pcap_filter);

  value = argv[0];
  if(TYPE(value) == T_STRING)
    if(RSTRING(value)->len == 0)
      nids_params.pcap_filter = NULL;
    else
      nids_params.pcap_filter = STR2CSTR(value);
  return obj;
}
/* int promisc */
static VALUE
rnids_promisc(argc, argv, obj)
     int argc;
     VALUE argv[];
     VALUE obj;
{
  if(argc == 0)
    return nids_params.promisc ? Qtrue : Qfalse;

  switch(TYPE(argv[0]))
    {
    case T_TRUE:
      nids_params.promisc = 1;
    case T_FALSE:
      nids_params.promisc = 0;
    }
  return obj;
}

static VALUE
rnids_callback(self,val)
     VALUE self,val;
{
  return Qtrue;
}

/**
 * Ruby Initialize Function
 */
Init_rnids()
{
  cNIDS = rb_define_class("NIDS", rb_cObject);

  rb_define_const(cNIDS, "NIDS_JUST_EST", INT2NUM(NIDS_JUST_EST));
  rb_define_const(cNIDS, "NIDS_DATA", INT2NUM(NIDS_DATA));
  rb_define_const(cNIDS, "NIDS_CLOSE", INT2NUM(NIDS_CLOSE));
  rb_define_const(cNIDS, "NIDS_RESET", INT2NUM(NIDS_RESET));
  rb_define_const(cNIDS, "NIDS_TIMED_OUT", INT2NUM(NIDS_TIMED_OUT));

  rb_define_method(cNIDS, "run", rnids_run, 0);
  rb_define_method(cNIDS, "callback", rnids_callback, 1);

  rb_define_method(cNIDS, "device", rnids_device, -1);
  rb_define_method(cNIDS, "pcap_filter", rnids_pcap_filter, -1);
  rb_define_method(cNIDS, "promisc", rnids_promisc, -1);

  rb_define_singleton_method(cNIDS, "new", rnids_s_new, -1);
  rb_define_method(cNIDS, "kill", rnids_kill, 1);
  rb_define_method(cNIDS, "ipfilter", rnids_ipfilter, 1);
  rb_define_method(cNIDS, "use_tcp", rnids_tcp_stream, -1);
  rb_define_method(cNIDS, "use_udp", rnids_udp_stream, -1);
  rb_define_method(cNIDS, "use_ip", rnids_ip_stream, -1);
  rb_define_method(cNIDS, "use_ipfilter", rnids_use_ipfilter, -1);

  rb_define_variable("$CURRENT", &cuNIDS);
  //rb_global_variable(&cuNIDS);

  eNidsError = rb_define_class_under(cNIDS, "NidsError", rb_eStandardError);

  Init_packet();
  Init_ippkt();
  Init_tcppkt();
  Init_udppkt();
}

/**
�����Υġ�����ä��������domain depenednt��IDMEF��ĥ��snort��
snort��signature�˹�碌��Ǥ�դ�alert_level���ѹ��Ǥ���IDMEF Proxy��
domain independent��IDMEF�˴�Ť�management�����ƥ�Ǥ��롣

As a result of this research, two are develped.
One is a domain dependent tools, snort IDMEF extention mechanizum and 
IDMEF proxy for select arbitary alert level, the other is 
a domain independent tool, management system for IDMEF.

���θ���Ͼ���IDMEF�������٤Ƥ�NIDS�ǥ��ݡ��Ȥ���������Ԥ��Ƥ��롣
����ˤ�ä�IDMEF(�ǡ���)�˰�¸���륿���פδ�������ή�ˤʤ�Ǥ�����
���ߤϼºݤΤȤ����NIDS�ġ��뤬�󶡤���ƻ륷���ƥ�˰�¸���Ƥ��ơ�
�ߴ����Τʤ��ġ���֤Υǡ����μ��Ϥ��Ͽʹ֤��ԤʤäƤ��롣

NIDS��A��firewall��B�Ȥ������ʤ˸ߴ������ʤ��Ȥ���ȡ�A�Υ�ݡ��Ȥ�
���äƿʹ֤�B��������ѹ����ƥ��ͥ������δ����򤷤ʤ���Ф����ʤ���
����ϥġ����¸���δ��������ƥ�Ǥ��äơ��ǡ�����¸�Ǥʤ����
�����Ԥ���ô�Ϥ��ä��Ʒڸ����ʤ��ΤǤ��롣�ġ��뤬�󶡤��ʤ����Ǥ��ʤ�
��ǽ��¸����뤿��ˤϥǡ�������ݲ���Ԥʤ����Ȥ�ɬ�פǤ��롣
����Ǥ�¸��Ǥ��ʤ���ǽ�Ȥ�����Τϡ����Τ褦�ʥġ���Ǥ⤱�ä���
�󶡤Ǥ��ʤ��ΤǤ��뤫�顣(�ǡ������ʤ��Τˡ�����ɤ���������?)

�Ĥޤ��������ϡ֥ǡ�����¸�Ǥʤ������flexiblity���ʤ���
�ִ����Ԥ���ô���ڸ����ʤ������products�ι����ˤ���פȤ������Ǥ��롣

����NIDS�����IDMEF��ݡ��Ȥ�IDMEF Proxy�Ȥ����ȹ礻�ϡ�Proxy��ǽ�Ϥ�
������¸���Ƥ��뤬�������ȥ�٥�ǤΥǡ����������Ԥʤ����Ȥ��Ǥ���
���˶��Ϥʼ��ʤǤ��롣NIDS��element�����Ƥˤ�ä�uniq��alertID��
��Ͽ����IDMEF audit tool�Ͼ���response���Ȥ߹�碌����Ͽ���뤳�Ȥ�
��ߤ�alertID��uniq���ݤĤ��Ȥ��Ǥ��롣���Υ����ƥ����Ƥ��뤳�ȤȤ��褦��
*/
