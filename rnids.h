/**
 * Copyright (c) 2000 Yasuhiro ABE <yasu@yasundial.org>. All rights reserved.
 * See the file COPYING for license details.
 *
 * If you have any comments, please send e-mail to yasu@yasundial.org.
 **/

/* common files */
#include "ruby.h"
#include "rubysig.h"

#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include "nids.h"

/* nids.c */
extern VALUE eNidsError;
// extern VALUE ippkt_s_new(VALUE,VALUE);
extern VALUE rnids_ippkt_new(struct ip *);
#define int_ntoa(x)     inet_ntoa(*((struct in_addr *)&x))

/* ipaddr.c */
extern VALUE cIPAddress;

/* ippkt.c */
extern void Init_ippkt(void);
extern VALUE cIPPacket;

/* packet.c */
EXTERN VALUE cNIDSPacket;
