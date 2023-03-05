/**
 * Copyright (c) 2000 Yasuhiro ABE <yasu@yasundial.org>. All rights reserved.
 * See the file COPYING for license details.
 *
 * If you have any comments, please send e-mail to yasu@yasundial.org.
 */

#include"rnids.h"

VALUE cNIDSPacket;

void
Init_packet() {
  cNIDSPacket = rb_define_class("NIDS_Packet", rb_cObject);
}
