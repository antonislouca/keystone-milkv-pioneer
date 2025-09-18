//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "eapp_utils.h"
#include "edge_call.h"
#include "string.h"
#include <syscall.h>

#define OCALL_PRINT_STRING 1

unsigned long ocall_print_string(char *string);

char __attribute__((aligned(0x1000))) secret[0x2000];

int *pt = (int *)secret;

int main() {
  memset(secret, 'A', 0x2000);

  ocall_print_string("Hello World");

  EAPP_RETURN(0);
}

unsigned long ocall_print_string(char *string) {
  unsigned long retval;
  ocall(OCALL_PRINT_STRING, pt, sizeof(pt), &retval, sizeof(unsigned long));
  return retval;
}
/*
 *
 * Verifying archive integrity... MD5 checksums are OK. All good.
 * Uncompressing Keystone Enclave Package
 * Buffer pointer: 0x3f87eb4000
 * Reading secret with badram
 * Buffer at j: [905442000]
 * Buffer at j: [905443000]
 * Error
 * */
