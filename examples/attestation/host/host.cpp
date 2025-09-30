//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
// [SM] Initializing ... hart [0]
//[SM] Keystone security monitor has been initialized!
// 5a5a5a5a3c3c3c3c2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f5a5a5a5a3c3c3c3c2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f
// Booting from Security Monitor
//============ PUBKEY =============
// 5a5a5a5a3c3c3c3c2d2d2d2d4b4b4b4b
// 87878787969696962e2e2e2e3f3f3f3f
//=================================
//=========== PRIVKEY =============
// 5a5a5a5a3c3c3c3c2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f5a5a5a5a3c3c3c3c2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f5a5a5a5a3c3c3c3c2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f5a5a5a5a3c3c3c3c2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f
// 5a5a5a5a3c3c3c3c2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f5a5a5a5a3c3c3c3c2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f015a5a5a5a3c3c3c3c2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f5a5a5a5a3c3c3c3c2d2d2d2d4b4b4b4b8787878796969696
//
//=================================
//=========== SIGNATURE ===========
// 5a5a5a5a3c3c3c3c2d2d2d2d4b4b4b4b
// 87878787969696962e2e2e2e3f3f3f3f
// 5a5a5a5a3c3c3c3c2d2d2d2d4b4b4b4b
// 87878787969696962e2e2e2e3f3f3f3f
//=================================
//------------------------------------------------------------------------------
#include "host.h"

#include <getopt.h>
#include <stdlib.h>

#include <cerrno>
#include <cstdio>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

#include "edge/edge_common.h"
#include "host/keystone.h"
#include "verifier/report.h"

// TODO: add paths to cmakelists
extern "C" {
#include "/home/alouka/Documents/repos/badram-riscv/alias-reversing/modules/read_alias/include/readalias.h"
#include "/home/alouka/Documents/repos/badram-riscv/alias-reversing/modules/read_alias/readalias.c"
}

#define OCALL_PRINT_BUFFER 1
#define OCALL_PRINT_VALUE 2
#define OCALL_COPY_REPORT 3
#define OCALL_GET_STRING 4

void SharedBuffer::set_ok() {
  edge_call_->return_data.call_status = CALL_STATUS_OK;
}

void SharedBuffer::set_bad_offset() {
  edge_call_->return_data.call_status = CALL_STATUS_BAD_OFFSET;
}
void SharedBuffer::set_bad_ptr() {
  edge_call_->return_data.call_status = CALL_STATUS_BAD_PTR;
}

int SharedBuffer::get_ptr_from_offset(edge_data_offset offset, uintptr_t *ptr) {
  /* Validate that _shared_start+offset is sane */
  if (offset > UINTPTR_MAX - buffer_ || offset > buffer_len_) {
    return -1;
  }

  /* ptr looks valid, create it */
  *ptr = buffer_ + offset;
  return 0;
}

int SharedBuffer::args_ptr(uintptr_t *ptr, size_t *size) {
  *size = edge_call_->call_arg_size;
  return get_ptr_from_offset(edge_call_->call_arg_offset, ptr);
}

std::optional<std::pair<uintptr_t, size_t>>
SharedBuffer::get_call_args_ptr_or_set_bad_offset() {
  uintptr_t call_args;
  size_t arg_len;
  if (args_ptr(&call_args, &arg_len) != 0) {
    set_bad_offset();
    return std::nullopt;
  }
  return std::pair{call_args, arg_len};
}

std::optional<char *> SharedBuffer::get_c_string_or_set_bad_offset() {
  auto v = get_call_args_ptr_or_set_bad_offset();
  return v.has_value() ? std::optional{(char *)v.value().first} : std::nullopt;
}

std::optional<unsigned long>
SharedBuffer::get_unsigned_long_or_set_bad_offset() {
  auto v = get_call_args_ptr_or_set_bad_offset();
  return v.has_value() ? std::optional{*(unsigned long *)v.value().first}
                       : std::nullopt;
}

std::optional<Report> SharedBuffer::get_report_or_set_bad_offset() {
  auto v = get_call_args_ptr_or_set_bad_offset();
  if (!v.has_value())
    return std::nullopt;
  Report ret;
  ret.fromBytes((byte *)v.value().first);
  return ret;
}

uintptr_t SharedBuffer::data_ptr() {
  return (uintptr_t)edge_call_ + sizeof(struct edge_call);
}

int SharedBuffer::validate_ptr(uintptr_t ptr) {
  /* Validate that ptr starts in range */
  if (ptr > buffer_ + buffer_len_ || ptr < buffer_) {
    return 1;
  }
  return 0;
}

int SharedBuffer::get_offset_from_ptr(uintptr_t ptr, edge_data_offset *offset) {
  int valid = validate_ptr(ptr);
  if (valid != 0)
    return valid;

  /* ptr looks valid, create it */
  *offset = ptr - buffer_;
  return 0;
}

int SharedBuffer::setup_ret(void *ptr, size_t size) {
  edge_call_->return_data.call_ret_size = size;
  return get_offset_from_ptr((uintptr_t)ptr,
                             &edge_call_->return_data.call_ret_offset);
}

void SharedBuffer::setup_ret_or_bad_ptr(unsigned long ret_val) {
  // Assuming we are done with the data section for args, use as
  // return region.
  //
  // TODO safety check?
  uintptr_t data_section = data_ptr();

  memcpy((void *)data_section, &ret_val, sizeof(unsigned long));

  if (setup_ret((void *)data_section, sizeof(unsigned long))) {
    set_bad_ptr();
  } else {
    set_ok();
  }
}

int SharedBuffer::setup_wrapped_ret(void *ptr, size_t size) {
  struct edge_data data_wrapper;
  data_wrapper.size = size;
  get_offset_from_ptr(buffer_ + sizeof(struct edge_call) +
                          sizeof(struct edge_data),
                      &data_wrapper.offset);

  memcpy(
      (void *)(buffer_ + sizeof(struct edge_call) + sizeof(struct edge_data)),
      ptr, size);

  memcpy((void *)(buffer_ + sizeof(struct edge_call)), &data_wrapper,
         sizeof(struct edge_data));

  edge_call_->return_data.call_ret_size = sizeof(struct edge_data);
  return get_offset_from_ptr(buffer_ + sizeof(struct edge_call),
                             &edge_call_->return_data.call_ret_offset);
}

void SharedBuffer::setup_wrapped_ret_or_bad_ptr(const std::string &ret_val) {
  if (setup_wrapped_ret((void *)ret_val.c_str(), ret_val.length() + 1)) {
    set_bad_ptr();
  } else {
    set_ok();
  }
  return;
}

void Host::print_buffer_wrapper(RunData &run_data) {
  SharedBuffer &shared_buffer = run_data.shared_buffer;

  auto t = shared_buffer.get_c_string_or_set_bad_offset();
  if (t.has_value()) {
    printf("Enclave said: %s", t.value());
    auto ret_val = strlen(t.value());
    shared_buffer.setup_ret_or_bad_ptr(ret_val);
  }
}

bool check_pattern(char buf[0x1000]) {

  char pattern[] = {0x5a, 0x5a, 0x5a, 0x5a, 0x3c, 0x3c, 0x3c, 0x3c,
                    0x2d, 0x2d, 0x2d, 0x2d, 0x4b, 0x4b, 0x4b, 0x4b};

  size_t pattern_len = sizeof(pattern);
  for (int i = 0; i <= (0x1000 - pattern_len); i++) {
    if (memcmp(&buf[i], pattern, pattern_len) == 0)
      return true;
  }
  return false;
}

void print_page(char buf[0x1000], uint64_t addr) {
  printf("Page at [%llx]: \n", addr);
  for (int val = 0; val < 0x1000; val++)
    printf("%x ", buf[val]);
  printf("\n");
}

void Host::print_value_wrapper(RunData &run_data) {
  SharedBuffer &shared_buffer = run_data.shared_buffer;

  auto t = shared_buffer.get_unsigned_long_or_set_bad_offset();
  if (t.has_value()) {
    printf("Enclave said value: %u\n", t.value());
    shared_buffer.set_ok();
  }

  // Just dump pages:
  char buf[4096] = {0};
  page_stats_t stats;

  for (uint64_t paddr_candidate = 0x200000000; paddr_candidate < 0x1000000000;
       paddr_candidate += 0x1000) {

    /*copy content of the page to buf using physical address*/
    if (memcpy_frompa(buf, paddr_candidate, 4096, &stats, true) != 0) {
      printf("PAddr reading Error\n");
      // return ;
      continue;
    }
    // compare page with public key
    if (check_pattern(buf))
      print_page(buf, paddr_candidate);

    // maybe compare with the public key to see that we can reach the page
    // the public key is in the report given by the enclave i beleive
  }
  return;
}

void Host::copy_report_wrapper(RunData &run_data) {
  SharedBuffer &shared_buffer = run_data.shared_buffer;

  auto t = shared_buffer.get_report_or_set_bad_offset();
  if (t.has_value()) {
    run_data.report = std::make_unique<Report>(std::move(t.value()));
    shared_buffer.set_ok();
  }
  return;
}

void Host::get_host_string_wrapper(RunData &run_data) {
  SharedBuffer &shared_buffer = run_data.shared_buffer;

  shared_buffer.setup_wrapped_ret_or_bad_ptr(run_data.nonce);
  return;
}

void Host::dispatch_ocall(RunData &run_data) {
  struct edge_call *edge_call =
      (struct edge_call *)run_data.shared_buffer.ptr();
  switch (edge_call->call_id) {
  case OCALL_PRINT_BUFFER:
    print_buffer_wrapper(run_data);
    break;
  case OCALL_PRINT_VALUE:
    print_value_wrapper(run_data);
    break;
  case OCALL_COPY_REPORT:
    copy_report_wrapper(run_data);
    break;
  case OCALL_GET_STRING:
    get_host_string_wrapper(run_data);
    break;
  }
  return;
}

Report Host::run(const std::string &nonce) {
  open_kmod();
  Keystone::Enclave enclave;
  enclave.init(eapp_file_.c_str(), rt_file_.c_str(), ld_file_.c_str(), params_);

  RunData run_data{
      SharedBuffer{enclave.getSharedBuffer(), enclave.getSharedBufferSize()},
      nonce, nullptr};

  enclave.registerOcallDispatch([&run_data](void *buffer) {
    assert(buffer == (void *)run_data.shared_buffer.ptr());
    dispatch_ocall(run_data);
  });

  uintptr_t encl_ret;
  enclave.run(&encl_ret);

  return *run_data.report;
}
