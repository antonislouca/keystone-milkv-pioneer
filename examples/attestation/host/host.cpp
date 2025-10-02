//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------

#include "host.h"

#include <getopt.h>
#include <memory>
#include <stddef.h>
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
#include "verifier/test_dev_key.h"
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

// NOTE: this function returns the report
// structure after reading from memory
std::optional<Report> SharedBuffer::get_report_or_set_bad_offset() {
  auto v = get_call_args_ptr_or_set_bad_offset();
  if (!v.has_value())
    return std::nullopt;

  // before setting the report we can get the bytes from the shared buffer
  //===========================
  //
  // get address to report bytes
  byte *report_bytes = (byte *)v.value().first;
  // create byte array size of report
  byte report[sizeof(struct report_t)];
  // copy report bytes
  std::memcpy(&report, report_bytes, sizeof(struct report_t));

  printf("Printing Report bytes\n");
  __print_bytes((const byte *)report, sizeof(report_t));
  struct report_t *report_s = (report_t *)report;
  printf("Testing casting:\n");

  __print_bytes(report_s->sm.public_key, PUBLIC_KEY_SIZE);
  __dump_memory(report_s->sm.public_key, report_s->enclave.hash);
  //===========================
  //
  // we might be able to memcopy to the report
  // byte location our new report
  // Normal operation below

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

bool __check_pattern(char buf[0x1000], const byte *pattern,
                     size_t pattern_len) {

  // char pattern[8] = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe};

  // uint64_t deadbeef = 0xdeadbeefcafebabe;
  // size_t pattern_len = sizeof(pattern);
  for (int i = 0; i <= (0x1000 - pattern_len); i++) {
    if (memcmp(&buf[i], pattern, pattern_len) == 0)
      return true;
  }
  return false;
}

static void __print_page(char buf[0x1000], uint64_t addr) {
  printf("Page at [%llx]: \n", addr);
  for (int val = 0; val < 0x1000; val++)
    printf("%02x ", buf[val]);
  printf("\n");
}
/**
 *Either the enclave hash or the SM hash (or both) does not match with expeced.
 *		=== Security Monitor ===
 *Hash:
 *0babf00d0babf00d2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f5a5a5a5a3c3c3c3c2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f
 *Pubkey: deadbabedeadbabe2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f
 *Signature:
 *deadfacedeadface2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f5a5a5a5a3c3c3c3c2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f
 *
 *		=== Enclave Application ===
 *Hash:
 *296b1fd3dd2d7a0ed2047c6bd9af4121a9d0090ba6d20c36fe88f15d3153ae95edea680d5ac69dc8eb718a285a3463e824f0749e730995e0c8324c5a0afd57c1
 *Signature:
 *9906b65dcc07496c73d57c21d6ea0cc6c69553902b04f457cdf290b4b9f2bd54a85940c0c3b1293ad2af05d2b4d3eb14783a2a43efbd9ab4c87ccaf329fe0007
 *Enclave Data: 3138303432383933383300
 *		-- Device pubkey --
 *deadcafedeadcafe2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f
 *Returned data in the report match with the nonce sent.
 *
 * */
static void __print_bytes(const byte *buf, size_t buf_len) {
  for (size_t i = 0; i < buf_len; i += 1) {
    printf("%02x ", *(buf + i));
  }
  printf("\n");
}

static void __dump_memory(const byte *pub_key, const byte *enclave_hash) {

  // Just dump pages:
  char buf[4096] = {0};
  page_stats_t stats;
  for (uint64_t paddr_candidate = 0x200000000; paddr_candidate < 0x1000000000;
       paddr_candidate += 0x1000) {

    /*copy content of the page to buf using physical address*/
    if (memcpy_frompa(buf, paddr_candidate, 4096, &stats, true) != 0) {
      printf("PAddr reading Error\n");
      return;
    }
    // if pub key exists and no enclave data exists we have the page to the
    // private key
    if (__check_pattern(buf, pub_key, PUBLIC_KEY_SIZE) &&
        !__check_pattern(buf, enclave_hash, MDSIZE))
      __print_page(buf, paddr_candidate);

    // maybe compare with the public key to see that we can reach the page
    // the public key is in the report given by the enclave i beleive
  }
}

void Host::print_value_wrapper(RunData &run_data) {
  SharedBuffer &shared_buffer = run_data.shared_buffer;

  auto t = shared_buffer.get_unsigned_long_or_set_bad_offset();
  if (t.has_value()) {
    printf("Enclave said value: %u\n", t.value());
    shared_buffer.set_ok();
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
