/* Default platform does nothing special here */
#include "../../enclave.h"
#include <sbi/sbi_string.h>

unsigned long platform_init_global_once() { return SBI_ERR_SM_ENCLAVE_SUCCESS; }

unsigned long platform_init_global() { return SBI_ERR_SM_ENCLAVE_SUCCESS; }

void platform_init_enclave(struct enclave *enclave) { return; }

void platform_destroy_enclave(struct enclave *enclave) { return; }

unsigned long platform_create_enclave(struct enclave *enclave) {
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

void platform_switch_to_enclave(struct enclave *enclave) { return; }

void platform_switch_from_enclave(struct enclave *enclave) { return; }

uint64_t platform_random() {
#pragma message("Platform has no entropy source, this is unsafe. TEST ONLY")
  static uint64_t w = 0, s = 0xb5ad4eceda1ce2a9;

  unsigned long cycles;
  asm volatile("rdcycle %0" : "=r"(cycles));

  // from Middle Square Weyl Sequence algorithm
  uint64_t x = cycles;
  x *= x;
  x += (w += s);
  return (x >> 32) | (x << 32);
}

// Initialization functions

/* from Sanctum BootROM */
extern byte sanctum_sm_hash[MDSIZE];
extern byte sanctum_sm_signature[SIGNATURE_SIZE];
extern byte sanctum_sm_secret_key[PRIVATE_KEY_SIZE];
extern byte sanctum_sm_public_key[PUBLIC_KEY_SIZE];
extern byte sanctum_dev_public_key[PUBLIC_KEY_SIZE];

extern byte sm_hash[MDSIZE];
extern byte sm_signature[SIGNATURE_SIZE];
extern byte sm_public_key[PUBLIC_KEY_SIZE];
extern byte sm_private_key[PRIVATE_KEY_SIZE];
extern byte dev_public_key[PUBLIC_KEY_SIZE];

// NOTE: modified SM copy for debug
void sm_copy_key_moded(void) {
  // add 0badf00d marking for sm hash
  sbi_memcpy(sm_hash, sanctum_sm_hash, MDSIZE);
  uint64_t badfood = 0x0badf00d0badf00d;
  sbi_memcpy(sm_hash + 0, &badfood, sizeof(badfood));

  // set sm signature to 0x5a
  byte five_a = 0x5a;
  sbi_memcpy(sm_signature, &five_a, SIGNATURE_SIZE);

  // copy deadbabe marking to sm public key
  sbi_memcpy(sm_public_key, sanctum_sm_public_key, PUBLIC_KEY_SIZE);
  uint64_t deadbabe = 0xdeadbabedeadbabe;
  sbi_memcpy(sm_public_key + 0, &deadbabe, sizeof(deadbabe));

  // copy deadbeefcafebabe marking to sm private key
  sbi_memcpy(sm_private_key, sanctum_sm_secret_key, PRIVATE_KEY_SIZE);
  uint64_t deadbeef = 0xdeadbeefcafebabe;
  sbi_memcpy(sm_private_key + 0, &deadbeef, sizeof(deadbeef));

  // copy deadcafe for dev public key
  sbi_memcpy(dev_public_key, sanctum_dev_public_key, PUBLIC_KEY_SIZE);
  uint64_t deadcafe = 0xdeadcafedeadcafe;
  sbi_memcpy(dev_public_key + 0, &deadcafe, sizeof(deadcafe));
}

// NOTE:normal sm copy
void sm_copy_key(void) {
  sbi_memcpy(sm_hash, sanctum_sm_hash, MDSIZE);
  sbi_memcpy(sm_signature, sanctum_sm_signature, SIGNATURE_SIZE);
  sbi_memcpy(sm_public_key, sanctum_sm_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(sm_private_key, sanctum_sm_secret_key, PRIVATE_KEY_SIZE);
  sbi_memcpy(dev_public_key, sanctum_dev_public_key, PUBLIC_KEY_SIZE);
}
