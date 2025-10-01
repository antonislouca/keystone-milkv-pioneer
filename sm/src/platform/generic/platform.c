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
  /* 0x0BADF00D0BADF00D*/
  uint8_t badfood[8] = {0x0B, 0xAB, 0xF0, 0x0D, 0x0B, 0xAB, 0xF0, 0x0D};
  /* 0xDEADFACEDEADFACE */
  uint8_t deadface[8] = {0xDE, 0xAD, 0xFA, 0xCE, 0xDE, 0xAD, 0xFA, 0xCE};
  /* 0xDEADBABEDEADBABE */
  uint8_t deadbabe[8] = {0xDE, 0xAD, 0xBA, 0xBE, 0xDE, 0xAD, 0xBA, 0xBE};
  /* 0xDEADBEEFCAFEBABE */
  uint8_t deadbeef[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
  /* 0xDEADCAFEDEADCAFE */
  uint8_t deadcafe[8] = {0xDE, 0xAD, 0xCA, 0xFE, 0xDE, 0xAD, 0xCA, 0xFE};

  // add 0badf00d marking for sm hash
  sbi_memcpy(sm_hash, sanctum_sm_hash, MDSIZE);
  sbi_memcpy(sm_hash + 0, badfood, sizeof(badfood));

  // adding deadfacedeadface to sm signature
  sbi_memcpy(sm_signature, sanctum_sm_signature, SIGNATURE_SIZE);
  sbi_memcpy(sm_signature + 0, deadface, sizeof(deadface));

  // copy deadbabe marking to sm public key
  sbi_memcpy(sm_public_key, sanctum_sm_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(sm_public_key + 0, deadbabe, sizeof(deadbabe));

  // copy deadbeefcafebabe marking to sm private key
  sbi_memcpy(sm_private_key, sanctum_sm_secret_key, PRIVATE_KEY_SIZE);
  sbi_memcpy(sm_private_key + 0, deadbeef, sizeof(deadbeef));

  // copy deadcafe for dev public key
  sbi_memcpy(dev_public_key, sanctum_dev_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(dev_public_key + 0, deadcafe, sizeof(deadcafe));
}
/**
 *
 *[SM] Initializing ... hart [1]
 *[SM] Keystone security monitor has been initialized!
 *0df0ad0b0df0ad0b2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f5a5a5a5a3c3c3c3c2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f
 *Booting from Security Monitor
 *============ PUBKEY =============
 *deadcafedeadcafe2d2d2d2d4b4b4b4b
 *87878787969696962e2e2e2e3f3f3f3f
 *=================================
 *=========== PRIVKEY =============
 *cafebabedeadbeef2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f5a5a5a5a3c3c3c3c2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f
 *deadbabedeadbabe2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3fdeadcafedeadcafe2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f
 *deadfacedeadface2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f5a5a5a5a3c3c3c3c2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f
 *01badf00dbadf00d2d2d2d2d4b4b4b4b87878787969696962e2e2e2e3f3f3f3f5a5a5a5a3c3c3c3c2d2d2d2d4b4b4b4b8787878796969696
 *
 *=================================
 *=========== SIGNATURE ===========
 *deadfacedeadface2d2d2d2d4b4b4b4b
 *87878787969696962e2e2e2e3f3f3f3f
 *5a5a5a5a3c3c3c3c2d2d2d2d4b4b4b4b
 *87878787969696962e2e2e2e3f3f3f3f
 *==================================================================
 */
// NOTE:normal sm copy
void sm_copy_key(void) {
  sbi_memcpy(sm_hash, sanctum_sm_hash, MDSIZE);
  sbi_memcpy(sm_signature, sanctum_sm_signature, SIGNATURE_SIZE);
  sbi_memcpy(sm_public_key, sanctum_sm_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(sm_private_key, sanctum_sm_secret_key, PRIVATE_KEY_SIZE);
  sbi_memcpy(dev_public_key, sanctum_dev_public_key, PUBLIC_KEY_SIZE);
}
