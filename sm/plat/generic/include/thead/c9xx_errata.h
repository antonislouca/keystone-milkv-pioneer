
#ifndef __RISCV_THEAD_C9XX_ERRATA_H____
#define __RISCV_THEAD_C9XX_ERRATA_H____

/**
 * T-HEAD board with this quirk need to execute sfence.vma to flush
 * stale entrie avoid incorrect memory access.
 */

#include <sbi/sbi_types.h>
#define BIT(nr) (1UL << (nr))
#define THEAD_QUIRK_ERRATA_TLB_FLUSH BIT(0)

void thead_register_tlb_flush_trap_handler(void);

#endif // __RISCV_THEAD_C9XX_ERRATA_H____
