
#include <platform_override.h>
#include <sbi_utils/fdt/fdt_fixup.h>
#include <sbi_utils/fdt/fdt_helper.h>
#include <sbi_utils/ipi/aclint_mswi.h>

#include "sm.h"

static int generic_final_init(bool cold_boot, const struct fdt_match *match) {
  // void *fdt;
  sm_init(cold_boot);
  // if (!cold_boot)
  //   return 0;
  // fdt = fdt_get_address();
  // fdt_fixups(fdt);
  return 0;
}
/*
 * Initialize IPI for current HART.
 */
// static int generic_ipi_init(bool cold_boot) {
//   int ret;
//
//   if (cold_boot) {
//     ret = aclint_mswi_cold_init(&mswi);
//     if (ret)
//       return ret;
//   }
//
//   return aclint_mswi_warm_init();
// }

static const struct fdt_match generic_match[] = {
    {.compatible = "riscv-virtio"},
    {.compatible = "riscv-virtio,qemu"},

    //    // NOTE: ADDED FOR SUPPORT?
    {.compatible = "milkv,pioneer"},
    {.compatible = "sophgo,sg2042"},

    {},
};

const struct platform_override generic = { //.ipi_init = generic_ipi_init,
    .match_table = generic_match,
    .final_init = generic_final_init};
