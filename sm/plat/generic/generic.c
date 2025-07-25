
#include <platform_override.h>
#include <sbi_utils/fdt/fdt_fixup.h>
#include <sbi_utils/fdt/fdt_helper.h>

#include "sm.h"

static int generic_final_init(bool cold_boot, const struct fdt_match *match) {
  sm_init(cold_boot);
  return 0;
}

static const struct fdt_match generic_match[] = {
    {.compatible = "riscv-virtio"},
    {.compatible = "riscv-virtio,qemu"},

    //    // NOTE: ADDED FOR SUPPORT?
    {.compatible = "milkv,pioneer"},
    {.compatible = "sophgo,sg2042"},

    {},
};

const struct platform_override generic = {.match_table = generic_match,
                                          .final_init = generic_final_init};
