/*
 * s5k3l7_mipi_raw sensor driver placeholder.
 *
 * The s5k3l7_mipi_raw driver for tb8788p1 is not available in any public
 * alps tree. This stub keeps the build happy; devices fitted with the
 * s5k3l6 sensor (the primary source) work via the real s5k3l6 driver.
 */
#include <linux/module.h>
#include <linux/kernel.h>

static int __init s5k3l7_stub_init(void)
{
	pr_info("s5k3l7_mipi_raw: placeholder driver (no real sensor driver)\n");
	return 0;
}

static void __exit s5k3l7_stub_exit(void) { }

module_init(s5k3l7_stub_init);
module_exit(s5k3l7_stub_exit);
MODULE_LICENSE("GPL");
