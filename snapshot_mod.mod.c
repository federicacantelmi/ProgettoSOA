#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x64f48f75, "filp_open" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0x8d522714, "__rcu_read_lock" },
	{ 0x656e4a6e, "snprintf" },
	{ 0xc5b6f236, "queue_work_on" },
	{ 0x69acdf38, "memcpy" },
	{ 0x37a0cba, "kfree" },
	{ 0x71ba2490, "pcpu_hot" },
	{ 0x2102ba16, "kern_path_create" },
	{ 0xba8fbd64, "_raw_spin_lock" },
	{ 0x75743af2, "path_put" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x5ed9c4e5, "crypto_destroy_tfm" },
	{ 0x122c3a7e, "_printk" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xa916b694, "strnlen" },
	{ 0xf0914569, "__brelse" },
	{ 0x2469810f, "__rcu_read_unlock" },
	{ 0x4c03a563, "random_kmalloc_seed" },
	{ 0x5a921311, "strncmp" },
	{ 0x87b77d87, "unregister_kretprobe" },
	{ 0x9166fada, "strncpy" },
	{ 0x8255d16e, "__bread_gfp" },
	{ 0x65929cae, "ns_to_timespec64" },
	{ 0xfb578fc5, "memset" },
	{ 0x8e50f680, "kern_path" },
	{ 0xbdf86743, "param_ops_charp" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xca156ea0, "vfs_rmdir" },
	{ 0xdd64e639, "strscpy" },
	{ 0x28aa6a67, "call_rcu" },
	{ 0x55c48a5a, "crypto_shash_final" },
	{ 0xeaa78587, "filp_close" },
	{ 0xf4cc6a9a, "__register_chrdev" },
	{ 0xfff5afc, "time64_to_tm" },
	{ 0x984866c0, "register_kretprobe" },
	{ 0x41ed3709, "get_random_bytes" },
	{ 0x22e14f04, "kmalloc_trace" },
	{ 0x54b1fac6, "__ubsan_handle_load_invalid_value" },
	{ 0x754d539c, "strlen" },
	{ 0x9bfe5c14, "crypto_alloc_shash" },
	{ 0xb5b54b34, "_raw_spin_unlock" },
	{ 0xc4f0da12, "ktime_get_with_offset" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x37a99944, "kmalloc_caches" },
	{ 0xb2c57545, "kernel_write" },
	{ 0x2d3385d3, "system_wq" },
	{ 0x6bc3fbc0, "__unregister_chrdev" },
	{ 0xc6227e48, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "E524DF053B42B7B423C965A");
