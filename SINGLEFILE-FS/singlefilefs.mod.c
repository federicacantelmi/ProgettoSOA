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
	{ 0x43e9e60c, "inode_init_owner" },
	{ 0x265c2a, "iget_locked" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0xeafb1cde, "unregister_filesystem" },
	{ 0xded4d643, "d_make_root" },
	{ 0xa54c164d, "write_dirty_buffer" },
	{ 0x237f782d, "iput" },
	{ 0x764d34c0, "register_filesystem" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0xb6f272f0, "kill_block_super" },
	{ 0xe4801d52, "unlock_new_inode" },
	{ 0x122c3a7e, "_printk" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xf0914569, "__brelse" },
	{ 0x57bc19d2, "down_write" },
	{ 0xce807a25, "up_write" },
	{ 0xd3fa4bc8, "set_nlink" },
	{ 0x9ec6ca96, "ktime_get_real_ts64" },
	{ 0x8255d16e, "__bread_gfp" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x6b10bee1, "_copy_to_user" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xca7f5127, "d_add" },
	{ 0xe6e53b72, "mount_bdev" },
	{ 0xd9b85ef6, "lockref_get" },
	{ 0xbc314156, "nop_mnt_idmap" },
	{ 0xc6227e48, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "F7F493BC47688471A2C732F");
