#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

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
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0xf9a482f9, "msleep" },
	{ 0x92997ed8, "_printk" },
	{ 0xb3f7646e, "kthread_should_stop" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x311eb2b7, "crypto_skcipher_encrypt" },
	{ 0xb5fff121, "crypto_skcipher_decrypt" },
	{ 0x25974000, "wait_for_completion" },
	{ 0x608741b5, "__init_swait_queue_head" },
	{ 0xe060ab1a, "crypto_alloc_skcipher" },
	{ 0x267fef80, "crypto_destroy_tfm" },
	{ 0xaf8ad12e, "crypto_req_done" },
	{ 0x41ed3709, "get_random_bytes" },
	{ 0x1fff517c, "crypto_skcipher_setkey" },
	{ 0xd0760fc0, "kfree_sensitive" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0x37a0cba, "kfree" },
	{ 0xb320cc0e, "sg_init_one" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0xf301d0c, "kmalloc_caches" },
	{ 0x35789eee, "kmem_cache_alloc_trace" },
	{ 0x167c5967, "print_hex_dump" },
	{ 0xfb578fc5, "memset" },
	{ 0x3f5af94, "kthread_create_on_node" },
	{ 0xe1b800b, "wake_up_process" },
	{ 0x952d5a34, "kthread_stop" },
	{ 0xd43859f2, "param_ops_uint" },
	{ 0xb4b19daa, "param_ops_charp" },
	{ 0x541a6db8, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "500E2E254A6428CB1AD333B");
