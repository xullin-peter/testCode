#include <crypto/skcipher.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/time.h>
static char *alg = NULL;
static unsigned int keylen = 16;
static unsigned int testlen = 16;
static unsigned int type = 0;
//static wait_queue_head_t wait_queue;
struct task_struct *task[10];
struct task_struct *task_time = NULL;
static unsigned long long g_unTotalLength = 0;
static unsigned int g_unTotalTimes = 0;
/* tie all data structures together */
struct skcipher_def {
	struct scatterlist sg;
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct crypto_wait wait;
};
/* Perform cipher operation */
static unsigned int test_skcipher_encdec(struct skcipher_def *sk,
		int enc)
{
	int rc;
	if (enc)
		rc = crypto_wait_req(crypto_skcipher_encrypt(sk->req), &sk->wait);
	else
		rc = crypto_wait_req(crypto_skcipher_decrypt(sk->req), &sk->wait);
	if (rc)
		pr_info("skcipher encrypt returned with result %d\n", rc);
	return rc;
}
/* Initialize and trigger cipher operation */
static long test_skcipher(void)
{
	struct skcipher_def sk;
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	struct scatterlist sg[4];
	unsigned int datalen = 16;
	unsigned int iv_len = 0;
	unsigned char *scratchpad = NULL;
	unsigned char *endata = NULL;
	unsigned char *dedata = NULL;
	unsigned char ivdata[128];
	unsigned char data[16] = {"0123456789123456"};
	unsigned char key[32] = {"12345678123456781234567812345678"};
	int ret = -EFAULT;
	//char *driver = "cbc-aes-aesni";
	char *driver = "cbc(sm4)";
	
	if(alg)
		driver = alg;
	crypto_init_wait(&sk.wait);
	
	skcipher = crypto_alloc_skcipher(driver, 0, 0);
	if (IS_ERR(skcipher)) {
		pr_info("could not allocate skcipher handle\n");
		return PTR_ERR(skcipher);
	}
	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req) {
		pr_info("could not allocate skcipher request\n");
		ret = -ENOMEM;
		goto out;
	}
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
			CRYPTO_TFM_REQ_MAY_SLEEP,
			crypto_req_done, &sk.wait);
	crypto_skcipher_clear_flags(skcipher, ~0);
	/* AES 256 with random key */
	//get_random_bytes(&key, 32);
	if (crypto_skcipher_setkey(skcipher, key, keylen)) {
		pr_info("key could not be set\n");
		ret = -EAGAIN;
		goto out;
	}
	/* IV will be random */
	iv_len = crypto_skcipher_ivsize(skcipher);
	if (iv_len)
		memset(ivdata, 0xff, iv_len);
	/* Input data will be random */
	scratchpad = kmalloc(datalen, GFP_KERNEL);
	if (!scratchpad) {
		pr_info("could not allocate scratchpad\n");
		goto out;
	}
	memcpy(scratchpad, data, datalen);
	//get_random_bytes(scratchpad, datalen);
	//pr_info("plaindata len:%u\n", datalen);
	//print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET, 16, 1, scratchpad, datalen, false);
	endata = kmalloc(datalen, GFP_KERNEL);
	if (!endata) {
		pr_info("endata could not allocate scratchpad\n");
		goto out;
	}
	memset(endata, 0x00, datalen);
	dedata = kmalloc(datalen, GFP_KERNEL);
	if (!dedata) {
		pr_info("dedata could not allocate scratchpad\n");
		goto out;
	}
	memset(dedata, 0x00, datalen);
	sk.tfm = skcipher;
	sk.req = req;
	/* We encrypt one block */
	sg_init_one(&sg[0], scratchpad, datalen);
	sg_init_one(&sg[1], endata, datalen);
	skcipher_request_set_crypt(req, &sg[0], &sg[1], datalen, ivdata);
	/* encrypt data */
	ret = test_skcipher_encdec(&sk, 1);
	if (ret)
		goto out;
	pr_info("Encryption triggered successfully\n");
	pr_info("cipherdata len:%u\n", sg[1].length);
	print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET, 16, 1, endata, sg[1].length, false);
	/* decrypt data */
	crypto_skcipher_clear_flags(skcipher, ~0);
	iv_len = crypto_skcipher_ivsize(skcipher);
	if (iv_len)
		memset(ivdata, 0xff, iv_len);
	sg_init_one(&sg[2], endata, sg[1].length);
	sg_init_one(&sg[3], dedata, datalen);
	skcipher_request_set_crypt(req, &sg[2], &sg[3], sg[1].length, ivdata);
	ret = test_skcipher_encdec(&sk, 0);
	if (ret)
		goto out;
	
	pr_info("decrypt len:%u\n", sg[3].length);
	print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET, 16, 1, dedata, sg[3].length, false);
	//pr_info("decrypt len:%u, data:%s\n", sg[2].length, (char *)sg_virt(&sg[2]));
	pr_info("Decryption triggered successfully\n");
out:
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (req)
		skcipher_request_free(req);
	if (scratchpad)
		kfree(scratchpad);
	if (endata)
		kfree(endata);
	if (dedata)
		kfree(dedata);
	return ret;
}
static long test_encrypt_skcipher(void)
{
	struct skcipher_def sk;
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	struct scatterlist sg[4];
	unsigned int datalen = 16;
	unsigned int iv_len = 0;
	unsigned char *scratchpad = NULL;
	unsigned char *endata = NULL;
	unsigned char ivdata[128];
	//unsigned char data[16] = {"0123456789123456"};
	unsigned char key[32];// = {"12345678123456781234567812345678"};
	int ret = -EFAULT;
	//char *driver = "cbc-aes-aesni";
	char *driver = "cbc(sm4)";
	
	if(alg)
		driver = alg;
	if(testlen) {
		if(testlen%16) {
			pr_info("testlen[%u]  is not a multiple of 16\n", testlen);
			ret = -ENOMEM;
			goto out;
		}
		datalen = testlen;
	}
	
	crypto_init_wait(&sk.wait);
	
	skcipher = crypto_alloc_skcipher(driver, 0, 0);
	if (IS_ERR(skcipher)) {
		pr_info("could not allocate skcipher handle\n");
		return PTR_ERR(skcipher);
	}
	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req) {
		pr_info("could not allocate skcipher request\n");
		ret = -ENOMEM;
		goto out;
	}
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
			CRYPTO_TFM_REQ_MAY_SLEEP,
			crypto_req_done, &sk.wait);
	crypto_skcipher_clear_flags(skcipher, ~0);
	/* AES 256 with random key */
	get_random_bytes(&key, keylen);
	if (crypto_skcipher_setkey(skcipher, key, keylen)) {
		pr_info("key could not be set\n");
		ret = -EAGAIN;
		goto out;
	}
	/* IV will be random */
	iv_len = crypto_skcipher_ivsize(skcipher);
	if (iv_len)
		memset(ivdata, 0xff, iv_len);
	/* Input data will be random */
	scratchpad = kmalloc(datalen, GFP_KERNEL);
	if (!scratchpad) {
		pr_info("could not allocate scratchpad\n");
		goto out;
	}
	memset(scratchpad, 0xa, datalen);
	//get_random_bytes(scratchpad, datalen);
	//pr_info("plaindata len:%u\n", datalen);
	//print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET, 16, 1, scratchpad, datalen, false);
	endata = kmalloc(datalen, GFP_KERNEL);
	if (!endata) {
		pr_info("endata could not allocate scratchpad\n");
		goto out;
	}
	memset(endata, 0x00, datalen);
	sk.tfm = skcipher;
	sk.req = req;
	/* We encrypt one block */
	sg_init_one(&sg[0], scratchpad, datalen);
	sg_init_one(&sg[1], endata, datalen);
	skcipher_request_set_crypt(req, &sg[0], &sg[1], datalen, ivdata);
	/* encrypt data */
	ret = test_skcipher_encdec(&sk, 1);
	if (ret)
		goto out;
	//pr_info("Encryption triggered successfully\n");
	//pr_info("cipherdata len:%u\n", sg[1].length);
	//print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET, 16, 1, endata, sg[1].length, false);
out:
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (req)
		skcipher_request_free(req);
	if (scratchpad)
		kfree(scratchpad);
	if (endata)
		kfree(endata);
	return ret;
}
static long test_decrypt_skcipher(void)
{
	struct skcipher_def sk;
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	struct scatterlist sg[4];
	unsigned int datalen = 16;
	unsigned int iv_len = 0;
	unsigned char *scratchpad = NULL;
	unsigned char *dedata = NULL;
	unsigned char ivdata[128];
	//unsigned char data[16] = {"0123456789123456"};
	unsigned char key[32];// = {"12345678123456781234567812345678"};
	int ret = -EFAULT;
	//char *driver = "cbc-aes-aesni";
	char *driver = "cbc(sm4)";
	
	if(alg)
		driver = alg;
	if(testlen) {
		if(testlen%16) {
			pr_info("testlen[%u]  is not a multiple of 16\n", testlen);
			ret = -ENOMEM;
			goto out;
		}
		datalen = testlen;
	}
	crypto_init_wait(&sk.wait);
	
	skcipher = crypto_alloc_skcipher(driver, 0, 0);
	if (IS_ERR(skcipher)) {
		pr_info("could not allocate skcipher handle\n");
		return PTR_ERR(skcipher);
	}
	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req) {
		pr_info("could not allocate skcipher request\n");
		ret = -ENOMEM;
		goto out;
	}
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
			CRYPTO_TFM_REQ_MAY_SLEEP,
			crypto_req_done, &sk.wait);
	crypto_skcipher_clear_flags(skcipher, ~0);
	/* AES 256 with random key */
	get_random_bytes(&key, keylen);
	if (crypto_skcipher_setkey(skcipher, key, keylen)) {
		pr_info("key could not be set\n");
		ret = -EAGAIN;
		goto out;
	}
	/* IV will be 0xff */
	iv_len = crypto_skcipher_ivsize(skcipher);
	if (iv_len)
		memset(ivdata, 0xff, iv_len);
	/* Input data will be random */
	scratchpad = kmalloc(datalen, GFP_KERNEL);
	if (!scratchpad) {
		pr_info("could not allocate scratchpad\n");
		goto out;
	}
	memset(scratchpad, 0xa, datalen);
	dedata = kmalloc(datalen, GFP_KERNEL);
	if (!dedata) {
		pr_info("dedata could not allocate scratchpad\n");
		goto out;
	}
	memset(dedata, 0x00, datalen);
	sk.tfm = skcipher;
	sk.req = req;
	/* decrypt data */
	/* We encrypt one block */
	sg_init_one(&sg[2], scratchpad, datalen);
	sg_init_one(&sg[3], dedata, datalen);
	skcipher_request_set_crypt(req, &sg[2], &sg[3], datalen, ivdata);
	ret = test_skcipher_encdec(&sk, 0);
	if (ret)
		goto out;
	
	//pr_info("decrypt len:%u\n", sg[3].length);
	//print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET, 16, 1, dedata, sg[3].length, false);
	//pr_info("Decryption triggered successfully\n");
out:
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (req)
		skcipher_request_free(req);
	if (scratchpad)
		kfree(scratchpad);
	if (dedata)
		kfree(dedata);
	return ret;
}
static int thread_sm4Encrypt(void* data)
{
	struct skcipher_def sk;
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	struct scatterlist sg[4];
	unsigned int datalen = 16;
	unsigned int iv_len = 0;
	unsigned char *scratchpad = NULL;
	unsigned char *endata = NULL;
	unsigned char ivdata[128];
	//unsigned char data[16] = {"0123456789123456"};
	unsigned char key[32];// = {"12345678123456781234567812345678"};
	int ret = -EFAULT;
	//char *driver = "cbc-aes-aesni";
	char *driver = "cbc(sm4)";
	if(alg)
		driver = alg;
	if(testlen) {
		if(testlen%16) {
			pr_info("testlen[%u]  is not a multiple of 16\n", testlen);
			ret = -ENOMEM;
			goto out;
		}
		datalen = testlen;
	}
	crypto_init_wait(&sk.wait);
	skcipher = crypto_alloc_skcipher(driver, 0, 0);
	if (IS_ERR(skcipher)) {
		pr_info("could not allocate skcipher handle\n");
		return PTR_ERR(skcipher);
	}
	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req) {
		pr_info("could not allocate skcipher request\n");
		ret = -ENOMEM;
		goto out;
	}
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
			CRYPTO_TFM_REQ_MAY_SLEEP,
			crypto_req_done, &sk.wait);
	crypto_skcipher_clear_flags(skcipher, ~0);
	/* AES 256 with random key */
	get_random_bytes(&key, keylen);
	if (crypto_skcipher_setkey(skcipher, key, keylen)) {
		pr_info("key could not be set\n");
		ret = -EAGAIN;
		goto out;
	}
	/* IV will be random */
	iv_len = crypto_skcipher_ivsize(skcipher);
	if (iv_len)
		memset(ivdata, 0xff, iv_len);
	/* Input data will be random */
	scratchpad = kmalloc(datalen, GFP_KERNEL);
	if (!scratchpad) {
		pr_info("could not allocate scratchpad\n");
		goto out;
	}
	memset(scratchpad, 0xa, datalen);
	//get_random_bytes(scratchpad, datalen);
	//pr_info("plaindata len:%u\n", datalen);
	//print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET, 16, 1, scratchpad, datalen, false);
	endata = kmalloc(datalen, GFP_KERNEL);
	if (!endata) {
		pr_info("endata could not allocate scratchpad\n");
		goto out;
	}
	memset(endata, 0x00, datalen);
	sk.tfm = skcipher;
	sk.req = req;
	g_unTotalLength = 0;
	g_unTotalTimes = 0;
	
	while(!kthread_should_stop())
	{
		/* We encrypt one block */
		sg_init_one(&sg[0], scratchpad, datalen);
		sg_init_one(&sg[1], endata, datalen);
		skcipher_request_set_crypt(req, &sg[0], &sg[1], datalen, ivdata);
		/* encrypt data */
		ret = test_skcipher_encdec(&sk, 1);
		if (ret)
			pr_info("Encryption triggered failed\n");
		g_unTotalLength += datalen;
		g_unTotalTimes++;
		//msleep(1);
	}
out:
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (req)
		skcipher_request_free(req);
	if (scratchpad)
		kfree(scratchpad);
	if (endata)
		kfree(endata);
	return 0;
}
static int thread_sm4Decrypt(void* data)
{
	struct skcipher_def sk;
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	struct scatterlist sg[4];
	unsigned int datalen = 16;
	unsigned int iv_len = 0;
	unsigned char *scratchpad = NULL;
	unsigned char *dedata = NULL;
	unsigned char ivdata[128];
	//unsigned char data[16] = {"0123456789123456"};
	unsigned char key[32];// = {"12345678123456781234567812345678"};
	int ret = -EFAULT;
	//char *driver = "cbc-aes-aesni";
	char *driver = "cbc(sm4)";
	if(alg)
		driver = alg;
	if(testlen) {
		if(testlen%16) {
			pr_info("testlen[%u]  is not a multiple of 16\n", testlen);
			ret = -ENOMEM;
			goto out;
		}
		datalen = testlen;
	}
	crypto_init_wait(&sk.wait);
	skcipher = crypto_alloc_skcipher(driver, 0, 0);
	if (IS_ERR(skcipher)) {
		pr_info("could not allocate skcipher handle\n");
		return PTR_ERR(skcipher);
	}
	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req) {
		pr_info("could not allocate skcipher request\n");
		ret = -ENOMEM;
		goto out;
	}
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
			CRYPTO_TFM_REQ_MAY_SLEEP,
			crypto_req_done, &sk.wait);
	crypto_skcipher_clear_flags(skcipher, ~0);
	/* AES 256 with random key */
	get_random_bytes(&key, keylen);
	if (crypto_skcipher_setkey(skcipher, key, keylen)) {
		pr_info("key could not be set\n");
		ret = -EAGAIN;
		goto out;
	}
	/* IV will be 0xff */
	iv_len = crypto_skcipher_ivsize(skcipher);
	if (iv_len)
		memset(ivdata, 0xff, iv_len);
	/* Input data will be random */
	scratchpad = kmalloc(datalen, GFP_KERNEL);
	if (!scratchpad) {
		pr_info("could not allocate scratchpad\n");
		goto out;
	}
	memset(scratchpad, 0xa, datalen);
	dedata = kmalloc(datalen, GFP_KERNEL);
	if (!dedata) {
		pr_info("dedata could not allocate scratchpad\n");
		goto out;
	}
	memset(dedata, 0x00, datalen);
	sk.tfm = skcipher;
	sk.req = req;
	g_unTotalLength = 0;
	g_unTotalTimes = 0;
	
	while(!kthread_should_stop())
	{
		/* decrypt data */
		/* We encrypt one block */
		sg_init_one(&sg[2], scratchpad, datalen);
		sg_init_one(&sg[3], dedata, datalen);
		skcipher_request_set_crypt(req, &sg[2], &sg[3], datalen, ivdata);
		ret = test_skcipher_encdec(&sk, 0);
		if (ret)
			pr_info("Decryption triggered failed\n");
		g_unTotalLength += datalen;
		g_unTotalTimes++;
		//msleep(1);
	}
out:
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (req)
		skcipher_request_free(req);
	if (scratchpad)
		kfree(scratchpad);
	if (dedata)
		kfree(dedata);
	return 0;
}
static int thread_Encrypt(void* data)
{
	while(!kthread_should_stop())
	{
		test_encrypt_skcipher();
		g_unTotalLength += testlen;
		g_unTotalTimes++;
	}
	return 0;
}
static int thread_time(void* data)
{
	unsigned int unTotalTimesStart, nSpeedTps;
	unsigned long long unTotalLengthStart;
	unsigned long long dSpeedMbps;
	unsigned int sleeptime = 1000;
	unsigned int times = 5;
	long totalTimes = 0;
	//printk("------- jiffies[%lu] -----\n", jiffies);
	//init_waitqueue_head(&wait_queue);
	while(!kthread_should_stop())
	{
		//wait_event_interruptible_timeout(wait_queue, false, HZ);	
		unTotalLengthStart = g_unTotalLength;
		unTotalTimesStart = g_unTotalTimes;
		//printk("g_unTotalTimes:%u\n", g_unTotalTimes);
		//printk("g_unTotalLength:%llu\n", g_unTotalLength);
		msleep(sleeptime*times);
		//dSpeedMbps = (g_unTotalLength - unTotalLengthStart) / ((tvEnd - tvBegin)/HZ) / (1024 * 1024 / 8);
		dSpeedMbps = (g_unTotalLength - unTotalLengthStart) / times/ (1024 * 1024 / 8);
		nSpeedTps = (g_unTotalTimes - unTotalTimesStart)/ times;
		printk("+ <%lluMbps,%uTps>\n", dSpeedMbps, nSpeedTps);
		totalTimes += times;
	}
	dSpeedMbps = g_unTotalLength / times / (1024 * 1024 / 8);
	nSpeedTps = g_unTotalTimes/totalTimes;
	printk("g_unTotalTimes:%u\n", g_unTotalTimes);
	printk("g_unTotalLength:%llu\n", g_unTotalLength);
	printk("test time:%lds\n", totalTimes);
	printk("+ <%lluMbps,%uTps>\n", dSpeedMbps, nSpeedTps);
	return 0;
}
static int __init test_init(void)
{
	long ret = 0;
	switch(type)
	{
		case 0:
			task[0] = kthread_run(thread_sm4Encrypt, NULL, "mythreadsm4Encrypt");
			if(IS_ERR(task[0])){
				printk("thread_sm4Encrypt create failed!\n");
			}else{
				printk("thread_sm4Encrypt create success!\n");
			}
			break;
		case 1:
			task[1] = kthread_run(thread_sm4Decrypt, NULL, "mythreadsm4Decrypt");
			if(IS_ERR(task[1])){
				printk("thread_sm4Decrypt create failed!\n");
			}else{
				printk("thread_sm4Decrypt create success!\n");
			}
			break;
		case 2:
			task[2] = kthread_run(thread_Encrypt, NULL, "mythreadEncrypt");
			if(IS_ERR(task[2])){
				printk("thread_Encrypt create failed!\n");
			}else{
				printk("thread_Encrypt create success!\n");
			}
			break;
		default :
			break;
	}
	task_time = kthread_run(thread_time, NULL, "mythreadTime");
	if(IS_ERR(task_time)){
		printk("thread_time create failed!\n");
	}else{
		printk("thread_time create success!\n");
	}
	printk("info: init test\n");
	ret = test_skcipher();
	printk("test_skcipher return:%ld\n", ret);
	ret = test_encrypt_skcipher();
	printk("test_encrypt_skcipher return:%ld\n", ret);
	ret = test_decrypt_skcipher();
	printk("test_decrypt_skcipher return:%ld\n", ret);
	return 0;
}
static void __exit test_exit(void)
{
	switch(type)
	{
		case 0:
			if(!IS_ERR(task[0])) {     //这里判断指针是否正常
				kthread_stop(task[0]);
				task[0] = NULL;
				printk("thread0 finished!\n");
			}
			break;
		case 1:
			if(!IS_ERR(task[1])) {
				kthread_stop(task[1]);
				task[1] = NULL;
				printk("thread1 finished!\n");
			}
			break;
		case 2:
			if(!IS_ERR(task[2])) {
				kthread_stop(task[2]);
				task[2] = NULL;
				printk("thread2 finished!\n");
			}
			break;
		default :
			break;
	}
	if(!IS_ERR(task_time)) {
		kthread_stop(task_time);
		task_time = NULL;
		printk("thread_time finished!\n");
	}
	printk("info: exit test\n");
}
module_init(test_init);
module_exit(test_exit);
module_param(alg, charp, 0);
module_param(keylen, uint, 0);
module_param(testlen, uint, 0);
module_param(type, uint, 0);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("author@author.com");
