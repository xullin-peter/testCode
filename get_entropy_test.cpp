#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/random.h>
#define NUM 10
 

void get_random_bytes(void *buf, int nbytes); 

static int get_random_number(void)
{
	unsigned long randNum[10];
	int i = 0;
 
	print(KERN_ALERT "Get some real random number.\n");
	for (i=0; i<NUM; i++)
	{
		get_random_bytes(&randNum[i], sizeof(unsigned long));
		print(KERN_ALERT "We get random number: %ld\n", randNum[i]);
	}
	return 0;
}

static void random_exit(void)
{
	print(KERN_ALERT "quit get_random_num.\n");
}
 
int main()
{
    get_random_num();
    random_exit();
}

module_init(get_random_number);
module_exit(random_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Test");
