#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/fs.h>          
#include <linux/errno.h>       
#include <linux/types.h>       
#include <linux/fcntl.h>       
#include <linux/moduleparam.h>
#include <linux/gpio.h>
#include <asm/uaccess.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/poll.h>

#include "ioctl_test.h"

#define gpioName(a,b) #a#b     //"led""0" == "led0"
#define GPIOLEDCNT 8
#define GPIOKEYCNT 8
#define OFF 0
#define ON 1

#define   LED_DEV_NAME            "ledkeydev"
#define   LED_DEV_MAJOR            230      
#define DEBUG 0
#define GPIOKEYGET 0

DECLARE_WAIT_QUEUE_HEAD(WaitQueue_Read);
static unsigned long ledvalue = 15;
static char * twostring = NULL;
static int sw_irq[8] = {0};
static char sw_no = 0;
module_param(ledvalue, ulong ,0);
module_param(twostring,charp,0);

static int gpioLed[GPIOLEDCNT] = {6,7,8,9,10,11,12,13};
static int gpioKey[GPIOKEYCNT] = {16,17,18,19,20,21,22,23};

static int gpioLedInit(void);
static void gpioLedSet(long);
static void gpioLedFree(void);
static int gpioKeyInit(void);
#if GPIOKEYGET
static int gpioKeyGet(void);
#endif
static void gpioKeyFree(void);
struct timer_list timerLed;

static void kerneltimer_registertimer(unsigned long timeover);
unsigned long timerVal;

static void kerneltimer_func(struct timer_list *t)
{
    gpioLedSet(ledvalue);
#if DEBUG
    //printk("ledvalue : %#04x\n",(unsigned int)(ledvalue));
#endif
    ledvalue = ~ledvalue & 0xff;
	mod_timer(t,get_jiffies_64() + timerVal);
}
static void kerneltimer_registertimer(unsigned long timeover)
{
    timer_setup( &timerLed,kerneltimer_func,0);
    timerLed.expires = get_jiffies_64() + timeover;  //10ms *100 = 1sec
    add_timer( &timerLed );
}







static int	gpioLedInit(void)
{
	int i;
	int ret = 0;
	for(i=0;i<GPIOLEDCNT;i++)
	{
		ret = gpio_request(gpioLed[i], gpioName(led,i));
		if(ret < 0) {
			printk("Failed Request gpio%d error\n", 6);
			return ret;
		}
	}
	for(i=0;i<GPIOLEDCNT;i++)
	{
		ret = gpio_direction_output(gpioLed[i], OFF);
		if(ret < 0) {
			printk("Failed direction_output gpio%d error\n", 6);
       	 return ret;
		}
	}
	return ret;
}

static void gpioLedSet(long val) 
{
	int i;
	for(i=0;i<GPIOLEDCNT;i++)
	{
		gpio_set_value(gpioLed[i], (val>>i) & 0x01);
	}
}
static void gpioLedFree(void)
{
	int i;
	for(i=0;i<GPIOLEDCNT;i++)
	{
		gpio_free(gpioLed[i]);
	}
}

static int gpioKeyInit(void) 
{
	int i;
	int ret=0;;
	for(i=0;i<GPIOKEYCNT;i++)
	{
		ret = gpio_request(gpioKey[i], gpioName(key,i));
		if(ret < 0) {
			printk("Failed Request gpio%d error\n", 6);
			return ret;
		}
	}
	for(i=0;i<GPIOKEYCNT;i++)
	{
		ret = gpio_direction_input(gpioKey[i]);
		if(ret < 0) {
			printk("Failed direction_output gpio%d error\n", 6);
       	 return ret;
		}
	}
	return ret;
}
#if GPIOKEYGET
static int	gpioKeyGet(void) 
{
	int i;
	int ret;
	int keyData=0;
	for(i=0;i<GPIOKEYCNT;i++)
	{
		ret=gpio_get_value(gpioKey[i]) << i;
		keyData |= ret;
	}
	return keyData;
}
#endif
static void gpioKeyFree(void) 
{
	int i;
	for(i=0;i<GPIOKEYCNT;i++)
	{
		gpio_free(gpioKey[i]);
	}
}

irqreturn_t sw_isr(int irq, void *unuse)
{
	int i;
	for(i=0;i<GPIOKEYCNT;i++)
	{
		if(irq == sw_irq[i])
		{
			sw_no = i+1;
			break;
		}
	}
	//printk("IRQ : %d, sw_no : %d\n",irq,sw_no);
	wake_up_interruptible(&WaitQueue_Read);
	return IRQ_HANDLED;
}
static int requestIrqInit(struct file *filp)
{
    int i;
    int result=0;
    for(i=0;i<GPIOKEYCNT;i++)
    {
        result = request_irq(sw_irq[i],sw_isr,IRQF_TRIGGER_RISING,gpioName(key,i),filp->private_data);
        if(result)
        {
            printk("#### FAILED Request irq %d. error : %d \n", sw_irq[i], result);
            break;
        }
    }
    return 0;
}

static void gpioKeyToIrq(void)
{
	int i;
    for (i = 0; i < GPIOKEYCNT; i++) {
        sw_irq[i] = gpio_to_irq(gpioKey[i]);
	}
}

static void gpioKeyFreeIrq(struct file* filp)
{
	int i;
	for (i = 0; i < GPIOKEYCNT; i++){
		free_irq(sw_irq[i],filp->private_data);
	}
}
static int ledkeydev_open (struct inode *inode, struct file *filp)
{
    keyled_data* data = NULL;
    int result = 0;
    int num0 = MAJOR(inode->i_rdev);
    int num1 = MINOR(inode->i_rdev);
    printk( "ledkeydev open -> major : %d\n", num0 );
    printk( "ledkeydev open -> minor : %d\n", num1 );

    result = gpioLedInit();
    if(result < 0)
        return result;     /* Device or resource busy */

    result = gpioKeyInit();
    if(result < 0)
        return result;     /* Device or resource busy */
    gpioKeyToIrq();

    data = kmalloc(sizeof(keyled_data),GFP_KERNEL);
    if(!data)
        return -ENOMEM;

    filp->private_data = data;
    requestIrqInit(filp);
    return 0;
}
static long ledkeydev_ioctl (struct file *filp, unsigned int cmd, unsigned long arg)
{
	keyled_data* data = filp->private_data;
    int err, size;
    if( _IOC_TYPE( cmd ) != IOCTLTEST_MAGIC ) return -EINVAL;
    if( _IOC_NR( cmd ) >= MAXNR ) return -EINVAL;

    size = _IOC_SIZE( cmd );
    if( size )
    {
        err = 0;
        if( _IOC_DIR( cmd ) & _IOC_READ )
            err = access_ok( (void *) arg, size );
        if( _IOC_DIR( cmd ) & _IOC_WRITE )
//          err = access_ok( VERIFY_READ , (void *) arg, size );
            err = access_ok( (void *) arg, size );
        if( !err ) return err;
    }
    switch( cmd )
    {
        case TIMER_START :
			if(!timer_pending(&timerLed))
			{
				kerneltimer_registertimer(data->timer_val);
			}
            break;
        case TIMER_STOP :
			if(timer_pending(&timerLed))
			{
		        del_timer(&timerLed);
			}
            break;
        case TIMER_VALUE :
            err = copy_from_user((void*)data,(void *)arg,(unsigned long)sizeof(keyled_data));
			if(data->timer_val==0)
			{
				break;
			}
			timerVal = data->timer_val;
			printk("timerval : %ld\n",timerVal);
			if(timer_pending(&timerLed))
			{
		        del_timer(&timerLed);
			}
			kerneltimer_registertimer(data->timer_val);
			break;
        default:
            err =-E2BIG;
            break;
    }
    return err;
}

static ssize_t ledkeydev_read(struct file *filp, char *buf, size_t count, loff_t *f_pos)
{
//	char kbuf;
	int ret;
#if DEBUG
    printk( "ledkeydev read -> buf : %08X, count : %08X \n", (unsigned int)buf, count );
#endif
//	kbuf = gpioKeyGet();     
	if(!(filp->f_flags & O_NONBLOCK))  //BLOCK Mode 
	{
  		if(sw_no == 0)
  			wait_event_interruptible(WaitQueue_Read,sw_no);
//  		wait_event_interruptible_timeout(WaitQueue_Read,sw_no,100); //100: 1/100 *100 = 1Sec
	}

	ret=copy_to_user(buf,&sw_no,count);
	sw_no = 0;
	if(ret < 0)
		return -ENOMEM;
    return count;
}

static ssize_t ledkeydev_write (struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
	char kbuf;
	int ret;
#if DEBUG
    //printk( "ledkeydev write -> buf : %08X, count : %08X \n", (unsigned int)buf, count );
#endif
	ret=copy_from_user(&kbuf,buf,count);
	ledvalue = kbuf;
	if(ret < 0)
		return -ENOMEM;
	gpioLedSet(ledvalue);
    return count;
}

static int ledkeydev_release (struct inode *inode, struct file *filp)
{
    printk( "ledkeydev release \n" );
	if(timer_pending(&timerLed))
	{
		del_timer(&timerLed);
	}   
	gpioLedSet(0);
    gpioLedFree();
    gpioKeyFreeIrq(filp);
    gpioKeyFree();
    if(filp->private_data)
        kfree(filp->private_data);
    return 0;
}

static unsigned int ledkeydev_poll(struct file * filp, struct poll_table_struct * wait)
{
	unsigned int mask = 0;
	//printk("_key : %u \n",(wait->_key & POLLIN));
	if(wait->_key & POLLIN)
		poll_wait(filp, &WaitQueue_Read, wait);
	if(sw_no > 0)
		mask = POLLIN;
	return mask;
}

static struct file_operations ledkeydev_fops =
{
    .owner    = THIS_MODULE,
    .open     = ledkeydev_open,     
    .read     = ledkeydev_read,     
    .write    = ledkeydev_write,    
	.unlocked_ioctl = ledkeydev_ioctl,
	.poll	  = ledkeydev_poll,
    .release  = ledkeydev_release,  
};

static int ledkeydev_init(void)
{
    int result=0;
    printk( "ledkeydev ledkeydev_init \n" );    

    result = register_chrdev( LED_DEV_MAJOR, LED_DEV_NAME, &ledkeydev_fops);
    if (result < 0) return result;
    return result;
}
static void ledkeydev_exit(void)
{
    printk( "ledkeydev ledkeydev_exit \n" );
    unregister_chrdev( LED_DEV_MAJOR, LED_DEV_NAME );
}

module_init(ledkeydev_init);
module_exit(ledkeydev_exit);

MODULE_AUTHOR("KCCI-AIOT KSH");
MODULE_DESCRIPTION("led key test module");
MODULE_LICENSE("Dual BSD/GPL");
