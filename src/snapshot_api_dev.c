#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/cdev.h>

#include "snapshot_api.h"
#include "snapshot_api_dev.h"

#define DEVICE_NAME "snapshot_api_device"

static int major;
static struct class *snapshot_class = NULL;
static struct device *snapshot_device = NULL;

static int driver_open(struct inode *inode, struct file *file) {
    printk(KERN_INFO "%s: Device opened\n", DEVICE_NAME);
    return 0;
}

static int driver_release(struct inode *inode, struct file *file) {
    printk(KERN_INFO "%s: Device closed\n", DEVICE_NAME);
    return 0;
}

static long int snapshot_ioctl(struct file *file, unsigned cmd, unsigned long arg) {

    struct snapshot_cmd user_data;

    // copio argomenti passati dall'utente
    if(copy_from_user(&user_data, (void __user *)arg, sizeof(struct snapshot_cmd))) {
        // todo controlla ritorno quando invocata
        return -EFAULT;
    }
    switch(cmd) {
        case ACTIVATE_VALUE:
            if(strlen(user_data.device_name) == 0 || strlen(user_data.password) == 0) {
                printk(KERN_ERR "%s: Device name or password is empty\n", DEVICE_NAME);
                
                return -EINVAL;
            }
            printk(KERN_INFO "%s: Activating snapshot for device %s\n", DEVICE_NAME, user_data.device_name);
            
            return activate_snapshot(user_data.device_name, user_data.password);

        case DEACTIVATE_VALUE:
            if(strlen(user_data.device_name) == 0 || strlen(user_data.password) == 0) {
                printk(KERN_ERR "%s: Device name or password is empty\n", DEVICE_NAME);
                return -EINVAL;
            }

            printk(KERN_INFO "%s: Deactivating snapshot for device %s\n", DEVICE_NAME, user_data.device_name);

            return deactivate_snapshot(user_data.device_name, user_data.password);
// todo get devices
        default:
            printk(KERN_ERR "%s: Unknown ioctl command %u\n", DEVICE_NAME, cmd);
            return -EINVAL;
    }
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = driver_open,
    .release = driver_release,
    .unlocked_ioctl = snapshot_ioctl,
};

// Funzione per inizializzare il device per esporre le API activate e deactivate
int dev_init(void) {
    major = register_chrdev(0, DEVICE_NAME, &fops);
    if(major < 0) {
        printk(KERN_ERR "%s: Failed to register character device with error %d\n", DEVICE_NAME, major);
        return major;
    }

    // todo sostituisci poi NULL con THIS_MODULE
    snapshot_class = class_create(DEVICE_NAME);
    if(IS_ERR(snapshot_class)) {
        printk(KERN_ERR "%s: Failed to create class\n", DEVICE_NAME);
        unregister_chrdev(major, DEVICE_NAME);
        return PTR_ERR(snapshot_class);
    }

    snapshot_device = device_create(snapshot_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    if(IS_ERR(snapshot_device)) {
        printk(KERN_ERR "%s: Failed to create device\n", DEVICE_NAME);
        class_destroy(snapshot_class);
        unregister_chrdev(major, DEVICE_NAME);
        return PTR_ERR(snapshot_device);
    }
    printk(KERN_INFO "%s: Device registered with major number %d\n", DEVICE_NAME, major);
    return 0;
}
    

// Funzione per deregistrare il device
void dev_cleanup(void) {
    device_destroy(snapshot_class, MKDEV(major, 0));
    class_destroy(snapshot_class);
    unregister_chrdev(major, DEVICE_NAME);
}