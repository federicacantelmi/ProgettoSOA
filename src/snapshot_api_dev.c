#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#include "snapshot_api.h"
#include "snapshot_api_dev.h"

#define DEVICE_NAME "snapshot_api_device"

static int major;

static long int snapshot_ioctl(struct file *file, unsigned cmd, unsigned long arg) {

    struct snapshot_cmd user_data;

    // copio argomenti passati dall'utente
    if(copy_from_user(&user_data, (void __user *)arg, sizeof(struct snapshot_cmd))) {
        // todo controlla ritorno quando invocata
        return -EFAULT;
    }
    switch(cmd) {
        case ACTIVATE_VALUE:
            return activate_snapshot(user_data.device_name, user_data.password);
        case DEACTIVATE_VALUE:
            return deactivate_snapshot(user_data.device_name, user_data.password);
        default:
        // todo controlla ritorno quando invocata
            return -EINVAL;
    }
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = snapshot_ioctl,
};

// Funzione per inizializzare il device per esporre le API activate e deactivate
int dev_init(void) {
    major = register_chrdev(0, DEVICE_NAME, &fops);
    if(major < 0) {
        // todo controlla ritorno in init
        return major;
    }
    return major;
}

// Funzione per deregistrare il device
void dev_cleanup(void) {
    unregister_chrdev(major, DEVICE_NAME);
}