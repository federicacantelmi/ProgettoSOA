/*
*   File che contiene implementazione delle API invocabili dallo user
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/cred.h>

#include "snapshot_api.h"
#include "snapshot_auth.h"
#include "snapshot.h"

#define MODNAME "SNAPSHOT MOD"

int activate_snapshot(const char *dev_name, const char *password) {

    int ret;
    ret = check_auth(password);
    if (ret < 0) {
        printk(KERN_ERR "%s: authentication failed\n", MODNAME);
        return -EACCES;
    }

    printk(KERN_INFO "%s: authentication successful\n", MODNAME);
    return snapshot_add_device(dev_name);
}

int deactivate_snapshot(const char *dev_name, const char *password) {

    int ret;
    ret = check_auth(password);
    if (ret < 0) {
        printk(KERN_ERR "%s: authentication failed\n", MODNAME);
        return -EACCES;
    }

    printk(KERN_INFO "%s: authentication successful\n", MODNAME);
    return snapshot_remove_device(dev_name);
}

int restore_snapshot(const char *dev_name, const char *password) {

    int ret;
    ret = check_auth(password);
    if (ret < 0) {
        printk(KERN_ERR "%s: authentication failed\n", MODNAME);
        return -EACCES;
    }

    printk(KERN_INFO "%s: authentication successful\n", MODNAME);
    return snapshot_restore_device(dev_name);
}