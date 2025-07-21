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
// #include "snapshot.h"

int activate_snapshot(const char *dev_name, const char *password) {

    if(!check_auth(password)) {
        // inoltra printk
        return -EACCES;
    }

    // se autenticazione non fallisce -> aggiunge device alla lista
    // return snapshot_add_device(dev_name)
    return 0;
}

int deactivate_snapshot(const char *dev_name, const char *password) {

    if(!check_auth(password)) {
        // inoltra printk
        return -EACCES;
    }

    // se autenticazione non fallisce -> aggiunge device alla lista
    // return snapshot_remove_device(dev_name);
    return 0;
}