/* 
*   Modulo per inizializzare architettura di8 snapshot
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/version.h>

#include "snapshot_auth.h"
#include "snapshot_api_dev.h"
#include "snapshot_kprobe.h"
#include "snapshot.h"

#define MODNAME "SNAPSHOT MOD"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Federica Cantelmi");

// parametro password per autenticazione
static char *snapshot_password = NULL;
module_param(snapshot_password, charp, 0000);
MODULE_PARM_DESC(snapshot_password, "Password for snapshot authentication");

int init_module(void) {
    int ret;

    printk("snapshot: 1\n");
    if (!snapshot_password) {
        printk(KERN_ERR "No password passed");
        return -EINVAL;
    }

    printk("snapshot: 2\n");
    // inizializzazione sistema auth
    ret = auth_init(snapshot_password);
    if(ret) {
        printk("%s: failed to initialize auth system\n", MODNAME);
        return ret;
    }
    printk("snapshot: 3\n");
    // memset(snapshot_password, 0, strlen(snapshot_password));

    
    printk("snapshot: 4\n");
    // registrazione char device
    ret = dev_init();
    printk("snapshot: 5\n");
    if(ret < 0) {
        cleanup_auth();
        printk(KERN_ERR "%s: dev_init failed\n", MODNAME);
        return ret;
    }
    printk(KERN_INFO "%s: device major = %d\n", MODNAME, ret);

    // inizializzazione struttura snapshot
    ret = snapshot_init();
    if(ret < 0) {
        cleanup_auth();
        dev_cleanup();
        printk(KERN_ERR "%s: snapshot_init failed\n", MODNAME);
        return ret;
    }

    // inizializzazione kprobes
    ret = kprobes_init();
    if(ret < 0) {
        cleanup_auth();
        dev_cleanup();
        snapshot_cleanup();

        printk(KERN_ERR "%s: kprobe_init failed\n", MODNAME);
        return ret;
    }


    printk(KERN_INFO "Modulo snapshot: caricamento riuscito\n");

    return 0;
}

void cleanup_module(void) {


    // cleanup sistema auth
    cleanup_auth();
    
    // deregistrazione char device
    dev_cleanup();

    // cleanup struttura snapshot
    snapshot_cleanup();
    
    // cleanup kprobes
    kprobes_cleanup();

    printk(KERN_INFO "Modulo snapshot: rimozione riuscita\n");


}

