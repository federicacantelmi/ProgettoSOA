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

#define MODNAME "SNAPSHOT MOD"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Federica Cantelmi");

// parametro password per autenticazione
static char *snapshot_password = NULL;
module_param(snapshot_password, charp, 0000);
MODULE_PARM_DESC(snapshot_password, "Password for snapshot authentication");

int init_module(void) {
    int ret;

    if (!snapshot_password) {
        printk(KERN_ERR "No password passed");
        return -EINVAL;
    }

    // inizializzazione sistema auth
    ret = auth_init(snapshot_password);
    if(ret) {
        printk("%s: failed to initialize auth system\n", MODNAME);
        return ret;
    }
    memset(snapshot_password, 0, strlen(snapshot_password));

    // registrazione char device

    // inizializzazione struttura snapshot

    // inizializzazione kprobes

    printk(KERN_INFO "Modulo snapshot: caricamento riuscito\n");

    return 0;
}

void cleanup_module(void) {


    // cleanup sistema auth
    cleanup_auth();

    // deregistrazione char device

    // cleanup struttura snapshot

    // cleanup kprobes

    printk(KERN_INFO "Modulo snapshot: rimozione riuscita\n");


}

