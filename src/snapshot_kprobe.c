#include <linux/kprobes.h>
#include <linux/timekeeping.h>
#include <linux/ktime.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/blkdev.h>


#include "snapshot.h"
#include "snapshot_kprobe.h"

#define MODNAME "SNAPSHOT MOD"

#define SNAPSHOT_SYNC

#ifdef SNAPSHOT_SYNC
    #define PROBE_TARGET "write_dirty_buffer"
#else
    #define PROBE_TARGET "__bread_gfp"
#endif

/*
*   Handler della kretprobe per la mount_bdev.
*   Usa kretprobe così la mount_bdev termina e si può controllare se ha avuto successo
*   o è fallita.
*/
static int kprobe_mount_bdev_handler(struct kretprobe_instance *kp, struct pt_regs *regs) {

    int ret;
    char timestamp[64];
    struct tm tm;

    struct dentry *ret_dentry = (struct dentry *)regs_return_value(regs);

    if(!ret_dentry || IS_ERR(ret_dentry)) {
        printk(KERN_ERR "%s: mount_bdev failed\n", MODNAME);
        return 0;
    }

    time64_t timestamp_s = ktime_to_timespec64(ktime_get_real()).tv_sec;
    time64_to_tm(timestamp_s, 0, &tm);

    // Formatta in stringa YYYY-MM-DD_HH:mm:SS
    snprintf(timestamp, 64, "%04ld-%02d-%02d_%02d:%02d:%02d",
        tm.tm_year+1900,
        tm.tm_mon+1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec);

    ret = snapshot_handle_mount(ret_dentry, timestamp);

    if (ret < 0) {
        printk(KERN_ERR "%s: snapshot_handle_mount failed\n", MODNAME);
    }
    return ret;
}


/*
*   Pre-handler per la kretprobe di kill_block_super -> serve pre-handler in cui prelevo dev_t e lo salvo
*   da qualche parte, poi nel post-handler invoco l'handler in snapshot.c per eliminarlo
*/
// static int kprobe_unmount_bdev_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
//     struct super_block *sb = (struct super_block *)regs->di;
//     memcpy(ri->data, &sb, sizeof(sb)); // Copia il puntatore sb nel buffer data
//     return 0;
// }


/*
*   Handler della kretprobe per la kill_block_super.
*/
static int kprobe_unmount_bdev_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

    struct block_device *bdev;
    // dev_t dev;
    int ret;
    struct super_block *sb;

    // memcpy(&sb, ri->data, sizeof(sb)); // Recupera il puntatore sb dal buffer data
    // if(!sb || !sb->s_bdev) {
    //     return 0;
    // }

    // bdev = sb->s_bdev;
    // dev = bdev->bd_dev;

    sb = (struct super_block *)regs->di;
    if(!sb || !sb->s_bdev) {
        printk(KERN_ERR "%s: super_block or block device is null in kprobe_unmount_bdev_handler\n", MODNAME);
        return 0;
    }
    bdev = sb->s_bdev;

    ret = snapshot_handle_unmount(bdev);
    // todo controlla ret
    // ret = snapshot_handle_unmount(dev);

    if (ret < 0) {
        // printk(KERN_ERR "%s: snapshot_handle_unmount failed for device (major=%d, minor=%d), error=%d\n", MODNAME, MAJOR(dev), MINOR(dev), ret);
        printk(KERN_ERR "%s: snapshot_handle_unmount failed for device (major=%d, minor=%d), error=%d\n", MODNAME, MAJOR(bdev->bd_dev), MINOR(bdev->bd_dev), ret);
        return ret;
    }

    return ret;
}


/*
*   Funzione che gestisce la scrittura di un blocco modificato.
*/
static int kprobe_modify_block_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct buffer_head *bh;
    int ret;

    bh = (struct buffer_head *)regs->di;
    if(!bh) {
        printk(KERN_ERR "%s: buffer_head is null in write_dirty_buffer_handler\n", MODNAME);
        return 0;
    }

#ifdef SNAPSHOT_SYNC
    if(buffer_dirty(bh)) {
        printk(KERN_INFO "%s: buffer is dirty\n", MODNAME);
        return 0;
    }
#endif

    ret = snapshot_handle_write(bh);
    if(ret < 0) {
        printk(KERN_ERR "%s: snapshot_handle_write failed, error=%d\n", MODNAME, ret);
        return ret;
    }
 
    return 0;
}

#ifdef SNAPSHOT_ASYNC
static int kprobe_post_modify_block_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct buffer_head *bh;
    int ret;

    bh = (struct buffer_head *)regs->di;
    if(!bh) {
        printk(KERN_ERR "%s: buffer_head is null in write_dirty_buffer_handler\n", MODNAME);
        return 0;
    }

    ret = snapshot_modify_block(bh);
    if(ret < 0) {
        printk(KERN_ERR "%s: snapshot_modify_block failed, error=%d\n", MODNAME, ret);
    }

    return 0;
}
#endif // SNAPSHOT_ASYNC


/*
*   Struttura kretprobe per intercettare mount_bdev e gestire il mount di un device
*/
static struct kretprobe kprobe_mount_bdev = {
    .kp.symbol_name = "mount_bdev",
    .handler = kprobe_mount_bdev_handler,
};


/*
*   Struttura kretprobe per intercettare kill_block_super e gestire l'unmount di un device
*/
static struct kretprobe kprobe_unmount_bdev = {
    .kp.symbol_name = "kill_block_super",
    .handler = kprobe_unmount_bdev_handler,
    // .entry_handler = kprobe_unmount_bdev_entry_handler,
    .data_size = sizeof(void *),
};


/*
*   Struttura kretprobe per gestire la modifica di un blocco.
*/
static struct kretprobe kprobe_modify_block = {
    .kp.symbol_name = PROBE_TARGET,
    #ifdef SNAPSHOT_SYNC
        .entry_handler = kprobe_modify_block_handler,
    #elif SNAPSHOT_ASYNC
        .handler = kprobe_modify_block_handler,
    #endif
};

#ifdef SNAPSHOT_ASYNC
static struct kretprobe kprobe_post_modify_block = {
    .kp.symbol_name = "write_dirty_buffer",
    .handler = kprobe_post_modify_block_handler,
};
#endif // SNAPSHOT_ASYNC

/*
*   Registrazione kretprobes
*/
int kprobes_init(void) {
    int ret;
    ret = register_kretprobe(&kprobe_mount_bdev);

    if(ret) {
        printk(KERN_ERR "%s: register_kretprobe for mount_bdev failed, error=%d\n", MODNAME, ret);
        return ret;
    }
    printk(KERN_INFO "%s: kprobe_mount_bdev registered successfully\n", MODNAME);

    ret = register_kretprobe(&kprobe_unmount_bdev);

    if(ret) {
        printk(KERN_ERR "%s: register_kretprobe for unmount_bdev failed, error=%d\n", MODNAME, ret);
        unregister_kretprobe(&kprobe_mount_bdev);
        return ret;
    }

    printk(KERN_INFO "%s: kprobe_unmount_bdev registered successfully\n", MODNAME);

    ret = register_kretprobe(&kprobe_modify_block);
    if(ret) {
        printk(KERN_ERR "%s: register_kretprobe for modify_block failed, error=%d\n", MODNAME, ret);
        unregister_kretprobe(&kprobe_mount_bdev);
        unregister_kretprobe(&kprobe_unmount_bdev);
        return ret;
    }

    printk(KERN_INFO "%s: kprobe_modify_block registered successfully\n", MODNAME);

#ifdef SNAPSHOT_ASYNC
    ret = register_kretprobe(&kprobe_post_modify_block);
    if(ret) {
        printk(KERN_ERR "%s: register_kretprobe for post_modify_block failed, error=%d\n", MODNAME, ret);
        unregister_kretprobe(&kprobe_mount_bdev);
        unregister_kretprobe(&kprobe_unmount_bdev);
        unregister_kretprobe(&kprobe_modify_block);
        return ret;
    }

    printk(KERN_INFO "%s: kprobe_post_modify_block registered successfully\n", MODNAME);
#endif // SNAPSHOT_ASYNC

    return 0;
}


/*
*   Deregistra kretprobes
*/
void kprobes_cleanup(void) {
    unregister_kretprobe(&kprobe_mount_bdev);
    unregister_kretprobe(&kprobe_unmount_bdev);
    unregister_kretprobe(&kprobe_modify_block);

#ifdef SNAPSHOT_ASYNC
    unregister_kretprobe(&kprobe_post_modify_block);
#endif // SNAPSHOT_ASYNC

    printk(KERN_INFO "%s: kprobes cleaned up successfully\n", MODNAME);
}