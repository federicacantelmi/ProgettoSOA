#include <linux/kprobes.h>
#include <linux/timekeeping.h>
#include <linux/ktime.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/blkdev.h>


#include "snapshot.h"
#include "snapshot_kprobe.h"

#define MODNAME "SNAPSHOT MOD"

/*
*   Handler della kretprobe per la mount_bdev.
*   Usa kretprobe così la mount_bdev termina e si può controllare se ha avuto successo
*   o è fallita.
*/
static int kprobe_mount_bdev_handler(struct kretprobe_instance *kp, struct pt_regs *regs) {

    int ret;
    char timestamp[64];
    struct tm tm;
    struct super_block *sb;

    struct dentry *ret_dentry = (struct dentry *)regs_return_value(regs);

    if(!ret_dentry || IS_ERR(ret_dentry)) {
        printk(KERN_ERR "%s: mount_bdev failed", MODNAME);
        return 0;
    }

    sb = ret_dentry->d_sb;
    if(!sb) {
        printk(KERN_ERR "%s: superblock is null", MODNAME);
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

    ret = snapshot_handle_mount(sb, timestamp);

    if (ret < 0) {
        printk(KERN_ERR "%s: snapshot_handle_mount failed for device with major=%d and minor=%d", MODNAME, MAJOR(sb->s_bdev->bd_dev), MINOR(sb->s_bdev->bd_dev));
    }
    return ret;
}


/*
*   Pre-handler per la kretprobe di kill_block_super -> serve pre-handler in cui prelevo dev_t e lo salvo
*   da qualche parte, poi nel post-handler invoco l'handler in snapshot.c per eliminarlo
*/
static int kprobe_unmount_bdev_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct super_block *sb = (struct super_block *)regs->di;
    memcpy(ri->data, &sb, sizeof(sb)); // Copia il puntatore sb nel buffer data
    return 0;
}


/*
*   Handler della kretprobe per la kill_block_super.
*/
static int kprobe_unmount_bdev_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

    struct block_device *bdev;
    dev_t dev;
    int ret;
    struct super_block *sb;

    memcpy(&sb, ri->data, sizeof(sb)); // Recupera il puntatore sb dal buffer data
    if(!sb || !sb->s_bdev) {
        return 0;
    }

    bdev = sb->s_bdev;
    dev = bdev->bd_dev;

    // todo controlla ret
    ret = snapshot_handle_unmount(dev);

    if (ret < 0) {
        printk(KERN_ERR "%s: snapshot_handle_unmount failed for device (major=%d, minor=%d), error=%d", MODNAME, MAJOR(dev), MINOR(dev), ret);
    }

    return ret;
}


/*
*   Funzione che gestisce la scrittura di un blocco modificato.
*/
static int kprobe_write_dirty_buffer_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct buffer_head *bh;
    sector_t b_blocknr;
    struct block_device *bdev;
    int ret;
    size_t size;

    bh = (struct buffer_head *)regs->di;
    if(!bh) {
        printk(KERN_ERR "%s: buffer_head is null in write_dirty_buffer_handler", MODNAME);
        return 0;
    }

    b_blocknr = bh->b_blocknr;
    bdev = bh->b_bdev;
    if(!bdev) {
        printk(KERN_ERR "%s: block_device is null in write_dirty_buffer_handler", MODNAME);
        return 0;
    }
    size = bh->b_size;

    ret = snapshot_handle_write(bdev, b_blocknr, size);
    if(ret < 0) {
        printk(KERN_ERR "%s: snapshot_handle_write failed for device (major=%d, minor=%d), error=%d", MODNAME, MAJOR(bdev->bd_dev), MINOR(bdev->bd_dev), ret);
        return ret;
    }
 
    return 0;
}


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
    .entry_handler = kprobe_unmount_bdev_entry_handler,
    .data_size = sizeof(void *),
};


/*
*   Struttura kretprobe per intercettare write_dirty_buffer e gestire la modifica di un blocco.
*   OSS: non uso kprobe su sb_bread perché non mi serve sapere quando un blocco viene letto,
*   ma quando viene scritto.
*/
static struct kretprobe kprobe_write_dirty_buffer = {
    .kp.symbol_name = "write_dirty_buffer",
    .entry_handler = kprobe_write_dirty_buffer_handler,
};


/*
*   Registrazione kretprobes
*/
int kprobes_init(void) {
    int ret;
    ret = register_kretprobe(&kprobe_mount_bdev);

    if(ret) {
        printk(KERN_ERR "%s: register_kretprobe for mount_bdev failed, error=%d", MODNAME, ret);
        return ret;
    }
    printk(KERN_INFO "%s: kprobe_mount_bdev registered successfully", MODNAME);

    ret = register_kretprobe(&kprobe_unmount_bdev);

    if(ret) {
        printk(KERN_ERR "%s: register_kretprobe for unmount_bdev failed, error=%d", MODNAME, ret);
        unregister_kretprobe(&kprobe_mount_bdev);
        return ret;
    }

    printk(KERN_INFO "%s: kprobe_unmount_bdev registered successfully", MODNAME);

    ret = register_kretprobe(&kprobe_write_dirty_buffer);
    if(ret) {
        printk(KERN_ERR "%s: register_kretprobe for write_dirty_buffer failed, error=%d", MODNAME, ret);
        unregister_kretprobe(&kprobe_mount_bdev);
        unregister_kretprobe(&kprobe_unmount_bdev);
        return ret;
    }

    printk(KERN_INFO "%s: kprobe_write_dirty_buffer registered successfully", MODNAME);

    return 0;
}


/*
*   Deregistra kretprobes
*/
void kprobes_cleanup(void) {
    unregister_kretprobe(&kprobe_mount_bdev);
    unregister_kretprobe(&kprobe_unmount_bdev);
    unregister_kretprobe(&kprobe_write_dirty_buffer);
    printk(KERN_INFO "%s: kprobes cleaned up successfully", MODNAME);
}