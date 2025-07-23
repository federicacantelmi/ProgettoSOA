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
*   Handler della kretprobe per la mount_bdev
*   Usa kretprobe così la mount_bdev termina e si può controllare se ha avuto successo
*   o è fallita
*/
static int kprobe_mount_bdev_handler(struct kretprobe_instance *kp, struct pt_regs *regs) {

    int ret;
    char *timestamp;
    struct tm tm;
    struct super_block *sb;
    struct block_device *bdev;
    const char *dev_name;
    struct gendisk *disk;
    dev_t dev;

    struct dentry *ret_dentry = (struct dentry *)regs_return_value(regs);

    if(!ret_dentry || IS_ERR(ret_dentry)) {
        printk(KERN_ERR "%s: mount_bdev failed", MODNAME);
        return 0;
    }

    sb = ret_dentry->d_sb;
    if(!sb || !sb->s_bdev) {
        printk(KERN_ERR "%s: superblock or bdev are null", MODNAME);
        return 0;
    }

    bdev = sb->s_bdev;
    disk = bdev->bd_disk;
    if(!disk) {
        printk(KERN_ERR "%s: bd_disk is null", MODNAME);
        return 0;
    }

    dev = bdev->bd_dev;
    dev_name = disk->disk_name;

    printk(KERN_INFO "%s: mount_bdev success -> device with major %d and minor %d mounted", MODNAME, MAJOR(dev), MINOR(dev));

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

    ret = snapshot_handle_mount(dev_name, dev, timestamp);

    // todo controlla ret
    return ret;
}

// todo kretprobe unmount
// OSS serve pre-handler in cui prelevo dev_t e lo salvo da qualche parte, poi nel post-handler invoco l'handler
// in snapshot.c per eliminarlo

static int kprobe_unmount_bdev_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

    struct super_block *sb = (struct super_block *)regs->di;
    ri->data = sb;
    return 0;
}

static int kprobe_mount_bdev_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

    struct block_device *bdev;
    dev_t dev;
    int ret;

    struct super_block *sb = (struct super_block *)ri->data;
    if(!sb || |sb->s_bdev) {
        return 0;
    }

    bdev = sb->s_bdev;
    dev = bdev->bd_dev;

    // todo controlla ret
    ret = snapshot_handle_unmount(dev);
    return ret;
}

static struct kretprobe kprobe_mount_bdev = {
    .kp.symbol_name = "mount_bdev",
    .handler = kprobe_mount_bdev_handler,
};

static struct kretprobe kprobe_unmount_bdev = {
    .kp.symbol_name = "kill_block_super",
    .handler = kprobe_unmount_bdev_handler,
    .entry_handler = kprobe_unmount_bdev_entry_handler,
    .data_size = sizeof(void *),
};

/*
*   Registra kretprobe per intercettare mount_bdev
*/
int kprobes_init(void) {
    int ret;
    ret = register_kretprobe(&kprobe_mount_bdev);

    if(ret) {
        // todo printk
        return ret;
    }

    ret = register_kretprobe(&kprobe_unmount_bdev);

    if(ret) {
        unregister_kretprobe(&kprobe_mount_bdev);
        // todo printk
        return ret;
    }

    return 0;
}

void kprobes_cleanup(void) {
    unregister_kretprobe(&kprobe_mount_bdev);
    unregister_kretprobe(&kprobe_unmount_bdev);
}