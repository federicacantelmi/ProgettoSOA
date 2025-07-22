#include <linux/kprobes.h>
#include <linux/timekeeping.h>
#include <linux/ktime.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/blkdev.h>


#include "snapshot.h"
#include "snapshot_kprobe.h"

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
        // todo printk mount_bdev fallito
        return 0;
    }

    sb = ret_dentry->d_sb;
    if(!sb || !sb->s_bdev) {
        // todo printk superblock o bdev null
        return 0;
    }

    bdev = sb->s_bdev;
    disk = bdev->bd_disk;
    if(!disk) {
        // todo printk bd_disk null
        return 0;
    }

    dev = bdev->bd_dev;
    dev_name = disk->disk_name;

    //todo printk mount_bdev success con minor e major

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

static struct kretprobe kprobe_mount_bdev = {
    .kp.symbol_name = "mount_bdev",
    .handler = kprobe_mount_bdev_handler,
};

/*
*   Registra kretprobe per intercettare mount_bdev
*/
int kprobe_mount_init(void) {
    return register_kretprobe(&kprobe_mount_bdev);
}

void kprobe_mount_cleanup(void) {
    unregister_kretprobe(&kprobe_mount_bdev);
}