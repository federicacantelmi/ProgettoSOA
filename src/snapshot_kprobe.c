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

    struct dentry *ret_dentry = (struct dentry *)regs_return_value(regs);

    if(!ret_dentry || IS_ERR(ret_dentry)) {
        printk(KERN_ERR "%s: mount_bdev failed\n", MODNAME);
        return 0;
    }

    printk(KERN_INFO "%s: mount_bdev intercepted\n", MODNAME);

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

    printk(KERN_INFO "%s: timestamp for snapshot directory: %s\n", MODNAME, timestamp);

    ret = snapshot_handle_mount(ret_dentry, timestamp);
    printk(KERN_INFO "%s: snapshot_handle_mount returned %d\n", MODNAME, ret);

    if (ret < 0) {
        printk(KERN_ERR "%s: snapshot_handle_mount failed\n", MODNAME);
        return ret;
    }
    return 0;
}


/*
*   Pre-handler per la kretprobe di kill_block_super -> serve pre-handler in cui prelevo dev_t e lo salvo
*   da qualche parte, poi nel post-handler invoco l'handler in snapshot.c per eliminarlo
*/
static int kprobe_unmount_bdev_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct super_block *sb = (struct super_block *)regs->di;
    struct block_device *bdev;
    char d_name[SNAPSHOT_DEV_NAME_LEN];

    if (!sb || !sb->s_bdev) {
        printk(KERN_ERR "%s: super_block or block device is null in kprobe_unmount_bdev_entry_handler\n", MODNAME);
        return -EINVAL;
    }
    bdev = sb->s_bdev;
    if (!bdev) {
        printk(KERN_ERR "%s: block device is null in kprobe_unmount_bdev_entry_handler\n", MODNAME);
        return -EINVAL;
    }

    int ret = snapshot_pre_handle_umount(bdev, d_name);
    if (ret < 0) {
        printk(KERN_ERR "%s: snapshot_pre_handle_umount failed, error=%d\n", MODNAME, ret);
        return ret;
    }

    memcpy(ri->data, d_name, sizeof(d_name)); // Copia il puntatore sb nel buffer data

    return 0;
}

/*
*   Handler della kretprobe per la kill_block_super.
*/
static int kprobe_unmount_bdev_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

    char d_name[SNAPSHOT_DEV_NAME_LEN];
    int ret;

    memcpy(d_name, ri->data, sizeof(d_name)); // Recupera il puntatore sb dal buffer data

    ret = snapshot_handle_unmount(d_name);
    if (ret < 0) {
        // printk(KERN_ERR "%s: snapshot_handle_unmount failed for device (major=%d, minor=%d), error=%d\n", MODNAME, MAJOR(dev), MINOR(dev), ret);
        printk(KERN_ERR "%s: snapshot_handle_unmount failed for device %s, error=%d\n", MODNAME, d_name, ret);
        return ret;
    }

    printk(KERN_INFO "%s: snapshot_handle_unmount completed successfully for device %s\n", MODNAME, d_name);
    return ret;
}

static int kprobe_pre_modify_block_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct buffer_head *bh = (struct buffer_head *)regs_return_value(regs);
    int ret;

    if(!bh) {
        printk(KERN_INFO "%s: buffer_head is null in kprobe_pre_modify_block_handler\n", MODNAME);
        return 0;
    }
    if(!bh->b_bdev) {
        printk(KERN_INFO "%s: buffer_head has no block device in kprobe_pre_modify_block_handler\n", MODNAME);
        return 0;
    }

    printk(KERN_INFO "%s: pre_modify_block_handler called for buffer_head at block %llu\n", MODNAME, (unsigned long long)bh->b_blocknr);

    ret = snapshot_add_block(bh);
    if (ret < 0) {
        printk(KERN_ERR "%s: snapshot_add_block failed for buffer_head at block %llu, error=%d\n", MODNAME, (unsigned long long)bh->b_blocknr, ret);
        return ret;
    }

    printk(KERN_INFO "%s: pre_modify_block_handler completed successfully for buffer_head at block %llu\n", MODNAME, (unsigned long long)bh->b_blocknr);
    return 0;
}

static int entry_kprobe_post_modify_block_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct buffer_head *bh = (struct buffer_head *)regs->di;

    if(!bh) {
        printk(KERN_INFO "%s: buffer_head is null in entry_kprobe_post_modify_block_handler\n", MODNAME);
        return 0;
    }
    if(!bh->b_bdev) {
        printk(KERN_INFO "%s: buffer_head has no block device in entry_kprobe_post_modify_block_handler\n", MODNAME);
        return 0;
    }

    memcpy(ri->data, &bh, sizeof(struct buffer_head *)); 

    printk(KERN_INFO "%s: entry_post_modify_block_handler called for buffer_head at block %llu\n", MODNAME, (unsigned long long)bh->b_blocknr);
    return 0;
}

static int ret_kprobe_post_modify_block_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

    struct buffer_head *bh;
    memcpy(&bh, ri->data, sizeof(struct buffer_head *));
    if(!bh) {
        printk(KERN_INFO "%s: buffer_head is null in ret_kprobe_post_modify_block_handler\n", MODNAME);
        return 0;
    }
    if(!bh->b_bdev) {
        printk(KERN_INFO "%s: buffer_head has no block device in ret_kprobe_post_modify_block_handler\n", MODNAME);
        return 0;
    }

    printk(KERN_INFO "%s: post_modify_block_handler called for buffer_head at block %llu\n", MODNAME, (unsigned long long)bh->b_blocknr);

    int ret = snapshot_save_block(bh);
    if (ret < 0) {
        printk(KERN_ERR "%s: snapshot_save_block failed for buffer_head at block %llu, error=%d\n", MODNAME, (unsigned long long)bh->b_blocknr, ret);
        return ret;
    }
    printk(KERN_INFO "%s: post_modify_block_handler completed successfully for buffer_head at block %llu\n", MODNAME, (unsigned long long)bh->b_blocknr);

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
    .data_size = SNAPSHOT_DEV_NAME_LEN, 
};


/*
*   Struttura kretprobe per gestire la modifica di un blocco.
*/

static struct kretprobe kprobe_pre_modify_block = {
    .kp.symbol_name = "__bread_gfp",
    .handler = kprobe_pre_modify_block_handler,
};

static struct kretprobe kprobe_post_modify_block = {
    .kp.symbol_name = "write_dirty_buffer",
    .entry_handler = entry_kprobe_post_modify_block_handler,
    .handler = ret_kprobe_post_modify_block_handler,
    .data_size = sizeof(struct buffer_head *),
};


// #ifdef USE_WDB
// static struct kretprobe kprobe_block_modified = {
//     .kp.symbol_name = "blk_mq_submit_bio",
//     .entry_handler = kprobe_block_modified_handler,
// };
// #endif // USE_WDB




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
    
    ret = register_kretprobe(&kprobe_pre_modify_block);
    if(ret) {
        printk(KERN_ERR "%s: register_kretprobe for block_modified failed, error=%d\n", MODNAME, ret);
        unregister_kretprobe(&kprobe_mount_bdev);
        unregister_kretprobe(&kprobe_unmount_bdev);
        return ret;
    }
    printk(KERN_INFO "%s: kprobe_block_modified registered successfully\n", MODNAME);

    ret = register_kretprobe(&kprobe_post_modify_block);
    if(ret) {
        printk(KERN_ERR "%s: register_kretprobe for post_modify_block failed, error=%d\n", MODNAME, ret);
        unregister_kretprobe(&kprobe_mount_bdev);
        unregister_kretprobe(&kprobe_unmount_bdev);
        unregister_kretprobe(&kprobe_pre_modify_block);
        return ret;
    }
    printk(KERN_INFO "%s: kprobe_post_modify_block registered successfully\n", MODNAME);

    /*
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
*/
    return 0;
}


/*
*   Deregistra kretprobes
*/
void kprobes_cleanup(void) {
    unregister_kretprobe(&kprobe_mount_bdev);
    unregister_kretprobe(&kprobe_unmount_bdev);
    unregister_kretprobe(&kprobe_pre_modify_block);
    unregister_kretprobe(&kprobe_post_modify_block);

    printk(KERN_INFO "%s: kprobes cleaned up successfully\n", MODNAME);
}