#include <linux/kprobes.h>
#include <linux/timekeeping.h>
#include <linux/ktime.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/version.h>

#include "snapshot.h"
#include "snapshot_kprobe.h"

#define MODNAME "SNAPSHOT MOD"


DEFINE_PER_CPU(unsigned long, BRUTE_START);
DEFINE_PER_CPU(unsigned long *, kprobe_context_pointer);

static struct kretprobe setup_probe;

struct kretprobe *the_retprobe = &setup_probe;

void run_on_cpu(void *cpu);

static int the_search(struct kretprobe_instance *ri, struct pt_regs *regs);

static int kprobe_mount_bdev_handler(struct kretprobe_instance *ri, struct pt_regs *regs);

struct umount_data {
    char d_name[SNAPSHOT_DEV_NAME_LEN];
    dev_t dev;
};

static int kprobe_unmount_bdev_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs);
static int kprobe_unmount_bdev_handler(struct kretprobe_instance *ri, struct pt_regs *regs);

static int kprobe_pre_modify_block_handler(struct kretprobe_instance *ri, struct pt_regs *regs);
static int entry_kprobe_post_modify_block_handler(struct kretprobe_instance *ri, struct pt_regs *regs);
static int ret_kprobe_post_modify_block_handler(struct kretprobe_instance *ri, struct pt_regs *regs);

/* solo dichiarazioni: i campi si riempiono in kprobes_init() */
static struct kretprobe kprobe_mount_bdev;
static struct kretprobe kprobe_unmount_bdev;
static struct kretprobe kprobe_pre_modify_block;
static struct kretprobe kprobe_post_modify_block;


void run_on_cpu(void *cpu) {
    printk("%s: running on CPU %d\n", MODNAME, smp_processor_id());
    return;   
}

static atomic_t successful_search_counter = ATOMIC_INIT(0);

unsigned long *reference_offset = 0x0;
static int the_search(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    unsigned long *temp = (unsigned long *)&BRUTE_START;

    while (temp > 0) {
        temp -= 1;
        /* cerca la per-CPU che punta al current kprobe */
#ifndef CONFIG_KRETPROBE_ON_RETHOOK
        if ((unsigned long)__this_cpu_read(*temp) == (unsigned long)&ri->rp->kp) {
#else
        if ((unsigned long)__this_cpu_read(*temp) == (unsigned long)&the_retprobe->kp) {
#endif
            atomic_inc(&successful_search_counter);
            printk(KERN_INFO "%s: found kprobe context pointer at %p\n", MODNAME, temp);
            reference_offset = temp;
            break;
        }
        if(temp <= 0)
            return 1;
    }
    __this_cpu_write(kprobe_context_pointer, temp);
    return 0;
}

static int snapshot_kprobe_setup_init(void)
{
    int ret;

    setup_probe.kp.symbol_name = "run_on_cpu";
    setup_probe.handler = NULL;
    setup_probe.entry_handler  = (kretprobe_handler_t)the_search;
    setup_probe.maxactive      = -1;

    ret = register_kretprobe(&setup_probe);
    if (ret) return ret;

    // forza esecuzione su tutte le CPU per popolare i per-CPU
    get_cpu();
    smp_call_function((smp_call_func_t)run_on_cpu, NULL, 1);

    if (atomic_read(&successful_search_counter) < num_online_cpus() - 1 || !reference_offset) {
        put_cpu();
        unregister_kretprobe(&setup_probe);
        return -EINVAL; 
    }

    __this_cpu_write(kprobe_context_pointer, reference_offset);

    put_cpu();

    return 0;
}



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

    // OSS devo passare riferimento a the_retprobe ?? O lo metto in header
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
    struct umount_data *data;

    if (!sb || !sb->s_bdev) {
        printk(KERN_ERR "%s: super_block or block device is null in kprobe_unmount_bdev_entry_handler\n", MODNAME);
        return -EINVAL;
    }
    bdev = sb->s_bdev;
    if (!bdev) {
        printk(KERN_ERR "%s: block device is null in kprobe_unmount_bdev_entry_handler\n", MODNAME);
        return -EINVAL;
    }

    data = (struct umount_data *)ri->data;
    int ret = snapshot_pre_handle_umount(bdev, data->d_name);
    if (ret < 0) {
        printk(KERN_ERR "%s: snapshot_pre_handle_umount failed, error=%d\n", MODNAME, ret);
        return ret;
    }

    data->dev = bdev->bd_dev; // Salva major e minor del device

    return 0;
}


/*
*   Handler della kretprobe per la kill_block_super.
*/
static int kprobe_unmount_bdev_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

    struct umount_data *data = (struct umount_data *)ri->data;
    int ret;

    the_retprobe = &kprobe_unmount_bdev;
    ret = snapshot_handle_unmount(data->d_name, data->dev);
    if (ret < 0) {
        // printk(KERN_ERR "%s: snapshot_handle_unmount failed for device (major=%d, minor=%d), error=%d\n", MODNAME, MAJOR(dev), MINOR(dev), ret);
        printk(KERN_ERR "%s: snapshot_handle_unmount failed for device %s, error=%d\n", MODNAME, data->d_name, ret);
        return ret;
    }

    printk(KERN_INFO "%s: snapshot_handle_unmount completed successfully for device %s\n", MODNAME, data->d_name);
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
    .data_size = sizeof(struct umount_data),
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

    ret = snapshot_kprobe_setup_init();
    if(ret) {
        printk(KERN_ERR "%s: snapshot lprobe setup init failed, error=%d\n", MODNAME, ret);
        return ret;
    }

    ret = register_kretprobe(&kprobe_mount_bdev);

    if(ret) {
        printk(KERN_ERR "%s: register_kretprobe for mount_bdev failed, error=%d\n", MODNAME, ret);
        return ret;
    }
    printk(KERN_INFO "%s: kprobe_mount_bdev registered successfully\n", MODNAME);

    the_retprobe = &kprobe_mount_bdev;

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
    unregister_kretprobe(&setup_probe);
    unregister_kretprobe(&kprobe_mount_bdev);
    unregister_kretprobe(&kprobe_unmount_bdev);
    unregister_kretprobe(&kprobe_pre_modify_block);
    unregister_kretprobe(&kprobe_post_modify_block);

    printk(KERN_INFO "%s: kprobes cleaned up successfully\n", MODNAME);
}