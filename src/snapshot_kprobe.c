/*
*   Questo file contiene le funzioni per gestire i kprobes per intercettare le operazioni di mount, unmount e modifica dei blocchi.
*/

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

/* Prototipi delle funzioni */
void run_on_cpu(void *cpu);
static int the_search(struct kretprobe_instance *ri, struct pt_regs *regs);

/* Funzioni di gestione per il mount */
static int kprobe_mount_bdev_handler(struct kretprobe_instance *ri, struct pt_regs *regs);

/* Struttura per i dati di unmount. */
struct umount_data {
    char d_name[SNAPSHOT_DEV_NAME_LEN];
    dev_t dev;
};

/* Funzioni di gestione per l'unmount */
static int kprobe_kill_super_block_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs);
static int kprobe_kill_super_block_handler(struct kretprobe_instance *ri, struct pt_regs *regs);

/* Funzioni di gestione per la modifica dei blocchi */
static int kprobe_bread_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs);
static int kprobe_write_dirty_buffer_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs);
static int kprobe_write_dirty_buffer_handler(struct kretprobe_instance *ri, struct pt_regs *regs);

/* solo dichiarazioni: i campi si riempiono in kprobes_init() */
static struct kretprobe kprobe_mount_bdev;
static struct kretprobe kprobe_kill_super_block;
static struct kretprobe kprobe_write_dirty_buffer;


void run_on_cpu(void *cpu) {
    printk("%s: running on CPU %d\n", MODNAME, smp_processor_id());
    return;   
}

static atomic_t successful_search_counter = ATOMIC_INIT(0);

unsigned long *reference_offset = 0x0;

/*
*   Funzione per cercare il puntatore al contesto del kprobe.
*/
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
            printk(KERN_DEBUG "%s: found kprobe context pointer at %p\n", MODNAME, temp);
            reference_offset = temp;
            break;
        }
        if(temp <= 0)
            return 1;
    }
    __this_cpu_write(kprobe_context_pointer, temp);
    return 0;
}


/*
*   Funzione di inizializzazione per il kprobe.
*/
static int snapshot_kprobe_setup_init(void)
{
    int ret;

    setup_probe.kp.symbol_name = "run_on_cpu";
    setup_probe.handler = NULL;
    setup_probe.entry_handler  = (kretprobe_handler_t)the_search;
    setup_probe.maxactive      = -1;

    ret = register_kretprobe(&setup_probe);
    if (ret) return ret;

    /* forza esecuzione su tutte le CPU per popolare i per-CPU */
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

    printk(KERN_DEBUG "%s: mount_bdev intercepted\n", MODNAME);

    time64_t timestamp_s = ktime_to_timespec64(ktime_get_real()).tv_sec;
    time64_to_tm(timestamp_s, 0, &tm);

    /* Formatta in stringa YYYY-MM-DD_HH:mm:SS */
    snprintf(timestamp, 64, "%04ld-%02d-%02d_%02d:%02d:%02d",
        tm.tm_year+1900,
        tm.tm_mon+1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec);

    printk(KERN_DEBUG "%s: timestamp for snapshot directory: %s\n", MODNAME, timestamp);

    ret = snapshot_handle_mount(ret_dentry, timestamp);
    printk(KERN_DEBUG "%s: snapshot_handle_mount returned %d\n", MODNAME, ret);

    if (ret < 0) {
        printk(KERN_ERR "%s: snapshot_handle_mount failed\n", MODNAME);
        return ret;
    }
    return 0;
}

/*
*   Pre-handler per la kretprobe di kill_block_super -> serve pre-handler in cui prelevo dev_t e lo salvo
*   da qualche parte, poi nel post-handler invoco l'handler in snapshot.c per eliminarlo.
*/
static int kprobe_kill_super_block_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct super_block *sb = (struct super_block *)regs->di;
    struct block_device *bdev;
    struct umount_data *data;

    if (!sb || !sb->s_bdev) {
        printk(KERN_ERR "%s: super_block or block device is null in kprobe_kill_super_block_entry_handler\n", MODNAME);
        return -EINVAL;
    }
    bdev = sb->s_bdev;
    if (!bdev) {
        printk(KERN_ERR "%s: block device is null in kprobe_kill_super_block_entry_handler\n", MODNAME);
        return -EINVAL;
    }

    data = (struct umount_data *)ri->data;
    int ret = snapshot_pre_handle_umount(bdev, data->d_name);
    if (ret < 0) {
        printk(KERN_ERR "%s: snapshot_pre_handle_umount failed, error=%d\n", MODNAME, ret);
        return ret;
    }

    data->dev = bdev->bd_dev;

    return 0;
}


/*
*   Handler della kretprobe per la kill_block_super.
*/
static int kprobe_kill_super_block_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

    struct umount_data *data = (struct umount_data *)ri->data;
    int ret;

    the_retprobe = &kprobe_kill_super_block;
    ret = snapshot_handle_unmount(data->d_name, data->dev);
    if (ret < 0) {
        printk(KERN_ERR "%s: snapshot_handle_unmount failed for device %s, error=%d\n", MODNAME, data->d_name, ret);
        return ret;
    }

    printk(KERN_DEBUG "%s: snapshot_handle_unmount completed successfully for device %s\n", MODNAME, data->d_name);
    return ret;
}


/*
*   Handler della kretprobe per la modifica di un blocco.
*   Viene chiamata prima della modifica del blocco, per salvare i dati del blocco
*   prima che vengano sovrascritti.
*/
static int kprobe_bread_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct buffer_head *bh = (struct buffer_head *)regs_return_value(regs);
    int ret;

    if(!bh) {
        printk(KERN_DEBUG "%s: buffer_head is null in kprobe_bread_ret_handler\n", MODNAME);
        return 0;
    }
    if(!bh->b_bdev) {
        printk(KERN_DEBUG "%s: buffer_head has no block device in kprobe_bread_ret_handler\n", MODNAME);
        return 0;
    }

    printk(KERN_DEBUG "%s: kprobe_bread_ret_handler called for buffer_head at block %llu\n", MODNAME, (unsigned long long)bh->b_blocknr);

    ret = snapshot_add_block(bh);
    if (ret < 0) {
        printk(KERN_ERR "%s: snapshot_add_block failed for buffer_head at block %llu, error=%d\n", MODNAME, (unsigned long long)bh->b_blocknr, ret);
        return ret;
    }

    printk(KERN_DEBUG "%s: kprobe_bread_ret_handler completed successfully for buffer_head at block %llu\n", MODNAME, (unsigned long long)bh->b_blocknr);
    return 0;
}


/*
*   Pre-handler della kretprobe per la modifica di un blocco.
*/
static int kprobe_write_dirty_buffer_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct buffer_head *bh = (struct buffer_head *)regs->di;

    if(!bh) {
        printk(KERN_DEBUG "%s: buffer_head is null in kprobe_write_dirty_buffer_entry_handler\n", MODNAME);
        return 0;
    }
    if(!bh->b_bdev) {
        printk(KERN_DEBUG "%s: buffer_head has no block device in kprobe_write_dirty_buffer_entry_handler\n", MODNAME);
        return 0;
    }

    memcpy(ri->data, &bh, sizeof(struct buffer_head *)); 

    printk(KERN_DEBUG "%s: kprobe_write_dirty_buffer_entry_handler called for buffer_head at block %llu\n", MODNAME, (unsigned long long)bh->b_blocknr);
    return 0;
}


/*
*   Post-handler della kretprobe per la modifica di un blocco.
*/
static int kprobe_write_dirty_buffer_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

    struct buffer_head *bh;
    memcpy(&bh, ri->data, sizeof(struct buffer_head *));
    if(!bh) {
        printk(KERN_DEBUG "%s: buffer_head is null in kprobe_write_dirty_buffer_handler\n", MODNAME);
        return 0;
    }
    if(!bh->b_bdev) {
        printk(KERN_DEBUG "%s: buffer_head has no block device in kprobe_write_dirty_buffer_handler\n", MODNAME);
        return 0;
    }

    printk(KERN_DEBUG "%s: kprobe_write_dirty_buffer_handler called for buffer_head at block %llu\n", MODNAME, (unsigned long long)bh->b_blocknr);

    int ret = snapshot_save_block(bh);
    if (ret < 0) {
        printk(KERN_ERR "%s: snapshot_save_block failed for buffer_head at block %llu, error=%d\n", MODNAME, (unsigned long long)bh->b_blocknr, ret);
        return ret;
    }
    printk(KERN_DEBUG "%s: kprobe_write_dirty_buffer_handler completed successfully for buffer_head at block %llu\n", MODNAME, (unsigned long long)bh->b_blocknr);

    return 0;
}


/* Struttura kretprobe per intercettare mount_bdev e gestire il mount di un device */
static struct kretprobe kprobe_mount_bdev = {
    .kp.symbol_name = "mount_bdev",
    .handler = kprobe_mount_bdev_handler,
};

/* Struttura kretprobe per intercettare kill_block_super e gestire l'unmount di un device. */
static struct kretprobe kprobe_kill_super_block = {
    .kp.symbol_name = "kill_block_super",
    .handler = kprobe_kill_super_block_handler,
    .entry_handler = kprobe_kill_super_block_entry_handler,
    .data_size = sizeof(struct umount_data),
};

/* Struttura kretprobe per gestire la modifica di un blocco. */
static struct kretprobe kprobe_bread_ret = {
    .kp.symbol_name = "__bread_gfp",
    .handler = kprobe_bread_ret_handler,
};

/* Struttura kretprobe per gestire la scrittura di un blocco modificato. */
static struct kretprobe kprobe_write_dirty_buffer = {
    .kp.symbol_name = "write_dirty_buffer",
    .entry_handler = kprobe_write_dirty_buffer_entry_handler,
    .handler = kprobe_write_dirty_buffer_handler,
    .data_size = sizeof(struct buffer_head *),
};


/*
*   Registrazione kprobes.
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

    ret = register_kretprobe(&kprobe_kill_super_block);

    if(ret) {
        printk(KERN_ERR "%s: register_kretprobe for kill_super_block failed, error=%d\n", MODNAME, ret);
        unregister_kretprobe(&kprobe_mount_bdev);
        return ret;
    }

    printk(KERN_INFO "%s: kprobe_kill_super_block registered successfully\n", MODNAME);

    ret = register_kretprobe(&kprobe_bread_ret);
    if(ret) {
        printk(KERN_ERR "%s: register_kretprobe for block_modified failed, error=%d\n", MODNAME, ret);
        unregister_kretprobe(&kprobe_mount_bdev);
        unregister_kretprobe(&kprobe_kill_super_block);
        return ret;
    }
    printk(KERN_INFO "%s: kprobe_bread_ret registered successfully\n", MODNAME);

    ret = register_kretprobe(&kprobe_write_dirty_buffer);
    if(ret) {
        printk(KERN_ERR "%s: register_kretprobe for write_dirty_buffer failed, error=%d\n", MODNAME, ret);
        unregister_kretprobe(&kprobe_mount_bdev);
        unregister_kretprobe(&kprobe_kill_super_block);
        unregister_kretprobe(&kprobe_bread_ret);
        return ret;
    }
    printk(KERN_INFO "%s: kprobe_write_dirty_buffer registered successfully\n", MODNAME);

    return 0;
}


/*
*   Deregistrazione kprobes.
*/
void kprobes_cleanup(void) {
    unregister_kretprobe(&setup_probe);
    unregister_kretprobe(&kprobe_mount_bdev);
    unregister_kretprobe(&kprobe_kill_super_block);
    unregister_kretprobe(&kprobe_bread_ret);
    unregister_kretprobe(&kprobe_write_dirty_buffer);

    printk(KERN_INFO "%s: kprobes cleaned up successfully\n", MODNAME);
}