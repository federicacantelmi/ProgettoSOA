#ifndef SNAPSHOT_H
#define SNAPSHOT_H

#include <linux/list.h>
#include <linux/types.h>
#include <linux/buffer_head.h>
#include <linux/kprobes.h>

#define MAX_DEVICES 32
#define SNAPSHOT_DEV_NAME_LEN 128
#define SNAPSHOT_DIR_PATH "/snapshot"
#define MAX_PATH_LEN 256

/**
*   Rappresenta un blocco di dati modificato su un device
*   @block_nr: numero del blocco;
*   @bdev: puntatore al block device;
*   @data: puntatore ai dati del blocco;
*   @size: dimensione del blocco in byte;
*   @list: list head per collegare i blocchi modificati;
*/
struct block {
    sector_t block_nr;
    struct block_device *bdev;
    void *data;
    size_t size;
    struct list_head list;
};

/**
*   Rappresenta un device montato su cui va eseguito lo snapshot
*   @dev_name: nome del device;
*   @dev: major e minor del device;
*   @sb: superblocco del device;
*   @dir_path: path della directory in cui salvare i blocchi modificati;
*   @block_bitmap: bitmap per i blocchi modificati: 0 se non modificato, 1 se modificato;
*   @bitmap_size: dimensione della bitmap in bit;
*   @list: list head per collegare device su cui eseguire snapshot;
*   @rcu_head: campo per la rimozione asincrona;
*   @deactivated: flag per indicare se è stato disattivato lo snapshot per quel device (allo smontaggio
*       il device viene rimosso completamente, non spostato alla lista dei device non attivi);
*   @restoring: flag per indicare se si sta ripristinando lo snapshot;
*   @block_list: lista dei blocchi acceduti;
*   @block_list_lock: lock per la lista dei blocchi modificati;
*   @wq: workqueue per gestire le scritture asincrone dei blocchi modificati;
*/
struct mounted_dev {
    char dev_name[SNAPSHOT_DEV_NAME_LEN];
    dev_t dev;
    struct super_block *sb;
    char dir_path[MAX_PATH_LEN];
    unsigned long *block_bitmap;
    size_t bitmap_size;
    unsigned long block_size;
    struct list_head list;
    struct rcu_head rcu_head;
    bool deactivated;
    bool restoring;
    struct list_head block_list;
    spinlock_t block_list_lock;
    struct workqueue_struct *wq;
};


/**
*   Rappresenta un device non ancora montato su cui va eseguito lo snapshot
*   @dev_name: nome del device;
*   @list: list head per collegare device su cui eseguire snapshot;
*   @rcu_head: campo per la rimozione asincrona;
*/
struct nonmounted_dev {
    char dev_name[SNAPSHOT_DEV_NAME_LEN];
    struct list_head list;
    struct rcu_head rcu_head;
};

/* puntatore globale per mount kprobe */
extern struct kretprobe *the_retprobe;

DECLARE_PER_CPU(unsigned long, BRUTE_START);
DECLARE_PER_CPU(unsigned long *, kprobe_context_pointer);

int snapshot_add_device(const char *);
int snapshot_remove_device(const char *);
int snapshot_restore_device(const char *);
int snapshot_handle_mount(struct dentry *, const char *);
int snapshot_pre_handle_umount(struct block_device *, char *);
int snapshot_handle_unmount(char *, dev_t);
int snapshot_add_block(struct buffer_head *);
int snapshot_save_block(struct buffer_head *);
int snapshot_init(void);
void snapshot_cleanup(void);

#endif // SNAPSHOT_H