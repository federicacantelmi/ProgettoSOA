/*
*   Questo file contiene le funzioni per gestire i kprobes per intercettare le operazioni di mount, unmount e modifica dei blocchi e
*   per gestire le operazioni di snapshot invocate dalle API.
*/

#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/rculist.h>
#include <linux/timekeeping.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
#include <linux/device.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/major.h>
#include <linux/list.h>
#include <linux/bitmap.h>

#include "snapshot.h"
#include "loop.h"
#define MODNAME "SNAPSHOT MOD"


static LIST_HEAD(mounted_devices_list);
static DEFINE_SPINLOCK(mounted_devices_list_lock);
static LIST_HEAD(nonmounted_devices_list);
static DEFINE_SPINLOCK(nonmounted_devices_list_lock);

/**
*   Struttura per passare lavoro a kworker
*   @work: struttura di lavoro per il kworker
*   @dev: major e minor del block device
*   @block_nr: numero del blocco
*   @size: dimensione del blocco
*   @data: dati del blocco modificato
*/
struct packed_work {
    struct work_struct work;
    dev_t dev;
    sector_t block_nr;
    size_t size;
    char *data;
};


/*
*   Funzione chiamata in callback per eliminazione dell'area allocata per device non montati
*/
static void free_device_nm_rcu(struct rcu_head *rcu) {
    struct nonmounted_dev *p = container_of(rcu, struct nonmounted_dev, rcu_head);
    kfree(p->block_bitmap);
    kfree(p);
}


/*
*   Funzione chiamata in callback per eliminazione dell'area allocata per device montati
*/
static void free_device_m_rcu(struct rcu_head *rcu) {
    struct mounted_dev *p = container_of(rcu, struct mounted_dev, rcu_head);
    kfree(p->block_bitmap);
    kfree(p);
}


/*
*   Funzione per ottenere il nome del device.
*/
static char *get_name(struct block_device *bdev, bool *is_device_file) {
    
    char *d_name = kmalloc(SNAPSHOT_DEV_NAME_LEN, GFP_ATOMIC);
    if (!d_name) {
        printk(KERN_ERR "%s: Failed to allocate memory for device name\n", MODNAME);
        return NULL;
    }

    if(!bdev || !bdev->bd_disk) {
        printk(KERN_ERR "%s: block device or disk is null in get_name\n", MODNAME);
        kfree(d_name);
        return NULL;
    }
    
    if(MAJOR(bdev->bd_dev) != LOOP_MAJOR) {
        snprintf(d_name, SNAPSHOT_DEV_NAME_LEN, "%s", bdev->bd_disk->disk_name);
        printk(KERN_DEBUG "%s: device name is %s\n", MODNAME, d_name);
        *is_device_file = false;
    } else {
        struct loop_device *ldev = (struct loop_device *)bdev->bd_disk->private_data;
        if(!ldev) {
            printk(KERN_ERR "%s: loop_device is null in snapshot_handle_mount\n", MODNAME);
            kfree(d_name);
            return NULL;
        }
        struct file *file = ldev->lo_backing_file;
        if(!file) {
            printk(KERN_ERR "%s: backing file is null in snapshot_handle_mount\n", MODNAME);
            kfree(d_name);
            return NULL;
        }
        char *tmp = d_path(&file->f_path, d_name, SNAPSHOT_DEV_NAME_LEN);
        if (IS_ERR(tmp)) {
            printk(KERN_ERR "%s: d_path failed in snapshot_handle_mount\n", MODNAME);
            kfree(d_name);
            return NULL;
        }
        snprintf(d_name, SNAPSHOT_DEV_NAME_LEN, "%s", tmp);
        printk(KERN_DEBUG "%s: loop device name is %s\n", MODNAME, d_name);
        *is_device_file = true;
    }

    return d_name;
}

/**
*   Inserisce device nella lista dei device non ancora montati ma su cui eseguire snapshot.
*   Invocata dalla API activate_snapshot().
*   @dev_name: nome del device su cui eseguire snapshot.
*/
int snapshot_add_device(const char *dev_name) {

    struct nonmounted_dev *new_dev;

    new_dev = kmalloc(sizeof(*new_dev), GFP_KERNEL);
    if(!new_dev) {
        printk(KERN_ERR "%s: add: kmalloc failed for non-mounted device\n", MODNAME);
        return -ENOMEM;
    }

    strscpy(new_dev->dev_name, dev_name,SNAPSHOT_DEV_NAME_LEN);
    INIT_LIST_HEAD(&new_dev->list);
    new_dev->rcu_head = (struct rcu_head){0};

    /* Usa rcu per consentire letture concorrenti visto che hook intercetta tante sb_bread */
    spin_lock(&nonmounted_devices_list_lock);
    list_add_rcu(&new_dev->list, &nonmounted_devices_list);
    spin_unlock(&nonmounted_devices_list_lock);

    printk(KERN_INFO "%s: add: device %s added to non-mounted devices list\n", MODNAME, dev_name);

    return 0;
}


/**
*   Rimuove device dalla lista dei device attivi.
*   Invocata dalla API deactivate_snapshot().
*   @dev_name: nome del device da rimuovere.
*/
int snapshot_remove_device(const char *dev_name) {

    struct nonmounted_dev *p, *tmp;

    struct mounted_dev *m;

    /* Controlla se il device è nella lista dei device montati */
    spin_lock(&mounted_devices_list_lock);
    list_for_each_entry(m, &mounted_devices_list, list) {
        if (strncmp(m->dev_name, dev_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            /* Se il device è montato, non può essere rimosso ma lo sarà allo smontaggio */
            m->deactivated = true;
            spin_unlock(&mounted_devices_list_lock);
            printk(KERN_INFO "%s: remove: device %s is still mounted, snapshot will be deactivated\n", MODNAME, dev_name);
            return -EBUSY;
        }
    }
    spin_unlock(&mounted_devices_list_lock);

    printk(KERN_DEBUG "%s: remove: device %s not found in mounted devices list\n", MODNAME, dev_name);

    /* Se non è montato, cerca e rimuove dalla lista dei device non montati */
    spin_lock(&nonmounted_devices_list_lock);
    
    list_for_each_entry_safe(p, tmp, &nonmounted_devices_list, list) {
        if (strncmp(p->dev_name, dev_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            list_del_rcu(&p->list);
            spin_unlock(&nonmounted_devices_list_lock);

            /* Posticipa la kfree a quando tutti i lettori avranno finito */
            call_rcu(&p->rcu_head, free_device_nm_rcu);
            printk(KERN_INFO "%s: remove: device %s removed from non-mounted devices list\n", MODNAME, dev_name);
            
            return 0;
        }
    }

    spin_unlock(&nonmounted_devices_list_lock);
    printk(KERN_ERR "%s: remove: device %s not found in nonactive or active list\n", MODNAME, dev_name);
    return -ENOENT;
}
    

/**
*   Ripristina lo snapshot di un device.
*   Invocata dalla API restore_snapshot().
*   @dev_name: nome del device su cui ripristinare lo snapshot.
*/
int snapshot_restore_device(const char *dev_name) {

    struct mounted_dev *m_dev;
    struct nonmounted_dev *n_dev;

    char target_path[SNAPSHOT_DEV_NAME_LEN];
    char dir_path[MAX_PATH_LEN];
    char file_path[MAX_PATH_LEN+ 20];
    unsigned long max;

    struct file *file, *f;
    char *buf = NULL;
    loff_t pos;
    ssize_t nread;
    ssize_t nwrite;
    sector_t blk;

    unsigned long *block_bitmap;
    unsigned long block_size;

    int ret = 0;

    /* Controlla se il device è nella lista dei device montati, se lo è -> no restore */
    rcu_read_lock();
    list_for_each_entry_rcu(m_dev, &mounted_devices_list, list) {
        if (strncmp(m_dev->dev_name, dev_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            rcu_read_unlock();
            printk(KERN_DEBUG "%s: restore: device %s found in mounted devices list\n", MODNAME, dev_name);
            return -EBUSY;
        }
    }
    rcu_read_unlock();

    rcu_read_lock();
    list_for_each_entry_rcu(n_dev, &nonmounted_devices_list, list) {
        if (strncmp(n_dev->dev_name, dev_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            /* Se il device non è un device file, non è supportato il restore */
            if(!n_dev->device_file) {
                rcu_read_unlock();
                printk(KERN_ERR "%s: restore: device %s is not a file device, feature not implemented\n", MODNAME, dev_name);
                return -EINVAL;
            }
            strscpy(target_path, n_dev->dev_name, SNAPSHOT_DEV_NAME_LEN);
            max = n_dev->bitmap_size;
            strscpy(dir_path, n_dev->dir_path, MAX_PATH_LEN);
            block_bitmap = n_dev->block_bitmap;
            block_size = n_dev->block_size;

            rcu_read_unlock();
            printk(KERN_DEBUG "%s: restore: device %s found in non mounted devices list\n", MODNAME, dev_name);

            goto found;
        }
    }
    rcu_read_unlock();
    printk(KERN_ERR "%s: restore: device %s not found in non mounted devices list\n", MODNAME, dev_name);
    return -ENOENT;

found:
     /* Apre il device file in scrittura */
    file = filp_open(target_path, O_WRONLY | O_LARGEFILE, 0);
    if(IS_ERR(file)) {
        ret = PTR_ERR(file);
        printk(KERN_ERR "%s: restore: filp_open failed for device %s, error=%d\n", MODNAME, target_path, ret);
        return ret;
    }

    buf = kmalloc(block_size, GFP_KERNEL);
    if(!buf) {
        filp_close(file, NULL);
        printk(KERN_ERR "%s: restore: kmalloc failed for buffer\n", MODNAME);
        return -ENOMEM;
    }

    /* Legge i blocchi dalla cartella dove salvo lo snapshot */
    for(blk = find_first_bit(block_bitmap, max); blk < max; blk = find_next_bit(block_bitmap, max, blk + 1)) {
        pos = 0;
        snprintf(file_path, sizeof(file_path), "%s/%llu.bin", dir_path, (unsigned long long)blk);

        f = filp_open(file_path, O_RDONLY, 0);
        if(IS_ERR(f)) {
            ret = PTR_ERR(f);
            printk(KERN_ERR "%s: restore: filp_open failed for file %s, error=%d\n", MODNAME, file_path, ret);
            goto out_close;
        }

        nread = kernel_read(f, buf, block_size, &pos);
        if (nread != block_size) {
            filp_close(f, NULL);
            ret = -EIO;
            printk(KERN_ERR "%s: restore: kernel_read failed for file %s, error=%zd\n", MODNAME, file_path, nread);
            goto out_close;
        }

        filp_close(f, NULL);

        /* Scrive il blocco sul device */
        pos = (loff_t)blk * (loff_t)block_size;
        nread = 0;
        while(nread < block_size) {
            nwrite = kernel_write(file, buf + nread, block_size - nread, &pos);
            if (nwrite < 0) {
                ret = nwrite;
                printk(KERN_ERR "%s: restore: kernel_write failed for device %s, block %llu, error=%zd\n", MODNAME, target_path, (unsigned long long)blk, nwrite);
                goto out_close;
            }
            nread += nwrite;
        }
    }
    vfs_fsync(file, 1);

out_close:
    kfree(buf);

    filp_close(file, NULL);

    return ret;
}


/**
*   Funzione invocata quando viene intercettata la mount di un device per definire
*   directory in cui salvare le modifiche ai blocchi del dispositivo.
*   @dentry: dentry del device montato;
*   @timestamp: timestamp del montaggio per creare un nome unico per la directory.
*/
int snapshot_handle_mount(struct dentry *dentry, const char *timestamp) {

    struct nonmounted_dev *n_dev;
    struct mounted_dev *m_dev, *p;
    bool is_device_file = false;
    char *dir_path = NULL;
    struct path root_path;
    int ret;
    bool found = false;
    bool already_active = false;
    struct dentry *dentry_ret;
    struct block_device *bdev;
    char d_name[SNAPSHOT_DEV_NAME_LEN];
    char d_name_path[SNAPSHOT_DEV_NAME_LEN];
    struct gendisk *disk;
    struct super_block *sb;

    bool read_only = false;

    sector_t nr_sectors;
    unsigned long block_size;

    unsigned long *kprobe_cpu;

    sb = dentry->d_sb;
    if(!sb) {
        printk(KERN_ERR "%s: handle_mount: super_block is null\n", MODNAME);
        return -EINVAL;
    }
    bdev = sb->s_bdev;
    if(!bdev) {
        printk(KERN_ERR "%s: handle_mount: block device is null\n", MODNAME);
        return -EINVAL;
    }

    char *name = get_name(bdev, &is_device_file);
    if(!name) {
        printk(KERN_ERR "%s: handle_mount: get_name failed for block device\n", MODNAME);
        return -EINVAL;
    }

    strscpy(d_name, name, SNAPSHOT_DEV_NAME_LEN);
    strscpy(d_name_path, name, SNAPSHOT_DEV_NAME_LEN);

    kfree(name);

    /* Cerca il device nella lista dei device per cui è attivo snapshot ma che non sono montati */
    rcu_read_lock();

    list_for_each_entry_rcu(n_dev, &nonmounted_devices_list, list) {
        if(strncmp(n_dev->dev_name, d_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            found = true;
            break;
        }
    }

    rcu_read_unlock();

    if(!found) {
        printk(KERN_ERR "%s: handle_mount: device %s has no snapshot activated\n", MODNAME, d_name);
        return -EINVAL;
    }

    /* Controlla che il fs non sia read only */
    if (sb_rdonly(sb)) {
        printk(KERN_WARNING "%s: handle_mount: filesystem is read-only, no snapshot will be saved for device %s\n", MODNAME, d_name);
        read_only = true;
    }

    if(!read_only) {

        /* Alloca spazio per il path della directory */
        dir_path = kmalloc(MAX_PATH_LEN, GFP_ATOMIC);
        if(!dir_path) {
            printk(KERN_ERR "%s: handle_mount: kmalloc while creating directory path failed: could not allocate dir_path\n", MODNAME);
            return -ENOMEM;
        }

        if (d_name_path[0] == '/') {
            size_t len = strlen(d_name_path);
            /* sposta tutto di un byte a sinistra, incluso il ‘\0’ */
            memmove(d_name_path, d_name_path+1, len);
        }

        for (size_t i = 0; d_name_path[i]; i++) {
            if (d_name_path[i] == '/')
                d_name_path[i] = '_';
        }

        /* Costruisce path */
        ret = snprintf(dir_path, MAX_PATH_LEN, "%s/%s_%s", SNAPSHOT_DIR_PATH, d_name_path, timestamp);
        if(ret >= MAX_PATH_LEN || ret < 0) {
            printk(KERN_ERR "%s: handle_mount: snprintf while creating directory path failed\n", MODNAME);
            kfree(dir_path);
            return -EINVAL;
        }

        /* Parte sleepable */
        kprobe_cpu = __this_cpu_read(kprobe_context_pointer);
        __this_cpu_write(*kprobe_cpu, 0UL);

        preempt_enable();

        /* Verifica che la directory /snapshot esista */
        ret = kern_path(SNAPSHOT_DIR_PATH, LOOKUP_DIRECTORY, &root_path);
        if(ret) {
            printk(KERN_ERR "%s: handle_mount: kern_path while creating directory path failed: there's no existing /snapshot\n", MODNAME);
            kfree(dir_path);

            preempt_disable();
            __this_cpu_write(*kprobe_cpu, (unsigned long)&the_retprobe->kp);

            return -ENOENT;
        }

        path_put(&root_path);

        /* Crea path per la nuova sottodirectory */
        dentry_ret = kern_path_create(AT_FDCWD, dir_path, &root_path, LOOKUP_PARENT);
        if (IS_ERR(dentry_ret)) {
            ret = PTR_ERR(dentry_ret);
            if (ret != -EEXIST) {
                printk(KERN_ERR "%s: handle_mount: failed to create snapshot path subdirectory (%d)\n", MODNAME, ret);
                kfree(dir_path);

                preempt_disable();
                __this_cpu_write(*kprobe_cpu, (unsigned long)&the_retprobe->kp);

                return ret;
            }
            /* La directory già esiste, non serve crearla */
            path_put(&root_path);
            goto exists;
        }

        /* Crea la sottodirectory */
        ret = vfs_mkdir(&nop_mnt_idmap, d_inode(root_path.dentry), dentry_ret, S_IFDIR | 0755);
        if (ret && ret != -EEXIST) {
            printk(KERN_ERR "%s: handle_mount: failed to create snapshot subdirectory (%d)\n", MODNAME, ret);
            done_path_create(&root_path, dentry_ret);

            kfree(dir_path);

            preempt_disable();
            __this_cpu_write(*kprobe_cpu, (unsigned long)&the_retprobe->kp);
            return ret;
        }

        done_path_create(&root_path, dentry_ret);
    } else {
        dir_path = NULL;

        /* Parte sleepable */
        kprobe_cpu = __this_cpu_read(kprobe_context_pointer);
        __this_cpu_write(*kprobe_cpu, 0UL);

        preempt_enable();
    }
exists:

    /* Alloca elemento device mounted */
    m_dev = kmalloc(sizeof(*m_dev), GFP_KERNEL);
    if(!m_dev) {
        printk(KERN_ERR "%s: handle_mount: kmalloc while creating directory path failed: could not allocate non-mounted device\n", MODNAME);
        kfree(dir_path);

        preempt_disable();
        __this_cpu_write(*kprobe_cpu, (unsigned long)&the_retprobe->kp);

        return -ENOMEM;
    }

    strscpy(m_dev->dev_name, d_name, SNAPSHOT_DEV_NAME_LEN);

    if(!read_only)
        strscpy(m_dev->dir_path, dir_path, MAX_PATH_LEN);
    else
        m_dev->dir_path[0] = '\0';

    
    m_dev->dev = bdev->bd_dev;
    m_dev->sb = sb;
    m_dev->read_only = read_only;
    m_dev->restoring = false;
    m_dev->device_file = is_device_file;

    if (read_only) {
        goto read_only;
    }

    disk = bdev->bd_disk;
    if(!disk) {
        printk(KERN_ERR "%s: handle_mount: disk is null\n", MODNAME);
        kfree(m_dev);
        kfree(dir_path);

        preempt_disable();
        __this_cpu_write(*kprobe_cpu, (unsigned long)&the_retprobe->kp);
        return -EINVAL;
    }

    /* Ritorna numero di settori del disco */
    nr_sectors = get_capacity(disk);
    /* Dimensione dei blocchi nel fs */
    block_size = sb->s_blocksize;
    m_dev->block_size = block_size;
    /* Calcola numero di blocchi nel fs (nr_sectors << 9 = nr_sectors * 512 => numero totale di byte sul disco)
    e poi divide per la dimensione del blocco */
    m_dev->bitmap_size = (nr_sectors << 9) / block_size;
    /* Alloca la bitmap (BITS_TO_LONG ritorna il numero di unisgned long per contenere quei bit) */
    m_dev->block_bitmap = kmalloc(BITS_TO_LONGS(m_dev->bitmap_size) * sizeof(unsigned long), GFP_ATOMIC);
    if(!m_dev->block_bitmap) {
        printk(KERN_ERR "%s: handle_mount: kmalloc failed for block_bitmap\n", MODNAME);
        kfree(m_dev);
        kfree(dir_path);
        return -ENOMEM;
    }
    /* Inizializza bitmap a zero */
    memset(m_dev->block_bitmap, 0, BITS_TO_LONGS(m_dev->bitmap_size) * sizeof(unsigned long));
    printk(KERN_DEBUG "%s: handle_mount: bitmap size for device %s is %zu bits\n", MODNAME, d_name, m_dev->bitmap_size);

    /* Crea workqueue per scrittura blocchi modificati */
    /* Usa workqueue dedicata così può eseguire cleanup */
    m_dev->wq = alloc_workqueue("snapshot_%d%d", WQ_UNBOUND | WQ_MEM_RECLAIM, 1, MAJOR(bdev->bd_dev), MINOR(bdev->bd_dev));
    if (!m_dev->wq) {
        printk(KERN_ERR "%s: handle_mount: alloc_workqueue failed for device %s\n", MODNAME, d_name);
        kfree(m_dev->block_bitmap);
        kfree(m_dev);
        kfree(dir_path);

        preempt_disable();
        __this_cpu_write(*kprobe_cpu, (unsigned long)&the_retprobe->kp);
        return -ENOMEM;
    }

read_only:

    if (read_only) {
        m_dev->block_bitmap = NULL;
        m_dev->bitmap_size = 0;
        m_dev->block_size = 0;
        m_dev->wq = NULL;
    }

    preempt_disable();
    __this_cpu_write(*kprobe_cpu, (unsigned long)&the_retprobe->kp);
    
    INIT_LIST_HEAD(&m_dev->list);

    if (!read_only) {
        INIT_LIST_HEAD(&m_dev->block_list);
        spin_lock_init(&m_dev->block_list_lock);
    }

    spin_lock(&mounted_devices_list_lock);
    spin_lock(&nonmounted_devices_list_lock);

    m_dev->deactivated = false;

    /* Controlla ancora se device è nella lista non mounted (potrei avere mount concorrente che nel frattempo lo ha spostato di lista) */
    found = false;
    list_for_each_entry(n_dev, &nonmounted_devices_list, list) {
        if(strncmp(n_dev->dev_name, d_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            found = true;
            break;
        }
    }

    list_for_each_entry(p, &mounted_devices_list, list) {
        if(strncmp(p->dev_name, d_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            already_active = true;
            break;
        }
    }

    if (!found && !read_only) {
        int err = already_active ? -EALREADY : -ENOENT;

        destroy_workqueue(m_dev->wq);
        spin_unlock(&mounted_devices_list_lock);
        spin_unlock(&nonmounted_devices_list_lock);

        kfree(m_dev->block_bitmap);
        kfree(m_dev);
        kfree(dir_path);

        printk(KERN_ERR "%s: device %s handle mount aborted (%d)\n", MODNAME, d_name, err);
        return err;
    } else if (!found && read_only) {
        spin_unlock(&mounted_devices_list_lock);
        spin_unlock(&nonmounted_devices_list_lock);
        
        kfree(m_dev);
        kfree(dir_path);
        printk(KERN_DEBUG "%s: device %s is read-only, skipping non-mounted devices list check\n", MODNAME, d_name);
        return 0;
    }

    /* Sposta device da non-mounted a mounted */
    list_add_tail_rcu(&m_dev->list, &mounted_devices_list);
    list_del_rcu(&n_dev->list);

    spin_unlock(&mounted_devices_list_lock);
    spin_unlock(&nonmounted_devices_list_lock);

    call_rcu(&n_dev->rcu_head, free_device_nm_rcu);

    kfree(dir_path);
    printk(KERN_INFO "%s: handle_mount: device %s mounted with snapshot at %s\n", MODNAME, d_name, m_dev->dir_path);

    return 0;
}


/**
*   Funzione chiamanta in pre-handler per intercettare l'unmount di un device, così da aver accesso al lo_backing_file.
*   @bdev: block device su cui è stato intercettato l'unmount;
*   @d_name: nome del device su cui è stato intercettato l'unmount.
*/
int snapshot_pre_handle_umount(struct block_device *bdev, char *d_name) {

    bool is_device_file = false;

    char *name = get_name(bdev, &is_device_file);
    if(!name) {
        printk(KERN_ERR "%s: pre_handle_umount:get_name failed for block device\n", MODNAME);
        return -EINVAL;
    }

    strscpy(d_name, name, SNAPSHOT_DEV_NAME_LEN);

    kfree(name);

    return 0;
}


/**
*   Funzione invocata quando viene intercettata la unmount di un device:
*   Se device ha ancora snapshot attivo, muove il device dalla lista dei device attivi e lo sposta
*   nella lista dei non attivi, se ha snapshot disattivato, lo rimuove in assoluto.
*   @d_name: nome del device su cui è stato intercettato l'unmount;
*   @dev: dev_t del device su cui è stato intercettato l'unmount.
*/
int snapshot_handle_unmount(char *d_name, dev_t dev) {
    struct nonmounted_dev *n_dev = NULL;
    struct nonmounted_dev *p;
    struct mounted_dev *m_dev;
    bool found = false;
    bool already_active = false;
    int ret;
    bool deactivated = false;

    /* Cerca il dev nella lista dei device attivi */
    rcu_read_lock();

    list_for_each_entry_rcu(m_dev, &mounted_devices_list, list) {
        if(m_dev->dev == dev) {
            if (READ_ONCE(m_dev->restoring)) {
                rcu_read_unlock();
                printk(KERN_INFO "%s: handle_umount: device %s is restoring, skipping unmount\n", MODNAME, d_name);
                return 0;
            }
            found = true;
            break;
        }
    }   

    rcu_read_unlock();

    if(!found) {
        printk(KERN_ERR "%s: handle_umount: device %s has no snapshot activated\n", MODNAME, d_name);
        return -EINVAL;
    }

    /* se found => device ha abilitato snapshot */

    /* Prende lock su lista active e lista non active */
    spin_lock(&mounted_devices_list_lock);
    spin_lock(&nonmounted_devices_list_lock);

    /* Dentro lock perché deactivated deve essere modificato in maniera atomica
       Se deactivated è false, significa che il device va spostato nella lista dei non mounted, altrimenti va eliminato da entrambe */
    if (!m_dev->deactivated) {
        printk(KERN_DEBUG "%s: handle_umount: device %s is still active, moving to non-mounted devices list\n", MODNAME, d_name);
        n_dev = kmalloc(sizeof(*n_dev), GFP_ATOMIC);
        if(!n_dev) {
            spin_unlock(&mounted_devices_list_lock);
            spin_unlock(&nonmounted_devices_list_lock);
            printk(KERN_ERR "%s: handle_umount: kmalloc failed while handling unmount for device %s\n", MODNAME, d_name);
            return -ENOMEM;
        }

        strscpy(n_dev->dev_name, m_dev->dev_name, SNAPSHOT_DEV_NAME_LEN);
        n_dev->device_file = m_dev->device_file;
        n_dev->block_bitmap = m_dev->block_bitmap;
        n_dev->bitmap_size = m_dev->bitmap_size;
        n_dev->block_size = m_dev->block_size;
        strscpy(n_dev->dir_path, m_dev->dir_path, MAX_PATH_LEN);
        INIT_LIST_HEAD(&n_dev->list);
    } else {
        printk(KERN_DEBUG "%s: handle_umount: device %s is already deactivated, removing from active list\n", MODNAME, d_name);
        deactivated = true;
    }

    /*  Segna il device come deactivated */
    m_dev->deactivated = true;
    /* Controllo ancora se device è nella lista active (potrei avere unmount concorrente che nel frattempo lo ha spostato di lista) */
    found = false;
    list_for_each_entry(m_dev, &mounted_devices_list, list) {
        if(m_dev->dev == dev) {
            found = true;
            break;
        }
    }

    list_for_each_entry(p, &nonmounted_devices_list, list) {
        if(strncmp(p->dev_name, m_dev->dev_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            already_active = true;
            break;
        }
    }

    /* Controllo di coerenza */
    if (found && already_active) {
        printk(KERN_ERR "%s: handle_umount: device %s found in both lists (incoherence)\n", MODNAME, d_name);
        ret = -EIO;
        goto out_unlock_free;
    }

    if (!found && !already_active) {
        printk(KERN_ERR "%s: handle_umount: device %s lost from both lists (race)\n", MODNAME, d_name);
        ret = -ENOENT;
        goto out_unlock_free;
    }

    if(!found && already_active) {
        printk(KERN_WARNING "%s: handle_umount: device %s was removed concurrently\n", MODNAME, d_name);
        ret = -EALREADY;
        goto out_unlock_free;
    }

    if(!deactivated) {
        list_add_tail_rcu(&n_dev->list, &nonmounted_devices_list);
        m_dev->block_bitmap = NULL;
        m_dev->bitmap_size = 0;
        m_dev->block_size = 0;
    }

    list_del_rcu(&m_dev->list);

    struct workqueue_struct *wq = m_dev->wq;
    /* Imposta a NULL per evitare che il kworker continui a lavorare su questo device */
    m_dev->wq = NULL;

    spin_unlock(&mounted_devices_list_lock);
    spin_unlock(&nonmounted_devices_list_lock);

    unsigned long *kprobe_cpu = __this_cpu_read(kprobe_context_pointer);
    __this_cpu_write(*kprobe_cpu, 0UL);
    preempt_enable();

    if(wq) {
        flush_workqueue(wq);
        destroy_workqueue(wq);
    }

    preempt_disable();
    __this_cpu_write(*kprobe_cpu, (unsigned long)&the_retprobe->kp);
    
    if(!m_dev->read_only) {
        struct block *bl, *tmp;
        spin_lock(&m_dev->block_list_lock);
        list_for_each_entry_safe(bl, tmp, &m_dev->block_list, list) {
            list_del(&bl->list);
            kfree(bl->data);
            kfree(bl);
        }
        spin_unlock(&m_dev->block_list_lock);
    }
    call_rcu(&m_dev->rcu_head, free_device_m_rcu);
    return 0;

out_unlock_free:

    if (!deactivated) {
            kfree(n_dev);
    }

    spin_unlock(&nonmounted_devices_list_lock);
    spin_unlock(&mounted_devices_list_lock);    

    return ret;
}


/**
*   Funzione che viene eseguita dal kworker per scrivere i dati modificati su file.
*   Prende i dati dal work item, apre il file corrispondente al blocco modificato,
*   e scrive i dati nel file.
*   @work: struttura di lavoro contenente i dati del blocco modificato.
*/
static void snapshot_worker(struct work_struct *work) {
    struct packed_work *my_work = container_of(work, struct packed_work, work);
    dev_t dev = my_work->dev;
    sector_t block_nr = my_work->block_nr;
    size_t size = my_work->size;
    char *data = my_work->data;

    struct mounted_dev *m_dev;
    char dir_path[MAX_PATH_LEN];
    bool found = false;

    struct file *file = NULL;
    char file_path[MAX_PATH_LEN];
    ssize_t ret_write = 0;
    size_t written = 0;

    rcu_read_lock();
    list_for_each_entry_rcu(m_dev, &mounted_devices_list, list) {
        if(m_dev->dev == dev) {
            strscpy(dir_path, m_dev->dir_path, MAX_PATH_LEN);
            found = true;
            break;
        }
    }
    rcu_read_unlock();
    if(!found) {
        printk(KERN_ERR "%s: snapshot_worker: device has no snapshot activated\n", MODNAME);
        goto out_free;
    }

    /* Crea il percorso del file per il blocco */
    snprintf(file_path, MAX_PATH_LEN, "%s/%llu.bin", dir_path, (unsigned long long)block_nr);

    /* Apre il file in scrittura, crea se non esiste, tronca se esiste */
    file = filp_open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(file)) {
        printk(KERN_ERR "%s: snapshot_worker: filp_open failed for %s, error=%ld\n", MODNAME, file_path, PTR_ERR(file));
        goto out_free;
    }

    while (written < size) {
        ret_write = kernel_write(file, data + written, size - written, &file->f_pos);
        if (ret_write < 0) {
            printk(KERN_ERR "%s: snapshot_worker: kernel_write failed for %s, error=%zd\n", MODNAME, file_path, ret_write);
            goto out_close;
        }
        written += ret_write;
    }

    printk(KERN_INFO "%s: snapshot_worker: wrote %zu bytes to %s for block %llu\n", MODNAME, written, file_path, (unsigned long long)block_nr);

out_close:
    if (file) {
        filp_close(file, NULL);
    }
out_free:
    kfree(data);
    kfree(my_work);

    return;
}


/**
*   Funzione chiamata quando viene intercettata una modifica di un blocco.
*   Se il blocco è già stato modificato, non fa nulla.
*   Altrimenti, crea un work item per il kworker che si occuperà di scrivere i dati su file.
*   @bh: buffer head del blocco modificato.
*/
int snapshot_save_block(struct buffer_head *bh) {
    struct packed_work *work;

    struct mounted_dev *m_dev;
    sector_t block_nr;
    struct block_device *bdev;
    dev_t dev;
    struct block *found_blk = NULL;

    struct workqueue_struct *wq;

    if (!bh || !bh->b_bdev) {
        printk(KERN_ERR "%s: save_block: buffer head or block device is null in snapshot_modify_block\n", MODNAME);
        return -EINVAL;
    }

    bdev = bh->b_bdev;
    dev = bdev->bd_dev;
    block_nr = bh->b_blocknr;

    rcu_read_lock();

    list_for_each_entry_rcu(m_dev, &mounted_devices_list, list) {
        if (m_dev->dev == dev) {
            if (READ_ONCE(m_dev->restoring)) {
                rcu_read_unlock();
                return 0;
            } else if (m_dev->read_only) {
                rcu_read_unlock();
                printk(KERN_DEBUG "%s: save_block: device %llu is read-only, cannot modify block\n", MODNAME, (unsigned long long)dev);
                return 0;
            }
            goto found_dev;
        }
    }

    rcu_read_unlock();
    printk(KERN_ERR "%s: save_block: device %llu not found in mounted devices list\n", MODNAME, (unsigned long long)dev);
    return 0;

found_dev:
    if(m_dev->deactivated) {
        /* Non devo fare nulla se il device è deactivated */
        rcu_read_unlock();
        printk(KERN_ERR "%s: save_block: device %llu is deactivated, cannot modify block\n", MODNAME, (unsigned long long)dev);
        return 0;
    }

    /* Controlla se il blocco è già stato modificato */
    if (block_nr >= m_dev->bitmap_size) {
        rcu_read_unlock();
        printk(KERN_ERR "%s: save_block: block number %llu out of range for device %llu\n", MODNAME, (unsigned long long)block_nr, (unsigned long long)dev);
        return -EINVAL;
    }    

    if (test_and_set_bit(block_nr, m_dev->block_bitmap)) {
        rcu_read_unlock();
        printk(KERN_INFO "%s: save_block: block %llu on device %llu already marked as modified\n", MODNAME, (unsigned long long)block_nr, (unsigned long long)dev);
        return 0;
    }
    printk(KERN_DEBUG "%s: save_block: block %llu on device marked as modified\n", MODNAME, (unsigned long long)block_nr);

    /* Accedo a lista del block per prelevare dati */
    struct block *blk, *tmp;

    spin_lock(&m_dev->block_list_lock);

    /* Itero su lista dei blocchi per trovare il blocco corrispondente */
    list_for_each_entry_safe(blk, tmp, &m_dev->block_list, list) {
        if (blk->block_nr == block_nr && blk->bdev == bdev && blk->size == bh->b_size) {
            list_del(&blk->list);
            printk(KERN_DEBUG "%s: save_block: block %llu on device removed from block list\n", MODNAME, (unsigned long long)block_nr);
            found_blk = blk;
            break;
        }
    }

    spin_unlock(&m_dev->block_list_lock);

    if (!found_blk) {
        printk(KERN_ERR "%s: save_block: block %llu on device not found in block list\n", MODNAME, (unsigned long long)block_nr);
        return -ENOENT;
    }

    wq = m_dev->wq;

    /* Alloca un nuovo work item per il kworker */
    work = kmalloc(sizeof(*work), GFP_ATOMIC);
    if (!work) {
        spin_lock(&m_dev->block_list_lock);
        list_add_tail(&found_blk->list, &m_dev->block_list);
        spin_unlock(&m_dev->block_list_lock);
        rcu_read_unlock();
        printk(KERN_ERR "%s: save_block: kmalloc failed for packed_work in snapshot_modify_block\n", MODNAME);
        return -ENOMEM;
    }

    rcu_read_unlock();

    /* Imposta i campi del work item */
    work->dev = dev;
    work->block_nr = block_nr;
    work->size = found_blk->size;
    work->data = found_blk->data;

    /* Inizializza la struttura di lavoro */
    INIT_WORK(&work->work, snapshot_worker);

    kfree(found_blk);

    /* Invia il lavoro al kworker */
    if (wq)
        queue_work(wq, &work->work);

    printk(KERN_INFO "%s: save_block: work item created for block %llu on device\n", MODNAME, (unsigned long long)block_nr);
    printk(KERN_DEBUG "%s: save_block: block %llu on device removed from list\n", MODNAME, (unsigned long long)block_nr);
    return 0;
}


/**
*   Funzione chiamata quando viene intercettata una modifica di un blocco.
*   Se il blocco è già stato modificato, non fa nulla.
*   Altrimenti, salva i dati del blocco in una lista di blocchi modificati.
*   @bh: buffer head del blocco modificato.
*/
int snapshot_add_block(struct buffer_head *bh) {

    struct mounted_dev *m_dev;
    struct block *blk;

    struct block_device *bdev;
    size_t size;
    sector_t block_nr;

    dev_t dev;

    bdev = bh->b_bdev;
    dev = bdev->bd_dev;
    size = bh->b_size;
    block_nr = bh->b_blocknr;

    /* Accede ai dati del device e li salva in lista */
    rcu_read_lock();
    list_for_each_entry_rcu(m_dev, &mounted_devices_list, list) {
        if(m_dev->dev == dev) {
            if (READ_ONCE(m_dev->restoring)) {
                rcu_read_unlock();
                return 0;
            } else if (m_dev->read_only) {
                rcu_read_unlock();
                printk(KERN_DEBUG "%s: add_block: device %llu is read-only, cannot add block\n", MODNAME, (unsigned long long)dev);
                return 0;
            }
            goto found_dev;
        }
    }   
    rcu_read_unlock();
    /* Se non trovo il device, non devo fare nulla */
    return 0;

    found_dev:
    if(m_dev->deactivated) {
        printk(KERN_ERR "%s: add_block: device %llu is deactivated, cannot add block\n", MODNAME, (unsigned long long)dev);
        rcu_read_unlock();
        /* Non devo fare nulla se il device è deactivated */
        return 0;
    }

    /* Controlla se il blocco è già stato modificato */

    if (block_nr >= m_dev->bitmap_size) {
        printk(KERN_ERR "%s: add_block: block number %llu out of range for device %llu\n", MODNAME, (unsigned long long)block_nr, (unsigned long long)dev);
        rcu_read_unlock();
        return -EINVAL;
    }

    if (size != m_dev->block_size || size > PAGE_SIZE) {
        printk(KERN_ERR "%s: add_block: block size %zu does not match device block size %zu\n", MODNAME, size, m_dev->block_size);
        rcu_read_unlock();
        return -EINVAL;
    }

    if (test_bit(block_nr, m_dev->block_bitmap)) {
        printk(KERN_DEBUG "%s: add_block: block %llu on device %llu already marked as modified\n", MODNAME, (unsigned long long)block_nr, (unsigned long long)dev);
        rcu_read_unlock();
        return 0;
    }

    /* Non devo segnare il blocco come modificato */
    blk = kmalloc(sizeof(struct block), GFP_ATOMIC);
    if (!blk) {
        printk(KERN_ERR "%s: add_block: kmalloc failed for block structure\n", MODNAME);
        rcu_read_unlock();
        return -ENOMEM;
    }

    /* Inizializza i campi del blocco */
    blk->block_nr = block_nr;
    blk->bdev = bdev;
    blk->size = size;
    blk->data = kmalloc(size, GFP_ATOMIC);
    if (!blk->data) {
        printk(KERN_ERR "%s: add_block: kmalloc failed for block data\n", MODNAME);
        kfree(blk);
        rcu_read_unlock();
        return -ENOMEM;
    }
    /* Copia i dati del blocco modificato */
    memcpy(blk->data, bh->b_data, size);

    INIT_LIST_HEAD(&blk->list);

    spin_lock(&m_dev->block_list_lock);
    list_add_tail(&blk->list, &m_dev->block_list);
    spin_unlock(&m_dev->block_list_lock);   

    rcu_read_unlock();

    printk(KERN_DEBUG "%s: add_block: block %llu on device added to block list\n", MODNAME, (unsigned long long)block_nr);
    return 0;
}


/*
*   Funzione di inizializzazione del modulo snapshot.
*/
int snapshot_init(void) {

    printk(KERN_INFO "%s: snapshot_init completed\n", MODNAME);
    return 0;
}


/*
*   Funzione di cleanup del modulo snapshot.
*   Libera tutte le strutture dati allocate e rimuove i device dalle liste.
*/
void snapshot_cleanup(void) {
    struct nonmounted_dev *p, *tmp;
    struct mounted_dev *m, *mtmp;

    /* Libera tutti i device non attivi */
    spin_lock(&nonmounted_devices_list_lock);
    list_for_each_entry_safe(p, tmp, &nonmounted_devices_list, list) {
        list_del_rcu(&p->list);
        call_rcu(&p->rcu_head, free_device_nm_rcu);
    }
    spin_unlock(&nonmounted_devices_list_lock);

    /* Libera tutti i device attivi */
    spin_lock(&mounted_devices_list_lock);
    list_for_each_entry_safe(m, mtmp, &mounted_devices_list, list) {
        list_del_rcu(&m->list);
        if(m->wq) {
            /* Assicura che tutti i lavori siano completati prima di rimuovere il device */
            flush_workqueue(m->wq);
            destroy_workqueue(m->wq);
            m->wq = NULL;
        }

        if(!m->read_only) {
            /* Libera tutte le strutture dati allocate per i blocchi */
            struct block *bl, *tmp;
            spin_lock(&m->block_list_lock);
            list_for_each_entry_safe(bl, tmp, &m->block_list, list) {
                list_del(&bl->list);
                kfree(bl->data);
                kfree(bl);
            }
            spin_unlock(&m->block_list_lock);
        }

        call_rcu(&m->rcu_head, free_device_m_rcu);

    }
    spin_unlock(&mounted_devices_list_lock);

    /* Aspetta che tutte le callback RCU siano terminate */
    rcu_barrier();

    printk(KERN_INFO "%s: snapshot_cleanup completed\n", MODNAME);
}