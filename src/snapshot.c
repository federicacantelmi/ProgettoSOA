#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/timekeeping.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
#include <linux/device.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/major.h>
#include <linux/loop.h>
#include <linux/list.h>

#include "snapshot.h"
#include "loop.h"
#define MODNAME "SNAPSHOT MOD"


static LIST_HEAD(mounted_devices_list);
static DEFINE_SPINLOCK(mounted_devices_list_lock);
static LIST_HEAD(nonmounted_devices_list);
static DEFINE_SPINLOCK(nonmounted_devices_list_lock);

/*
*   Struttura per passare lavoro a kworker
*   @work: struttura di lavoro per il kworker
*   @dev: major e minor del block device
*   @block_nr: numero del blocco
*   @size: dimensione del blocco
*   @data: dati del blocco modificato
*/
struct packed_work {
    struct work_struct work;
    char dev_name[SNAPSHOT_DEV_NAME_LEN];
    sector_t block_nr;
    size_t size;
    char *data;
};


/*
*   Funzione chiamata in callback per eliminazione dell'area allocata per device non montati
*/
static void free_device_nm_rcu(struct rcu_head *rcu) {
    struct nonmounted_dev *p = container_of(rcu, struct nonmounted_dev, rcu_head);
    kfree(p);
}


/*
*   Funzione chiamata in callback per eliminazione dell'area allocata per device montati
*/
static void free_device_m_rcu(struct rcu_head *rcu) {
    struct mounted_dev *p = container_of(rcu, struct mounted_dev, rcu_head);
    kfree(p->dir_path);
    kfree(p->block_bitmap);
    kfree(p);
}

static char *get_name(struct block_device *bdev) {

    char *d_name = kmalloc(SNAPSHOT_DEV_NAME_LEN, GFP_KERNEL);
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
    }

    return d_name;
}

/*
*   Inserisce device nella lista dei device non ancora montati ma su cui eseguire snapshot
*   Invocata dalla API activate_snapshot().
*/
int snapshot_add_device(const char *dev_name) {

    struct nonmounted_dev *new_dev;

    new_dev = kmalloc(sizeof(*new_dev), GFP_KERNEL);
    if(!new_dev) {
        printk(KERN_ERR "%s: kmalloc failed for non-mounted device\n", MODNAME);
        return -ENOMEM;
    }

    strscpy(new_dev->dev_name, dev_name,SNAPSHOT_DEV_NAME_LEN);
    INIT_LIST_HEAD(&new_dev->list);
    new_dev->rcu_head = (struct rcu_head){0};

    // Usa rcu per consentire letture concorrenti visto che hook intercetta tante sb_bread
    spin_lock(&nonmounted_devices_list_lock);
    list_add_rcu(&new_dev->list, &nonmounted_devices_list);
    spin_unlock(&nonmounted_devices_list_lock);

    printk(KERN_INFO "%s: device %s added to non-mounted devices list\n", MODNAME, dev_name);

    return 0;
}


/*
*   Rimuove device dalla lista dei device attivi.
*   Invocata dalla API deactivate_snapshot().
*/
int snapshot_remove_device(const char *dev_name) {

    struct nonmounted_dev *p, *tmp;

    struct mounted_dev *m;

    // Controlla se il device è nella lista dei device montati
    spin_lock(&mounted_devices_list_lock);
    list_for_each_entry_rcu(m, &mounted_devices_list, list) {
        if (strncmp(m->dev_name, dev_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            // Se il device è montato, non può essere rimosso ma lo sarà allo smontaggio
            m->deactivated = true;
            spin_unlock(&mounted_devices_list_lock);
            printk(KERN_INFO "%s: device %s is still mounted, snapshot will be deactivated\n", MODNAME, dev_name);
            return -EBUSY;
        }
    }
    spin_unlock(&mounted_devices_list_lock);

    // Se non è montato, cerca e rimuove dalla lista dei device non montati
    spin_lock(&nonmounted_devices_list_lock);
    
    list_for_each_entry_safe(p, tmp, &nonmounted_devices_list, list) {
        if (strncmp(p->dev_name, dev_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            list_del_rcu(&p->list);
            spin_unlock(&nonmounted_devices_list_lock);

            // Posticipa la kfree a quando tutti i lettori avranno finito
            call_rcu(&p->rcu_head, free_device_nm_rcu);

            return 0;
        }
    }

    spin_unlock(&nonmounted_devices_list_lock);
    printk(KERN_ERR "%s: device %s not found in nonactive or active list\n", MODNAME, dev_name);
    return -ENOENT;
}


/*
*   Funzione invocata quando viene intercettata la mount di un device per definire
*   directory in cui salvare le modifiche ai blocchi del dispositivo.
*/
int snapshot_handle_mount(struct dentry *dentry, const char *timestamp) {

    struct nonmounted_dev *n_dev;
    struct mounted_dev *m_dev, *p;
    char *dir_path = NULL;
    struct path path;
    int ret;
    bool found = false;
    bool already_active = false;
    struct dentry *dentry_ret;
    struct block_device *bdev;
    char d_name[SNAPSHOT_DEV_NAME_LEN];
    struct gendisk *disk;
    struct super_block *sb;

    sector_t nr_sectors;
    unsigned long block_size;

    bdev = dentry->d_sb->s_bdev;
    if(!bdev) {
        printk(KERN_ERR "%s: block device is null in snapshot_handle_mount\n", MODNAME);
        return -EINVAL;
    }

    char *name = get_name(bdev);
    if(!name) {
        printk(KERN_ERR "%s: get_name failed for block device in snapshot_handle_write\n", MODNAME);
        return -EINVAL;
    }

    strscpy(d_name, name, SNAPSHOT_DEV_NAME_LEN);

    kfree(name);

    printk(KERN_INFO "%s: mount_bdev success\n", MODNAME);

    // Cerca il dev nella lista dei device per cui è attivo snapshot ma non montati
    rcu_read_lock();

    list_for_each_entry_rcu(n_dev, &nonmounted_devices_list, list) {
        if(strncmp(n_dev->dev_name, d_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            found = true;
            break;
        }
    }

    rcu_read_unlock();

    if(!found) {
        printk(KERN_ERR "%s: device %s has no snapshot activated\n", MODNAME, d_name);
        return -EINVAL;
    }

    // Alloca spazio per il path della directory
    dir_path = kmalloc(MAX_PATH_LEN, GFP_ATOMIC);
    if(!dir_path) {
        printk(KERN_ERR "%s: kmalloc while creating directory path failed: could not allocate dir_path\n", MODNAME);
        return -ENOMEM;
    }

    // Costruisce path
    ret = snprintf(dir_path, MAX_PATH_LEN, "%s/%s_%s", SNAPSHOT_DIR_PATH, d_name, timestamp);
    if(ret >= MAX_PATH_LEN || ret < 0) {
        printk(KERN_ERR "%s: snprintf while creating directory path failed\n", MODNAME);
        kfree(dir_path);
        return -EINVAL;
    }

    // Verifica che la directory /snapshot esista
    ret = kern_path(SNAPSHOT_DIR_PATH, LOOKUP_DIRECTORY, NULL);
    if(ret) {
        printk(KERN_ERR "%s: kern_path while creating directory path failed: there's no existing /snapshot\n", MODNAME);
        kfree(dir_path);
        return -ENOENT;
    }

    // Crea path per la nuova sottodirectory
    dentry_ret = kern_path_create(AT_FDCWD, dir_path, &path, 0);
    if (IS_ERR(dentry_ret)) {
        ret = PTR_ERR(dentry_ret);
        if (ret != -EEXIST) {
            printk(KERN_ERR "%s: failed to create snapshot subdirectory (%d)\n", MODNAME, ret);
            kfree(dir_path);
            return ret;
        }
        // La directory già esiste, non serve crearla
        goto exists;
    }

    // Crea la sottodirectory
    ret = vfs_mkdir(NULL, dentry_ret->d_inode, dentry_ret, 0755);
    if (ret && ret != -EEXIST) {
        printk(KERN_ERR "%s: failed to create snapshot subdirectory (%d)\n", MODNAME, ret);
        done_path_create(&path, dentry_ret);
        return ret;
    }
    
    done_path_create(&path, dentry_ret);

exists:

    // Alloca elemento device active
    m_dev = kmalloc(sizeof(*m_dev), GFP_ATOMIC);
    if(!m_dev) {
        printk(KERN_ERR "%s: kmalloc while creating directory path failed: could not allocate non-mounted device\n", MODNAME);
        kfree(dir_path);
        return -ENOMEM;
    }

    strscpy(m_dev->dev_name, d_name, SNAPSHOT_DEV_NAME_LEN);
    strscpy(m_dev->dir_path, dir_path, MAX_PATH_LEN);

    disk = bdev->bd_disk;
    sb = dentry->d_sb;
    if(!disk || !sb) {
        printk(KERN_ERR "%s: disk or super_block is null in snapshot_handle_mount\n", MODNAME);
        kfree(m_dev);
        kfree(dir_path);
        return -EINVAL;
    }

    // Ritorna numero di settori del disco
    nr_sectors = get_capacity(disk);
    // Dimensione dei blocchi nel fs
    block_size = sb->s_blocksize;
    // Calcola numero di blocchi nel fs (nr_sectors << 9 = nr_sectors * 512 => numero totale di byte sul disco)
    // e poi divide per la dimensione del blocco
    m_dev->bitmap_size = (nr_sectors << 9) / block_size;
    // Alloca la bitmap (BITS_TO_LONG ritorna il numero di unisgned long per contenere quei bit)
    m_dev->block_bitmap = kmalloc(BITS_TO_LONGS(m_dev->bitmap_size) * sizeof(unsigned long), GFP_KERNEL);
    if(!m_dev->block_bitmap) {
        printk(KERN_ERR "%s: kmalloc failed for block_bitmap in snapshot_handle_mount\n", MODNAME);
        kfree(m_dev);
        kfree(dir_path);
        return -ENOMEM;
    }
    // Inizializza bitmap a zero
    memset(m_dev->block_bitmap, 0, BITS_TO_LONGS(m_dev->bitmap_size) * sizeof(unsigned long));

    INIT_LIST_HEAD(&m_dev->list);

    #ifdef SNAPSHOT_ASYNC
        INIT_LIST_HEAD(&m_dev->block_list);
        spin_lock_init(&m_dev->block_list_lock);
    #endif

    // Prende lock su lista active e lista non active
    spin_lock(&mounted_devices_list_lock);
    spin_lock(&nonmounted_devices_list_lock);

    m_dev->deactivated = false;

    // Controlla ancora se device è nella lista non active (potrei avere mount concorrente che nel frattempo lo ha spostato di lista)
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

    if(!found && already_active) {
        printk(KERN_ERR "%s: device was already mounted in concurrency\n", MODNAME);
        spin_unlock(&mounted_devices_list_lock);
        spin_unlock(&nonmounted_devices_list_lock);

        kfree(m_dev);

        // Elimina directory creata
        ret = kern_path(dir_path, LOOKUP_DIRECTORY, &path);
        if (!ret) {
            vfs_rmdir(NULL, path.dentry->d_parent->d_inode, path.dentry);
            path_put(&path);
        }

        kfree(dir_path);
        return -EALREADY;
    }

    // Sposta device da nonactive a active
    list_add_tail_rcu(&m_dev->list, &mounted_devices_list);
    list_del_rcu(&n_dev->list);

    spin_unlock(&mounted_devices_list_lock);
    spin_unlock(&nonmounted_devices_list_lock);

    call_rcu(&n_dev->rcu_head, free_device_nm_rcu);

    // todo scrivi metadati 
    kfree(dir_path);  
    return 0;
}


/*
*   Funzione invocata quando viene intercettata la unmount di un device:
*   Se device ha ancora snapshot attivo, muove il device dalla lista dei device attivi e lo sposta
*   nella lista dei non attivi, se ha snapshot disattivato, lo rimuove in assoluto.
*/
int snapshot_handle_unmount(struct block_device *bdev) {
    struct nonmounted_dev *n_dev = NULL;
    struct nonmounted_dev *p;
    struct mounted_dev *m_dev;
    bool found = false;
    bool already_active = false;
    int ret;
    char d_name[SNAPSHOT_DEV_NAME_LEN];

    char *name = get_name(bdev);
    if(!name) {
        printk(KERN_ERR "%s: get_name failed for block device in snapshot_handle_write\n", MODNAME);
        return -EINVAL;
    }

    strscpy(d_name, name, SNAPSHOT_DEV_NAME_LEN);

    kfree(name);

    // Cerca il dev nella lista dei device attivi
    rcu_read_lock();

    list_for_each_entry_rcu(m_dev, &mounted_devices_list, list) {
        if(strncmp(m_dev->dev_name, d_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            found = true;
            break;
        }
    }

    rcu_read_unlock();

    if(!found) {
        printk(KERN_ERR "%s: device %s has no snapshot activated\n", MODNAME, d_name);
        return -EINVAL;
    }

    // se found => device ha abilitato snapshot

    // Prende lock su lista active e lista non active
    spin_lock(&mounted_devices_list_lock);
    spin_lock(&nonmounted_devices_list_lock);

    // Dentro lock perché deactivated deve essere modificato in maniera atomica
    // Se deactivated è false, significa che il device va spostato nella lista dei non attivi, altrimenti va eliminato da entrambe
    if (!m_dev->deactivated) {
        // Alloca elemento device active
        n_dev = kmalloc(sizeof(*n_dev), GFP_ATOMIC);
        if(!n_dev) {
            printk(KERN_ERR "%s: kmalloc failed while handling unmount for device %s\n", MODNAME, d_name);
            return -ENOMEM;
        }

        strscpy(n_dev->dev_name, m_dev->dev_name, SNAPSHOT_DEV_NAME_LEN);
        INIT_LIST_HEAD(&n_dev->list);
    }

    // Controllo ancora se device è nella lista active (potrei avere unmount concorrente che nel frattempo lo ha spostato di lista)
    found = false;
    list_for_each_entry(m_dev, &mounted_devices_list, list) {
        if(strncmp(m_dev->dev_name, d_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
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

    // Controllo di coerenza
    if (found && already_active) {
        printk(KERN_ERR "%s: device %s found in both lists (incoherence)\n", MODNAME, d_name);
        ret = -EIO;
        goto out_unlock_free;
    }

    if (!found && !already_active) {
        printk(KERN_ERR "%s: device %s lost from both lists (race)\n", MODNAME, d_name);
        ret = -ENOENT;
        goto out_unlock_free;
    }

    if(!found && already_active) {
        printk(KERN_WARNING "%s: device %s was removed concurrently\n", MODNAME, d_name);
        ret = -EALREADY;
        goto out_unlock_free;
    }

    if(!m_dev->deactivated) {
        list_add_tail_rcu(&n_dev->list, &nonmounted_devices_list);
    }

    list_del_rcu(&m_dev->list);

    spin_unlock(&mounted_devices_list_lock);
    spin_unlock(&nonmounted_devices_list_lock);

#ifdef SNAPSHOT_ASYNC
    struct block *bl, *tmp;
    spin_lock(&m_dev->block_list_lock);
    list_for_each_entry_safe(bl, tmp, &m_dev->block_list, list) {
        list_del(&bl->list);
        kfree(bl->data);
        kfree(bl);
    }
    spin_unlock(&m_dev->block_list_lock);
#endif // SNAPSHOT_ASYNC

    call_rcu(&m_dev->rcu_head, free_device_m_rcu);
    return 0;

out_unlock_free:

    if (!m_dev->deactivated) {
            kfree(n_dev);
    }

    spin_unlock(&nonmounted_devices_list_lock);
    spin_unlock(&mounted_devices_list_lock);    

    return ret;
}


/*
*   Funzione che viene eseguita dal kworker per scrivere i dati modificati su file.
*   Prende i dati dal work item, apre il file corrispondente al blocco modificato,
*   e scrive i dati nel file.
*/
static void snapshot_worker(struct work_struct *work) {
    struct packed_work *my_work = container_of(work, struct packed_work, work);
    char dev_name[SNAPSHOT_DEV_NAME_LEN];
    strscpy(dev_name, my_work->dev_name, SNAPSHOT_DEV_NAME_LEN);
    sector_t block_nr = my_work->block_nr;
    size_t size = my_work->size;
    char *data = my_work->data;

    struct mounted_dev *m_dev;
    bool found = false;

    struct file *file;
    char file_path[MAX_PATH_LEN];
    ssize_t ret_write = 0;

    rcu_read_lock();
    list_for_each_entry_rcu(m_dev, &mounted_devices_list, list) {
        if(strncmp(m_dev->dev_name, dev_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            found = true;
            break;
        }
    }
    rcu_read_unlock();
    if(!found) {
        printk(KERN_ERR "%s: device %s has no snapshot activated\n", MODNAME, dev_name);
        kfree(data);
        kfree(my_work);
        return;
    } 
    // Scrive i dati modificati nel file system
    snprintf(file_path, MAX_PATH_LEN, "%s/%llu.bin", m_dev->dir_path, (unsigned long long)block_nr);

    file = filp_open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(file)) {
        printk(KERN_ERR "%s: filp_open failed for %s, error=%ld\n", MODNAME, file_path, PTR_ERR(file));
        kfree(data);
        kfree(my_work);
        return;
    }

    ret_write = kernel_write(file, data, size, &file->f_pos);
    filp_close(file, NULL);
    if (ret_write < 0) {
        printk(KERN_ERR "%s: kernel_write failed for %s, error=%zd\n", MODNAME, file_path, ret_write);
        kfree(data);
        kfree(my_work);
        return;
    }
    
    // Libera la memoria allocata
    kfree(data);
    kfree(my_work);

    return;
}

#ifdef SNAPSHOT_ASYNC
int snapshot_modify_block(struct buffer_head *bh) {
    struct packed_work *work;

    struct mounted_dev *m_dev;
    bool found = false;
    sector_t block_nr;
    char d_name[SNAPSHOT_DEV_NAME_LEN];
    struct block_device *bdev;

    // Controllo se ho già block nella lista dei block del device


    if (!bh || !bh->b_bdev) {
        printk(KERN_ERR "%s: buffer head or block device is null in snapshot_modify_block\n", MODNAME);
        return -EINVAL;
    }

    bdev = bh->b_bdev;

    char *name = get_name(bdev);
    if(!name) {
        printk(KERN_ERR "%s: get_name failed for block device in snapshot_handle_write\n", MODNAME);
        return -EINVAL;
    }

    strscpy(d_name, name, SNAPSHOT_DEV_NAME_LEN);

    kfree(name);

    block_nr = bh->b_blocknr;

    rcu_read_lock();
    list_for_each_entry_rcu(m_dev, &mounted_devices_list, list) {
        if (strncmp(m_dev->dev_name, d_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            found = true;
            break;
        }
    }

    rcu_read_unlock();
    if (!found) {
        printk(KERN_ERR "%s: device %s has no snapshot activated\n", MODNAME, d_name);
        return -EINVAL;
    }
    // Controlla se il blocco è già stato modificato
    if (block_nr < 0 || block_nr >= m_dev->bitmap_size) {
        printk(KERN_ERR "%s: block number %llu out of range for device %s\n", MODNAME, (unsigned long long)block_nr, d_name);
        return -EINVAL;
    }       
    if (test_and_set_bit(block_nr, m_dev->block_bitmap)) {
        printk(KERN_INFO "%s: block %llu on device %s already marked as modified\n", MODNAME, (unsigned long long)block_nr, d_name);
        return 0;
    }
    printk(KERN_INFO "%s: block %llu on device %s marked as modified\n", MODNAME, (unsigned long long)block_nr, d_name);

    // Accedo a lista del block per prelevare dati
    struct block *blk, *tmp;

    spin_lock(&m_dev->block_list_lock); // Prendo lock sulla lista dei blocchi
    // Itero su lista dei blocchi per trovare il blocco corrispondente
    list_for_each_entry_safe(blk, tmp, &m_dev->block_list, list) {
        if (blk->block_nr == block_nr && blk->bdev == bdev && blk->size == bh->b_size) {
            
            // Alloca un nuovo work item per il kworker
            work = kmalloc(sizeof(*work), GFP_ATOMIC);
            if (!work) {
                printk(KERN_ERR "%s: kmalloc failed for packed_work in snapshot_modify_block\n", MODNAME);
                return -ENOMEM;
            }

            // Imposta i campi del work item
            strscpy(work->dev_name, d_name, SNAPSHOT_DEV_NAME_LEN);
            work->block_nr = bh->b_blocknr;
            work->size = bh->b_size;
            work->data = blk->data; // usa i dati del blocco

            // Inizializza la struttura di lavoro
            INIT_WORK(&work->work, snapshot_worker);

            // Invia il lavoro al kworker
            queue_work(system_wq, &work->work);
            printk(KERN_INFO "%s: work item created for block %llu on device %s\n", MODNAME, (unsigned long long)block_nr, d_name);

            // Libera il blocco dalla lista
            list_del(&blk->list);
            kfree(blk); // Libera la memoria del blocco
            spin_unlock(&m_dev->block_list_lock); // Rilascio lock sulla lista
            printk(KERN_INFO "%s: block %llu on device %s removed from list\n", MODNAME, (unsigned long long)block_nr, d_name);
            return 0;
        }
    }

    spin_unlock(&m_dev->block_list_lock); // Rilascio lock sulla lista
    printk(KERN_ERR "%s: block %llu on device %s not found in block list\n", MODNAME, (unsigned long long)block_nr, d_name);

    return 0;
}
#endif // SNAPSHOT_ASYNC


#ifdef SNAPSHOT_SYNC
/*
*   Funzione invocata quando viene intercettata la scrittura su device di un blocco:
*   se il blocco è già stato modificato, non fa nulla, altrimenti
*   lo segna come modificato nella bitmap e crea un work item per il kworker.
*   Il kworker si occuperà di scrivere i dati modificati su file.
*/
int snapshot_handle_write(struct buffer_head *bh) {

    struct mounted_dev *m_dev;
    bool found = false;
    struct packed_work *work = NULL;
    char d_name[SNAPSHOT_DEV_NAME_LEN];

    struct bio *bio;
    struct page *page;
    int ret;

    sector_t block_nr;
    struct block_device *bdev;
    size_t size;

    block_nr = bh->b_blocknr;
    bdev = bh->b_bdev;


    if(!bdev) {
        printk(KERN_ERR "%s: block_device is null in write_dirty_buffer_handler\n", MODNAME);
        return -EINVAL;
    }   

    char *name = get_name(bdev);
    if(!name) {
        printk(KERN_ERR "%s: get_name failed for block device in snapshot_handle_write\n", MODNAME);
        return -EINVAL;
    }

    strscpy(d_name, name, SNAPSHOT_DEV_NAME_LEN);

    kfree(name);

    size = bh->b_size;
    if (size > PAGE_SIZE) {
        printk(KERN_ERR "%s: block size %zu exceeds PAGE_SIZE (%lu)\n", MODNAME, size, (unsigned long)PAGE_SIZE);
        return -EINVAL;
    }

    rcu_read_lock();
    list_for_each_entry_rcu(m_dev, &mounted_devices_list, list) {
        if(strncmp(m_dev->dev_name, d_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            found = true;
            break;
        }
    }
    rcu_read_unlock();
    if(!found) {
        printk(KERN_ERR "%s: device %s has no snapshot activated\n", MODNAME, d_name);
        return -EINVAL;
    }

    // Controlla se il blocco è già stato modificato
    
    if(block_nr < 0 || block_nr >= m_dev->bitmap_size) {
        printk(KERN_ERR "%s: block number %llu out of range for device %s\n", MODNAME, (unsigned long long)block_nr, d_name);
        return -EINVAL;
    }

    if (test_and_set_bit(block_nr, m_dev->block_bitmap)) {
        printk(KERN_INFO "%s: block %llu on device %s already marked as modified\n", MODNAME, (unsigned long long)block_nr, d_name);
        return 0;
    }
    printk(KERN_INFO "%s: block %llu on device %s marked as modified\n", MODNAME, (unsigned long long)block_nr, d_name);

    // Crea un nuovo work item per il kworker
    work = kmalloc(sizeof(*work), GFP_ATOMIC);
    if (!work) {
        printk(KERN_ERR "%s: kmalloc failed for packed_work in snapshot_handle_write\n", MODNAME);
        return -ENOMEM;
    }

    strscpy(work->dev_name, d_name, SNAPSHOT_DEV_NAME_LEN);
    work->block_nr = block_nr;
    work->size = size;
    work->data = kmalloc(size, GFP_ATOMIC);
    if (!work->data) {
        printk(KERN_ERR "%s: kmalloc failed for data buffer in snapshot_handle_write\n", MODNAME);
        kfree(work);
        return -ENOMEM;
    }

    // // Copia i dati del blocco modificato -> no perché leggerei da cache dati già modificati
    // struct buffer_head *bh = __bread(bdev, block_nr, size);
    // if (!bh) {
    //     printk(KERN_ERR "%s: __bread failed for device (%d, %d) at block %llu\n", MODNAME, MAJOR(bdev->bd_dev), MINOR(bdev->bd_dev), (unsigned long long)block_nr);
    //     kfree(work->data);
    //     kfree(work);
    //     return -EIO;
    // }

    // memcpy(work->data, bh->b_data, size);
    // brelse(bh);


    // OSS: non supporto fs che usano blocchi più grandi di 4096 byte -> dovrei mettere controllo

    page = alloc_page(GFP_ATOMIC);
    if (!page) {
        printk(KERN_ERR "%s: alloc_page failed for device %s at block %llu\n", MODNAME, d_name, (unsigned long long)block_nr);
        kfree(work->data);
        kfree(work);
        return -ENOMEM;
    }

    bio = bio_alloc(GFP_ATOMIC, 1);
    if (!bio) {
        printk(KERN_ERR "%s: bio_alloc failed for device %s at block %llu\n", MODNAME, d_name, (unsigned long long)block_nr);
        __free_page(page);
        kfree(work->data);
        kfree(work);
        return -ENOMEM;
    }   

    bio->bi_iter.bi_sector = block_nr; // indirizzo nel device in termini di settori
    bio_set_dev(bio, bdev);
    bio_add_page(bio, page, size, 0); // aggiunge page alla bio che sto preparando => voglio leggere size byte all'interno della page
    bio->bi_opf = REQ_OP_READ; // lettura sincrona dal disco (serve sincrona altrimenti rischio di leggere dati modificati)

    preempt_disable(); // disabilita preemption

    ret = submit_bio_wait(bio); // invia richiesta I/O al device e aspetta che sia eseguita
    if (ret < 0) {
        printk(KERN_ERR "%s: submit_bio_wait failed for device %s at block %llu, error=%d\n", MODNAME, d_name, (unsigned long long)block_nr, ret);
        __free_page(page);
        kfree(work->data);
        kfree(work);
        return -EIO;
    }

    memcpy(work->data, page_address(page), size);

    preempt_enable(); // riabilita preemption

    __free_page(page);
    bio_put(bio);

    INIT_WORK(&work->work, snapshot_worker);
    // Aggiunge il lavoro alla workqueue
    schedule_work(&work->work);

    printk(KERN_INFO "%s: scheduled work for block %llu on device %s\n", MODNAME, (unsigned long long)block_nr, d_name);
    return 0;
}

#elif SNAPSHOT_ASYNC

int snapshot_handle_write(struct buffer_head *bh) {

    struct mounted_dev *m_dev;
    bool found = false;
    struct block *blk;
    char d_name[SNAPSHOT_DEV_NAME_LEN];

    struct block_device *bdev;
    size_t size;
    sector_t block_nr;

    bdev = bh->b_bdev;
    if(!bdev) {
        printk(KERN_ERR "%s: block_device is null in write_dirty_buffer_handler\n", MODNAME);
        return 0;
    }

    char *name = get_name(bdev);
    if(!name) {
        printk(KERN_ERR "%s: get_name failed for block device in snapshot_handle_write\n", MODNAME);
        return -EINVAL;
    }

    strscpy(d_name, name, SNAPSHOT_DEV_NAME_LEN);

    kfree(name);

    size = bh->b_size;
    block_nr = bh->b_blocknr;

    // Accedo ai dati del device e li salvo in lista
    rcu_read_lock();
    list_for_each_entry_rcu(m_dev, &mounted_devices_list, list) {
        if(strncmp(m_dev->dev_name, d_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            found = true;
            break;
        }
    }   
    rcu_read_unlock();
    if(!found) {
        printk(KERN_ERR "%s: device %s has no snapshot activated\n", MODNAME, d_name);
        return -EINVAL;
    }

    // Controlla se il blocco è già stato modificato
    
    if(block_nr < 0 || block_nr >= m_dev->bitmap_size) {
        printk(KERN_ERR "%s: block number %llu out of range for device %s\n", MODNAME, (unsigned long long)block_nr, d_name);
        return -EINVAL;
    }

    if (test_bit(block_nr, m_dev->block_bitmap)) {
        printk(KERN_INFO "%s: block %llu on device %s already marked as modified\n", MODNAME, (unsigned long long)block_nr, d_name);
        return 0;
    }
    // In questo caso non devo segnare il blocco come modificato
    blk = kmalloc(sizeof(struct block), GFP_ATOMIC);
    if (!blk) {
        printk(KERN_ERR "%s: kmalloc failed for block structure\n", MODNAME);
        return -ENOMEM;
    }

    blk->block_nr = block_nr;
    blk->bdev = bdev;
    blk->size = size;
    blk->data = kmalloc(size, GFP_ATOMIC);
    if (!blk->data) {
        printk(KERN_ERR "%s: kmalloc failed for block data\n", MODNAME);
        kfree(blk);
        return -ENOMEM;
    }
    // Copia i dati del blocco modificato
    memcpy(blk->data, bh->b_data, size);

    INIT_LIST_HEAD(&blk->list);

    spin_lock(&m_dev->block_list_lock);       // 2. prendi il lock
    list_add_tail(&blk->list, &m_dev->block_list); // 3. aggiungi alla lista
    spin_unlock(&m_dev->block_list_lock);     // 4. rilascia il lock

    printk(KERN_INFO "%s: block %llu on device %s added to block list\n", MODNAME, (unsigned long long)block_nr, d_name);
    return 0;
}
#endif // SNAPSHOT_SYNC


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

    // Libera tutti i device non attivi
    spin_lock(&nonmounted_devices_list_lock);
    list_for_each_entry_safe(p, tmp, &nonmounted_devices_list, list) {
        list_del_rcu(&p->list);
        call_rcu(&p->rcu_head, free_device_nm_rcu);
    }
    spin_unlock(&nonmounted_devices_list_lock);

    // Libera tutti i device attivi
    spin_lock(&mounted_devices_list_lock);
    list_for_each_entry_safe(m, mtmp, &mounted_devices_list, list) {
        list_del_rcu(&m->list);

        #ifdef SNAPSHOT_ASYNC
            struct block *bl, *tmp;
            spin_lock(&m->block_list_lock);
            list_for_each_entry_safe(bl, tmp, &m->block_list, list) {
                list_del(&bl->list);
                kfree(bl->data);
                kfree(bl);
            }
            spin_unlock(&m->block_list_lock);
        #endif // SNAPSHOT_ASYNC

        call_rcu(&m->rcu_head, free_device_m_rcu);

    }
    spin_unlock(&mounted_devices_list_lock);

    rcu_barrier(); // Aspetta che tutte le callback RCU siano terminate

    printk(KERN_INFO "%s: snapshot_cleanup completed\n", MODNAME);
}