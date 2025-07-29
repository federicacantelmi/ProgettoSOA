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
#include <linux/buffer_head.h>

#include "snapshot.h"
#define MODNAME "SNAPSHOT MOD"


static LIST_HEAD(active_devices_list);
static DEFINE_SPINLOCK(active_devices_list_lock);
static LIST_HEAD(nonactive_devices_list);
static DEFINE_SPINLOCK(nonactive_devices_list_lock);

/*
*   Struttura per passare lavoro a kworker
*   @dev: major e minor del block device
*   @block_nr: numero del blocco
*   @list: per inserimento in hashtable
*/
struct packed_work {
    struct work_struct work;
    dev_t dev;
    sector_t block_nr;
    size_t size;
    char *data;
};


/*
*   Funzione chiamata in callback per eliminazione dell'area allocata
*/
static void free_snapshot_device_nm_rcu(struct rcu_head *rcu) {
    struct nonmounted_dev *p = container_of(rcu, struct nonmounted_dev, rcu_head);
    kfree(p->dev_name);
    kfree(p);
}

static void free_snapshot_device_m_rcu(struct rcu_head *rcu) {
    struct mounted_dev *p = container_of(rcu, struct mounted_dev, rcu_head);
    kfree(p->dev_name);
    kfree(p->dir_path);
    kfree(p->block_bitmap);
    kfree(p);
}

/*
*   Inserisce device nella lista dei device non ancora montati ma s cui eseguire4 snapshot
*   - crea snapshot_device
*   - cerca major/minor -> OSS: può essere block device o loop device
*   - aggiunge device alla lista
*   Invocata dalla API activate_snapshot().
*/
int snapshot_add_device(const char *dev_name) {

    struct nonmounted_dev *new_dev;

    new_dev = kmalloc(sizeof(*new_dev), GFP_KERNEL);
    if(!new_dev) {
        // todo controlla ritorno
        return -ENOMEM;
    }

    strncpy(new_dev->dev_name, dev_name,SNAPSHOT_DEV_NAME_LEN);
    INIT_LIST_HEAD(&new_dev->list);

    // Usa rcu per consentire letture concorrenti visto che hook intercetta tante sb_bread
    spin_lock(&nonactive_devices_list_lock);
    list_add_rcu(&new_dev->list, &nonactive_devices_list);
    spin_unlock(&nonactive_devices_list_lock);

    return 0;
}

/*
*   Rimuove device dalla lista dei device attivi.
*   Invocata dalla API deactivate_snapshot().
*/
//todo controlla caso in cui invoca deactivate ma dispositivo è ancora montato
int snapshot_remove_device(const char *dev_name) {

    struct nonmounted_dev *p, *tmp;

    struct mounted_dev *m;

    // Prima controlla se il device è nella lista active
    spin_lock(&active_devices_list_lock);
    list_for_each_entry(m, &active_devices_list, list) {
        if (strncmp(m->dev_name, dev_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            spin_unlock(&active_devices_list_lock);
            printk(KERN_ERR "%s: cannot deactivate snapshot on device %s: device is still mounted", MODNAME, dev_name);
            return -EBUSY;
        }
    }
    spin_unlock(&active_devices_list_lock);

    // Poi cerca e rimuovi dalla lista nonactive
    spin_lock(&nonactive_devices_list_lock);
    
    list_for_each_entry_safe(p, tmp, &nonactive_devices_list, list) {
        if (strncmp(p->dev_name, dev_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            list_del_rcu(&p->list);
            spin_unlock(&nonactive_devices_list_lock);

            // Posticipa la kfree a quando tutti i lettori avranno finito
            call_rcu(&p->rcu_head, free_snapshot_device_nm_rcu);

            return 0;
        }
    }

    spin_unlock(&nonactive_devices_list_lock);
    printk(KERN_ERR "%s: device %s not found in nonactive list", MODNAME, dev_name);
    return -ENOENT;
}

/*
*   Funzione invocata quando viene intercettata la mount di un device per definire
*   directory in cui salvare le modifiche ai blocchi del dispositivo.
*/
int snapshot_handle_mount(super_block sb, const char *timestamp) {

    struct nonmounted_dev *n_dev;
    struct mounted_dev *m_dev, *p;
    char *dir_path = NULL;
    struct path path;
    int ret;
    bool found = false;
    bool already_active = false;
    struct dentry *dentry_ret;
    dev_t dev;
    struct block_device *bdev;
    struct gendisk *disk;
    char dev_name[SNAPSHOT_DEV_NAME_LEN];

    // Controlla che bdev non siano null
    if(!sb->s_bdev) {
        printk(KERN_ERR "%s: bdev is null", MODNAME);
        return -EINVAL;
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


    // Cerca il dev nella lista dei device per cui è attivo snapshot ma non montati
    rcu_read_lock();

    list_for_each_entry_rcu(n_dev, &nonactive_devices_list, list) {
        if(strncmp(n_dev->dev_name, dev_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            found = true;
            break;
        }
    }

    rcu_read_unlock();

    if(!found) {
        printk(KERN_ERR "%s: device (%d, %d) has no snapshot acivated", MODNAME, MAJOR(dev), MINOR(dev));
        return -EINVAL;
    }

    // Alloca spazio per il path della directory
    dir_path = kmalloc(MAX_PATH_LEN, GFP_KERNEL);
    if(!dir_path) {
        printk(KERN_ERR "%s: kmalloc while creating directory path failed: could not allocate dir_path", MODNAME);
        return -ENOMEM;
    }

    // Costruisce path
    ret = snprintf(dir_path, MAX_PATH_LEN, "%s/%s_%s", SNAPSHOT_DIR_PATH, dev_name, timestamp);
    if(ret >= MAX_PATH_LEN || ret < 0) {
        printk(KERN_ERR "%s: snprintf while creating directcory path failed", MODNAME);
        kfree(dir_path);
        return -EINVAL;
    }

    // Verifica che la directory /snapshot esista
    ret = kern_path(SNAPSHOT_DIR_PATH, LOOKUP_DIRECTORY, NULL);
    if(ret) {
        printk(KERN_ERR "%s: kern_path while creating directory path failed: there's no existing /snapshot", MODNAME);
        kfree(dir_path);
        return -ENOENT;
    }

    // Crea nuova sottodirectory
    dentry_ret = kern_path_create(AT_FDCWD, dir_path, NULL, 0);
    if (IS_ERR(dentry_ret)) {
        ret = PTR_ERR(dentry_ret);
        if (ret != -EEXIST) {
            printk(KERN_ERR "%s: failed to create snapshot subdirectory (%d)", MODNAME, ret);
            return ret;
        }
    }

    // Alloca elemento device active
    m_dev = kmalloc(sizeof(*m_dev), GFP_ATOMIC);
    if(!m_dev) {
        printk(KERN_ERR "%s: kmalloc while creating directory path failed: could not allocate non-mounted device", MODNAME);
        kfree(dir_path);
        return -ENOMEM;
    }

    strscpy(m_dev->dev_name, dev_name, SNAPSHOT_DEV_NAME_LEN);
    m_dev->dev = dev;
    strscpy(m_dev->dir_path, dir_path, MAX_PATH_LEN);
    
    // todo sistema qui
    // Ritorna numero di settori del disco
    sector_t nr_sectors = get_capacity(disk);
    // Dimensione dei blocchi nel fs
    unsigned long block_size = sb->s_blocksize;
    // Calcola numero di blocchi nel fs (nr_sectors << 9 = nr_sectors * 512 => numero totale di byte sul disco)
    // e poi divide per la dimensione del blocco
    m_dev->bitmap_size = (nr_sectors << 9) / block_size;
    // Alloca la bitmap (BITS_TO_LONG ritorna il numero di unisgned long per contenere quei bit)
    m_dev->block_bitmap = kmalloc(BITS_TO_LONG(m_dev->bitmap_size) * sizeof(unsigned long), GFP_KERNEL);
    if(!m_dev->block_bitmap) {
        printk(KERN_ERR "%s: kmalloc failed for block_bitmap in snapshot_handle_mount", MODNAME);
        kfree(m_dev);
        kfree(dir_path);
        return -ENOMEM;
    }
    // Inizializza bitmap a zero
    memset(m_dev->block_bitmap, 0, BITS_TO_LONG(m_dev->bitmap_size) * sizeof(unsigned long));

    INIT_LIST_HEAD(&m_dev->list);

    // Prende lock su lista active e lista non active
    spin_lock(&active_devices_list_lock);
    spin_lock(&nonactive_devices_list_lock);

    // Controlla ancora se device è nella lista non active (potrei avere mount concorrente che nel frattempo lo ha spostato di lista)
    found = false;
    list_for_each_entry(n_dev, &nonactive_devices_list, list) {
        if(strncmp(n_dev->dev_name, dev_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            found = true;
            break;
        }
    }

    list_for_each_entry(p, &active_devices_list, list) {
        if(strncmp(p->dev_name, dev_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            already_active = true;
            break;
        }
    }

    if(!found && already_active) {
        printk(KERN_ERR "%s: device was already mounted in concurrency", MODNAME);
        spin_unlock(&active_devices_list_lock);
        spin_unlock(&nonactive_devices_list_lock);

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
    list_add_tail_rcu(&m_dev->list, &active_devices_list);
    list_del_rcu(&n_dev->list);

    spin_unlock(&active_devices_list_lock);
    spin_unlock(&nonactive_devices_list_lock);

    call_rcu(&n_dev->rcu_head, free_snapshot_device_nm_rcu);

    // todo scrivi metadati 
    kfree(dir_path);  
    return 0;
}

// todo handler unmount
int snapshot_handle_unmount(dev_t dev) {
    struct nonmounted_dev *n_dev, *p;
    struct mounted_dev *m_dev;
    bool found = false;
    bool already_active = false;
    int ret;

    // Cerca il dev nella lista dei device attivi
    rcu_read_lock();

    list_for_each_entry_rcu(m_dev, &active_devices_list, list) {
        if(m_dev->dev == dev) {
            found = true;
            break;
        }
    }

    rcu_read_unlock();

    if(!found) {
        printk(KERN_ERR "%s: device (%d, %d) has no snapshot", MODNAME, MAJOR(dev), MINOR(dev));
        return -EINVAL;
    }

    // se found => device ha abilitato snapshot

    // Alloca elemento device active
    n_dev = kmalloc(sizeof(*n_dev), GFP_ATOMIC);
    if(!n_dev) {
        printk(KERN_ERR "%s: kmalloc failed while handling unmount for device (%d, %d)", MODNAME, MAJOR(dev), MINOR(dev));
        return -ENOMEM;
    }

    strscpy(n_dev->dev_name, m_dev->dev_name, SNAPSHOT_DEV_NAME_LEN);
    INIT_LIST_HEAD(&n_dev->list);

    // Prende lock su lista active e lista non active
    spin_lock(&active_devices_list_lock);
    spin_lock(&nonactive_devices_list_lock);

    // Controllo ancora se device è nella lista active (potrei avere unmount concorrente che nel frattempo lo ha spostato di lista)
    found = false;
    list_for_each_entry(m_dev, &active_devices_list, list) {
        if(m_dev->dev == dev) {
            found = true;
            break;
        }
    }

    list_for_each_entry(p, &nonactive_devices_list, list) {
        if(strncmp(p->dev_name, m_dev->dev_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            already_active = true;
            break;
        }
    }

    // Controllo di coerenza
    if (found && already_active) {
        printk(KERN_ERR "%s: device (%d, %d) found in both lists (incoherence)", MODNAME, MAJOR(dev), MINOR(dev));
        ret = -EIO;
        goto out_unlock_free;
    }

    if (!found && !already_active) {
        printk(KERN_ERR "%s: device (%d, %d) lost from both lists (race?)", MODNAME, MAJOR(dev), MINOR(dev));
        ret = -ENOENT;
        goto out_unlock_free;
    }

    if(!found && already_active) {
        printk(KERN_WARNING "%s: device (%d, %d) was removed concurrently", MODNAME, MAJOR(dev), MINOR(dev));
        ret = -EALREADY;
        goto out_unlock_free;
    }

    list_add_tail_rcu(&n_dev->list, &nonactive_devices_list);
    list_del_rcu(&m_dev->list);

    spin_unlock(&active_devices_list_lock);
    spin_unlock(&nonactive_devices_list_lock);

    call_rcu(&m_dev->rcu_head, free_snapshot_device_m_rcu);
    return 0;

out_unlock_free:
    spin_unlock(&nonactive_devices_list_lock);
    spin_unlock(&active_devices_list_lock);
    kfree(n_dev);
    return ret;
}

static int snapshot_handle_write(dev_t dev, sector_t block_nr, size_t size) {

    // Cerca directory del device
    // Se non esiste, ritorna errore
    struct mounted_dev *m_dev;
    bool found = false;
    rcu_read_lock();
    list_for_each_entry_rcu(m_dev, &active_devices_list, list) {
        if(m_dev->dev == dev) {
            found = true;
            break;
        }
    }
    rcu_read_unlock();
    if(!found) {
        printk(KERN_ERR "%s: device (%d, %d) has no snapshot", MODNAME, MAJOR(dev), MINOR(dev));
        return -EINVAL;
    }

    // Controlla se il blocco è già stato modificato
    
    if(block_nr < 0 || block_nr >= m_dev->bitmap_size) {
        printk(KERN_ERR "%s: block number %llu out of range for device (%d, %d)", MODNAME, (unsigned long long)block_nr, MAJOR(dev), MINOR(dev));
        return -EINVAL;
    }

    if (test_bit(bit_index, m_dev->block_bitmap)) {
        printk(KERN_INFO "%s: block %llu on device (%d, %d) already modified", MODNAME, (unsigned long long)block_nr, MAJOR(dev), MINOR(dev));
        return 0; // Il blocco è già stato modificato
    }

    // Segna il blocco come modificato nella bitmap
    set_bit(bit_index, bitmap);
    printk(KERN_INFO "%s: block %llu on device (%d, %d) marked as modified", MODNAME, (unsigned long long)block_nr, MAJOR(dev), MINOR(dev));
    
    // Crea un nuovo work item per il kworker
    struct packed_work *work = kmalloc(sizeof(*work), GFP_KERNEL);
    if (!work) {
        printk(KERN_ERR "%s: kmalloc failed for packed_work in snapshot_handle_write", MODNAME);
        return -ENOMEM;
    }

    work->dev = dev;
    work->block_nr = block_nr;
    work->size = size;
    work->data = kmalloc(size, GFP_KERNEL);
    if (!work->data) {
        printk(KERN_ERR "%s: kmalloc failed for data buffer in snapshot_handle_write", MODNAME);
        kfree(work);
        return -ENOMEM;
    }

    // Copia i dati del blocco modificato
    struct buffer_head *bh = __bread(dev, block_nr, size);
    if (!bh) {
        printk(KERN_ERR "%s: __bread failed for device (%d, %d) at block %llu", MODNAME, MAJOR(dev), MINOR(dev), (unsigned long long)block_nr);
        kfree(work->data);
        kfree(work);
        return -EIO;
    }

    memcpy(work->data, bh->b_data, size);
    brelse(bh);
    INIT_WORK(&work->work, snapshot_worker);
    // Aggiunge il lavoro alla workqueue
    schedule_work(&work->work);
    
    printk(KERN_INFO "%s: scheduled work for block %llu on device (%d, %d)", MODNAME, (unsigned long long)block_nr, MAJOR(dev), MINOR(dev));
    return 0;
}


static int snapshot_worker(struct work_struct *work) {
    struct packed_work *work = container_of(work, struct packed_work, work);
    dev_t dev = work->dev;
    sector_t block_nr = work->block_nr;
    size_t size = work->size;
    char *data = work->data;

    struct mounted_dev *m_dev;
    bool found = false;
    rcu_read_lock();
    list_for_each_entry_rcu(m_dev, &active_devices_list, list) {
        if(m_dev->dev == dev) {
            found = true;
            break;
        }
    }
    rcu_read_unlock();
    if(!found) {
        printk(KERN_ERR "%s: device (%d, %d) has no snapshot", MODNAME, MAJOR(dev), MINOR(dev));
        kfree(data);
        kfree(work);
        return -EINVAL;
    } 
    // Scrive i dati modificati nel file system
    struct file *file;
    char file_path[MAX_PATH_LEN];
    snprintf(file_path, MAX_PATH_LEN, "%s/%llu.bin", m_dev->dir_path, (unsigned long long)block_nr);

    file = filp_open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(file)) {
        printk(KERN_ERR "%s: filp_open failed for %s, error=%ld", MODNAME, file_path, PTR_ERR(file));
        kfree(data);
        kfree(work);
        return PTR_ERR(file);
    }

    ssize_t ret_write = kernel_write(file, data, size, &file->f_pos);
    filp_close(file, NULL);
    if (ret_write < 0) {
        printk(KERN_ERR "%s: kernel_write failed for %s, error=%zd", MODNAME, file_path, ret_write);
        kfree(data);
        kfree(work);
        return ret_write;
    }
    printk(KERN_INFO "%s: wrote %zd bytes to %s for block %llu on device (%d, %d)", MODNAME, file_path, written, (unsigned long long)block_nr, MAJOR(dev), MINOR(dev)); 
    
    // Libera la memoria allocata
    kfree(data);
    kfree(work);

    return ret;
}


int snapshot_init(void) {
    printk(KERN_INFO "%s: snapshot_init completed", MODNAME);
    return 0;
}

void snapshot_cleanup(void) {
    struct nonmounted_dev *p, *tmp;
    struct mounted_dev *m, *mtmp;

    // Libera tutti i device non attivi
    spin_lock(&nonactive_devices_list_lock);
    list_for_each_entry_safe(p, tmp, &nonactive_devices_list, list) {
        list_del_rcu(&p->list);
        call_rcu(&p->rcu_head, free_snapshot_device_nm_rcu);
    }
    spin_unlock(&nonactive_devices_list_lock);

    // Libera tutti i device attivi
    spin_lock(&active_devices_list_lock);
    list_for_each_entry_safe(m, mtmp, &active_devices_list, list) {
        list_del_rcu(&m->list);
        call_rcu(&m->rcu_head, free_snapshot_device_m_rcu);
    }
    spin_unlock(&active_devices_list_lock);

    printk(KERN_INFO "%s: snapshot_cleanup completed", MODNAME);
}