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

#include "snapshot.h"

static LIST_HEAD(active_devices_list);
static DEFINE_SPINLOCK(active_devices_list_lock);
static LIST_HEAD(nonactive_devices_list);
static DEFINE_SPINLOCK(nonactive_devices_list_lock);

/*
*   Funzione chiamata in callback per eliminazione dell'area allocata
*/
static void free_snapshot_device_rcu(struct rcu_head *rcu) {
    struct nonmounted_dev *p = container_of(rcu, struct nonmounted_dev, rcu_head);
    kfree(p->dev_name);
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

    spin_lock(&nonactive_devices_list_lock);
    
    list_for_each_entry_safe(p, tmp, &nonactive_devices_list, list) {
        if (strncmp(p->dev_name, dev_name, SNAPSHOT_DEV_NAME_LEN) == 0) {
            list_del_rcu(&p->list);
            spin_unlock(&nonactive_devices_list_lock);

            // Posticipa la kfree a quando tutti i lettori avranno finito
            call_rcu(&p->rcu_head, free_snapshot_device_rcu);

            return 0;
        }
    }

    spin_unlock(&nonactive_devices_list_lock);
    // printk
    return -ENOENT;
}

/*
*   Funzione invocata quando viene intercettata la mount di un device per definire
*   directory in cui salvare le modifiche ai blocchi del dispositivo.
*/
int snapshot_handle_mount(const char *dev_name, dev_t dev, const char *timestamp) {

    struct nonmounted_dev *n_dev;
    struct mounted_dev *m_dev, *p;
    char *dir_path = NULL;
    struct path path;
    int ret;
    bool found = false;
    bool already_active = false;
    struct dentry *dentry_ret;

    // Cerca il dev nella lista dei device attivi
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

    // se found => device ha abbilitato snapshot

    // Inizia a costruire directory
    dir_path = kmalloc(MAX_PATH_LEN, GFP_KERNEL);
    if(!dir_path) {
        printk(KERN_ERR "%s: kmalloc while creating directory path failed: could not allocate dir_path", MODNAME);
        return -ENOMEM;
    }

    // Costruisce path
    ret = snprintf(dir_path, MAX_PATH_LEN, "%s/%s_%s", SNAPSHOT_DIR_PATH, dev_name, timestamp);
    if(ret >= MAX_PATH_LEN || ret < 0) {
        kfree(dir_path);
        printk(KERN_ERR "%s: snprintf while creating directcory path failed", MODNAME);
        return -EINVAL;
    }

    // Crea directory
    ret = kern_path(SNAPSHOT_DIR_PATH, LOOKUP_DIRECTORY, NULL);
    if(ret) {
        printk(KERN_ERR "%s: kern_path while creating directory path failed: there's no existing /snapshot", MODNAME);
        goto out;
    }

    // Crea nuova sottodirectory
    dentry_ret = kern_path_create(AT_FDCWD, dir_path, NULL, 0);
    if (IS_ERR(dentry_ret)) {
        ret = PTR_ERR(dentry_ret);
        if (ret != -EEXIST)
        // todo printk
            goto out;
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
    INIT_LIST_HEAD(&m_dev->list);

    // Prende lock su lista active e lista non active
    spin_lock(&active_devices_list_lock);
    spin_lock(&nonactive_devices_list_lock);

    // Controllo ancora se device è nella lista non active (potrei avere mount concorrente che nel frattempo lo ha spostato di lista)
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

        // elimino directory creata
        ret = kern_path(dir_path, LOOKUP_DIRECTORY, &path);
        if (!ret) {
            vfs_rmdir(NULL, path.dentry->d_parent->d_inode, path.dentry);
            path_put(&path);
        }

        kfree(dir_path);
        // todo cambia valore return
        return 0;
    }

    list_add_tail_rcu(&m_dev->list, &active_devices_list);
    list_del_rcu(&n_dev->list);

    spin_unlock(&active_devices_list_lock);
    spin_unlock(&nonactive_devices_list_lock);

    call_rcu(&n_dev->rcu_head, free_snapshot_device_rcu);

    // todo scrivi metadati 
out:
    kfree(dir_path);  
    return ret;
}

// todo handler unmount
int snapshot_handle_unmount(dev_t dev) {
    struct nonmounted_dev *n_dev, *p;
    struct mounted_dev *m_dev;
    bool found = false;
    bool already_active = false;

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
        // todo printk device non ha abilitato snapshot
        return -EINVAL;
    }

    // se found => device ha abilitato snapshot

    // Alloca elemento device active
    n_dev = kmalloc(sizeof(*n_dev), GFP_ATOMIC);
    if(!n_dev) {
        //todo printk
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
        if(p->dev_name == m_dev->dev_name) {
            already_active = true;
            break;
        }
    }

    // Controllo di coerenza
    if (found && already_active) {
        pr_warn("Snapshot: device %u trovato in entrambe le liste (incoerenza)\n", dev);
        WARN_ONCE(1, "Device presente in entrambe le liste!\n");
        goto out_unlock_free;
    }

    if (!found && !already_active) {
        pr_warn("Snapshot: device %u perso da entrambe le liste (race?)\n", dev);
        WARN_ONCE(1, "Device scomparso da entrambe le liste!\n");
        goto out_unlock_free;
    }

    if(!found && already_active) {
        // printk elemento è stato eliminato in concorrenza da qualcun altro
        goto out_unlock_free;
    }

    list_add_tail_rcu(&n_dev->list, &nonactive_devices_list);
    list_del_rcu(&m_dev->list);

    spin_unlock(&active_devices_list_lock);
    spin_unlock(&nonactive_devices_list_lock);

    call_rcu(&m_dev->rcu_head, free_snapshot_device_rcu);

out_unlock_free:
    spin_unlock(&nonactive_devices_list_lock);
    spin_unlock(&active_devices_list_lock);
    kfree(n_dev);
    return 0;
}

/*
*   Alloca workqueue
*   crea directory /snapshot
*/
int snapshot_init(void) {
    return 0;
}

void snapshot_cleanup(void) {
}