#ifndef SNAPSHOT_H
#define SNAPSHOT_H

#include <linux/list.h>
#include <linux/types.h>

#define MAX_DEVICES 32
#define SNAPSHOT_DEV_NAME_LEN 128
#define SNAPSHOT_DIR_PATH "/snapshot"
#define MAX_PATH_LEN 256

/*
*   Rappresenta un device montato su cui va eseguito lo snapshot
*   @dev_name: nome del device;
*   @dev: mantiene major/minor del device;
*   @list: list head per collegare device su cui eseguire snapshot;
*/
struct mounted_dev {
    char dev_name[SNAPSHOT_DEV_NAME_LEN];
    dev_t dev;
    struct list_head list;
};

/*
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

int snapshot_add_device(const char *);
int snapshot_remove_device(const char *);
int snapshot_handle_mount(const char *, dev_t, const char *);
int snapshot_init(void);
void snapshot_cleanup(void);




#endif // SNAPSHOT_H