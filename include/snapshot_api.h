#ifndef SNAPSHOT_API_H
#define SNAPSHOT_API_H

#define SNAPSHOT_MAGIC 's'

/*
*   Comandi per il modulo snapshot.
*/
#define ACTIVATE_VALUE _IOW(SNAPSHOT_MAGIC, 1, struct snapshot_cmd)
#define DEACTIVATE_VALUE _IOW(SNAPSHOT_MAGIC, 2, struct snapshot_cmd)
#define RESTORE_VALUE _IOW(SNAPSHOT_MAGIC, 3, struct snapshot_cmd)

/**
*   Comando per attivare lo snapshot
*   @password: password per autenticare l'operazione;
*   @device_name: nome del device su cui attivare lo snapshot;
*/
struct snapshot_cmd {
    char password[64];
    char device_name[128];
};

int activate_snapshot(const char *device_name, const char *password);
int deactivate_snapshot(const char *device_name, const char *password);
int restore_snapshot(const char *device_name, const char *password);

#endif // SNAPSHOT_API_H