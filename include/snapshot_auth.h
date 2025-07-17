#ifndef SNAPSHOT_AUTH_H
#define SNAPSHOT_AUTH_H

#include <linux/types.h>

int check_auth(const char *password);
int auth_init(const char *password);
void cleanup_auth(void);

#endif // SNAPSHOT_AUTH_H