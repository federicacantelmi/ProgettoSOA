#ifndef SNAPSHOT_AUTH_H
#define SNAPSHOT_AUTH_H

#include <linux/types.h>

#define PSW_SALT_LEN 16
#define PSW_HASH_LEN 32

struct salted_hash_psw_t {

    unsigned char salt[PSW_HASH_LEN];
    unsigned char psw_hash[PSW_HASH_LEN];

};

int check_auth(const char *password);
int auth_init(const char *password);
void cleanup_auth(void);

#endif // SNAPSHOT_AUTH_H