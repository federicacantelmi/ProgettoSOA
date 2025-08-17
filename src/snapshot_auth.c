/*
*   Codice si occupa di inizializzare la struttura per la
*   gestione della password e di effettuare il check ogni
*   volta che si invoca l'attivazione/deattivazione/restore di uno snapshot.
*/

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/random.h>
#include <linux/string.h>
#include <crypto/hash.h>

#include "snapshot_auth.h"

#define MODNAME "SNAPSHOT MOD"

static struct salted_hash_psw_t salted_hash_psw;

static int calculate_sha256(const char *password, const char *salt, unsigned char *output){
    struct crypto_shash *tfm;
    struct shash_desc *desc;

    int ret;
    unsigned char *buffer = NULL;

    size_t psw_len = strlen(password);

    if(!password || psw_len == 0)
        return -EINVAL;

    buffer = kmalloc(psw_len + PSW_SALT_LEN, GFP_KERNEL);
    if (!buffer)
        return -ENOMEM;

    /* concatena salt e password */
    memcpy(buffer, salt, PSW_SALT_LEN);
    memcpy(buffer + PSW_SALT_LEN, password, psw_len);

    /* calcola SHA256 */
    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        kfree(buffer);
        return PTR_ERR(tfm);
    }

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        kfree(buffer);
        return -ENOMEM;
    }

    desc->tfm = tfm;

    ret = crypto_shash_final(desc, output);

    kfree(desc);
    kfree(buffer);
    crypto_free_shash(tfm);

    return ret;


}

/*  
*   Funzione invocata quando viene invocata API activate_snapshot, deactivate_snapshot o restore_snapshot.
*/
int check_auth(const char *password) {

    unsigned char hash_output[PSW_HASH_LEN];
    int ret;

    /* verifica che utente sia root */
    if(current_euid().val != 0) {
        printk(KERN_ERR "%s: only root can perform this operation\n", MODNAME);
       return -EPERM;
    }

    ret = calculate_sha256(password, salted_hash_psw.salt, hash_output);
    if (ret < 0) {
        printk(KERN_ERR "%s: error calculating hash (err=%d)\n", MODNAME, ret);
        return ret;
    }

    if(memcmp(hash_output, salted_hash_psw.hash, PSW_HASH_LEN) != 0) {
        printk(KERN_ERR "%s: password does not match\n", MODNAME);
        return -EACCES;
    }

    return 0;
}

/*
*   Funzione invocata all'inserimento del modulo
*/
int auth_init(const char *password) {
    int ret;
    unsigned char hash_output[PSW_HASH_LEN];

    /* genera salt casuale */
    get_random_bytes(salted_hash_psw.salt, PSW_SALT_LEN);

    /* calcola hash della password */
    ret = calculate_sha256(password, salted_hash_psw.salt, hash_output);
    if(ret < 0) {
        return -EINVAL;
    }

    /* copia hash nella struttura */
    memcpy(salted_hash_psw.hash, hash_output, PSW_HASH_LEN);
    printk(KERN_INFO "%s: password hash initialized successfully\n", MODNAME);
    
    return 0;
    
}

/*
*   Funzione invocata alla cleanup del modulo
*/
void cleanup_auth(void) {
    memset(salted_hash_psw.salt, 0, PSW_SALT_LEN);
    memset(salted_hash_psw.hash, 0, PSW_HASH_LEN);
    printk(KERN_INFO "%s: password hash cleaned up successfully\n", MODNAME);
}