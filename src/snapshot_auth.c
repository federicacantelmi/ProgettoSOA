/*
*   Codice si occupa di inizializzare la struttura per la
*   gestione della password e di effettuare il check ogni
*   volta che si invoca l'attivazione di uno snapshot.
*/

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/random.h>
#include <linux/string.h>
#include <crypto/hash.h>

#include "snapshot_auth.h"

static struct salted_hash_psw_t salted_hash_psw;

static int calculate_sha256(const char *password, const char *salt, unsigned char *output){
    struct crypto_shash *tfm;
    struct shash_desc *desc;

    int ret;
    unsigned char *buffer = NULL;

    size_t psw_len = strlen(password);

    if(!password || psw_len == 0) return -EINVAL;

    buffer = kmalloc(psw_len + PSW_SALT_LEN, GFP_KERNEL);
    if (!buffer) return -ENOMEM;

    // concatena salt e password
    memcpy(buffer, salt, PSW_SALT_LEN);
    memcpy(buffer + PSW_SALT_LEN, password, psw_len);

    // calcola SHA256
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
    // desc->flags = 0;

    ret = crypto_shash_final(desc, output);

    kfree(desc);
    kfree(buffer);
    crypto_free_shash(tfm);

    return ret;


}

// Funzione invocata quando viene invocata API activate_snapshot
// o deactivate_snapshot
// todo inserisci controllo errori quando invochi check_auth
int check_auth(const char *password) {

    unsigned char hash_output[PSW_HASH_LEN];

    // verifica che utente sia root
    if(current_euid().val != 0) {
        // Utente non root
       return -EPERM;
    }

    calculate_sha256(password, salted_hash_psw.salt, hash_output);

    if(memcmp(hash_output, salted_hash_psw.psw_hash, PSW_HASH_LEN) != 0) {
        // Password errata
        return -EACCES;
    }

    return 0;
}

// Funzione invocata all'inserimento del modulo
int auth_init(const char *password) {
    int ret;
    unsigned char hash_output[PSW_HASH_LEN];

    // genera salt casuale
    get_random_bytes(salted_hash_psw.salt, PSW_SALT_LEN);

    ret = calculate_sha256(password, salted_hash_psw.salt, hash_output);
    if(ret < 0) {
        return -EINVAL;
    }

    return 0;
    
}

// Funzione invocata alla cleanup del modulo
void cleanup_auth(void) {
    memset(salted_hash_psw.salt, 0, PSW_SALT_LEN);
    memset(salted_hash_psw.psw_hash, 0, PSW_HASH_LEN);
}