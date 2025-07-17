/*
*   Codice si occupa di inizializzare la struttura per la
*   gestione della password e di effettuare il check ogni
*   volta che si invoca l'attivazione di uno snapshot.
*/

#include "snapshot_auth.h"

// Funzione invocata quando viene invocata API activate_snapshot
// o deactivate_snapshot
int check_auth(const char *password) {

    return 0;
}

// Funzione invocata all'inserimento del modulo
int auth_init(const char *password) {

    return 0;
}

// Funzione invocata alla cleanup del modulo
void cleanup_auth(void) {

}