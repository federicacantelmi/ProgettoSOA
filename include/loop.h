// Qui ci copio la definizione di loop_device perché non è esportata dal kernel

#ifndef LOOP_H
#define LOOP_H

// 6.8.0
struct loop_device {
    int lo_number; // numero del loop device
    struct file *lo_backing_file; // file di backing del loop device
    /* altri campi che non mi servono */
};

#endif // LOOP_H