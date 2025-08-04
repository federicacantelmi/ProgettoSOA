#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "snapshot_api.h"

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <activate|deactivate> <device_name> <password>\n", argv[0]);
        return 1;
    }

    const char *command = argv[1];
    const char *device_name = argv[2];
    const char *password = argv[3];

    struct snapshot_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    strncpy(cmd.device_name, device_name, sizeof(cmd.device_name) - 1);
    strncpy(cmd.password, password, sizeof(cmd.password) - 1);

    int fd = open("/dev/snapshot_api_device", O_RDWR);
    if (fd < 0) {
        perror("Failed to open /dev/snapshot_api_device");
        return 1;
    }

    int ret;
    if (strcmp(command, "activate") == 0) {
        ret = ioctl(fd, ACTIVATE_VALUE, &cmd);
        if (ret < 0) {
            perror("Failed to activate snapshot");
            close(fd);
            return 1;
        }
        printf("Snapshot activated for device: %s\n", device_name);
    } else if (strcmp(command, "deactivate") == 0) {
        ret = ioctl(fd, DEACTIVATE_VALUE, &cmd);
        if (ret < 0) {
            perror("Failed to deactivate snapshot");
            close(fd);
            return 1;
        }
        printf("Snapshot deactivated for device: %s\n", device_name);
    } else {
        fprintf(stderr, "Unknown command: %s. Use 'activate' or 'deactivate'.\n", command);
        close(fd);
        return 1;
    }

    close(fd);
    return 0;
}