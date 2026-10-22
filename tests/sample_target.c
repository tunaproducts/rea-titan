#include <stdio.h>
#include <string.h>

int verify_license(const char *key) {
    if (strcmp(key, "TITAN-SECRET-KEY-2026") == 0) {
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <license_key>\n", argv[0]);
        return 1;
    }

    if (verify_license(argv[1])) {
        printf("[+] Access Granted! Welcome to REA-TITAN Core.\n");
    } else {
        printf("[-] Access Denied! Invalid key.\n");
    }
    return 0;
}
