#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <unistd.h>

void anti_debug_check(void) {
    // Standard Linux Anti-Debugging detection
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        printf("[!] Anti-Debug Alert: Active debugger (GDB/Tracer) detected! Exiting...\n");
        exit(1);
    }
}

int validate_product_key(const char *license_input) {
    // Expected format: TITAN-XXXX-PRO
    if (strlen(license_input) != 14) {
        return 0;
    }

    if (strncmp(license_input, "TITAN-", 6) != 0) {
        return 0;
    }

    if (strcmp(license_input + 10, "-PRO") != 0) {
        return 0;
    }

    // Mathematical check on inner 4 digits: sum must equal 24
    int sum = 0;
    for (int i = 6; i < 10; i++) {
        if (license_input[i] < '0' || license_input[i] > '9') return 0;
        sum += (license_input[i] - '0');
    }

    return (sum == 24); // e.g. TITAN-6666-PRO (6+6+6+6=24)
}

int main(int argc, char **argv) {
    printf("===========================================\n");
    printf("       TITAN ENTERPRISE SECURE PORTAL      \n");
    printf("===========================================\n");

    // Perform security integrity check
    anti_debug_check();

    if (argc < 2) {
        printf("[*] Usage: %s <LICENSE_SERIAL_KEY>\n", argv[0]);
        printf("[*] Example: %s TITAN-XXXX-PRO\n", argv[0]);
        return 1;
    }

    printf("[*] Verifying serial key '%s' against license server...\n", argv[1]);

    if (validate_product_key(argv[1])) {
        printf("\n[+] ================================================\n");
        printf("[+] SUCCESS! Valid License Key. Access Granted.\n");
        printf("[+] Welcome, Registered Enterprise User.\n");
        printf("[+] ================================================\n");
        return 0;
    } else {
        printf("\n[-] ERROR: Invalid License Key or Hardware ID mismatch.\n");
        printf("[-] Access Denied. Contact support@titan-corp.internal\n");
        return 2;
    }
}
