#include <stdio.h>
#include <oqs/oqs.h>

int main() {
    const char *method_name = "DEFAULT";
    OQS_KEM *kem = OQS_KEM_new(method_name);
    if (kem == NULL) {
        printf("Error: Failed to create KEM object.\n");
        return 1;
    }

    printf("KEM object created successfully.\n");

    // Use the kem object as needed

    // Cleanup
    OQS_KEM_free(kem);

    return 0;
}