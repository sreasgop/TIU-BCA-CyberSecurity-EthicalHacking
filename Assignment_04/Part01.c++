#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>  // For printf to match sample style
using namespace std;

// Function that should not be called unless overflow occurs
void secret_function() {
    cout << "\n*** !! BUFFER OVERFLOW ATTACK SUCCESSFUL !! ***\n";
    cout << "Secret function executed!\n";
    exit(0); 
}

// Vulnerable function: could be overflowed to jump to secret_function
void vulnerable_function(char *input) {
    char buffer[16];
    cout << "Vulnerable Function is being executed." << endl;
    cout << "Input Buffer address: " << &buffer << endl; 
    cout << "Secret function address: " << (void*)&secret_function << endl;
    // Deliberately unsafe copy (classic overflow)
    strcpy(buffer, input);
    printf("Input stored: %s\n", buffer);
}

int main() {
    char input[64];
    cout << "\n\n====================================================\n";
    cout << "||      Buffer Overflow Attack Demonstration      ||\n";
    cout << "====================================================\n";
    cout << "\nCrucial Details:\n";
    cout <<   "----------------\n";
    cout << "Vulnerable function address: " << (void*)&vulnerable_function << endl;
    cout << "Secret function address    : " << (void*)&secret_function << endl;
    cout << "Enter a string (of length < 16) : ";
    // Use fgets for demo safety but simulates using unsafe strcpy later
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;  // Remove newline

    cout << "\n\n*** Normal execution: ***\n-------------------------\n";
    vulnerable_function(input);  // Safe demo like sample

    // Compile with: g++ -fno-stack-protector -z execstack -no-pie -o demo file.cpp
    // Offset: ~24 bytes (16 buffer + 8 saved rbp on 64-bit) to overwrite return addr
    cout << "\n\n*** Attempting Buffer Overflow Attack (with crafted payload) ***\n";
    cout <<   "----------------------------------------------------------------\n";
    void* secret_addr = (void*)&secret_function;
    char payload[64];
    memset(payload, 'A', 24);  // Junk to reach return addr
    memcpy(payload + 24, &secret_addr, sizeof(secret_addr));  // Overwrite with addr
    payload[sizeof(payload) - 1] = '\0';
    cout << "Payoad Generation Complete!\n";
    cout << "Payload: " << payload << endl;
    if (strlen(payload) > 16){
        printf("Warning: Payload exceeds buffer size! Potential overflow may trigger secret_function()\n");
    }
    vulnerable_function(payload);  // Triggers secret_function!

    printf("\n[!] Program finished (no exploit above).\n");
    printf("[Hint: Use gdb for manual crafting: gdb ./demo; break vulnerable_function; run; x/32x $rsp]\n");
    return 0;
}
