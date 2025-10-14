// Compile with: g++ -fno-stack-protector -z execstack -no-pie -o demo file.cpp
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio> 
using namespace std;

// Function that should not be called unless overflow occurs
void secret_function() {
    cout << "\n\n" <<string(49, '-') << endl;
    cout << "***  !! BUFFER OVERFLOW ATTACK SUCCESSFUL !!  ***"
    "\n-------------------------------------------------\n";
    cout << "         !! Secret function executed !!\n";
    cout << string(49, '-') << endl;
    exit(0); 
}

// Vulnerable function: could be overflowed to jump to secret_function
void vulnerable_function(char *input) {
    char buffer[16];
    cout << "Vulnerable Function is being executed..." << endl;
    cout << "Input Buffer address: " << &buffer << endl; 
    cout << "Secret function address: " << (void*)&secret_function << endl;
    strcpy(buffer, input);
    cout << "Input stored: " << buffer << "\n\n";
}

int main() {
    
    char input[64];
    
    cout << "\n\n====================================================\n"
            "||      Buffer Overflow Attack Demonstration      ||\n"
            "====================================================\n"
            "\n----------------\nCrucial Details:\n----------------\n";
    cout << "Vulnerable function address: " << (void*)&vulnerable_function << endl;
    cout << "Secret function address    : " << (void*)&secret_function << endl;
    cout << "Enter a string (of length < 16) : ";

    // Use fgets for demo safety but simulates using unsafe strcpy later
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;  // Remove newline

    cout << "\n\n\n*** Normal execution: ***"
    "\n-------------------------\n";
    vulnerable_function(input);  // Safe demo like sample

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
        cout << "Warning: Payload exceeds buffer size!"
        "\nPotential overflow may trigger secret_function()\n\n";
    }
    vulnerable_function(payload);  // Triggers secret_function!
    return 0;
}
