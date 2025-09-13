#include <iostream>
#include "01_CeaserCipher.c++"
using namespace std;

int main() {
    string user_input, encrypted_text, decrypted_text;
    int user_key, option;
    while (true) {
        cout << "Main Menu:\n";
        cout << "1. Encrypt Text.\n";
        cout << "2. De-crypt Text.\n";
        cout << "3. Quit.\n";
        cout << "Enter choice (1-3): ";
        cin >> option;
        switch (option) {
        case 1:
            cout << "\nEnter text: ";
            cin >> user_input;
            cout << "\nEnter key: ";
            cin >> user_key;
            encrypted_text = caesar_encrypt(user_input, user_key);
            cout << "Ciphered-Text: " << encrypted_text << endl << endl;
            break;
        case 2:
            cout << "\nEnter text: ";
            cin >> user_input;
            cout << "\nEnter key: ";
            cin >> user_key;
            decrypted_text = caesar_decrypt(user_input, user_key);
            cout << "Plain-Text: " << decrypted_text << endl << endl;
            break;
        case 3:
            cout << "\nExiting program.";
            exit(0);
        default:
            cout << "\nInvalid Input! (Enter a number between 1 - 3).";
            break;
        }
    }

    return 0;
}