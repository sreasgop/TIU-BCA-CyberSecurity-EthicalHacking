#include <iostream>
#include <string>
#include <limits>
using namespace std;

struct user_data{
    string user_input;
    int user_key;
};

user_data prompt(){
    user_data d;
    cout << "\nEnter text: ";
    cin.ignore(1, '\n'); 
    getline(cin, d.user_input);
    cout << "Enter key: ";
    cin >> d.user_key;
    return d;
}

char caesar_shift_char(char ch, int k) {
    if ('A' <= ch && ch <= 'Z') return char((ch - 'A' + k + 26) % 26 + 'A');
    if ('a' <= ch && ch <= 'z') return char((ch - 'a' + k + 26) % 26 + 'a');
    return ch;
}
string caesar_encrypt(const string& text, int key) {
    string out; out.reserve(text.size());
    key %= 26;
    for (char c : text) out.push_back(caesar_shift_char(c, key));
    return out;
}
string caesar_decrypt(const string& text, int key) {
    return caesar_encrypt(text, -key);
}

int main() {
    string encrypted_text, decrypted_text;
    int user_key, option;
    while (true) {
        cout << "Ceaser Cipher\n============\n";
        cout << "Main Menu:\n";
        cout << "1. Encrypt Text.\n";
        cout << "2. De-crypt Text.\n";
        cout << "3. Quit.\n";
        cout << "Enter choice (1-3): ";
        cin >> option;
        if (cin.fail()) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "\nInvalid Input! Please enter a number (1-3).\n" << endl;
            continue;  
        }
        switch (option) {
        case 1: {
            user_data data = prompt();
            encrypted_text = caesar_encrypt(data.user_input, data.user_key);
            cout << "Ciphered-Text: " << encrypted_text << endl << endl;
            break;
        }
        case 2: {
            user_data data = prompt();
            decrypted_text = caesar_decrypt(data.user_input, data.user_key);
            cout << "Plain-Text: " << decrypted_text << endl << endl;
            break;
        }
        case 3:
            cout << "\nExiting program.";
            exit(0);
        default:
            cout << "\nInvalid Input!.";
            break;
        }
    }

    return 0;
}