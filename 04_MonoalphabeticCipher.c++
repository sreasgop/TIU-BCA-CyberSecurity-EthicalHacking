#include <iostream>
#include <string>
#include <array>
#include <limits>
using namespace std;

struct SubstMaps {
    array<char,26> encU, encL, decU, decL;
};
SubstMaps build_subst_maps(const string& keyAlphabet) {
    string key;
    for (char c : keyAlphabet) if (isalpha((unsigned char)c)) key.push_back(toupper(c));
    if (key.size() != 26) throw runtime_error("Key must have 26 letters");
    array<int,26> seen{}; seen.fill(0);
    for (char c : key) {
        if (c < 'A' || c > 'Z' || seen[c - 'A']) throw runtime_error("Key must have 26 unique A-Z letters");
        seen[c - 'A'] = 1;
    }
    SubstMaps M;
    for (int i = 0; i < 26; ++i) {
        char cu = key[i];
        M.encU[i] = cu;
        M.encL[i] = tolower(cu);
    }
    for (int i = 0; i < 26; ++i) {
        M.decU[M.encU[i]-'A'] = char('A' + i);
        M.decL[M.encL[i]-'a'] = char('a' + i);
    }
    return M;
}
string mono_encrypt(const string& text, const string& keyAlphabet) {
    SubstMaps M = build_subst_maps(keyAlphabet);
    string out; out.reserve(text.size());
    for (char ch : text) {
        if ('A' <= ch && ch <= 'Z') out.push_back(M.encU[ch - 'A']);
        else if ('a' <= ch && ch <= 'z') out.push_back(M.encL[ch - 'a']);
        else out.push_back(ch);
    }
    return out;
}
string mono_decrypt(const string& text, const string& keyAlphabet) {
    SubstMaps M = build_subst_maps(keyAlphabet);
    string out; out.reserve(text.size());
    for (char ch : text) {
        if ('A' <= ch && ch <= 'Z') out.push_back(M.decU[ch - 'A']);
        else if ('a' <= ch && ch <= 'z') out.push_back(M.decL[ch - 'a']);
        else out.push_back(ch);
    }
    return out;
}

struct user_data {
    string user_input;
    string key_alphabet;
};

user_data prompt() {
    user_data d;
    cout << "\nEnter text: ";
    cin.ignore(1, '\n'); 
    getline(cin, d.user_input); 
    cout << "Enter key alphabet (26 unique letters): ";
    getline(cin, d.key_alphabet);
    return d;
}

int main() {
    int option = 0;
    while (true) {
        cout << "Monoalphabetic Substitution Cipher\n==================================\n";
        cout << "Main Menu:\n";
        cout << "1. Encrypt Text.\n";
        cout << "2. Decrypt Text.\n";
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
            try {
                user_data data = prompt();
                string encrypted = mono_encrypt(data.user_input, data.key_alphabet);
                cout << "Ciphered-Text: " << encrypted << endl << endl;
            } catch (const exception& e) {
                cout << "Error: " << e.what() << endl << endl;
            }
            break;
        }
        case 2: {
            try {
                user_data data = prompt();
                string decrypted = mono_decrypt(data.user_input, data.key_alphabet);
                cout << "Plain-Text: " << decrypted << endl << endl;
            } catch (const exception& e) {
                cout << "Error: " << e.what() << endl << endl;
            }
            break;
        }
        case 3:
            cout << "\nExiting program.\n";
            return 0;
        default:
            cout << "\nInvalid Input! Please enter a number between 1-3.\n" << endl;
            break;
        }
    }
    return 0;
}
