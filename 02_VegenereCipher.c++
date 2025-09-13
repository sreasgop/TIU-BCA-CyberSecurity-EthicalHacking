#include <iostream>
#include <string>
#include <vector>
#include <limits>
using namespace std;

struct user_data{
    string user_text;
    string user_keyword;
};

user_data prompt(){
    user_data d;
    cout << "\nEnter text: ";
    cin.ignore(1, '\n'); 
    getline(cin, d.user_text);
    cout << "Enter key: ";
    cin.ignore(1, '\n'); 
    getline(cin, d.user_keyword);
    return d;
}

string vigenere_encrypt(const string& plaintext, const string& key) {
    vector<int> k;
    for (char c : key) if (isalpha((unsigned char)c)) k.push_back(toupper(c) - 'A');
    if (k.empty()) return plaintext;
    string res; res.reserve(plaintext.size());
    size_t j = 0, m = k.size();
    for (char ch : plaintext) {
        if (isalpha((unsigned char)ch)) {
            bool up = isupper((unsigned char)ch);
            int base = up ? 'A' : 'a';
            int shift = k[j % m];
            res.push_back(char((ch - base + shift) % 26 + base));
            j++;
        } else res.push_back(ch);
    }
    return res;
}
string vigenere_decrypt(const string& ciphertext, const string& key) {
    vector<int> k;
    for (char c : key) if (isalpha((unsigned char)c)) k.push_back(toupper(c) - 'A');
    if (k.empty()) return ciphertext;
    string res; res.reserve(ciphertext.size());
    size_t j = 0, m = k.size();
    for (char ch : ciphertext) {
        if (isalpha((unsigned char)ch)) {
            bool up = isupper((unsigned char)ch);
            int base = up ? 'A' : 'a';
            int shift = k[j % m];
            res.push_back(char((ch - base - shift + 26) % 26 + base));
            j++;
        } else res.push_back(ch);
    }
    return res;
}

int main(){
    string encrypted_text, decrypted_text;
    int user_key, option;
    while (true) {
        cout << "Vegenere Cipher\n============\n";
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
            encrypted_text = vigenere_encrypt(data.user_text, data.user_keyword);
            cout << "Ciphered-Text: " << encrypted_text << endl << endl;
            break;
        }
        case 2: {
            user_data data = prompt();
            decrypted_text = vigenere_decrypt(data.user_text, data.user_keyword);
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