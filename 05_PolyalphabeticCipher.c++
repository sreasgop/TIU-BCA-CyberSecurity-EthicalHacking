#include <iostream>
#include <string>
#include <array>
#include <vector>
#include <limits>
#include <cctype>
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

struct TableMaps {
    array<char,26> eU, eL, dU, dL;
};

TableMaps build_table(const string& keyAlphabet) {
    SubstMaps M = build_subst_maps(keyAlphabet);
    return {M.encU, M.encL, M.decU, M.decL};
}

string polyalpha_encrypt(const string& text, const vector<string>& tables) {
    if (tables.empty()) return text;
    vector<TableMaps> T; T.reserve(tables.size());
    for (auto& t : tables) T.push_back(build_table(t));
    string out; out.reserve(text.size());
    size_t j = 0, r = T.size();
    for (char ch : text) {
        if ('A' <= ch && ch <= 'Z') out.push_back(T[j%r].eU[ch - 'A']), j++;
        else if ('a' <= ch && ch <= 'z') out.push_back(T[j%r].eL[ch - 'a']), j++;
        else out.push_back(ch);
    }
    return out;
}

string polyalpha_decrypt(const string& text, const vector<string>& tables) {
    if (tables.empty()) return text;
    vector<TableMaps> T; T.reserve(tables.size());
    for (auto& t : tables) T.push_back(build_table(t));
    string out; out.reserve(text.size());
    size_t j = 0, r = T.size();
    for (char ch : text) {
        if ('A' <= ch && ch <= 'Z') out.push_back(T[j%r].dU[ch - 'A']), j++;
        else if ('a' <= ch && ch <= 'z') out.push_back(T[j%r].dL[ch - 'a']), j++;
        else out.push_back(ch);
    }
    return out;
}

struct user_data {
    string user_input;
    vector<string> key_alphabets;
};

user_data prompt() {
    user_data d;
    cout << "\nEnter text: ";
    cin.ignore(1, '\n'); 
    getline(cin, d.user_input);

    int num_keys;
    cout << "Enter number of key alphabets (1 or more): ";
    cin >> num_keys;
    if (cin.fail() || num_keys < 1) {
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        throw runtime_error("Invalid number of keys. Must be 1 or more.");
    }

    d.key_alphabets.resize(num_keys);
    cin.ignore(1, '\n'); 
    for (int i = 0; i < num_keys; ++i) {
        cout << "Enter key alphabet " << (i + 1) << " (26 unique letters): ";
        getline(cin, d.key_alphabets[i]);
    }

    return d;
}

int main() {
    int option = 0;
    while (true) {
        cout << "Polyalphabetic Substitution Cipher\n===================================\n";
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
                string encrypted = polyalpha_encrypt(data.user_input, data.key_alphabets);
                cout << "Ciphered-Text: " << encrypted << endl << endl;
            } catch (const exception& e) {
                cout << "Error: " << e.what() << endl << endl;
            }
            break;
        }
        case 2: {
            try {
                user_data data = prompt();
                string decrypted = polyalpha_decrypt(data.user_input, data.key_alphabets);
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