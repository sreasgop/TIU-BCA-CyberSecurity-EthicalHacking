#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <ctime>
#include <cstdlib>
#include <cmath>
#include <limits>
using namespace std;

bool is_prime(long long n) {
    if(n<2) return false;
    if(n==2) return true;
    if(n%2==0) return false;
    for(long long i=3; i*i<=n; i+=2)
        if(n%i == 0) return false;
    return true;
}

long long rand_prime(long long low, long long high) {
    long long p;
    do {
        p = low + rand() % (high - low + 1);
    } while (!is_prime(p));
    return p;
}

long long gcd(long long a, long long b) {
    return b == 0 ? a : gcd(b, a % b);
}

long long modexp(long long base, long long exp, long long mod) {
    long long res =1;
    base%=mod;
    while(exp>0) {
        if(exp&1) res=(res*base)%mod;
        base=(base*base)%mod;
        exp>>=1;
    }
    return res;
}

long long modinv(long long a, long long m) {
    long long m0 = m, t, q;
    long long x0 = 0, x1 = 1;
    if (m == 1) return 0;
    while (a > 1) {
        q = a / m;
        t = m;
        m = a % m;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0) x1 += m0;
    return x1;
}

struct RSAKeyPair {
    long long p, q, n, e, d;
};

RSAKeyPair generate_keys() {
    long long p = rand_prime(700, 1000);
    long long q;
    do {
        q = rand_prime(700, 1000);
    } while (q == p);
    long long n = p*q;
    long long phi = (p-1)*(q-1);
    long long e = 65537;
    if (gcd(e,phi)!=1) {
        e=3;
        while (gcd(e,phi)!=1) e+=2;
    }
    long long d = modinv(e,phi);
    return {p,q,n,e,d};
}

vector<long long> encode_message(const string& msg, int blockSize, long long n) {
    vector<long long> blocks;
    for (size_t i=0; i<msg.size(); i+=blockSize) {
        long long blockNum=0;
        for (int j=0; j<blockSize && i+j<msg.size(); ++j){
            blockNum = blockNum * 256 + (unsigned char)msg[i+j];
        }
        if (blockNum >= n) {
            cerr << "Block value exceeds modulus n, increase key size or reduce block size.\n";
            exit(1);
        }
        blocks.push_back(blockNum);
    }
    return blocks;
}

string decode_message(const vector<long long>& blocks, int blockSize) {
    string msg;
    for (auto block : blocks) {
        string temp(blockSize,'\0');
        for (int i=blockSize-1; i>=0; --i) {
            temp[i] = (char)(block & 0xFF);
            block >>= 8;
        }
        for(char c : temp)
            if (c != 0) msg += c;
    }
    return msg;
}

vector<long long> encrypt_decrypt_block(const vector<long long>& blocks, long long exp, long long n) {
    vector<long long> result;
    for(auto block : blocks)
        result.push_back(modexp(block, exp, n));
    return result;
}

vector<long long> readNumbers() {
    vector<long long> nums;
    string line; getline(cin,line);
    stringstream ss(line);
    long long x;
    while(ss >> x) nums.push_back(x);
    return nums;
}

int get_choice(int min, int max) {
    int choice;
    while(true){
        cout << "\nEnter choice (" << min << "-" << max << "): ";
        if(cin >> choice && choice >= min && choice <= max) {
            cin.ignore(numeric_limits<streamsize>::max(),'\n');
            return choice;
        }
        else {
            cout << "Invalid choice. Try again.\n";
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(),'\n');
        }
    }
}

int main() {
    srand(time(nullptr));
    RSAKeyPair keys = generate_keys();
    cout << "\n[In real-world RSA, p and q must be kept secret.]";
    cout << "\np = (" << keys.p << ")";
    cout << "\nq = (" << keys.q << ")";
    cout << "\n\nRSA keys generated:";
    cout << "\nPublic Key (n, e) = (" << keys.n << ", " << keys.e << ")\n";
    cout << "Private Key (n, d) = (" << keys.n << ", " << keys.d << ")\n";
    const int blockSize = 2;
    while(true) {
        cout << "\nMain Menu:\n";
        cout << "==========\n";
        cout << "1. Encrypt message\n2. Decrypt message\n3. Sign message\n4. Verify signature\n5. Exit\n";
        int choice = get_choice(1,5);
        switch (choice) {
            case 1: {
                cout << "Enter message to encrypt: ";
                string msg; getline(cin,msg);
                vector<long long> blocks = encode_message(msg, blockSize, keys.n);
                vector<long long> cipher = encrypt_decrypt_block(blocks, keys.e, keys.n);
                cout << "Ciphertext: ";
                for (auto c : cipher) cout << c << " ";
                cout << "\n";
                break;
            }
            case 2: {
                cout << "Enter ciphertext numbers (space-separated): ";
                vector<long long> cipher = readNumbers();
                vector<long long> plainBlocks = encrypt_decrypt_block(cipher, keys.d, keys.n);
                string decrypted = decode_message(plainBlocks, blockSize);
                cout << "Decrypted: " << decrypted << '\n';
                break;
            }
            case 3: {
                cout << "Enter message to sign: ";
                string msg; getline(cin,msg);
                vector<long long> blocks = encode_message(msg, blockSize, keys.n);
                vector<long long> signature = encrypt_decrypt_block(blocks, keys.d, keys.n);
                cout << "Signature: ";
                for (auto s : signature) cout << s << " ";
                cout << "\n";
                break;
            }
            case 4: {
                cout << "Enter original message to verify: ";
                string msg; getline(cin,msg);
                vector<long long> msgBlocks = encode_message(msg, blockSize, keys.n);
                cout << "Do you want to use the present public key? (y/yes or n/no): ";
                string answer; getline(cin, answer);
                long long pub_n, pub_e;
                if (answer == "y" || answer == "Y" || answer == "yes" || answer == "YES") {
                    pub_n = keys.n;
                    pub_e = keys.e;
                } else {
                    cout << "Enter public key (n e): ";
                    cin >> pub_n >> pub_e;
                    cin.ignore(numeric_limits<streamsize>::max(),'\n');
                }
                cout << "Enter signature numbers (space-separated): ";
                vector<long long> signature = readNumbers();
                if (signature.size() != msgBlocks.size()) {
                    cout << "Error: signature/message length mismatch.\n";
                    continue;
                }
                vector<long long> verifiedBlocks = encrypt_decrypt_block(signature, pub_e, pub_n);
                bool valid = true;
                for (size_t i=0; i<msgBlocks.size(); ++i) {
                    if (msgBlocks[i] != verifiedBlocks[i]) {
                        valid = false;
                        break;
                    }
                }

                if (valid) {
                    cout <<  "\n-----------------------------------\nSignature verification \"SUCCEEDED\".\n-----------------------------------\n";
                } else {
                    cout << "\n--------------------------------\nSignature verification \"FAILED\".\n--------------------------------\n";
                }
            
                break;
            }
            case 5:
                cout << "\nExiting Program.\n";
                return 0;
        }
    }
    return 0;
}
