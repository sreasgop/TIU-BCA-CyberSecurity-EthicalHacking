#include <vector>
#include <string>
#include <stdexcept>
#include <iostream>
#include <cctype>
#include <limits>
using namespace std;


// Utilities for modular arithmetic and matrices (mod 26)
long long egcd(long long a, long long b, long long &x, long long &y){
    if(b==0){ x=1; y=0; return a; }
    long long x1,y1; long long g=egcd(b,a%b,x1,y1);
    x=y1; y=x1 - (a/b)*y1; return g;
}
int modinv(int a, int m=26){
    long long x,y; long long g=egcd((a%m+m)%m,m,x,y);
    if(g!=1) throw runtime_error("Key not invertible modulo 26");
    long long res=(x%m + m)%m; return (int)res;
}
using Mat = vector<vector<int>>;
Mat matmul(const Mat& A, const Mat& B, int mod=26){
    int r=A.size(), p=A[0].size(), c=B[0].size();
    Mat R(r, vector<int>(c,0));
    for(int i=0;i<r;i++)
        for(int j=0;j<c;j++){
            long long s=0;
            for(int k=0;k<p;k++) s += 1LL*A[i][k]*B[k][j];
            R[i][j] = (int)((s%mod+mod)%mod);
        }
    return R;
}
Mat modmat(Mat A,int mod=26){ for(auto& row:A) for(int& x:row) x=((x%mod)+mod)%mod; return A; }

// 2x2 inverse
int det2(const Mat& M){ return M[0][0]*M[1][1] - M[0][1]*M[1][0]; }
Mat inv2(Mat M,int mod=26){
    int d = ((det2(M)%mod)+mod)%mod; int invd = modinv(d,mod);
    Mat adj={{ M[1][1], -M[0][1]}, {-M[1][0], M[0][0]}};
    for(auto& row:adj) for(int& x:row) x = (int)((1LL*invd*((x%mod)+mod)%mod)%mod);
    return modmat(adj,mod);
}

// 3x3 inverse
int det3(const Mat& a){
    int A=a[0][0], B=a[0][1], C=a[0][2];
    int D=a[1][0], E=a[1][1], F=a[1][2];
    int G=a[2][0], H=a[2][1], I=a[2][2];
    return A*(E*I - F*H) - B*(D*I - F*G) + C*(D*H - E*G);
}
Mat cofactor3(const Mat& a){
    Mat c(3, vector<int>(3));
    int A=a[0][0], B=a[0][1], C=a[0][2];
    int D=a[1][0], E=a[1][1], F=a[1][2];
    int G=a[2][0], H=a[2][1], I=a[2][2];
    c[0][0] = (E*I - F*H); c[0][1]=-(D*I - F*G); c[0][2]= (D*H - E*G);
    c[1][0]=-(B*I - C*H); c[1][1]= (A*I - C*G); c[1][2]=-(A*H - B*G);
    c[2][0]= (B*F - C*E); c[2][1]=-(A*F - C*D); c[2][2]= (A*E - B*D);
    return c;
}
Mat transpose(const Mat& a){ Mat t(a.size(), vector<int>(a.size())); for(size_t i=0;i<a.size();++i) for(size_t j=0;j<a.size();++j) t[j][i]=a[i][j]; return t; }
Mat inv3(Mat M,int mod=26){
    int d = ((det3(M)%mod)+mod)%mod; int invd = modinv(d,mod);
    Mat adj = transpose(cofactor3(M));
    for(auto& row:adj) for(int& x:row) x = (int)((1LL*invd*((x%mod)+mod)%mod)%mod);
    return modmat(adj,mod);
}

// Helpers for text blocks
vector<int> letters_only_upper(const string& s){
    vector<int> v;
    for(char c: s){ if('A'<=c && c<='Z') v.push_back(c-'A'); else if('a'<=c && c<='z') v.push_back(toupper(c)-'A'); }
    return v;
}
string to_text(const vector<int>& v){
    string out; out.reserve(v.size());
    for(int x: v) out.push_back(char(x%26 + 'A'));
    return out;
}

string hill_encrypt(const string& plaintext, const Mat& K, int mod=26){
    int n = (int)K.size(); for(auto& row:K) if((int)row.size()!=n) throw runtime_error("Key must be square");
    Mat Km = modmat(K,mod);
    vector<int> p = letters_only_upper(plaintext);
    int pad = (n - (int)(p.size()%n))%n; while(pad--) p.push_back('X'-'A');
    vector<int> out; out.reserve(p.size());
    for(size_t i=0;i<p.size();i+=n){
        Mat vec(n, vector<int>(1));
        for(int j=0;j<n;j++) vec[j][0]=p[i+j];
        Mat enc = matmul(Km, vec, mod);
        for(int j=0;j<n;j++) out.push_back(enc[j][0]);
    }
    return to_text(out);
}
string hill_decrypt(const string& ciphertext, const Mat& K, int mod=26){
    int n = (int)K.size(); for(auto& row:K) if((int)row.size()!=n) throw runtime_error("Key must be square");
    Mat Km = modmat(K,mod), Ki;
    if(n==2) Ki = inv2(Km,mod);
    else if(n==3) Ki = inv3(Km,mod);
    else throw runtime_error("Only 2x2 or 3x3 supported here");
    vector<int> c = letters_only_upper(ciphertext);
    if(c.size()%n!=0) throw runtime_error("Ciphertext length (letters only) must be multiple of block size");
    vector<int> out; out.reserve(c.size());
    for(size_t i=0;i<c.size();i+=n){
        Mat vec(n, vector<int>(1));
        for(int j=0;j<n;j++) vec[j][0]=c[i+j];
        Mat dec = matmul(Ki, vec, mod);
        for(int j=0;j<n;j++) out.push_back(dec[j][0]);
    }
    return to_text(out);
}

struct user_data {
    string user_input;
    Mat key_matrix;
};

user_data prompt() {
    user_data d;
    cout << "\nEnter text: ";
    cin.ignore(1, '\n');
    getline(cin, d.user_input);

    int n;
    cout << "Enter matrix size (2 or 3): ";
    cin >> n;
    if (cin.fail() || (n != 2 && n != 3)) {
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        throw runtime_error("Invalid matrix size. Must be 2 or 3.");
    }

    d.key_matrix.resize(n, vector<int>(n));
    cout << "Enter the " << n << "x" << n << " key matrix (row by row):\n";
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < n; ++j) {
            cin >> d.key_matrix[i][j];
            if (cin.fail()) {
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                throw runtime_error("Invalid input for matrix element.");
            }
        }
    }

    return d;
}

// Sample main to test
int main() {
    // 2x2 example
    // Text: help
    // {{3,3},{2,5}};
    
    // 3x3 example
    // Text: act
    // {{6,24,1},{13,16,10},{20,17,15}};
    
    string encrypted_text, decrypted_text;
    int user_key, option;

    while (true) {
        cout << "Hill Cipher\n============\n";
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
            encrypted_text = hill_encrypt(data.user_input, data.key_matrix);
            cout << "Ciphered-Text: " << encrypted_text << endl << endl;
            break;
        }
        case 2: {
            user_data data = prompt();
            decrypted_text = hill_decrypt(data.user_input, data.key_matrix);
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