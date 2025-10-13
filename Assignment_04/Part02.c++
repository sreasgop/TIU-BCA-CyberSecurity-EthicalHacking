#include <iostream>
#include <string>
#include <random>
#include <cctype>
#include <set>
#include <vector>
#include <algorithm>
#include <regex>
#include<limits>

using namespace std;

string to_lower(const string& s) {
    string lower_s = s;
    transform(lower_s.begin(), lower_s.end(), lower_s.begin(), ::tolower);
    return lower_s;
}

string generate_password(int length, bool force_diversity = true) {
    const string lowercase = "abcdefghijklmnopqrstuvwxyz";
    const string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const string digits = "0123456789";
    const string symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?/~";
    string all_chars = lowercase + uppercase + digits + symbols;
    
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dist(0, all_chars.size() - 1);
    
    string pwd;
    if (force_diversity && length >= 4) {
        // Ensure at least one of each type for better security
        pwd += lowercase[uniform_int_distribution<>(0, lowercase.size() - 1)(gen)];
        pwd += uppercase[uniform_int_distribution<>(0, uppercase.size() - 1)(gen)];
        pwd += digits[uniform_int_distribution<>(0, digits.size() - 1)(gen)];
        pwd += symbols[uniform_int_distribution<>(0, symbols.size() - 1)(gen)];
        // Fill the rest randomly
        for (int i = 4; i < length; ++i) {
            pwd += all_chars[dist(gen)];
        }
    } else {
        for (int i = 0; i < length; ++i) {
            pwd += all_chars[dist(gen)];
        }
    }
    // Shuffle to ensure randomness
    shuffle(pwd.begin(), pwd.end(), gen);
    return pwd;
}

struct PasswordAnalysis {
    string label;
    int score;
    vector<pair<string, bool>> feedback;  // pair<message, is_good (true for ✓, false for ✗/⚠)>
};

PasswordAnalysis rate_password(const string& pwd) {
    int score = 0;
    vector<pair<string, bool>> feedback;
    int len = pwd.length();
    
    // Check character types
    bool has_lower = false, has_upper = false, has_digit = false, has_symbol = false;
    for (char c : pwd) {
        if (islower(c)) has_lower = true;
        else if (isupper(c)) has_upper = true;
        else if (isdigit(c)) has_digit = true;
        else if (!isalnum(c)) has_symbol = true;
    }
    int variety = has_lower + has_upper + has_digit + has_symbol;

    // Length scoring
    if (len >= 16) {
        score += 30;
        feedback.emplace_back("✓ Excellent length (16+ characters)", true);
    } else if (len >= 12) {
        score += 25;
        feedback.emplace_back("✓ Good length (12-15 characters)", true);
    } else if (len >= 8) {
        score += 15;
        feedback.emplace_back("✓ Acceptable length (8-11 characters)", true);
    } else {
        score += 5;
        feedback.emplace_back("✗ Too short (<8 characters - increase for security)", false);
    }

    // Variety scoring
    if (variety == 4) {
        score += 30;
        feedback.emplace_back("✓ Full character variety (upper, lower, digits, symbols)", true);
    } else if (variety == 3) {
        score += 20;
        feedback.emplace_back("✓ Good variety (3 character types)", true);
    } else if (variety == 2) {
        score += 10;
        feedback.emplace_back("⚠ Fair variety (2 types) - add more types for strength", false);
    } else {
        score += 0;
        feedback.emplace_back("✗ Poor variety (1 type) - use mixed characters", false);
    }

    // Common patterns penalty (case-insensitive)
    vector<string> common_patterns = {"123", "abc", "qwerty", "password", "admin", "letmein", "monkey", "111", "aaa"};
    bool has_common = false;
    string lower_pwd = to_lower(pwd);
    for (const auto& pat : common_patterns) {
        if (lower_pwd.find(to_lower(pat)) != string::npos) {
            has_common = true;
            score -= 15;
            feedback.emplace_back("✗ Contains common pattern: '" + pat + "' - avoid dictionary words", false);
            break;
        }
    }
    if (!has_common) {
        feedback.emplace_back("✓ No common or dictionary patterns detected", true);
    }

    // Repeated characters penalty (consecutive or triples)
    bool has_repeats = false;
    for (size_t i = 1; i < pwd.length(); ++i) {
        if (pwd[i] == pwd[i-1]) {
            has_repeats = true;
            break;
        }
    }
    for (size_t i = 2; i < pwd.length(); ++i) {
        if (pwd[i] == pwd[i-1] && pwd[i] == pwd[i-2]) {
            has_repeats = true;
            break;
        }
    }
    if (has_repeats) {
        score -= 10;
        feedback.emplace_back("✗ Contains repeated characters - use unique sequences", false);
    } else {
        feedback.emplace_back("✓ No repeated characters", true);
    }

    // Sequential characters penalty (e.g., abc, 123)
    bool has_sequential = false;
    string seq_lower = to_lower(pwd);
    for (size_t i = 2; i < seq_lower.length(); ++i) {
        if (isalpha(seq_lower[i]) && isalpha(seq_lower[i-1]) && isalpha(seq_lower[i-2])) {
            char c1 = seq_lower[i-2], c2 = seq_lower[i-1], c3 = seq_lower[i];
            if (c3 == c1 + 2 && c2 == c1 + 1) {
                has_sequential = true;
                break;
            }
        } else if (isdigit(seq_lower[i]) && isdigit(seq_lower[i-1]) && isdigit(seq_lower[i-2])) {
            int d1 = seq_lower[i-2] - '0', d2 = seq_lower[i-1] - '0', d3 = seq_lower[i] - '0';
            if (d3 == d1 + 2 && d2 == d1 + 1) {
                has_sequential = true;
                break;
            }
        }
    }
    if (has_sequential) {
        score -= 10;
        feedback.emplace_back("✗ Contains sequential characters (e.g., abc/123) - randomize more", false);
    } else {
        feedback.emplace_back("✓ No sequential patterns", true);
    }

    // Uniqueness/Entropy bonus (high ratio of unique chars)
    set<char> unique_chars(pwd.begin(), pwd.end());
    double uniqueness = static_cast<double>(unique_chars.size()) / len;
    if (uniqueness >= 0.7) {
        score += 15;
        feedback.emplace_back("✓ High entropy/uniqueness (good randomness)", true);
    } else {
        feedback.emplace_back("⚠ Low uniqueness - aim for more diverse chars", false);
    }

    // Clamp score to 0-100
    score = max(0, min(100, score));

    // Determine label
    string label;
    if (score >= 80) label = "Very Strong";
    else if (score >= 60) label = "Strong";
    else if (score >= 40) label = "Moderate";
    else if (score >= 20) label = "Weak";
    else label = "Very Weak";

    return {label, score, feedback};
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
    cout << "Ultimate Password Generator & Analyzer" << endl;
    cout << "======================================" << endl;
    // cout << "Powered by advanced randomness, diversity enforcement, and comprehensive checks." << endl;
    // cout << "Supports random lengths (6-25), custom lengths, and rating existing passwords." << endl;
    // cout << "Feedback uses ✓ (good), ⚠ (warning), ✗ (bad) for clarity." << endl << endl;

    int choice;
    do {
	
	cout << "\n------------------------" << endl;
        cout << "--- Interactive Menu ---" << endl;
	cout << "------------------------" << endl;
        cout << "1. Generate completely random password (auto length 6-25)" << endl;
        cout << "2. Generate password with specified length" << endl;
        cout << "3. Rate strength of an existing password" << endl;
        cout << "4. Generate multiple suggestions (random mode)" << endl;
        cout << "5. Exit" << endl;
        // cout << "Your choice (1-6): ";
        choice = get_choice(1, 5);

        if (choice == 1 || choice == 4) {
            random_device rd;
            mt19937 gen(rd());
            uniform_int_distribution<> len_dist(6, 25);
            int num_to_gen = (choice == 4) ? 3 : 1;
            for (int g = 0; g < num_to_gen; ++g) {
                int len = len_dist(gen);
                string pwd = generate_password(len);
                cout << "\n[" << (g+1) << "/" << num_to_gen << "] Generated (len " << len << "): " << pwd << endl;
                auto analysis = rate_password(pwd);
                cout << "Strength: " << analysis.label << " (Score: " << analysis.score << "/100)" << endl;
                cout << "Analysis:" << endl;
                for (const auto& item : analysis.feedback) {
                    cout << "  " << item.first << endl;
                }
                cout << string(50, '-') << endl;
            }
        } else if (choice == 2) {
            int len;
            cout << "Enter length (min 6, max 50): ";
            cin >> len;
            if (len < 6) len = 6;
            if (len > 50) len = 50;
            string pwd = generate_password(len);
            cout << "\nGenerated (len " << len << "): " << pwd << endl;
            auto analysis = rate_password(pwd);
            cout << "Strength: " << analysis.label << " (Score: " << analysis.score << "/100)" << endl;
            cout << "Analysis:" << endl;
            for (const auto& item : analysis.feedback) {
                cout << "  " << item.first << endl;
            }
        } else if (choice == 3) {
            string pwd;
            cout << "Enter password to analyze: ";
            getline(cin, pwd);
            if (pwd.empty()) {
                cout << "No input provided." << endl;
                continue;
            }
            auto analysis = rate_password(pwd);
            cout << "\nStrength: " << analysis.label << " (Score: " << analysis.score << "/100)" << endl;
            cout << "Analysis:" << endl;
            for (const auto& item : analysis.feedback) {
                cout << "  " << item.first << endl;
            }
        } else if (choice == 5) {
            cout << "\nThanks for using the Ultimate Password Tool! Stay secure." << endl;
        } else {
            cout << "Invalid choice - please try 1-5." << endl;
        }
    } while (choice != 5);

    return 0;
}
