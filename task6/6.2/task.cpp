#include "sha256.h"

//use CryptoPP for testing implementation only
#include "cryptopp/cryptlib.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"
bytes urandom(int n)
{
    bytes arr(16);
    srand(time(NULL));
    for (int i = 0; i < n; i++)
    {
        arr[i] = rand() % 256;
    }
    return arr;
}
bytes str_to_bytes(string s)
{
    vector<uint8_t> bytes(s.begin(), s.end());
    return bytes;
}

string bytes_to_str(bytes b)
{
    return string(b.begin(), b.end());
}
void test_hash()
{
    string test = "thaivinhdat";
    CryptoPP::SHA256 cryptopp_hash;
    SHA256 myhash(str_to_bytes(test));
    cryptopp_hash.Update((const CryptoPP::byte *)test.data(), test.size());

    string cryptopp_digest, cryptopp_hexdigest;
    cryptopp_digest.resize(cryptopp_hash.DigestSize());
    cryptopp_hash.Final((CryptoPP::byte*)&cryptopp_digest[0]);
    CryptoPP::StringSource(cryptopp_digest, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(cryptopp_hexdigest)));
    for (auto &c : cryptopp_hexdigest)
    {
        c = tolower(c);
    }

    if (myhash.hexdigest() != cryptopp_hexdigest)
    {
        cerr << "Test fail!!!\n";
        return;
    }
    cout << "Pass hashing test!!\n";
}
void test_attack()
{
    // random secret key
    bytes key = urandom(16);
    // test data
    bytes data = str_to_bytes("Thái Vĩnh Đạt");
    bytes add = str_to_bytes("22520235");
    
    SHA256 myhash(concat(key, data));
    string sig = myhash.hexdigest();
    // attack
    pair<bytes, string> result = myhash.attack(16, data, add, sig);
    bytes new_data = result.first;
    string new_sig = result.second;
    SHA256 test_hash(concat(key,new_data));

    if (new_sig != test_hash.hexdigest())
    {
        cerr << "Test fail!!!\n";
        return;
    }
    cout << "Pass testing length extension attack!!" << endl;
}
int main()
{
    std::locale::global(std::locale("C.UTF-8"));
    // test implementation
    test_hash();
    test_attack();

    string original, appended, signature;
    cout << "Enter original data: ";
    getline(cin, original);
    cout << "Enter appended data: ";
    getline(cin, appended);
    cout << "Enter signature in SHA256: ";
    cin >> signature;
    if (signature.length() != 64)
    {
        cerr << "Make sure you have a correct SHA256 signature!!!\n";
        return -1;
    }
    int k;
    cout << "Enter key length: ";
    cin >> k;
    SHA256 hash;
    // convert data to bytes
    bytes original_bytes = str_to_bytes(original);
    bytes appended_bytes = str_to_bytes(appended);
    // attack
    pair<bytes, string> result = hash.attack(k, original_bytes, appended_bytes, signature);
    bytes new_data = result.first;
    string new_sig = result.second;
    cout << "New data: " << hex(new_data) << endl;
    cout << "Predicted signature: " << new_sig << endl;
    return 0;
}