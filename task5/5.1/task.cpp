#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
// using namespace std;
using std::string;
using std::cin;
using std::cout;
using std::endl;
using std::cerr;
using std::ifstream;

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <windows.h>
#endif
#include <chrono>
#include <clocale>
#include "cryptopp/cryptlib.h"
#include "cryptopp/sha3.h"
#include "cryptopp/sha.h"
#include "cryptopp/shake.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"
using CryptoPP::FileSink;


int main (int argc, char* argv[])
{
    #ifdef linux
        std::locale::global(std::locale("C.UTF-8"));
    #endif

    #ifdef _WIN32
        // Set console code page to UTF-8 on Windows
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
    #endif
    if (argc != 4 && argc != 3)
    {
        cerr << "Usage: task.exe <Hash type> <message/file> (<filename>) " << endl;
        cerr << "Hash type: SHA224, SHA256, SHA384, SHA512, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256" << endl;
        cerr << "Example: \"task.exe SHA224 file test.pdf\" or \"task.exe SHA512 message\"" << endl;
        return 1;
    }
    // Determine hash algorithm
    int lenHash = 0;
    std::unique_ptr<CryptoPP::HashTransformation> hash;
    string hashType = string(argv[1]);
    transform(hashType.begin(), hashType.end(), hashType.begin(), ::toupper); 
    if (hashType == "SHA3_224") {
        hash.reset(new CryptoPP::SHA3_224);
    } else if (hashType == "SHA3_256") {
        hash.reset(new CryptoPP::SHA3_256);
    } else if (hashType == "SHA3_384") {
        hash.reset(new CryptoPP::SHA3_384);
    } else if (hashType == "SHA3_512") {
        hash.reset(new CryptoPP::SHA3_512);
    }
    else if (hashType == "SHA224")
    {
        hash.reset(new CryptoPP::SHA224);
    } 
    else if (hashType == "SHA256")
    {
        hash.reset(new CryptoPP::SHA256);
    } 
    else if (hashType == "SHA384")
    {
        hash.reset(new CryptoPP::SHA384);
    }
    else if (hashType == "SHA512")
    {
        hash.reset(new CryptoPP::SHA512);
    }
    else if (hashType == "SHAKE128")
    {
        cout << "Enter hash length:"<<endl;
        cin >> lenHash;
        hash.reset(new CryptoPP::SHAKE128(lenHash));
        
    }
    else if (hashType == "SHAKE256")
    {
        cout << "Enter hash length (bytes):"<<endl;
        cin >> lenHash;
        hash.reset(new CryptoPP::SHAKE256(lenHash));
    }
    else {
        cerr << "Invalid hash type: " << hashType << endl;
        return 1;
    }
    string msg;
    if (string(argv[2]) == "message")
    {
        if (argc != 3)
        {
            cerr << "Usage: task.exe <Hash type> <message/file> (<filename>) " << endl;
            cerr << "Hash type: SHA224, SHA256, SHA384, SHA512, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256" << endl;
            cerr << "Example: \"task.exe SHA224 file test.pdf\" or \"task.exe SHA512 message\"" << endl;
            return 1;
        }
        cout << "Enter message to hash: ";
        getline(cin,msg);
        // cin.ignore();
    }
    else if (string(argv[2]) == "file")
    {
        if (argc != 4)
        {
            cerr << "Usage: task.exe <Hash type> <message/file> (<filename>) " << endl;
            cerr << "Hash type: SHA224, SHA256, SHA384, SHA512, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256" << endl;
            cerr << "Example: \"task.exe SHA224 file test.pdf\" or \"task.exe SHA512 message\"" << endl;
            return 1;
        }
        ifstream file(argv[3], std::ios::binary);
        if (!file)
        {
            cerr << "Error opening file " << argv[3] << endl;
            return 1; 
        }
        string mess((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        msg = mess;
    }
    string digest;
    string encoded;
    auto start = std::chrono::high_resolution_clock::now();

    hash->Update((const CryptoPP::byte*)msg.data(), msg.size());
    digest.resize(hash->DigestSize());
    hash->Final((CryptoPP::byte*)&digest[0]);

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double time = static_cast<double>(duration);
    cout << "Time for hashing: " << time << " microseconds" << std::endl;
    
    // cout << "Message: " << msg << endl;
    std::cout << "Digest: ";
    CryptoPP::StringSource(digest, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded)));
    std::cout <<encoded << std::endl;
    return 0; 
}