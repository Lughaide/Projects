// Sample.cpp

#include "cryptopp/hrtimer.h"
using CryptoPP::ThreadUserTimer;


#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;

#include "cryptopp/rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include "cryptopp/sha.h"
using CryptoPP::SHA1;

#include "cryptopp/filters.h" //string input, output
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::BufferedTransformation;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include "cryptopp/files.h" // File input, output
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/osrng.h" // random generator
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/SecBlock.h" // byte in CryptoPP
using CryptoPP::SecByteBlock;

// using CryptoPP::byte;

#include "cryptopp/cryptlib.h"
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <string>
using std::wstring;
using std::string;

#include <exception>
using std::exception;

#include <iostream>
using std::wcin;
using std::wcout;
using std::cerr;
using std::endl;

#include <assert.h>

/* Set _setmode()*/ 
#ifdef _WIN32
    #include <io.h>
#elif __linux__
    #include <inttypes.h>
    #include <unistd.h>
    #define __int64 int64_t
    #define _close close
    #define _read read
    #define _lseek64 lseek64
    #define _O_RDONLY O_RDONLY
    #define _open open
    #define _lseeki64 lseek64
    #define _lseek lseek
    #define stricmp strcasecmp
#endif
#include <fcntl.h>
/* Convert string*/ 
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;
wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);

/*Reading key from file*/
#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;
#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;
/*Define functions*/
// Load
void Load(const string& filename, BufferedTransformation& bt);
void LoadPrivateKey(const string& filename, PrivateKey& key);
void LoadPublicKey(const string& filename, PublicKey& key);
// Save
void Save(const string& filename, const BufferedTransformation& bt);
void SaveBase64(const string& filename, const BufferedTransformation& bt);
void SavePrivateKey(const string& filename, const PublicKey& key);
void SavePublicKey(const string& filename, const PublicKey& key);
// Others
void print_parameters (const InvertibleRSAFunction& params);
void print_keys(const string& filename);
using namespace std;

int main(int argc, char* argv[])
{
    try
    {
        int select = -1;
        cout << "RSA Key Generator program: " << endl;
        cout << "Generate new key or load key?" << endl;
        cout << "0. Generate." << endl << "1. Load key." << endl;
        cout << "Selection: "; cin >> select;
        ThreadUserTimer timer(CryptoPP::TimerBase::MILLISECONDS);
        switch (select)
        {
            case 0:
            {
                
                cout << "Generating key:" << endl;
                // Generate keys

                AutoSeededRandomPool rng; // Pseudo Random Number Generator

                InvertibleRSAFunction parameters; // Parameters generation
                timer.StartTimer();
                parameters.GenerateRandomWithKeySize(rng, 3072);
                RSA::PrivateKey privateKey(parameters);
                RSA::PublicKey publicKey(parameters);
                double elasped = timer.ElapsedTimeAsDouble();
                //Time check
                cout << "Time spent generating key: " << elasped << " ms" << endl;
                ofstream outfile;
                outfile.open("rsa-keygen-time.txt", ios_base::app);
                outfile << "\n";
                outfile << elasped;
                outfile.close();
                print_parameters(parameters); // Print parameters
                SavePrivateKey("rsa-private.key", privateKey);
                SavePublicKey("rsa-public.key", publicKey);
                break;
            }
            case 1:
            {
                cout << "Loading keys in local directory." << endl;
                RSA::PrivateKey privateKey;
                RSA::PublicKey publicKey;
                LoadPrivateKey("rsa-private.key", privateKey);
                LoadPublicKey("rsa-public.key", publicKey);

            }
            default:
            {
                return 0;
                break;
            }
        }
        cout << "Private key (Base64): " << endl;
        print_keys("rsa-private-b64.key");
        cout << "Public key (Base64): " << endl;
        print_keys("rsa-public-b64.key");            
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }
    
    return 0;
}

/* print key in Base64 form */
void print_keys(const string& filename)
{
    string line;
    ifstream myfile (filename);
    if (myfile.is_open())
    {
        while ( myfile.good() )
        {
            getline (myfile,line);
            cout << line << endl;
        }
    myfile.close();
    }
    else cout << "Unable to open file";
}

/* print key's parameters */
void print_parameters (const InvertibleRSAFunction& params)
{
    const CryptoPP::Integer& n = params.GetModulus();
    const CryptoPP::Integer& p = params.GetPrime1();
    const CryptoPP::Integer& q = params.GetPrime2();
    const CryptoPP::Integer& d = params.GetPrivateExponent();
    const CryptoPP::Integer& e = params.GetPublicExponent();
    cout << "RSA Parameters:" << endl;
    cout << " n: " << n << endl;
    cout << " p: " << p << endl;
    cout << " q: " << q << endl;
    cout << " d: " << d << endl;
    cout << " e: " << e << endl;
    cout << endl;
}


/* convert string to wstring */
wstring string_to_wstring (const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string (const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}

void SavePublicKey(const string& filename, const PublicKey& key)
{
    ByteQueue queue;
    key.Save(queue);
    Save(filename, queue);
    string filename64 = "rsa-public-b64.key";
    SaveBase64(filename64, queue);
}
void SavePrivateKey(const string& filename, const PublicKey& key)
{
    ByteQueue queue;
    key.Save(queue);
    Save(filename, queue);
    string filename64 = "rsa-private-b64.key";
    SaveBase64(filename64, queue);
}
void Save(const string& filename, const BufferedTransformation& bt)
{
    FileSink file(filename.c_str());

    bt.CopyTo(file);
    file.MessageEnd();
}
void SaveBase64(const string& filename, const BufferedTransformation& bt)
{
    Base64Encoder encoder;

    bt.CopyTo(encoder);
    encoder.MessageEnd();

    Save(filename, encoder);
}

void LoadPrivateKey(const string& filename, PrivateKey& key)
{
	ByteQueue queue;
	Load(filename, queue);
	key.Load(queue);	
}

void LoadPublicKey(const string& filename, PublicKey& key)
{
	ByteQueue queue;
	Load(filename, queue);
	key.Load(queue);	
}

void Load(const string& filename, BufferedTransformation& bt)
{
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}