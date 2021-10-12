#include "cryptopp/hrtimer.h"
using CryptoPP::ThreadUserTimer;

#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;

#include "cryptopp/sha.h"
using CryptoPP::SHA256;

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

/* Integer arithmatics*/
#include <cryptopp/integer.h>
using CryptoPP::Integer;
#include <cryptopp/nbtheory.h>
using CryptoPP::ModularSquareRoot;

#include <cryptopp/ecp.h>
#include <cryptopp/eccrypto.h>
using CryptoPP::ECP;    // Prime field p
using CryptoPP::ECIES;
using CryptoPP::ECPPoint;
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::DL_GroupPrecomputation;
using CryptoPP::DL_FixedBasePrecomputation;

#include <cryptopp/pubkey.h>
using CryptoPP::PublicKey;
using CryptoPP::PrivateKey;

/* standard curves*/
#include <cryptopp/asn.h>
#include <cryptopp/oids.h> // 
namespace ASN1 = CryptoPP::ASN1;
using CryptoPP::OID;

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

using namespace std;
using namespace CryptoPP;
/* Convert string*/ 
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8_utf16;
wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);

/*Define functions*/
// Load
void Load(const string& filename, BufferedTransformation& bt);
void LoadPrivateKey(const string& filename, ECDSA<ECP, SHA256>::PrivateKey& key);
void LoadPublicKey(const string& filename, ECDSA<ECP, SHA256>::PublicKey& key);
// Others
void print_keys(const string& filename);
wstring open_file(const string& filename);
string open_file_string(const string& filename);
// Signing & verifying
bool SignMessage( const ECDSA<ECP, SHA256>::PrivateKey& key, const string& message, string& signature );
bool VerifyMessage( const ECDSA<ECP, SHA256>::PublicKey& key, const string& message, const string& signature );


int main()
{
    try
    {
        #ifdef __linux__
            setlocale(LC_ALL,"");
        #elif _WIN32
            _setmode(_fileno(stdin), _O_U16TEXT);
            _setmode(_fileno(stdout), _O_U16TEXT);
        #else
        #endif

        /* Variables */
        int choice = -1;
        bool result = false;
        AutoSeededRandomPool rng;
        ECDSA<ECP, SHA256>::PrivateKey privateKey;
        ECDSA<ECP, SHA256>::PublicKey publicKey;
        wstring wfilename, wplain;
        wstring wmessage;
        string message, signature, encoded;
        LoadPrivateKey("ecc-private.key", privateKey);
        LoadPublicKey("ecc-public.key", publicKey);
        
        /* Display keys */
        wcout << L"Hiển thị key?" << endl;
        wcout << L"1. Yes." << endl;
        wcout << L"2. No." << endl;
        wcout << L"Lựa chọn thao tác: ";
        wcin >> choice;
        switch (choice)
        {
            case 1:
            {
                wcout << "Private key (Base64): " << endl;
                print_keys("ecc-private-b64.key");
                wcout << "Public key (Base64): " << endl;
                print_keys("ecc-public-b64.key");
                break;
            }
            default:
                break;
        }
        
        /* Interaction block */
        wcout << L"Các thao tác:" << endl;
        wcout << L"1. Signing." << endl;
        wcout << L"2. Verifying." << endl;
        wcout << L"Lựa chọn thao tác: ";    
        wcin >> choice;
        switch (choice)
        {
            case 1:
            {
                wcout << "Input filename? ";
                wcin >> wfilename;
                string filename = wstring_to_string(wfilename);
                wplain = open_file(filename);
                message = wstring_to_string(wplain);
                wcout << "From file: " << wfilename << endl;
                wcout << "Message: " << endl << wplain << endl;
                // Signing
                result = SignMessage(privateKey, message, signature);
                if (!result)
                {
                    wcout << "File error. Signature is empty!";
                    return -2;
                }
                else
                {
                    encoded.clear();
	                StringSource(signature, true,
		            new HexEncoder(
		        	    new StringSink(encoded)
		                ) // HexEncoder
	                ); // StringSource
                    ofstream out("ecc-test-signature.txt");
                    out << encoded;
                    wcout << "Signature: "<< endl << string_to_wstring(encoded)<< endl;
                }
                break;
            }
            case 2:
            {
                wcout << L"Start verification." << endl;
                // Get signature
                wcout << "Input filename for signature? ";
                wcin >> wfilename;
                string filename = wstring_to_string(wfilename);
                encoded.clear();
                encoded = open_file_string(filename);
                wcout << "From file: " << wfilename << endl;
                wcout << "Signature: " << endl << string_to_wstring(encoded) << endl;

                // Decode signature
                StringSource (encoded, true,
                    new HexDecoder(
                        new StringSink(signature)
                    ) // HexDecoder
                ); // StringSource
                // Get message
                wcout << "Input filename for message? ";
                wcin >> wfilename;
                filename = wstring_to_string(wfilename);
                wplain = open_file(filename);
                wcout << "From file: " << wfilename << endl;
                wcout << "Message: " << endl << wplain << endl;
                message = wstring_to_string(wplain);
                result = VerifyMessage(publicKey, message, signature);
                if (result) 
                {
                    wcout << L"Chữ ký hợp lệ." << endl;
                }
                else
                {
                    wcout << L"Chữ ký không hợp lệ." << endl;
                }
                // Verifying
                break;
            }
            default:
                break;
        }
        wcout << L"Kết thúc chương trình." << endl;
        return 0;
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return -1;
    }
    

}


wstring open_file(const string& filename)
{
    wstring data;
    wstring wline;
    wifstream myfile (filename);
    myfile.imbue(locale(locale(), new codecvt_utf8_utf16<wchar_t>));    
    if (myfile.is_open())
    {
        while ( myfile.good() )
        {
            getline (myfile,wline);
            data += wline;
        }
    myfile.close();
    }
    return data;
}

string open_file_string(const string& filename)
{
    string data;
    string line;
    ifstream myfile (filename);   
    if (myfile.is_open())
    {
        while ( myfile.good() )
        {
            getline (myfile,line);
            data += line;
        }
    myfile.close();
    }
    return data;
}
/* print key in Base64 form */
void print_keys(const string& filename)
{
    wstring wline;
    wifstream myfile (filename);
    if (myfile.is_open())
    {
        while ( myfile.good() )
        {
            getline (myfile,wline);
            wcout << wline << endl;
        }
    myfile.close();
    }
    else wcout << "Unable to open file";
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

void LoadPrivateKey(const string& filename, ECDSA<ECP, SHA256>::PrivateKey& key)
{
    ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);	
}

void LoadPublicKey(const string& filename, ECDSA<ECP, SHA256>::PublicKey& key)
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

bool SignMessage( const ECDSA<ECP, SHA256>::PrivateKey& key, const string& message, string& signature )
{
    AutoSeededRandomPool prng;
    
    signature.erase();    

    StringSource( message, true,
        new SignerFilter( prng,
            ECDSA<ECP,SHA256>::Signer(key),
            new StringSink( signature )
        ) // SignerFilter
    ); // StringSource
    
    return !signature.empty();
}

bool VerifyMessage( const ECDSA<ECP, SHA256>::PublicKey& key, const string& message, const string& signature )
{
    bool result = false;

    StringSource( signature+message, true,
        new SignatureVerificationFilter(
            ECDSA<ECP,SHA256>::Verifier(key),
            new ArraySink( (CryptoPP::byte*)&result, sizeof(result) )
        ) // SignatureVerificationFilter
    );

    return result;
}
