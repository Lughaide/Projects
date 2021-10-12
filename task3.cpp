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
using  std::codecvt_utf8_utf16;
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
// Others
void print_keys(const string& filename);
wstring open_file(const string& filename);
string open_file_string(const string& filename);
using namespace std;


int main(int argc, char *argv[])
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
        AutoSeededRandomPool rng;
        string encoded, decoded;
        wstring wplain;
        wstring wfilename;
        string plain, cipher, recovered;
        int choice = 0;
        int choice2 = 0;
        /* Loading local keys */
        RSA::PrivateKey privateKey;
        RSA::PublicKey publicKey;
        LoadPrivateKey("rsa-private.key", privateKey);
        LoadPublicKey("rsa-public.key", publicKey);

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
                print_keys("rsa-private-b64.key");
                wcout << "Public key (Base64): " << endl;
                print_keys("rsa-public-b64.key");  
                break;
            }
            default:
                break;
        }

        /* Interaction block */
        wcout << L"Các thao tác:" << endl;
        wcout << L"1. Encrypt." << endl;
        wcout << L"2. Decrypt." << endl;
        wcout << L"Lựa chọn thao tác: ";    
        wcin >> choice;

        /* Selection block */
        switch (choice)
        {
            case 1:
            {
                wcout << L"Start encryption." << endl;
                /* Get input */                
                wcout << L"Nhập thủ công hay từ file?"<< endl;
                wcout << L"1. Thủ công" << endl;
                wcout << L"2. Từ file" << endl;
                wcout << L"Lựa chọn thao tác: "; 
                wcin >> choice2;
                switch (choice2)
                {
                    case 1:
                    {
                        wcout << "Input plaintext: ";
                        wcin.ignore();
                        wcin.ignore();  
                        getline(wcin,wplain);
                        plain= wstring_to_string(wplain);
                        wcout << "plaintext: " << wplain << endl;  
                        break;                      
                    }
                    default:
                    {
                        wcout << "Input filename? ";
                        wcin >> wfilename;
                        string filename = wstring_to_string(wfilename);
                        wplain = open_file(filename);
                        plain= wstring_to_string(wplain);
                        wcout << "From file: " << wfilename << endl;
                        wcout << "plaintext: " << wplain << endl;
                        break;
                    }
                }
                // Encryption
                RSAES_OAEP_SHA_Encryptor e(publicKey);
                StringSource( plain, true,
                    new PK_EncryptorFilter( rng, e,
                        new StringSink( cipher )
                    ) // PK_EncryptorFilter
                 ); // StringSource
                 /* Pretty Print cipher text */
                encoded.clear();
	            StringSource(cipher, true,
		            new HexEncoder(
		        	    new StringSink(encoded)
		                ) // HexEncoder
	            ); // StringSource
                ofstream out("rsa-test-decrypt.txt");
                out << encoded;
                wcout << "cipher text: "<< endl << string_to_wstring(encoded)<< endl;
                break;
            }
            case 2:
            {
                wcout << L"Start decryption." << endl;
                wcout << "Input filename? ";
                wcin >> wfilename;
                string filename = wstring_to_string(wfilename);
                encoded.clear();
                encoded = open_file_string(filename);
                wcout << "From file: " << wfilename << endl;
                wcout << "Content: " << endl << string_to_wstring(encoded) << endl;
                // Decryption
                StringSource (encoded, true,
                    new HexDecoder(
                        new StringSink(cipher)
                    ) // HexDecoder
                ); // StringSource
                RSAES_OAEP_SHA_Decryptor d( privateKey );
                StringSource( cipher, true,
                    new PK_DecryptorFilter( rng, d,
                        new StringSink( recovered )
                    ) // PK_EncryptorFilter
                 ); // StringSource
                wcout << "recovered text:" << string_to_wstring(recovered) << endl;
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
    }
    

}

/* get data from file */
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