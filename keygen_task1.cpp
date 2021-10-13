#include <string>
using std::wstring;
using std::string;
#include <exception>
#include <iostream>
#include <assert.h>
#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
#include "cryptopp/hrtimer.h"
using CryptoPP::ThreadUserTimer;
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

// Standards
#include "cryptopp/aes.h"
#include "cryptopp/des.h"

#include "cryptopp/osrng.h" // random generator
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/SecBlock.h" // byte in CryptoPP
using CryptoPP::SecByteBlock;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

// Operation modes
#include "cryptopp/modes.h"
#include "cryptopp/ccm.h"

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
void print_keys(const string& filename);
using namespace std;
using namespace CryptoPP;

int main()
{
    try
    {
        int select = -1;
        cout << "DES/AES Key & Initial Vector Generator program: " << endl;
        cout << "Generate new key or load key?" << endl;
        cout << "0. Generate." << endl << "1. Load key." << endl;
        cout << "Selection: "; cin >> select;
        ThreadUserTimer timer(CryptoPP::TimerBase::MILLISECONDS);
        /* Variables */
        AutoSeededRandomPool prng;
        string cipher, encoded, recovered;
        switch (select)
        {
            case 0:
            {
                cout << "Generating key:" << endl;
                int choice = -1;
                cout << "DES or AES?" << endl;
                cout << "0. DES." << endl << "1. AES." << endl;
                cout << "Selection: "; cin >> choice;
                switch (choice)
                {
                    case 0:
                    {
                        cout << "Generating key and iv for DES." << endl;
	                    SecByteBlock key(DES::DEFAULT_KEYLENGTH);
	                    CryptoPP::byte iv[DES::BLOCKSIZE];
                        //HexEncoder encoder(new FileSink(std::cout));
                        prng.GenerateBlock(key, key.size());
                        prng.GenerateBlock(iv, sizeof(iv));
                        // Save key & iv
                        StringSource ss1(key, sizeof(key), true , new FileSink( "DES-key.key"));
                        StringSource ss2(iv, sizeof(iv), true , new FileSink( "DES-IV.key"));
	                    // Pretty print key & save
	                    encoded.clear();
	                    StringSource(key, key.size(), true,
	                    	new HexEncoder(
	                    		new StringSink(encoded)
	                    	) // HexEncoder
	                    ); // StringSource
	                    cout << "DES key: " << encoded << endl;
                        ofstream outfile;
                        outfile.open("DES-key-HEX.key");
                        outfile << encoded;
                        outfile.close();

	                    // Pretty print iv & save
	                    encoded.clear();
	                    StringSource(iv, sizeof(iv), true,
	                    	new HexEncoder(
	                    		new StringSink(encoded)
	                    	) // HexEncoder
	                    ); // StringSource
	                    cout << "DES iv: " << encoded << endl;
                        outfile.open("DES-IV-HEX.key");
                        outfile << encoded;
                        outfile.close();

                        ///* Print key and IV */
                        //std::cout << "DES key: ";
                        //encoder.Put(key, key.size());
                        //encoder.MessageEnd();
                        //std::cout << std::endl;
                    //
                        //std::cout << "DES iv: ";
                        //encoder.Put(iv, sizeof(iv));
                        //encoder.MessageEnd();
                        //std::cout << std::endl;    

                        break;
                    }
                    case 1:
                    {
                        cout << "Generating key and iv for AES." << endl;
                        SecByteBlock key(AES::DEFAULT_KEYLENGTH);
                        SecByteBlock iv(AES::BLOCKSIZE);
                        //HexEncoder encoder(new FileSink(std::cout));
                        prng.GenerateBlock(key, key.size());
                        prng.GenerateBlock(iv, iv.size());
                        StringSource ss1(key, sizeof(key), true , new FileSink( "AES-key.key"));
                        StringSource ss2(iv, sizeof(iv), true , new FileSink( "AES-IV.key"));
                        
	                    // Pretty print key & save
	                    encoded.clear();
	                    StringSource(key, key.size(), true,
	                    	new HexEncoder(
	                    		new StringSink(encoded)
	                    	) // HexEncoder
	                    ); // StringSource
	                    cout << "AES key: " << encoded << endl;
                        ofstream outfile;
                        outfile.open("AES-key-HEX.key");
                        outfile << encoded;
                        outfile.close();

	                    // Pretty print iv & save
	                    encoded.clear();
	                    StringSource(iv, iv.size(), true,
	                    	new HexEncoder(
	                    		new StringSink(encoded)
	                    	) // HexEncoder
	                    ); // StringSource
	                    cout << "AES iv: " << encoded << endl;
                        outfile.open("AES-IV-HEX.key");
                        outfile << encoded;
                        outfile.close();

                        /* Print key and IV */
                        //std::cout << "AES key: ";
                        //encoder.Put(key, key.size());
                        //encoder.MessageEnd();
                        //std::cout << std::endl;
                    //
                        //std::cout << "AES iv: ";
                        //encoder.Put(iv, iv.size());
                        //encoder.MessageEnd();
                        //std::cout << std::endl;

                        break;
                    }
                    default:
                        break;
                }
                break;
            }
            case 1:
            {
                cout << "Loading keys in local directory." << endl;
                int choice = -1;
                cout << "DES or AES?" << endl;
                cout << "0. DES." << endl << "1. AES." << endl;
                cout << "Selection: "; cin >> choice;
                switch (choice)
                {
                    case 0:
                    {
                        cout << "DES keys and iv: " << endl;
                        print_keys("DES-key-HEX.key");
                        print_keys("DES-IV-HEX.key");
                        break;
                    }
                    case 1:
                    {
                        cout << "AES keys and iv: " << endl;
                        print_keys("AES-key-HEX.key");
                        print_keys("AES-IV-HEX.key");
                        break;
                    }
                    default:
                        break;
                }
                break;
            }
            default:
            {
                return 0;
                break;
            }
        }
         
    }
    catch( const std::exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }
    return 0;
}


/* print from file*/
void print_keys(const string& filename)
{
    string line;
    string data;
    ifstream myfile (filename);
    if (myfile.is_open())
    {
        while ( myfile.good() )
        {
            getline (myfile,line);
            data += line;
        }
        myfile.close();
        cout << filename << ": "  << data << endl;
    }
    else cout << "Unable to open file";
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
