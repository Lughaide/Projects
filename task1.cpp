#include <string>
using std::wstring;
using std::string;
#include <exception>
#include <iostream>
#include <assert.h>
#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
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
// Others
void print_keys(const string& filename);
using namespace std;
using namespace CryptoPP;


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
        // DES key & iv
        CryptoPP::SecByteBlock DES_key(DES::DEFAULT_KEYLENGTH);
        CryptoPP::SecByteBlock DES_IV(DES::BLOCKSIZE);
        // AES key & iv
        CryptoPP::SecByteBlock AES_key(AES::DEFAULT_KEYLENGTH);
        CryptoPP::SecByteBlock AES_IV(AES::BLOCKSIZE);
        // Variables
        string plain, cipher, recovered, encoded;
        wstring wplain, wcipher, wrecovered, wencoded;
        int choice = -1;

        wcout << L"Nhập message: " ;
        getline(wcin,wplain);
        plain = wstring_to_string(wplain);
        wcout << L"Hiển thị key?" << endl;
        wcout << L"1. Yes." << endl;
        wcout << L"2. No." << endl;
        wcout << L"Lựa chọn thao tác: ";
        wcin >> choice;
        switch (choice)
        {
            case 1:
            {
                wcout << "DES key & IV: " << endl;
                print_keys("DES-key-HEX.key");
                print_keys("DES-IV-HEX.key");
                wcout << "AES key & IV: " << endl;
                print_keys("AES-key-HEX.key");
                print_keys("AES-IV-HEX.key"); 
                break;
            }
            default:
                break;
        }
        int choice2 = -1;
        wcout << "DES hay AES?" << endl;
        wcout << "0. DES." << endl << "1. AES." << endl;
        wcout << "Selection: "; 
        wcin >> choice2;
        switch (choice2)
        {
            case 0:
            {
                // Load DES key
                FileSource fs("DES-key.key", false);
                CryptoPP::ArraySink copykey(DES_key, sizeof(DES_key));
	            /*Copy data from DES_key.key  to  DES_key */ 
	            fs.Detach(new Redirector(copykey));
	            fs.Pump(sizeof(DES_key));

                // Load DES IV
                FileSource fs2("DES-IV.key", false);
                CryptoPP::ArraySink copyIV(DES_IV, sizeof(DES_IV));
	            /*Copy data from DES_IV.key  to  DES_IV */ 
	            fs2.Detach(new Redirector(copyIV));
	            fs2.Pump(sizeof(DES_IV));

                break;
            }
            case 1:
            {
                // Load AES key
                FileSource fs("AES-key.key", false);
                CryptoPP::ArraySink copykey(AES_key, sizeof(AES_key));
	            /*Copy data from AES_key.key  to  AES_key */ 
	            fs.Detach(new Redirector(copykey));
	            fs.Pump(sizeof(AES_key));

                // Load AES IV
                FileSource fs2("AES-IV.key", false);
                CryptoPP::ArraySink copyIV(AES_IV, sizeof(AES_IV));
	            /*Copy data from AES_IV.key  to  AES_IV*/ 
	            fs2.Detach(new Redirector(copyIV));
	            fs2.Pump(sizeof(AES_IV));
                break;
            }
            default:
            {
                return 0;
                break;
            }
        }
        wcout << L"Key & IV đã được nhận từ file." << endl;
        wcout << L"Bắt đầu encrypt & decrypt." << endl;
        wcout << L"Mode CBC" << endl;
        wcout << "Plain text: " << wplain << endl;
        switch (choice2)
        {
            case 0:
            {
                // Encryption
                CBC_Mode< DES >::Encryption e;
                e.SetKeyWithIV(DES_key, DES_key.size(), DES_IV);
                // The StreamTransformationFilter adds padding
                //  as required. ECB and CBC Mode must be padded
                //  to the block size of the cipher.
                StringSource(plain, true, 
                    new StreamTransformationFilter(e,
                        new StringSink(cipher)
                    ) // StreamTransformationFilter      
                ); // StringSource

                // Pretty print
                encoded.clear();
                StringSource(cipher, true,
                    new HexEncoder(
                        new StringSink(encoded)
                    ) // HexEncoder
                ); // StringSource
                wcout << "Cipher text: " << string_to_wstring(encoded) << endl;

                // Decryption
                CBC_Mode< DES >::Decryption d;
                d.SetKeyWithIV(DES_key, DES_key.size(), DES_IV);

                // The StreamTransformationFilter removes
                //  padding as required.
                StringSource s(cipher, true, 
                    new StreamTransformationFilter(d,
                        new StringSink(recovered)
                    ) // StreamTransformationFilter
                ); // StringSource
                wcout << "Recovered text: " << string_to_wstring(recovered) << endl;
                break;
            }
            case 1:
            {
                cout << "Plain text: " << plain << endl;

                // Encryption
                CBC_Mode< AES >::Encryption e;
                e.SetKeyWithIV(AES_key, AES_key.size(), AES_IV);
                // The StreamTransformationFilter adds padding
                //  as required. ECB and CBC Mode must be padded
                //  to the block size of the cipher.
                StringSource(plain, true, 
                    new StreamTransformationFilter(e,
                        new StringSink(cipher)
                    ) // StreamTransformationFilter      
                ); // StringSource

                // Pretty print
                encoded.clear();
                StringSource(cipher, true,
                    new HexEncoder(
                        new StringSink(encoded)
                    ) // HexEncoder
                ); // StringSource
                wcout << "Cipher text: " << string_to_wstring(encoded) << endl;

                // Decryption
                CBC_Mode< AES >::Decryption d;
                d.SetKeyWithIV(AES_key, AES_key.size(), AES_IV);

                // The StreamTransformationFilter removes
                //  padding as required.
                StringSource s(cipher, true, 
                    new StreamTransformationFilter(d,
                        new StringSink(recovered)
                    ) // StreamTransformationFilter
                ); // StringSource
                wcout << "Recovered text: " << string_to_wstring(recovered) << endl;
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
    
    return 0;
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
    else wcout << "Unable to open file" << endl;
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

