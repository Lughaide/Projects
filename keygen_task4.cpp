//  Defines the entry point for the console application
/*ECC parameters p,a,b, P (or G), n, h where p=h.n*/

/* Source, Sink */
#include "cryptopp/filters.h"

#include "cryptopp/hrtimer.h"
using CryptoPP::ThreadUserTimer;

#include <ctime>
#include <iostream>
#include <string>
using namespace std;
using namespace CryptoPP;

/* Random number generator*/
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/files.h" // File input, output
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;

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

/* Define Fuctions */
// Load
void Load(const string& filename, BufferedTransformation& bt);
void LoadPrivateKey(const string& filename, ECDSA<ECP, SHA256>::PrivateKey& key);
void LoadPublicKey(const string& filename, ECDSA<ECP, SHA256>::PublicKey& key);
// Save
void Save(const string& filename, const BufferedTransformation& bt);
void SaveBase64(const string& filename, const BufferedTransformation& bt);
void SavePrivateKey(const string& filename, const ECDSA<ECP, SHA256>::PrivateKey& key);
void SavePublicKey(const string& filename, const ECDSA<ECP, SHA256>::PublicKey& key);
// Others
void print_keys(const string& filename);
void PrintDomainParameters( const ECDSA<ECP, SHA256>::PrivateKey& key );
void PrintDomainParameters( const ECDSA<ECP, SHA256>::PublicKey& key );
void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params );
void PrintPrivateKey( const ECDSA<ECP, SHA256>::PrivateKey& key );
void PrintPublicKey( const ECDSA<ECP, SHA256>::PublicKey& key );

int main(int argc, char* argv[])
{
        try
        {
                int select = -1;
                cout << "ECC Key Generator program: " << endl;
                cout << "Generate new key or load key?" << endl;
                cout << "0. Generate." << endl << "1. Load key." << endl;
                cout << "Selection: "; cin >> select;
                ThreadUserTimer timer(CryptoPP::TimerBase::MILLISECONDS);
                ECDSA<ECP, SHA256>::PrivateKey privatekey;        
                ECDSA<ECP, SHA256>::PublicKey publickey;                
                switch (select)
                {
                        case 0:
                        {
                                AutoSeededRandomPool rng;
                                /* Using standard curve secp256r1 https://neuromancer.sk/std/secg/secp256r1 */
                                /* Create curve parameters and key variables */
                                timer.StartTimer();
                                DL_GroupParameters_EC<ECP> params(ASN1::secp256r1());

                                /* Private key generation and validation */
                                privatekey.Initialize(rng, params);

                                /* Public key generation and validation */
                                privatekey.MakePublicKey(publickey);
                                bool result = privatekey.Validate(rng, 3);
                                double elasped = timer.ElapsedTimeAsDouble();

                                /* Abort if key gen failed */
                                if (!result) { cout << "Private Key generation failed. Aborting."; return -1; }
                                result = publickey.Validate(rng, 3);
                                if (!result) { cout << "Public Key generation failed. Aborting."; return -1; }
                                // Time check
                                cout << "Time spent generating key: " << elasped << " ms" << endl;
                                ofstream outfile;
                                outfile.open("ecc-keygen-time.txt", ios_base::app);
                                outfile << "\n";
                                outfile << elasped;
                                outfile.close();

                                SavePrivateKey("ecc-private.key", privatekey);
                                SavePublicKey("ecc-public.key", publickey);
                                break;
                        }
                        case 1:
                        {
                                cout << "Loading keys in local directory." << endl;
                                LoadPrivateKey("ecc-private.key", privatekey);
                                LoadPublicKey("ecc-public.key", publickey);
                                break;
                        }
                        default:
                                break;

                }
                cout << "Private key (Base64) /w details: " << endl;
                print_keys("ecc-private-b64.key");
                PrintDomainParameters(privatekey);
                PrintPrivateKey(privatekey);
                cout << "/////////////////////////////////" << endl;
                cout << "Public key (Base64) /w details: " << endl;
                print_keys("ecc-public-b64.key");
                PrintDomainParameters(publickey);
                PrintPublicKey(publickey);
        }
        catch(CryptoPP::Exception& e)
        {
                cerr << "Caught Exception..." << endl;
                std::cerr << e.what() << '\n';
        }
        return 0;

}


void PrintDomainParameters( const ECDSA<ECP, SHA256>::PrivateKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );
}

void PrintDomainParameters( const ECDSA<ECP, SHA256>::PublicKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );
}

void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params )
{
    cout << endl;
 
    cout << "Modulus:" << endl;
    cout << " " << params.GetCurve().GetField().GetModulus() << endl;
    
    cout << "Coefficient A:" << endl;
    cout << " " << params.GetCurve().GetA() << endl;
    
    cout << "Coefficient B:" << endl;
    cout << " " << params.GetCurve().GetB() << endl;
    
    cout << "Base Point:" << endl;
    cout << " X: " << params.GetSubgroupGenerator().x << endl; 
    cout << " Y: " << params.GetSubgroupGenerator().y << endl;
    
    cout << "Subgroup Order:" << endl;
    cout << " " << params.GetSubgroupOrder() << endl;
    
    cout << "Cofactor:" << endl;
    cout << " " << params.GetCofactor() << endl;    
}

void PrintPrivateKey( const ECDSA<ECP, SHA256>::PrivateKey& key )
{   
    cout << endl;
    cout << "Private Exponent:" << endl;
    cout << " " << key.GetPrivateExponent() << endl; 
}

void PrintPublicKey( const ECDSA<ECP, SHA256>::PublicKey& key )
{   
    cout << endl;
    cout << "Public Element:" << endl;
    cout << " X: " << key.GetPublicElement().x << endl; 
    cout << " Y: " << key.GetPublicElement().y << endl;
}



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

void SavePublicKey(const string& filename, const ECDSA<ECP, SHA256>::PublicKey& key)
{
    ByteQueue queue;
    key.Save(queue);
    Save(filename, queue);
    string filename64 = "ecc-public-b64.key";
    SaveBase64(filename64, queue);
}
void SavePrivateKey(const string& filename, const ECDSA<ECP, SHA256>::PrivateKey& key)
{
    ByteQueue queue;
    key.Save(queue);
    Save(filename, queue);
    string filename64 = "ecc-private-b64.key";
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
