#include <iostream>
#include <io.h>
#include <fcntl.h>
#include <cryptopp/aes.h>
#include <cryptopp/des.h>
#include <cryptopp/modes.h>
using namespace std;
using namespace CryptoPP;
int main()
{
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
    wchar_t test[256] = { 0 };
    wcout << L"Test input tiếng Việt 01: " << endl;    
    wcin >> test;
    wcout << test;
    return 0;
}