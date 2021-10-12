#include <iostream>
#include <io.h>
#include <fcntl.h>
#include <math.h>
#include <cryptopp/3way.h>
using namespace std;

int main()
{
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
    wcout << "Hello world! This is program 1" << endl;
    wcout << L"Xin chào";
    return 0;
}