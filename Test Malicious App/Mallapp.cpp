//Compile with g++ Malapp.cpp -o malapp

#include <iostream>
#include <fstream>
#include <string>

int main()
{
    std::ifstream myfile;
    std::string filedata;
    int x;

    myfile.open("exploit.png",std::ios::in);
    if (!myfile) {
		std::cout << "Payload not found";
        std::exit(0);
	}
    else{
        myfile >> filedata;
    }

    std::cout<<"Hello PyCode";

    char *url;
    url=new char[36];
    url="WEAREINPYCODEANDTHISISALONGSTRINGRT";
    
    std::cin>>x;

    myfile.close();
    return 0;

}
