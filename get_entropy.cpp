#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <random>
#include <fstream>
#include <iostream>
#include <exception>
#include <cstring> 
#include <bitset>

int random_number(char* buff,long long &len, int min, long long max)
{
    assert(max > min);
    
    std::ifstream fd("/dev/random", std::ios::out);
    assert(fd.is_open());
       
    /* read 
     */
    int count = 1;
    while(count <= 10)
    {
        std::random_device rd;
        std::default_random_engine eng(rd());
        std::uniform_int_distribution<int> distr(min, max);
        long long entropy_len = distr(eng);
	std::cout<<"random len:"<<entropy_len<<std::endl;
        try{
            fd.read(buff, entropy_len/8 + 1);
            len = entropy_len/8 + 1; 
            std::cout<<"read entropy sucessfully."<<std::endl;
            return 0;
        }
        catch(std::exception &e)
        {
            max = (min + (entropy_len - min)/2);
            count++;
            continue;
        }
    }
    
    return -1;
}

int main()
{
    long long max = 34359738368;
    char *buff = new char[max/8 + 1]; 
    
    long long len=0;
    int res = random_number(buff, len, 256, 440);
    if (res == 0)
    {std::cout<<"buff:"<<buff<<std::endl;} 
    std::cout<<"buff size:"<<len<<std::endl;
    
    for(auto i=0; i<len; i++)
    {std::cout<<std::bitset<8>(buff[i]);}
    return 0; 
}

