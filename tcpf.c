/*
*	(Peace be upon you)
*
*	Tool Name: tcpf
*	Author: Abdul Wajed <abdul.wajed@neehack.com>
*	Copyright (C) 2020 by Abdul Wajed
*	Date  : 30-April-2019
*
*	This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY
*	This is a free packet crafting software.
*
*	Guide: This software uses libpcap engine, before compiling this software please make sure
*       you have libpcap-dev installed and compile the source with -lpcap parameter or using
*       GCC as following: "gcc -o tcpf tcpf.c -lm -lpcap"
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdlib.h> 
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <math.h>


/* TCP header */
struct sniff_tcp {
    u_short th_sport;   /* source port */
    u_short th_dport;   /* destination port */
    tcp_seq th_seq;     /* sequence number */
    tcp_seq th_ack;     /* acknowledgement number */

    u_char th_offx2;    /* data offset, rsvd */
    #define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;     /* window */
    u_short th_sum;     /* checksum */
    u_short th_urp;     /* urgent pointer */
};

char *splitstring(char str[]);
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char * , int);
void print_ip_packet(const u_char * , int);
void print_tcp_packet(const u_char *  , int );
void p_snif();
void Inject(char source_ip[32],char destination_ip[32], char pkdata[4024], int source_port, int destination_port, int seq_n, int ack_n, int window_size);

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t  placeholder;
    u_int8_t  protocol;
    u_int16_t tcp_length;
};

/*
    Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long  sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

char sourceip          [32]="";
char sourceports       [10]="";
char destinationip     [32]="";
char destinationports  [10]="";
char sequence_value    [20]="";
char ack_value         [20]="";
char packet_data       [65535] = "Inject";
int  sourceport        = 80;
int  destinationport   = 80;
int  seqn	       = 0;
int  ackn	       = 1;
int  i		       = 0;
int  autoinject        = 0;
int  fin=0, syn=0, rst=0, push=0, ack=0, urg=0;
int  flags 	       = 0, flagss = 0;
int  win 	       = 65536;
int  packet_count      = 1;
int  timer	       = 3;
int  verbose	       = 0;
int  x 		       = 1;

int main (int argc, char *argv[])
{
    for(i=0;i<argc;i++){
        if(strcmp(argv[i], "-sn") == 0){
	    strcpy(sequence_value, argv[i+1]);
	} else if(strcmp(argv[i], "-an") == 0){
	    strcpy(ack_value, argv[i+1]);
	} else if(strcmp(argv[i], "-s")  == 0){
            strcpy(sourceip, argv[i+1]);
        } else if(strcmp(argv[i], "-d")  == 0){
            strcpy(destinationip, argv[i+1]);
        } else if(strcmp(argv[i], "-sp") == 0){
            strcpy(sourceports, argv[i+1]);
        } else if(strcmp(argv[i], "-dp") == 0){
            strcpy(destinationports, argv[i+1]);
        } else if(strcmp(argv[i], "-v") == 0){
            verbose = 1;
        } else if(strcmp(argv[i], "-1") == 0){
            fin = 1;
            flags = 1;
	} else if(strcmp(argv[i], "-2") == 0){
            syn = 1;
	    flags = 1;
	    flagss = 1;
        } else if(strcmp(argv[i], "-3") == 0){
            rst = 1;
            flags = 1;
	} else if(strcmp(argv[i], "-4") == 0){
            push = 1;
            flags = 1;
	} else if(strcmp(argv[i], "-5") == 0){
            ack = 1;
            flags = 1;
	} else if(strcmp(argv[i], "-6") == 0){
            urg = 1;
            flags = 1;
	} else if(strcmp(argv[i], "-pd") == 0){
	    strcpy(packet_data, argv[i+1]);
	} else if(strcmp(argv[i], "-w") == 0){
	    sscanf(argv[i+1], "%d", &win);
	} else if(strcmp(argv[i], "-c") == 0){
	    sscanf(argv[i+1], "%d", &packet_count);
	} else if(strcmp(argv[i], "-t") == 0){
	    sscanf(argv[i+1], "%d", &timer);
	} else if(strcmp(argv[i], "-autoinject") == 0){
	    autoinject = 1;
	}
    }
    if(flags == 1 && flagss != 1) syn = 0;

    if(argc < 2 || argc > 30 || strcmp(argv[1], "--help") == 0 || destinationip == NULL){
	printf("Usage ./tcpf [Options]:\n");
	printf("  -s		Set Source IP address, to specify a subnet, add x.x.x.x/x e.g. 127.0.0.1/8\n");
	printf("  -d		Set Destination IP Address, to specify a subnet, add x.x.x.x/x e.g. 127.0.0.1/8\n");
	printf("  -sp		Set Source Port Number\n");
	printf("  -dp		Set Destination Port Number\n");
	printf("  -pd		Set Packet Data, Default value is \"Inject\"\n");
	printf("  -1		Set Fin Flag\n");
	printf("  -2		Set Syn Flag\n");
	printf("  -3		Set Rst Flag\n");
	printf("  -4		Set Psh Flag\n");
	printf("  -5		Set Ack Flag\n");
	printf("  -6		Set Urg Flag\n");
	printf("  -sn		Set Packet Sequence Number\n");
	printf("  -an		Set Packet Acknowledgement Number\n");
	printf("  -w		Set Packet Window size\n");
	printf("  -c		Set Packet counter, by default it's 1 or set 0 for unlimited\n");
	printf("  -t		Set Packet timer, by default it's 2 seconds or set 0 for unlimited\n");
	printf("  -v		Print packet details\n");
	printf("  -autoinject	Sniff the sequence and acknolwedgement number and inject data\n");
	printf("  --help	For Help\n");

	return -1;
    }

    if(strlen(sourceip) == 0){
	strcpy(sourceip, "127.0.0.1");
    }
    if(strlen(sourceports) == 0){
	sourceport = 80;
    } else {
	sscanf(sourceports, "%d", &sourceport);
    }
    if(strlen(destinationports) == 0){
	destinationport = 80;
    } else {
	sscanf(destinationports, "%d", &destinationport);
    }

    if(strlen(sequence_value) != 0){
	sscanf(sequence_value, "%d", &seqn);
    }
    if(strlen(ack_value) != 0){
        sscanf(ack_value, "%d", &ackn);
    }
    char *singleIP = malloc(15);
    char *srcIP = malloc(15);
    int dstsub = 0;
    
    char dsub[3] ="";
    for(int i=0; i<strlen(destinationip);i++){
	destinationip[i] = destinationip[i];
	if(destinationip[i] == '/'){
	    dstsub = 1;
	    dsub[0] = destinationip[i+1];
	    if(destinationip[i+2] != '\0'){
		dsub[1] =  destinationip[i+2];
	    }
	    destinationip[i]='\0';
	    break;
	}
    }
    if(dstsub == 1){
	unsigned int subto_int=0;
	sscanf(dsub, "%d", &subto_int);
	subto_int = pow(2, subto_int);
		
	singleIP = destinationip;
	if(subto_int <= 0){
	    printf("Invalid IP Range: %d\n", subto_int);
	    exit(0);
	}
	for(int i=0;i<((4294967296/subto_int)-1);i++){
	    singleIP = splitstring(singleIP);
	    Inject(sourceip, singleIP, packet_data, sourceport, destinationport, seqn, ackn, win);
	}
	exit(0);
    }

    char sub[3] ="";
    int srcsub = 0;
    for(int i =0; i<strlen(sourceip);i++){
	sourceip[i] = sourceip[i];
	if(sourceip[i] == '/'){
	    srcsub = 1;
	    sub[0] = sourceip[i+1];
	    if(sourceip[i+2] != '\0'){
		sub[1] =  sourceip[i+2];
		}
		sourceip[i]='\0';
		break;
	    }
	}
    if(srcsub == 1){
	unsigned int subto_int=0;
	sscanf(sub, "%d", &subto_int);
	subto_int = pow(2, subto_int);
	srcIP = sourceip;
	if(subto_int <= 0){
	    printf("Invalid IP Range: %d\n", subto_int);
	    exit(0);
	}
	for(int i=0;i<((4294967296/subto_int)-1);i++){
		srcIP = splitstring(srcIP);
		Inject(srcIP, destinationip, packet_data, sourceport, destinationport, seqn, ackn, win);
	}
	exit(0);
    }
    
    if(autoinject == 1){
	p_snif();
    } else {
	while(x <= packet_count || packet_count == 0){
	    if(packet_count != 0) x++;
	    Inject(sourceip, destinationip, packet_data, sourceport, destinationport, seqn, ackn, win);
	}
    }
    return 0;
}

void Inject(char source_ip[32],char destination_ip[32], char pkdata[4024], int source_port, int destination_port, int seq_n, int ack_n, int window_size){
    char pkt_hdr_cnt[5000];

    //Create a raw socket
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);

    if(s == -1)
    {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create socket");
        exit(1);
    }

    //Datagram to represent the packet
    char datagram[4096] , *data , *pseudogram;

        //zero out the packet buffer
        memset (datagram, 0, 4096);
        strcpy(datagram, pkdata);
    
        //IP header
        struct iphdr *iph = (struct iphdr *) datagram;

        //TCP header
        struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
        struct sockaddr_in sin;
        struct pseudo_header psh;
 
        
        //Data part
        data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
        strcpy(data, datagram);
        //some address resolution
        sin.sin_family = AF_INET;
        sin.sin_port = htons(80);
        sin.sin_addr.s_addr = inet_addr (destination_ip);

        //Fill in the IP Header
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
        iph->id = htonl (54321); //Id of this packet
        iph->frag_off = 0;
        iph->ttl = 255;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;      //Set to 0 before calculating checksum
        iph->saddr = inet_addr ( source_ip );    //Spoof the source ip address
        iph->daddr = sin.sin_addr.s_addr;

        //Ip checksum
        iph->check = csum ((unsigned short *) datagram, iph->tot_len);
	if(syn == 0 && syn == 0 && rst == 0 && push == 0 && ack == 0 && urg == 0){
	    push = 1;
	    ack = 1;
	}
        //TCPfinHeader
        tcph->source  = htons (source_port);
        tcph->dest    = htons (destination_port);
        tcph->seq     = htonl (seq_n);
        tcph->ack_seq = htonl (ack_n);
        tcph->doff    = 5;  //tcp header size
        tcph->fin     = fin;
        tcph->syn     = syn;
        tcph->rst     = rst;
        tcph->psh     = push;
        tcph->ack     = ack;
        tcph->urg     = urg;
        tcph->window  = htons (window_size); /* maximum allowed window size */
        tcph->check   = 0; //leave checksum 0 now, filled later by pseudo header
        tcph->urg_ptr = 0;

        //Now the TCP checksum
        psh.source_address = inet_addr( source_ip );
        psh.dest_address = sin.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data) );

        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
        pseudogram = malloc(psize);

        memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + strlen(data));

        tcph->check = csum( (unsigned short*) pseudogram , psize);

        //IP_HDRINCL to tell the kernel that headers are included in the packet
        int one = 1;
        const int *val = &one;

        if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
        {
            perror("Error setting IP_HDRINCL");
            exit(0);
        }
	if(verbose == 1){
	    printf("\n  ------------------------------------------------------\n");
    	    printf("  Source IP             :  %s\n", source_ip);
    	    printf("  Destination IP        :  %s\n", destination_ip);
    	    printf("  Source Port           :  %d\n", source_port);
    	    printf("  Destination Port      :  %d\n", destination_port);
    	    printf("  Flags                 :  %s%s%s%s%s%s\n", fin>0 ? "[ fin " : "[ ", syn>0 ? "syn " : "", rst>0 ? "rst " : "", push>0 ? "psh " : "", ack>0 ? "ack " : "", urg>0 ? "urg]" : "]");
    	    printf("  Sequence Number       :  %u\n", seq_n);
    	    printf("  Acknowledgement Number:  %u\n", ack_n);
    	    printf("  Window Size           :  %d\n", window_size);
    	    printf("  Length                :  %d\n", iph->tot_len);
    	    printf("  Packet Data           :  %s\n", strlen(packet_data)>0 ? packet_data : "Not Set");
	    printf("  Packet Status         :  Sent\n");
    	    printf("  ------------------------------------------------------\n\n");

	}
	//Send the packet
        if (sendto (s, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
        {
            perror("sendto failed");
        }

	seq_n = ntohl(tcph->seq)+strlen(packet_data);
	if(timer != 0)
	    sleep(timer);
}

int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
void p_snif(){
    pcap_if_t *alldevsp , *device;
    pcap_t *handle; //Handle of the device that shall be sniffed
 
    char errbuf[100] , *devname , devs[100][100];
    int count = 1 , n;
     
    //First get the list of available devices
    printf("Finding available devices ... ");
    if( pcap_findalldevs( &alldevsp , errbuf) )
    {
        printf("Error finding devices : %s" , errbuf);
        exit(1);
    }
    printf("Done");
     
    //Print the available devices
    printf("\nAvailable Devices are :\n");
    for(device = alldevsp ; device != NULL ; device = device->next)
    {
        printf("%d. %s - %s\n" , count , device->name , device->description);
        if(device->name != NULL)
        {
            strcpy(devs[count] , device->name);
        }
        count++;
    }
     
    //Ask user which device to sniff
    printf("Enter the number of the device you want to sniff : ");
    scanf("%d" , &n);
    devname = devs[n];
     
    //Open the device for sniffing
    printf("Opening device %s for sniffing ... " , devname);
    handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
     
    if (handle == NULL) 
    {
        fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
        exit(1);
    }
    printf("Done\n");
     
    //Put the device in sniff loop
    pcap_loop(handle , -1 , process_packet , NULL);
     
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;
     
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 6:  //TCP Protocol
	    ++tcp;
            print_tcp_packet(buffer , size);
            break;
         
        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
}

void print_tcp_packet(const u_char * Buffer, int Size)
{
    struct sockaddr_in source, dest;

    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
   
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
    
    if(strlen(sourceports) == 0) sourceport = ntohs(tcph->source);
    if(strlen(destinationports) == 0) destinationport = ntohs(tcph->dest);
    if(strlen(sourceip) == 0 || strcmp(sourceip, "127.0.0.1")==0) strcpy(sourceip, inet_ntoa(source.sin_addr));
    if(strlen(destinationip) == 0) strcpy(destinationip, inet_ntoa(dest.sin_addr));
   
    if(ntohs(tcph->source) == sourceport && ntohs(tcph->dest) == destinationport && strcmp(sourceip, inet_ntoa(source.sin_addr))==0){
	    if(strcmp(destinationip, inet_ntoa(dest.sin_addr))==0){
		    char tsrc[32] ;
		    char tdst[32] ;
		    strcpy(tsrc, inet_ntoa(source.sin_addr));
		    strcpy(tdst, inet_ntoa(dest.sin_addr));
		    if((unsigned int)tcph->psh != 0 && (unsigned int)tcph->ack != 0){
		    if(x <= packet_count || packet_count==0){
			x++;
		    } else { exit(0); }
			Inject(tsrc, 
			       tdst,
		               packet_data, 
		               ntohs(tcph->source),
		               ntohs(tcph->dest), 
		               (unsigned)(ntohl(tcph->seq)+((Size - header_size))), 
		               (unsigned)(ntohl(tcph->ack_seq)),
		               ntohs(tcph->window));
		}
	    }
    }
   
}


char *splitstring(char str[]){
	int ipD[4];
	int dots=0, p=0;
	char ipp1[4]="", ipp2[4]="", ipp3[4]="", ipp4[4]="";
	for(int i=0;i<strlen(str);i++){
		if(str[i] != '.' && dots==0){
			ipp1[i] = str[i];
		} else if(dots==0){
			dots++;
			continue;
		}
		if(str[i] != '.' && dots == 1){
			ipp2[p] = str[i];
			p++;
		} else if(dots==1){
			dots++;
			p=0;
			continue;
		}

		if(str[i] != '.' && dots == 2){
                        ipp3[p] = str[i];
                        p++;
                } else if(dots==2){
                        dots++;
			p=0;
                        continue;
                }
		if(str[i] != '.' && dots == 3){
                        ipp4[p] = str[i];
                        p++;
                } else if(dots==3){
                        dots++;
                        continue;
                }
	}
	int part1,part2=0,part3=0,part4=0;
	sscanf(ipp1, "%d", &part1);
	sscanf(ipp2, "%d", &part2);
	sscanf(ipp3, "%d", &part3);
	sscanf(ipp4, "%d", &part4);

	if(!(part4 >= 255)){
		part4++;
	} else {
		if(!(part3 >= 255)){
			part3++;
			part4=1;
		} else {
			if(!(part2 >= 255)){
				part2++;
				part3=0;
				part4=1;
			} else {
				if(!(part1 >= 255)){
					part1++;
					part2=0;
					part3=0;
					part4=1;
				} else return "Invalid IP";
			}
		}
	}
	char r1[4], r2[4], r3[4], r4[4];
	snprintf(r1, sizeof(part1), "%d", part1);
	snprintf(r2, sizeof(part2), "%d", part2);
	snprintf(r3, sizeof(part3), "%d", part3);
	snprintf(r4, sizeof(part4), "%d", part4);
	char *result = malloc(15);
	snprintf(result, (strlen(r1)+strlen(r2)+strlen(r3)+strlen(r4)+4), "%s.%s.%s.%s", r1,r2,r3,r4);
	return result;
}
