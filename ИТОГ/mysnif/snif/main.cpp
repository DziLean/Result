#include "myhead.h"

extern u_char D_port[2];
extern u_char A_port[2];

void ifprint(pcap_if_t *);
char * iptostr(u_long );
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void print_udp(udp u);
void print_tcp(tcp t);
void print_arp(arp a);
void print_ip(ip_header ip);
void print_mac(mac_address mac);
void changetoIP (u_long address,ip_address *stat);
DWORD WINAPI MyThreadForWorkAndDump(LPVOID adhandler);


void main()
{
	pcap_if_t *alldevs; //односвязный спісок структур
	pcap_if_t *d; // указатель на структуру-адаптер
	char errbuf[PCAP_ERRBUF_SIZE];//string filled by libpcap with a description of the error if something goes wrong
	int i=0,j=0,adapter1,adapter2;

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) //1-'rpcap://' for local adapters or 'rpcap://host:port' for adapters on a remote host,2-localhost-NULL
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex(): %s\n", errbuf);
        exit(1);
	}

	//вывод в цікле інформаціі о імеющіхся сетевых адаптерах
	for(d=alldevs;d;d=d->next)
	{
		if (d->description)
		{   
			printf("%d) ",++i);
            ifprint(d);
		}
        else
            printf(" Description is not available \n");			
	}
	//we check the quantity of the interfaces
	if(i==0)
    {
       printf("\nNo interfaces has been found! \n");
       exit(1);
    }
    
    printf("Enter the interface number for VMnet1,please (1-%d):",i);
    scanf("%d",&adapter1);
    //in a case of error
    if(adapter1 < 1 || adapter1 > i)
    {
        printf("\nInterface number is out of range.\n");
        pcap_freealldevs(alldevs);
        exit(1);
    }	

	printf("Enter the interface number for VMnet2,please (1-%d):",i);
    scanf("%d",&adapter2);
    //in a case of error
    if(adapter2 < 1 || adapter2 > i)
    {
        printf("\nInterface number is out of range.\n");
        pcap_freealldevs(alldevs);
        exit(1);
    }	

	//free all the devices excluding the chosen device 
	for( j=0,d=alldevs; j< adapter1-1 ;d=d->next, j++);
	
	extern pcap_t * adhandle1;
	//opening an adapter1 and capturing the packets
	adhandle1 = pcap_open(d->name, 65536,  PCAP_OPENFLAG_PROMISCUOUS,  5,  NULL, errbuf);
	if(adhandle1 == NULL) 
	{
		printf(" WinPcap cannot work with such a divice! ");
		return;
	}
	for( j=0,d=alldevs; j< adapter2-1 ;d=d->next, j++);
	
	extern pcap_t *adhandle2;
	//opening an adapter2 and capturing the packets
	adhandle2 = pcap_open(d->name, 65536,  PCAP_OPENFLAG_PROMISCUOUS, 5,  NULL, errbuf);
	if(adhandle2 == NULL) 
	{
		printf(" WinPcap cannot work with such a divice! ");
		return;
	}

	pcap_freealldevs(alldevs);

	char ipstat[16];
	//fgets(ipstat,sizeof(ipstat),stdin);
	extern ip_address A;
	extern ip_address B;
	extern ip_address C;
	extern ip_address D;
	strcpy(ipstat,"192.168.3.6");
	changetoIP(inet_addr(ipstat),&A);
	strcpy(ipstat,"192.168.3.12");
	changetoIP(inet_addr(ipstat),&B);
	strcpy(ipstat,"192.168.3.18");
	changetoIP(inet_addr(ipstat),&C);
	strcpy(ipstat,"192.168.3.24");
	changetoIP(inet_addr(ipstat),&D);


	//созданіе і установка фільтра
	/*u_int netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr; //маска локальной сеті
	struct bpf_program fcode; //переменная заполняется функціей pcap_compile()
    if (pcap_compile(adhandle, &fcode, "ip or arp or tcp or udp", 1, netmask) < 0)
    {
        fprintf(stderr,"\n Unable to compile the packet filter. Check the syntax.\n");
        return;
    }    
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        printf("\nError setting the filter.\n");
        return;
    }*/
	//создаём 2 потока для работы с 2 интерфейсами
	DWORD thID;
	CreateThread(NULL, NULL, MyThreadForWorkAndDump,adhandle1, NULL, &thID);
	CreateThread(NULL, NULL, MyThreadForWorkAndDump,adhandle2, NULL, &thID);
	printf("Threads are working.\n");	
	printf("press 0 to quit");
	int change = 1;
	while(change)
		scanf("%d",&change);

}
