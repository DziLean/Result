#include "myhead.h"
//#include "pcap.h"
#define FIRST_INTERFACE "first_interface.pcap"
#define SECOND_INTERFACE "second_interface.pcap"
#define INTERFACE "interface.pcap"
#define LENGTH_TCP 27
#define ETH_LENGTH 14

pcap_t * adhandle1;
pcap_t * adhandle2;
MacAddressTable MAT,MATA;
ip_address A;
ip_address B;
ip_address C;
ip_address D;
u_char D_port[2];
u_char A_port[2];




#define IPTOSBUFFERS  12
char * iptostr(u_long in) //вывод расшіренной інформаціі об устройстве
{
	static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    _snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]),"%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}
//инициализация кода функций
//расшіренный ввод-вывод
void ifprint(pcap_if_t *d)
{
	pcap_addr_t *a;
	printf("%s\n",d->name);
	if (d->description)
	printf("\tDescription: %s\n",d->description);
  
  
	for(a=d->addresses;a;a=a->next)
	{
		if(iptostr(((struct sockaddr_in *)a->addr)->sin_addr.s_addr)[0] == '0') continue;
		if (a->addr)
			printf("\tAddress: %s\n",iptostr(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
		if (a->netmask)
			printf("\tNetmask: %s\n",iptostr(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
	}
	printf("\n");
}

//расшіренный ввод-вывод - ifprint

void print_mac(mac_address m)
{
	printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",m.b1,m.b2,m.b3,m.b4,m.b5,m.b6);
}

void print_arp(arp a)
{
	printf("Hardware type: %.2x%.2x \n",a.equip[0],a.equip[1]);
	printf("Protokol type: %.2x%.2x \n",a.prot[0],a.prot[1]);
	printf("Hardware size: %d \n",a.mac_len);
	printf("Protokol size: %d \n",a.ip_len);
	printf("Operation: %.2x%.2x \n",a.oper[0],a.oper[1]);
	printf(" Source MAC: ");
	print_mac(a.source_mac);
	printf("Source IP: %d.%d.%d.%d\n",a.source_ip.b1,a.source_ip.b2,a.source_ip.b3,a.source_ip.b4);
	printf("Destination MAC: ");
	print_mac(a.dest_mac);
	printf("Destination IP: %d.%d.%d.%d\n",a.dest_ip.b1,a.dest_ip.b2,a.dest_ip.b3,a.dest_ip.b4);
}

void print_ip(ip_header ip)
{
	u_char mem = ip.ver_ihl;
	printf("Version: %d\nHeader length: %d bytes \n", mem>>4, (mem & 0x0f)<<2);
	printf("ToS: %.2x\n", ip.tos);
	printf("Length: %u\n",((u_int)(ip.tlen[0]))*256+(u_int)ip.tlen[1]);
	printf("ID: %u\n",((u_int)ip.identification[0])*256+(u_int)ip.identification[1]);
	printf("Flags and fragment offset: %.2x%.2x\n", ip.flags_fo[0], ip.flags_fo[1]);
	printf("TTL: %u\n", ip.ttl);
	printf("Protocol: %.2x\n", ip.proto);
	printf("Checksum: %.2x\n",((u_int)ip.crc[0])*256+(u_int)ip.crc[1]);
	printf("Source IP: %d.%d.%d.%d\n",ip.saddr.b1,ip.saddr.b2,ip.saddr.b3,ip.saddr.b4);
	printf("Destination IP: %d.%d.%d.%d\n",ip.daddr.b1,ip.daddr.b2,ip.daddr.b3,ip.daddr.b4);
}

void print_udp(udp u)
{
	printf("Source port: %d\n", (((u_int)u.sport[0]))*256+(u_int)u.sport[1]);
	printf("Destination port: %d\n", (((u_int)u.dport[0]))*256+(u_int)u.dport[1]);
	printf("Length: %d\n", (((u_int)u.len[0])*256)+(u_int)u.len[1]);
	printf("Checksum: %.2x\n", ((u_int)u.crc[0])*256+(u_int)u.crc[1]);
}

void print_tcp(tcp t) 
{
	printf("Source port: %d\n", (((u_int)t.sport[0]))*256+(u_int)t.sport[1]);
	printf("Destination port: %d\n", (((u_int)t.dport[0]))*256+(u_int)t.dport[1]);	
	printf("Sequence number: %u\n", ((u_int)t.seq_numb[0]*4194304)+((u_int)t.seq_numb[1]*65536)+((u_int)t.seq_numb[3]*256)+(u_int)t.seq_numb[0]);
	printf("Asknowlegment number: %u\n",((u_int)t.ask_numb[0]*4194304)+((u_int)t.ask_numb[1]*65536)+((u_int)t.ask_numb[3]*256)+(u_int)t.ask_numb[0]);
	printf("Data offset: %u\n", ((t.other[0] & 0xf0) >> 4) <<2);
	printf("Code bits: %x\n", t.other[1] & 0x3f);
	printf("Window: %u\n", ((u_int)(t.window[0]))*256+(u_int)t.window[1]);
	printf("Checksum: %.2x\n",((u_int)t.crc[0])*256+(u_int)t.crc[1]);
}


u_short checksumIP(const u_char *pkt_data)
{
	u_short result;
	u_long hdr_sum = 0;
	
	ip_header *iphdr = (ip_header *)(pkt_data + ETH_LENGTH);
	u_char mem=iphdr->ver_ihl;
	u_int iphdrlen = (mem & 0x0f) * 4;
	iphdr->crc[0] = 0;
	iphdr->crc[1] = 0;

	u_short *point = (u_short *)iphdr;
	for(int j = 0; j < iphdrlen; j+=2)
	{
		hdr_sum += *point;
		point++;
	}

	hdr_sum = (hdr_sum >> 16) + (hdr_sum & 0xffff);
	hdr_sum = (hdr_sum >> 16) + (hdr_sum & 0xffff);
	result = (u_short)~hdr_sum;
	return result;
}
void checksumIPb(const u_char *pkt_data)
{
	u_short result;
	u_long hdr_sum = 0;
	
	ip_header *iphdr = (ip_header *)(pkt_data + ETH_LENGTH);
	u_char mem=iphdr->ver_ihl;
	u_int iphdrlen = (mem & 0x0f) * 4;
	iphdr->crc[0] = 0;
	iphdr->crc[1] = 0;

	u_short *point = (u_short *)iphdr;
	for(int j = 0; j < iphdrlen; j+=2)
	{
		hdr_sum += *point;
		point++;
	}

	hdr_sum = (hdr_sum >> 16) + (hdr_sum & 0xffff);
	hdr_sum = (hdr_sum >> 16) + (hdr_sum & 0xffff);
	result = (u_short)~hdr_sum;
	iphdr->crc[0]=result&0xff;
	iphdr->crc[1]=(result&0xff00)>>8;
}


u_short checksumTCP(const u_char *pkt_data)
{
	u_short result;
	u_long hdr_sum = 0;
	
	ip_header *ip = (ip_header *)(pkt_data + ETH_LENGTH);
	u_char mem=ip->ver_ihl;
	tcp *t = (tcp *)(pkt_data + ETH_LENGTH + (mem & 0x0f) * 4);
	t->crc[0] = 0;
	t->crc[1] = 0;
	u_short *p = (u_short *)t;
	
	int tcp_segment = ((u_int)(ip->tlen[0]))*256 + (u_int)(ip->tlen[1])-  (u_int)(mem & 0x0f) * 4;
	
	int j;
	for(j = 1; j < tcp_segment; j+=2)
	{
		hdr_sum += ntohs(*p);
		p++;		
	}
	if(j == tcp_segment) //Если нечетное количество байтов
	{
		hdr_sum += ntohs(*p) & 0xff00;//добавление нулей для чётности байт
	}

	//Псевдозаголовок
	hdr_sum += ip->daddr.fcs();
	hdr_sum += ip->saddr.fcs();
	hdr_sum += (u_short)ip->proto;
	hdr_sum += (u_short)tcp_segment;

	hdr_sum = (hdr_sum >> 16) + (hdr_sum & 0xffff);
	hdr_sum = hdr_sum + (hdr_sum >> 16);
	result = (u_short)~hdr_sum;
	return result;
}

u_short CheckSum(u_short *buffer, int len)
{
	u_long cksum=0;
	while(len >1){
		cksum+=*buffer++;
		len -=sizeof(u_short);
	}
	if(len)
		cksum += *(u_char*)buffer;
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);	
	return (u_short)(~cksum);
}

u_short ControlTCPData(const u_char *pkt_data,pcap_t * adhandle,const struct pcap_pkthdr *header)
{
	ether *eth_hed;
    eth_hed = (ether *) pkt_data;
	ip_header *ip;
	ip = (ip_header *)(pkt_data+ETH_LENGTH);
	tcp *t;
	u_char mem = ip->ver_ihl;
	t = (tcp *)(pkt_data+ETH_LENGTH+((mem & 0xf)<<2));
	mem=ip->ver_ihl;
	const u_char * data; 
	u_char tcphead = ((t->other[0] & 0xf0) >> 4) <<2;	
	u_int data_length = (u_int)(((u_int)ip->tlen[0])*256 + (u_int)ip->tlen[1] - (u_int)((mem & 0x0f)<<2) - (u_int)(((t->other[0] & 0xf0) >> 4) <<2));
	if(ip->proto == 06 && data_length>LENGTH_TCP)
	{	

		data = pkt_data + ETH_LENGTH+((mem & 0xf)<<2)+tcphead;
		FILE* f;
		f = fopen("Allowed.txt","a");
		*(char *)(pkt_data + header->len - 1) = 0;
		if(f==NULL)
		{
			printf("file error...");
			exit(1);
		}
		fprintf(f,"Data: %s \r\n",data);
		fclose(f);
		u_int hellen = ((u_int)ip->tlen[0])*256+((u_int)ip->tlen[1]) - data_length+ETH_LENGTH;// длина нового пакета,равная прежднему без поля данных
		printf("%d",hellen);

		mac_address helpmac = eth_hed->dest_mac;
		eth_hed->dest_mac=eth_hed->source_mac;
		eth_hed->source_mac=helpmac;

		ip_address helpip = ip->daddr;
		ip->daddr=ip->saddr;
		ip->saddr=helpip;

		u_char helpport[2];
		helpport[0]=t->dport[0];
		helpport[1]=t->dport[1];
		t->dport[0]=t->sport[0];
		t->dport[1]=t->sport[1];
		t->sport[0]=helpport[0];
		t->sport[1]=helpport[1];
		
		u_char numb[4];
		numb[0]=t->seq_numb[0];
		numb[1]=t->seq_numb[1];
		numb[2]=t->seq_numb[2];
		numb[3]=t->seq_numb[3];
		t->seq_numb[0]=t->ask_numb[0];
		t->seq_numb[1]=t->ask_numb[1];
		t->seq_numb[2]=t->ask_numb[2];
		t->seq_numb[3]=t->ask_numb[3];

		u_int  helpnu;
		helpnu=(((u_int)numb[0])*256*256*256+((u_int)numb[1])*256*256+((u_int)numb[2])*256+((u_int)numb[3]) + data_length);
		t->ask_numb[0]=(helpnu>>24) & 0xff;
		t->ask_numb[1]=(helpnu>>16) & 0xff;
		t->ask_numb[2]=(helpnu>>8) & 0xff;
		t->ask_numb[3]=	helpnu & 0xff;	
		ip->tlen[0]=((hellen-ETH_LENGTH)>>8) & 0xff;
		ip->tlen[1]=(hellen-ETH_LENGTH) & 0xff;
		t->other[1]=0x10;//АСК
		/*ip->crc[1]=((checksumIP(pkt_data)>>8)&0xff);
		ip->crc[0]=(checksumIP(pkt_data)&0xff);
		t->crc[1]=((ntohs(checksumTCP(pkt_data)>>8)&0xff));
		t->crc[0]=(ntohs(checksumTCP(pkt_data))&0xff);*/

		//checksumIPb(pkt_data);
		ip->crc[0]=0;
		ip->crc[1]=0;
		u_short crc=CheckSum((u_short*)ip,((mem & 0xf)<<2));
		ip->crc[1]=(crc>>8)&0xff;
		ip->crc[0]=crc&0xff;

		t->crc[0]=0;
		t->crc[1]=0;
		psh* pseudo=new psh;
		pseudo->so=ip->saddr;
		pseudo->de=ip->daddr;
		pseudo->full=0;
		pseudo->prot=6;
		u_short help = (u_short)(((u_short)ip->tlen[0])*256 + (u_short)ip->tlen[1] - (u_short)((mem & 0x0f)<<2));// TCP и данные
		pseudo->tcplen[0]=help>>8;
		pseudo->tcplen[1]=help&0xff;
		
		u_char* pshTcphData_Buf = new u_char [1500];
		memcpy(pshTcphData_Buf , (u_char*)pseudo , sizeof(psh));
		memcpy(pshTcphData_Buf+sizeof(psh), (u_char*)t, (((t->other[0] & 0xf0) >> 4) <<2));
		//memcpy(pshTcphData_Buf+sizeof(psh)+(((t->other[0] & 0xf0) >> 4) <<2) , (u_char*)data ,(data_length));

		
		u_short crctcp=CheckSum((u_short*)pshTcphData_Buf, sizeof(psh)+(((t->other[0] & 0xf0) >> 4) <<2));
		crctcp=crctcp;
		t->crc[1]=crctcp>>8;
		t->crc[0]=crctcp&0xff;

		/*u_char* mess = new u_char [hellen];
		for(int i=0;i<hellen;++i)
			*(mess+i)=*(pkt_data+i);*/
	
		if(pcap_sendpacket(adhandle,pkt_data,hellen) != 0)
		{
			fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle));
			return 0;
		}		
		return 1;
	}
	else 
		return 0;
}
void ControlUDP(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	ip_header *ip;
	ip = (ip_header *)(pkt_data+ETH_LENGTH);
	if( ip->saddr==D && ip->daddr==C)
		pcap_dump(dumpfile, header, pkt_data);
	return;
}

short ControlTCPData1(const u_char *pkt_data,pcap_t * adhandle,const struct pcap_pkthdr *header)
{
	ether *eth_hed;
    eth_hed = (ether *) pkt_data;
	ip_header *ip;
	ip = (ip_header *)(pkt_data+ETH_LENGTH);
	tcp *t;
	u_char mem = ip->ver_ihl;
	t = (tcp *)(pkt_data+ETH_LENGTH+((mem & 0xf)<<2));
	mem=ip->ver_ihl;
	const u_char * data; 
	u_char tcphead = ((t->other[0] & 0xf0) >> 4) <<2;	
	u_int data_length = (u_int)(((u_int)ip->tlen[0])*256 + (u_int)ip->tlen[1] - (u_int)((mem & 0x0f)<<2) - (u_int)(((t->other[0] & 0xf0) >> 4) <<2));
	if(ip->proto == 06 && data_length>LENGTH_TCP && C==ip->daddr)
	{	

		data = pkt_data + ETH_LENGTH+((mem & 0xf)<<2)+tcphead;
		FILE* f;
		f = fopen("Allowed.txt","a");
		*(char *)(pkt_data + header->len - 1) = 0;
		if(f==NULL)
		{
			printf("file error...");
			exit(1);
		}
		fprintf(f,"Data: %s \r\n",data);
		fclose(f);
		u_int hellen = ((u_int)ip->tlen[0])*256+((u_int)ip->tlen[1]) - data_length+ETH_LENGTH;// длина нового пакета,равная прежднему без поля данных
		
		u_char * mass = new u_char[data_length];
		for(int j=0;j<data_length;++j)
		{
			*(mass+j)='f';
		}		

		memcpy((void*)(pkt_data+hellen),mass,data_length);
		/*ip->crc[1]=((checksumIP(pkt_data)>>8)&0xff);
		ip->crc[0]=(checksumIP(pkt_data)&0xff);
		t->crc[1]=((ntohs(checksumTCP(pkt_data)>>8)&0xff));
		t->crc[0]=(ntohs(checksumTCP(pkt_data))&0xff);*/

		//checksumIPb(pkt_data);
		ip->crc[0]=0;
		ip->crc[1]=0;
		u_short crc=CheckSum((u_short*)ip,((mem & 0xf)<<2));
		ip->crc[1]=(crc>>8)&0xff;
		ip->crc[0]=crc&0xff;

		t->crc[0]=0;
		t->crc[1]=0;
		psh* pseudo=new psh;
		pseudo->so=ip->saddr;
		pseudo->de=ip->daddr;
		pseudo->full=0;
		pseudo->prot=6;
		u_short help = (u_short)(((u_short)ip->tlen[0])*256 + (u_short)ip->tlen[1] - (u_short)((mem & 0x0f)<<2));// TCP и данные
		pseudo->tcplen[0]=help>>8;
		pseudo->tcplen[1]=help&0xff;
		
		u_char* pshTcphData_Buf = new u_char [1500];
		memcpy(pshTcphData_Buf , (u_char*)pseudo , sizeof(psh));
		memcpy(pshTcphData_Buf+sizeof(psh), (u_char*)t, (((t->other[0] & 0xf0) >> 4) <<2));
		memcpy(pshTcphData_Buf+sizeof(psh)+(((t->other[0] & 0xf0) >> 4) <<2) , (u_char*)mass ,(data_length));

		
		u_short crctcp=CheckSum((u_short*)pshTcphData_Buf, sizeof(psh)+(((t->other[0] & 0xf0) >> 4) <<2)+data_length);
		crctcp=crctcp;
		t->crc[1]=crctcp>>8;
		t->crc[0]=crctcp&0xff;

		/*u_char* mess = new u_char [hellen];
		for(int i=0;i<hellen;++i)
			*(mess+i)=*(pkt_data+i);*/
	
		if(pcap_sendpacket(adhandle,pkt_data,hellen+data_length) != 0)
		{
			fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle));
			return 0;
		}		
		return 1;
	}
	else 
		return 0;
}


void ModifyTCP(const u_char *pkt_data)
{
	
	ip_header *ip;
	ip = (ip_header *)(pkt_data+ETH_LENGTH);
	tcp *t;
	u_char mem = ip->ver_ihl;
	const u_char * data; 
	u_char tcphead = ((t->other[0] & 0xf0) >> 4) <<2;	
	u_int data_length = (u_int)(((u_int)ip->tlen[0])*256 + (u_int)ip->tlen[1] - (u_int)((mem & 0x0f)<<2) - (u_int)(((t->other[0] & 0xf0) >> 4) <<2));
	data = pkt_data + ETH_LENGTH+((mem & 0xf)<<2)+tcphead;
	t = (tcp *)(pkt_data+ETH_LENGTH+((mem & 0xf)<<2));

	if(D==ip->saddr && C==ip->daddr &&  (t->other[1] & 0x2)==1 )
	{
		D_port[0]=t->sport[0];
		D_port[1]=t->sport[1];//запоминание глобальной переменной порта;
		//реконструирование пакета

		ip->saddr=A;
		ip->crc[0]=0;
		ip->crc[1]=0;
		u_short crc=CheckSum((u_short*)ip,((mem & 0xf)<<2));
		ip->crc[1]=(crc>>8)&0xff;
		ip->crc[0]=crc&0xff;

		t->crc[0]=0;
		t->crc[1]=0;
		psh* pseudo=new psh;
		pseudo->so=ip->saddr;
		pseudo->de=ip->daddr;
		pseudo->full=0;
		pseudo->prot=6;
		u_short help = (u_short)(((u_short)ip->tlen[0])*256 + (u_short)ip->tlen[1] - (u_short)((mem & 0x0f)<<2));// TCP и данные
		pseudo->tcplen[0]=help>>8;
		pseudo->tcplen[1]=help&0xff;
		
		u_char* pshTcphData_Buf = new u_char [1500];
		memcpy(pshTcphData_Buf , (u_char*)pseudo , sizeof(psh));
		memcpy(pshTcphData_Buf+sizeof(psh), (u_char*)t, (((t->other[0] & 0xf0) >> 4) <<2));
		memcpy(pshTcphData_Buf+sizeof(psh)+(((t->other[0] & 0xf0) >> 4) <<2) , (u_char*)data ,(data_length));

		
		u_short crctcp=CheckSum((u_short*)pshTcphData_Buf, sizeof(psh)+(((t->other[0] & 0xf0) >> 4) <<2)+data_length);
		crctcp=crctcp;
		t->crc[1]=crctcp>>8;
		t->crc[0]=crctcp&0xff;

	}

	if(A==ip->saddr && C==ip->daddr && (t->other[1] & 0x2)==1)
	{
		A_port[0]=t->sport[0];
		A_port[1]=t->sport[1];//запоминание глобальной переменной порта;
		//реконструирование пакета
	}

	if(ip->saddr==C && ip->daddr ==A && D_port == t->dport)
	{
		ip->daddr=D;//подмена на D

		ip->crc[0]=0;
		ip->crc[1]=0;
		u_short crc=CheckSum((u_short*)ip,((mem & 0xf)<<2));
		ip->crc[1]=(crc>>8)&0xff;
		ip->crc[0]=crc&0xff;

		t->crc[0]=0;
		t->crc[1]=0;
		psh* pseudo=new psh;
		pseudo->so=ip->saddr;
		pseudo->de=ip->daddr;
		pseudo->full=0;
		pseudo->prot=6;
		u_short help = (u_short)(((u_short)ip->tlen[0])*256 + (u_short)ip->tlen[1] - (u_short)((mem & 0x0f)<<2));// TCP и данные
		pseudo->tcplen[0]=help>>8;
		pseudo->tcplen[1]=help&0xff;
		
		u_char* pshTcphData_Buf = new u_char [1500];
		memcpy(pshTcphData_Buf , (u_char*)pseudo , sizeof(psh));
		memcpy(pshTcphData_Buf+sizeof(psh), (u_char*)t, (((t->other[0] & 0xf0) >> 4) <<2));
		memcpy(pshTcphData_Buf+sizeof(psh)+(((t->other[0] & 0xf0) >> 4) <<2) , (u_char*)data ,(data_length));

		
		u_short crctcp=CheckSum((u_short*)pshTcphData_Buf, sizeof(psh)+(((t->other[0] & 0xf0) >> 4) <<2)+data_length);
		crctcp=crctcp;
		t->crc[1]=crctcp>>8;
		t->crc[0]=crctcp&0xff;

	}

	if(ip->saddr==C && ip->daddr ==A && A_port == t->dport)
		true;
}

void packet_handler1(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{

	Sleep(50);
    ether *eth_hed;
    eth_hed = (ether *) pkt_data;	
	
	//проверка таблиц с МАС-адресами.
	if(MATA.findin(eth_hed->source_mac) == true)
		return;
	if(MAT.findin(eth_hed->source_mac) == false)
		MAT.addto(eth_hed->source_mac);
	extern pcap_t * adhandle1;
	extern pcap_t * adhandle2;
	//контроль TCP/UDP
	if(eth_hed->len_or_type[0]==0x08 && eth_hed->len_or_type[1]==0x00 )
	{	
		ip_header *ip;
		ip = (ip_header *)(pkt_data+ETH_LENGTH);
		//////////////////////////////////////// первая проверка
		if(ip->proto == 6) //проверка на запрет TCP трафика
		{
			u_short check = ControlTCPData1((u_char *)pkt_data,adhandle2,header);
			if(check)
				return;
		}
		//////////////////////////////////////// вторая проверка
		if(ip->proto == 17)
			ControlUDP(dumpfile, header,pkt_data);
		//////////////////////////////////////// третяя проверка
		if(ip->proto == 6)
		{
			ModifyTCP(pkt_data);
		}
	}
	
	extern pcap_t* adhandle2;
	if (pcap_sendpacket(adhandle2, pkt_data, header->len) != 0)
		{
			fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle2));
			return;
		}		
	
}
void packet_handler2(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	Sleep(50);
	ether *eth_hed;
    eth_hed = (ether *) pkt_data;	
	
	//проверка таблиц с МАС-адресами.
	if(MAT.findin(eth_hed->source_mac) == true)
		return;
	if(MATA.findin(eth_hed->source_mac) == false)
		MATA.addto(eth_hed->source_mac);
	extern pcap_t * adhandle2;
	extern pcap_t * adhandle1;
	if(eth_hed->len_or_type[0]==0x08 && eth_hed->len_or_type[1]==0x00 )
	{	
		ip_header *ip;
		ip = (ip_header *)(pkt_data+ETH_LENGTH);
		//////////////////////////////////////// первая проверка
		if(ip->proto == 6) //проверка на запрет TCP трафика
		{
			u_short check = ControlTCPData1((u_char *)pkt_data,adhandle1,header);
			if(check)
				return;
		}
		//////////////////////////////////////// вторая проверка
		if(ip->proto == 17)
			ControlUDP(dumpfile, header,pkt_data);
		//////////////////////////////////////// третяя проверка
		if(ip->proto == 6)
		{
			ModifyTCP(pkt_data);
		}
	}

	extern pcap_t* adhandle1;
	if (pcap_sendpacket(adhandle1, pkt_data, header->len) != 0)
		{
			fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle1));
			return;
		}
    
}

DWORD WINAPI MyThreadForWorkAndDump(LPVOID adhandler)
{
	extern pcap_t * adhandle1;
	if ((pcap_t *)adhandler == adhandle1)
	{
		pcap_dumper_t *dumpfile = pcap_dump_open(adhandle1, INTERFACE);
		pcap_loop((pcap_t *)adhandler, 0, packet_handler1, (u_char *)dumpfile);
		pcap_close((pcap_t *)adhandler);
		pcap_dump_close(dumpfile);
		return 0;
	}
	extern pcap_t * adhandle2;
	if((pcap_t *)adhandler == adhandle2)
	{
		pcap_dumper_t *dumpfile = pcap_dump_open(adhandle2, INTERFACE);
		pcap_loop((pcap_t *)adhandler, 0, packet_handler2, (u_char *)dumpfile);
		pcap_close((pcap_t *)adhandler);
		pcap_dump_close(dumpfile);
		return 0;		
	}
}

void changetoIP (u_long address,ip_address *stat)
{
	stat->b1 = address & 0xff;
	stat->b2 = (address >> 8) & 0xff;
	stat->b3 = (address >> 16) & 0xff;
	stat->b4 = (address>>24) & 0xff;
}

