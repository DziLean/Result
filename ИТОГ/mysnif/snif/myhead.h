#include "pcap.h"
#include <winsock2.h> 
#include <windows.h>
#include <stdlib.h>
#pragma comment(lib , "ws2_32.lib")
struct mac_address
{//6 байт - байт 1, байт 2, байт 3, байт 4,байт 5, байт 6
    u_char b1;
    u_char b2;
    u_char b3;
    u_char b4;
	u_char b5;
    u_char b6;
	bool operator==(mac_address formac)
	{  
		if(formac.b1 == b1 && formac.b2 == b2 && formac.b3 == b3 && formac.b4 == b4 && formac.b5 == b5 && formac.b6 == b6)
			return true;
		return false;
	}

};

struct ip_address
{ //4 байта - байт 1, байт 2, байт 3, байт 4
    u_char b1;
    u_char b2;
    u_char b3;
    u_char b4;
	bool operator==(ip_address forip)//перегрузка оператора сравнения
	{  
		if(forip.b1 == b1 && forip.b2 == b2 && forip.b3 == b3 && forip.b4 == b4)
			return true;
		return false;
	}
	u_short fcs()
	{
		return ((u_short)b1 *256 |(u_short)b2) + ((u_short)b3 *256 |(u_short)b4);
	}
};

struct arp
{
	u_char equip[2]; //тіп оборудованія,технологія організаціі сеті
	u_char prot[2];	 //тіп протокола,IP,напрімер
	u_char mac_len; 
	u_char ip_len;
	u_char oper[2];
	mac_address source_mac;
	ip_address source_ip;
	mac_address dest_mac;
	ip_address dest_ip;
};

struct ether
{
	mac_address dest_mac;
	mac_address source_mac;
	u_char len_or_type[2]; //поле завісіт от віда кадра Ethernet
};

struct ip_header
{
    u_char ver_ihl;        // Версія (4 bits) +дліна заголовка IP (4 bits)
    u_char tos;            // Тіп сервіса - 8 біт
    u_char tlen[2];        // обўая дліна
    u_char identification[2];// ідентіфікатор заголовка
    u_char flags_fo[2];    // Flags (3 bits) + Fragment offset (13 bits) 
    u_char ttl;            // Time to live -8 біт
    u_char proto;          // Protocol
    u_char crc[2];           // Header checksum
    ip_address saddr;      // Source address
    ip_address daddr;      // Destination address
};

struct tcp
{
	u_char sport[2];
	u_char dport[2];
	u_char seq_numb[4];
	u_char ask_numb[4];
	u_char other[2];	// 4 - data offset, 6 bits - reserved, 6 bits - flags
	u_char window[2];
	u_char crc[2];
};

struct psh
{
	ip_address so;
	ip_address de;
	u_char full;
	u_char prot;
	u_char tcplen[2];
};

struct udp
{
	u_char sport[2];// Source port
	u_char dport[2];// Destination port
	u_char len[2];  // Datagram length
	u_char crc[2];  // Checksum
};

class MacAddressTable
{
	mac_address table[20];
	int count;
public:
	MacAddressTable()
	{
		count = 0;
	}
	void addto(mac_address mac)
	{
		table[count] = mac;
		++count;
	}
	bool findin(mac_address mac)
	{
		for(int i =0; i < count; ++i)
			if(table[i] == mac) 
				return true;
		return false;
	}
};

