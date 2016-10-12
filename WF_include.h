#include "pcap.h"
#include <windows.h>
#include <winsock2.h>

#pragma comment(lib,"ws2_32.lib")

struct ether_header{
	u_int8_t ether_dhost[6];
	u_int8_t ether_shost[6];
	u_int16_t ether_type;
};

struct arp_header{
	u_int16_t arp_hardware_type;
	u_int16_t arp_protocol_type;
	u_int8_t  arp_hardware_length;
	u_int8_t  arp_protocol_length;
	u_int16_t arp_operation_code;

	u_int8_t  arp_source_ethernet_address[6];
	u_int8_t  arp_source_ip_address[4];
	u_int8_t  arp_destination_ethernet_address[6];
	u_int8_t  arp_destination_ip_address[4];
};

struct terminal{
	struct terminal *next;
	u_int8_t ip_address[4];
	u_int8_t mac_address[6];
	char hostname[128];
};

struct net_info{
	int 		net_interface_id;
	char 		net_interface[128];
	u_int8_t 	ip_address[4];
	u_int8_t 	net_mask[4];
	u_int8_t	gateway_ip_address[4];

	u_int8_t  	ether_address[6];
	u_int8_t  	broadcast_address[6];
	u_int8_t	empty_ether_address[6];

	struct 		terminal	*host;
	struct 		terminal 	*target_A ;
	struct 		terminal 	*target_B ;
	struct 		terminal	*target_fbd;

	//state flag
	int 		wlan_scan;
	int 		mitm_attack;
	int 		ip_forbidden;
};

struct net_info GLOBAL_info;

#include "common_func.c"
#include "packet_callback.c"
#include "arp_spoofing.c"
