#include <string.h>
#include <stdlib.h>

#include "WF_include.h"

int init(struct net_info *info)
{
	int state = chose_interface(info->net_interface);
	if(state == 0)
	{
		get_local_net_info(info, info->net_interface);
		display_net_info(info);
		return 1;
	}
	else
	{
		printf("error: in finding interface\n");
		return -1;
	}	
}

int destory(struct net_info *info)
{
	return 0;
}

void debug(char *net_interface)
{
	u_int8_t empty_mac_addr[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
	u_int8_t mac_addr[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
	u_int8_t local_mac_addr[6] = {0xb4,0xae,0x2b,0x2e,0xd8,0x1d};
	u_int8_t local_ip_addr[4] = {0x0a,0x08,0x38,0xb5};
	u_int8_t dest_ip_addr[4] = {0x0a,0x08,0x20,0x02};

	struct ether_header ether_hdr;
	memcpy(ether_hdr.ether_dhost,mac_addr,6*sizeof(u_int8_t));
	memcpy(ether_hdr.ether_shost,local_mac_addr,6*sizeof(u_int8_t));
	ether_hdr.ether_type = 0x0608;

	struct arp_header arp_hdr;
	arp_hdr.arp_hardware_type = 0x0100;
	arp_hdr.arp_protocol_type = 0x0008;
	arp_hdr.arp_hardware_length = 0x06;
	arp_hdr.arp_protocol_length = 0x04;
	arp_hdr.arp_operation_code = 0x0100;

	memcpy(arp_hdr.arp_source_ethernet_address,local_mac_addr,6*sizeof(u_int8_t));
	memcpy(arp_hdr.arp_source_ip_address,local_ip_addr,4*sizeof(u_int8_t) );

	memcpy(arp_hdr.arp_destination_ethernet_address,empty_mac_addr,6*sizeof(u_int8_t));
	memcpy(arp_hdr.arp_destination_ip_address,dest_ip_addr,4*sizeof(u_int8_t));

	u_int8_t packet_content[1024];

	int packet_length;
	make_packet(packet_content,&packet_length,&ether_hdr,&arp_hdr);
	send_packet(net_interface,packet_content,packet_length);
}

char helper[] = "WlanF@cker\nwlan-scan:scanning the wlan to collect the information of computer at wlan\nip-forbidden: ip-forbidden <add (target ip)>|<start|stop>\nmid-attack: mid-attack <start|stop> listen the packet between A and B\nadd-target: add-target <A||B(target set)> <(target ip)> \n\n";

char oper[128];

int main(int argc, char const *argv[])
{
	printf("%s",helper );
	char net_interface[512];
	//struct terminal *target_A = NULL,*target_B = NULL;

	if(init(&GLOBAL_info) == -1) 
	{
		printf("init error!\n");
		return 0;
	}
	HANDLE handle_listen = CreateThread(NULL,0,wlan_info_collect,(LPVOID*)&GLOBAL_info,0,NULL);
	
	while(~scanf("%s",oper))
	{

		if(strcmp(oper,"wlan-scan") == 0)
		{
			wlan_scaning(&GLOBAL_info);
		}
		else if(strcmp(oper,"ip-forbidden") == 0)
		{
			char tmp[100],tmp_ip[10];
			scanf("%s",tmp);
			u_int8_t ip_address[4];

			if(strcmp(tmp,"add") == 0)
			{
				scanf("%s",tmp_ip);
				ip_string_to_int8(tmp_ip,ip_address);
				add_target(&GLOBAL_info,ip_address,&GLOBAL_info.target_fbd);
			}
			else if(strcmp(tmp,"start") == 0)
			{
				GLOBAL_info.ip_forbidden = 1;
				HANDLE handle_mitm = CreateThread(NULL,0,ip_forbidden_send,(LPVOID*)&GLOBAL_info,0,NULL);
			}
			else if(strcmp(tmp,"stop") == 0)
			{
				GLOBAL_info.ip_forbidden = 0;
			}
			else
			{
				printf("unknown !\n");
			}
		}
		else if(strcmp(oper,"mitm-attack") == 0)
		{
			char tmp[10];
			scanf("%s",tmp);

			if(strcmp(tmp,"start") == 0)
			{
				GLOBAL_info.mitm_attack = 1;
				HANDLE handle_mitm = CreateThread(NULL,0,mitm_packet_send,(LPVOID*)&GLOBAL_info,0,NULL);
			}
			else if(strcmp(tmp,"stop") == 0)
			{
				GLOBAL_info.mitm_attack = 0;
			}
			else
			{
				printf("??? unknown %s\n",tmp);
			}
		}
		else if(strcmp(oper,"host-list") == 0)
		{
			host_list(&GLOBAL_info);
		}
		else if(strcmp(oper,"add-target") == 0)
		{
			char tmp_tgt[10],ip_string[20];
			u_int8_t ip_address[4];
			scanf("%s%s",tmp_tgt,ip_string);
			
			if(strlen(tmp_tgt) == 1 && ip_string_to_int8(ip_string,ip_address) != -1)
			{
				if(tmp_tgt[0] == 'A')
				{
					add_target(&GLOBAL_info, ip_address,&GLOBAL_info.target_A);
				}
				else if(tmp_tgt[0] == 'B')
				{
					add_target(&GLOBAL_info, ip_address,&GLOBAL_info.target_B);
				}
				else
				{
					printf("unknown target\n");
				}
			}	
			else
			{
				printf("unknown !\n");
			}
		}
		else if(strcmp(oper , "exit") == 0)
		{	
			break;
		}
		else{
			printf("unknown!\n");
		}
	}

	destory(&GLOBAL_info);
	return 0;
}