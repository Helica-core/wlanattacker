#include "common_func.c"
#include <stdlib.h>
#include <string.h>

void arp_protocal_packet_callback(
			u_char 		*argument,
	const 	struct 		pcap_pkthdr* packet_header,
	const 	u_char* 	packet_content );

void ethernet_protocol_packet_callback(
	  u_char	*argument,
const struct 	pcap_pkthdr*  packet_header,
const u_char	*packet_content);

void get_packet(struct net_info *info);

void wlan_update(u_int8_t *ip_address,
				 u_int8_t *ether_address,
				 struct terminal **head
	)
{
	int find = 0;
	struct terminal *ptr = *head,*last = *head;

	u_int8_t empty_ether_address[6] = {0,0,0,0,0,0};
	if(memcmp(ether_address,empty_ether_address,6*sizeof(u_int8_t)) == 0)
	{
		return ;
	}

	while(ptr != NULL)
	{
		if(memcmp(ip_address,ptr->ip_address,4*sizeof(u_int8_t)) == 0)
		{
			memcpy(ptr->mac_address,ether_address,6*sizeof(u_int8_t));
			find = 1;
			break;
		}
		last = ptr;
		ptr = ptr->next;
	}

	if(!find && *head == NULL)
	{
		printf("add host: ");
		printf("%d.%d.%d.%d\n",ip_address[0],ip_address[1],ip_address[2],ip_address[3]);
		*head = (struct terminal *)malloc(sizeof(struct terminal));
		memcpy((*head)->ip_address,ip_address,4*sizeof(u_int8_t));
		memcpy((*head)->mac_address,ether_address,6*sizeof(u_int8_t));
		(*head)->next = NULL;
		return ;
	}
	if(!find)
	{
		printf("add host: ");
		printf("%d.%d.%d.%d\n",ip_address[0],ip_address[1],ip_address[2],ip_address[3]);
		last->next = (struct terminal *)malloc(sizeof(struct terminal));
		ptr = last->next;
		ptr->next = NULL;

		memcpy(ptr->ip_address,ip_address,4*sizeof(u_int8_t));
		memcpy(ptr->mac_address,ether_address,6*sizeof(u_int8_t));
	}
}

void arp_protocal_packet_callback(
			u_char 		*argument,
	const 	struct 		pcap_pkthdr* packet_header,
	const 	u_char* 	packet_content )
{
	struct 	arp_header 	*arp_protocol;
	u_short protocol_type,
			hardware_type,
			operation_code;

	u_char  *mac_string;
	struct 	in_addr 	source_ip_address,
						destiantion_ip_address;

	u_char 	hardware_length,
			protocol_length;

	//printf("-----arp protocol-----\n");
	arp_protocol 	=	(struct arp_header *)(packet_content+14);
	hardware_type 	= 	ntohs(arp_protocol->arp_hardware_type);
	protocol_type 	= 	ntohs(arp_protocol->arp_protocol_type);
	operation_code 	= 	ntohs(arp_protocol->arp_operation_code);
	hardware_length = 	arp_protocol->arp_hardware_length;
	protocol_length = 	arp_protocol->arp_protocol_length;

	//printf("hardware type: %d\n", hardware_type);
	//printf("protocol type: %d\n", protocol_type);
	//printf("arp operation: %d\n", operation_code);
	/*
	switch(operation_code)
	{
		case 1: printf("arp  request\n");break;
		case 2: printf("arp  reply\n");break;
		case 3: printf("rarp request\n");break;
		case 4: printf("rarp reply\n");break;
		default: break;
	}
	*/
	
	//printf("source mac address: ");
	mac_string = arp_protocol->arp_source_ethernet_address;
	//printf("%02x-%02x-%02x-%02x-%02x-%02x\n",*mac_string,*(mac_string+1),*(mac_string+2)
	//								,*(mac_string+3),*(mac_string+4),*(mac_string+5));	
	memcpy((void *) &source_ip_address ,(void *)&arp_protocol->arp_source_ip_address, sizeof(struct in_addr));
	wlan_update(arp_protocol->arp_source_ip_address,mac_string,&(GLOBAL_info.host));

	//printf("source ip  address: %s\n", inet_ntoa(source_ip_address));

	//printf("destination mac address: ");

	mac_string = arp_protocol->arp_destination_ethernet_address;
	//printf("%02x-%02x-%02x-%02x-%02x-%02x\n",*mac_string,*(mac_string+1),*(mac_string+2)
	//								,*(mac_string+3),*(mac_string+4),*(mac_string+5));	
	memcpy((void*)&destiantion_ip_address,(void*)&arp_protocol->arp_destination_ip_address,sizeof(struct in_addr));
	//printf("destination ip  address: %s\n", inet_ntoa(destiantion_ip_address));
	wlan_update(arp_protocol->arp_destination_ip_address,mac_string,&(GLOBAL_info.host));
}

void ethernet_protocol_packet_callback(
	  u_char	*argument,
const struct 	pcap_pkthdr*  packet_header,
const u_char	*packet_content)
{
	 	   u_short 			ethernet_type;
	struct ether_header 	*ethernet_protocol;
		   u_char			*mac_string;
	static int 				packet_number = 1;
/*
	printf("--------------------------------------------\n");
	printf("packte: %d\n",packet_number);
	printf("time: 	%s\n",ctime((const time_t*)&packet_header->ts.tv_sec));
	printf("length: %d\n",packet_header->len);
	printf("----------ethernet protocol ----------------\n");
*/

	ethernet_protocol = (struct ether_header*) packet_content;
	ethernet_type = ntohs(ethernet_protocol->ether_type);
/*
	switch(ethernet_type)
	{
		case 0x0800: printf("ip   protocol packet\n");break;
		case 0x0806: printf("arp  protocol packet\n");break;
		case 0x8035: printf("rarp protocol packet\n");break;
		default	   : break;
	}
*/
	mac_string = ethernet_protocol->ether_shost;
	/*
	printf("source mac address: ");
	printf("%02x-%02x-%02x-%02x-%02x-%02x\n",*mac_string,*(mac_string+1),*(mac_string+2)
									,*(mac_string+3),*(mac_string+4),*(mac_string+5));
	*/
	mac_string = ethernet_protocol->ether_dhost;
	/*
	printf("destination mac address: ");
	printf("%02x-%02x-%02x-%02x-%02x-%02x\n",*mac_string,*(mac_string+1),*(mac_string+2)
									,*(mac_string+3),*(mac_string+4),*(mac_string+5));
	*/
	switch(ethernet_type)
	{
		case 0x0806:
			arp_protocal_packet_callback(
				argument,
				packet_header,
				packet_content
				);
			break;
	}
	//printf("--------------------------------------------\n");
	packet_number++;
}

void get_packet(struct net_info *info)
{
	pcap_t* pcap_handle;
	char error_content[PCAP_ERRBUF_SIZE];
	//char net_interface[128];
	struct bpf_program bpf_filter;
	char bpf_filter_string[] = "arp";
	bpf_u_int32 net_mask;
	bpf_u_int32 net_ip;

	//chose_interface(net_interface);

	printf("use interface %s\n", info->net_interface);
	pcap_lookupnet(
		info->net_interface,
		&net_ip,
		&net_mask,
		error_content
		);
	pcap_handle = pcap_open_live(
					info->net_interface,
					BUFSIZ,
					1,
					1,
					error_content);
	pcap_compile(pcap_handle,
				 &bpf_filter,
				 bpf_filter_string,
				 0,
				 net_ip
				);
	pcap_setfilter(pcap_handle,&bpf_filter);
	if(pcap_datalink(pcap_handle) != DLT_EN10MB)
		return ;
	printf("ready to loop\n");
	pcap_loop(
		pcap_handle,
		-1,
		ethernet_protocol_packet_callback,
		NULL);

	pcap_close(pcap_handle);
}

void display_packet(u_int8_t *packet_content,int packet_length)
{
	int i;
	for(i=0;i<packet_length;i++)
	{
		printf(" %x",packet_content[i] );
	}
	puts("");
}

void make_ether_packet(
		u_int16_t	ether_type,
		u_int8_t	source_ethernet_address[6],
		u_int8_t	destiantion_ethernet_address[6],
		struct ether_header *ether_hdr
	)
{
	ether_hdr->ether_type = ether_type;

	memcpy(ether_hdr->ether_dhost,destiantion_ethernet_address,6*sizeof(u_int8_t));
	memcpy(ether_hdr->ether_shost,source_ethernet_address,6*sizeof(u_int8_t));

	return ;
}

void make_arp_packet(
		u_int16_t 	operation_code,
		u_int8_t 	source_ip_address[4],
		u_int8_t	source_ethernet_address[6],
		u_int8_t	destiantion_ip_address[4],
		u_int8_t	destiantion_ethernet_address[6],
		struct arp_header *arp_hdr
	)
{
	arp_hdr->arp_hardware_type = 0x0100;
	arp_hdr->arp_protocol_type = 0x0008;
	arp_hdr->arp_hardware_length = 0x06;
	arp_hdr->arp_protocol_length = 0x04;
	arp_hdr->arp_operation_code = operation_code;

	memcpy(arp_hdr->arp_source_ethernet_address,source_ethernet_address,6*sizeof(u_int8_t));
	memcpy(arp_hdr->arp_source_ip_address,source_ip_address,4*sizeof(u_int8_t) );

	memcpy(arp_hdr->arp_destination_ethernet_address,destiantion_ethernet_address,6*sizeof(u_int8_t));
	memcpy(arp_hdr->arp_destination_ip_address,destiantion_ip_address,4*sizeof(u_int8_t));

	return ;
}

void make_packet(u_int8_t *packet_content,
					 int *packet_length ,
					 struct ether_header *ether_hdr,
					 struct arp_header *arp_hdr
					 )
{

	memcpy(packet_content,ether_hdr,sizeof(struct ether_header));

	memcpy((packet_content+sizeof(struct ether_header)) ,arp_hdr, sizeof(struct arp_header));

	*packet_length = (int)sizeof(struct ether_header) + (int)sizeof(struct arp_header);
	//printf("len :%d\n", *packet_length);
	return ;
}

void send_packet(char *net_interface,
			   u_int8_t* packet_content,
			   int packet_length)
{
	char error_content[PCAP_ERRBUF_SIZE];
	pcap_t* pcap_handle;

	pcap_handle = pcap_open_live(
			net_interface,
			packet_length,
			1,
			1,
			error_content
		);

	pcap_sendpacket(
			pcap_handle,
			packet_content,
			packet_length
		);

	pcap_close(pcap_handle);
	//printf("len: %d\n", packet_length);
	//display_packet(packet_content,packet_length);

	//printf("error_content: %s\n",error_content );
}

