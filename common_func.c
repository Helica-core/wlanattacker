#ifndef COMMON_FUNC 

#define COMMON_FUNC

void 	get_ip_string(char *ip_string,const unsigned int ip);
int 	get_interface_info(char table[][128]);
int 	chose_interface(char *res);

void display_net_info(struct net_info *info)
{
	printf("name: %s\n", info->net_interface);
	char ip_string[20];
	//get_ip_string(ip_string,info->ip_address);
	printf("ip address: %d.%d.%d.%d \n",info->ip_address[0],info->ip_address[1],info->ip_address[2],info->ip_address[3] );
	printf("mac address: %2x:%2x:%2x:%2x:%2x:%2x\n", info->ether_address[0],info->ether_address[1],info->ether_address[2],info->ether_address[3],info->ether_address[4],info->ether_address[5]);
	printf("broadcast_address: %2x:%2x:%2x:%2x:%2x:%2x\n",info->broadcast_address[0],info->broadcast_address[1],info->broadcast_address[2],info->broadcast_address[3],info->broadcast_address[4],info->broadcast_address[5]);
}

void display_host_list(struct terminal *list)
{
	struct terminal *ptr = list;
	int cnt = 0;
	while(ptr != NULL)
	{
		printf("host ip: %d.%d.%d.%d\n", ptr->ip_address[0],ptr->ip_address[1],ptr->ip_address[2],ptr->ip_address[3] );
		printf("mac add: %2x:%2x:%2x:%2x:%2x:%2x\n",ptr->mac_address[0],ptr->mac_address[1],ptr->mac_address[2],ptr->mac_address[3],ptr->mac_address[4],ptr->mac_address[5] );
		printf("\n");
		ptr = ptr->next;
		cnt++;
	}
	printf("total:%d\n", cnt);
}

int is_ip_in_list(struct net_info *info,u_int8_t *ip_address,u_int8_t* mac_address)
{
	struct terminal *ptr = info->host;

	while(ptr != NULL)
	{
		if(memcmp(ip_address,ptr->ip_address,4*sizeof(u_int8_t)) == 0)
		{
			memcpy(mac_address , ptr->mac_address , 6*sizeof(u_int8_t));
			return 1;
		}
		ptr = ptr->next;
	}
	return -1;
}

void ether_address_aton(u_int8_t *ether_address , char *ether_address_string)
{

	sscanf(ether_address_string,"%2x:%2x:%2x:%2x:%2x:%2x",&ether_address[0],&ether_address[1],&ether_address[2],&ether_address[3],&ether_address[4],&ether_address[5]);
	return ;
}

void get_local_ip_mac(struct net_info *info , u_int8_t ip_address[] , u_int8_t mac_address[])
{
	char ip_string[100],mac_string[100],gateway_string[100];
	printf("please input your ip address,as x.x.x.x\n");
	scanf("%s",ip_string);

	printf("please input your mac address,as x:x:x:x:x:x\n");
	scanf("%s",mac_string);

	printf("please input your gateway ip address,as x.x.x.x\n");
	scanf("%s",gateway_string);

	sscanf(ip_string,"%d.%d.%d.%d",ip_address,ip_address+1,ip_address+2,ip_address+3);
	sscanf(mac_string,"%x:%x:%x:%x:%x:%x",mac_address,mac_address+1,mac_address+2,mac_address+3,mac_address+4,mac_address+5);
	sscanf(gateway_string,"%d.%d.%d.%d",info->gateway_ip_address,info->gateway_ip_address+1,info->gateway_ip_address+2,info->gateway_ip_address+3);

	printf("what a f@cking solution!\n");
}

void get_local_net_info(struct net_info *info ,char *net_interface)
{
	char 	error_content[PCAP_ERRBUF_SIZE];
	int 	mac_address_num;

	u_int8_t broadcast_address[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
	memcpy(info->broadcast_address,broadcast_address,6*sizeof(u_int8_t));
	
	u_int8_t ether_address[6] = {0x00,0x50,0x56,0xc0,0x00,0x01}; 
	
	u_int8_t ip_address[4];
	u_int32_t ip,mask;

	get_local_ip_mac(info,ip_address,ether_address);
	pcap_lookupnet(net_interface,&ip,&mask,error_content);
	memcpy(info->ip_address,ip_address,4*(sizeof(u_int8_t)));
	memcpy(info->ether_address,ether_address,6*sizeof(u_int8_t));
	memcpy(info->net_mask,&mask,4*sizeof(u_int8_t));
	strcpy(info->net_interface,net_interface);


	int i;
	for(i=0;i<6;i++) info->empty_ether_address[i] = 0x01;
	
	//info->ether_address = {0x00,0x50,0x56,0xc0,0x00,0x01};

	info->host = NULL;
	info->target_A = NULL;
	info->target_B = NULL;
}

void get_ip_string(char *ip_string,const u_int32_t ip)
{
	int tmp[4],i,j;
	for(i=0;i<4;i++)
	{
		tmp[i] = 0;
		for(j=0;j<8;j++)
		{
			if(ip & (1<<(i*8+j)) ) tmp[i] += (1<<j);
		}
	}
	sprintf(ip_string,"%d.%d.%d.%d",tmp[0],tmp[1],tmp[2],tmp[3]);
	return ;
}

int ip_string_to_int8(char *ip_string,u_int8_t *ip_address)
{
	int a,b,c,d;
	if(sscanf(ip_string,"%d.%d.%d.%d",&a,&b,&c,&d) != 4)
	{
		return -1;
	}

	ip_address[0] = a;
	ip_address[1] = b;
	ip_address[2] = c;
	ip_address[3] = d;
	return 0;
}

int get_interface_info(char table[][128])
{
	char 	error_content[PCAP_ERRBUF_SIZE];
	struct 	pcap_if 	*head_interface,*p_interface;
	int 	cnt = 0;
	char 	net_interface[128];
	char 	net_ip_string[20];
	char 	net_mask_string[20];
	u_int32_t net_ip;
	u_int32_t net_mask;
	
	int interface_state = pcap_findalldevs(&head_interface,error_content);

	printf("net interface table\n");
	for(p_interface = head_interface;p_interface != NULL;p_interface = p_interface->next)
	{
		printf("id:   %d\n", cnt);
		printf("name: %s\n", p_interface->name);
		strcpy(table[cnt],p_interface->name);
		printf("desp: %s\n", p_interface->description);

		pcap_lookupnet(p_interface->name,&net_ip,&net_mask,error_content);

		get_ip_string(net_ip_string,net_ip);
		printf("local ip:%s\n", net_ip_string);

		get_ip_string(net_mask_string,net_mask);
		printf("net mask:%s\n\n", net_mask_string);
		cnt++;
		//printf("addr: %s\n", p_interface->addresses);
	}
	return cnt;
}

int chose_interface(char *res)
{
	char name[30][128];
	int idx;

	int size = get_interface_info(name);
	if(size == 0)
	{
		printf("can not find any devise!\n");
		return -1;
	}
	printf("please chose one net interface\n");
	printf("input the id\n");

	scanf("%d",&idx);

	if(idx < size && idx >= 0 )
	{
		GLOBAL_info.net_interface_id = idx;
		strcpy(res,name[idx]);
		return 0;
	}
	else
	{
		printf("Error: illgal input\n");
		return -1;
	}
}	

#endif