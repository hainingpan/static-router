/*
READ DEVICE INFO
READ ROUTE INFO
READ ARP INFO
DO IT
{
	get MAC
	check MAC in device
	if MAC == device.MAC
	{
		RECEIVE DATA
		GET TYPE,JUDGE IF IT IS IP PROTOCOL
		IF YES(0800)
		{	GET DESTINATION IP
 			CHECK IP (ATTENTION)
			IF YES
			{	CHECK THE ARP TO GET THE NEXTHOP(MAC)
				IF YES
				{	MODIFY THE MAC
					INCLUDING DES AND SRC MAC
					SENDTO NEXT HOP
				}
			}
		}
	}

}
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <string.h>
#include <errno.h>//#include <netinet/in.h>
//#include <linux/if_packet.h>
#include <netpacket/packet.h>
#include <net/if_arp.h>
#include <linux/sockios.h>
#include <linux/if.h>

#define BUFFER_MAX 2048
#define ROUTE_INFO_MAX 20		/*max number of route item*/
#define ARP_SIZE_MAX 20			/*max number of arp item*/
#define DEVICE_MAX 10

struct route_item			//route item
{
	char destination[16];		//des_ip
	char gateway[16];		//gateway
	char netmask[16];		//netmask
	int interface;
}route_info[ROUTE_INFO_MAX];	
int route_item_index=0;			

struct arp_table_item
{
	char ip_addr[16];		//gateway IP
	char mac_addr[18];		//NEXT HOP MAC
}arp_table[ARP_SIZE_MAX];		
int arp_item_index=0;			

struct device_info
{
	char mac[18];			//LOCAL MAC
	int interface;			//LOCAL INTERFACE
}device[DEVICE_MAX];		
int device_index=0;				

struct sockaddr_ll des_addr;
struct sockaddr_ll src_addr;

int read_route_table_info()
{
	FILE *fp=fopen("route_table_info","r");	//open 
	if(fp==NULL)
	{
		printf("can't open the route_table_info\n");
		return -1;
	}
	char buf[100];
	memset(buf,0,100);//initial
	char *p;//temp
	fgets(buf,100,fp);//GET LOTS OF CHARS
	while(!feof(fp))//DISTRIBUTE THE CHARS
	{
		if(route_item_index<ROUTE_INFO_MAX)
		{
			p=strtok(buf," ");
			strcpy(route_info[route_item_index].destination,p);
			p=strtok(NULL," ");/*A second call to strtok using a NULL as the first parameter returns a pointer to the character following the token*/
			strcpy(route_info[route_item_index].gateway,p);
			p=strtok(NULL," ");
			strcpy(route_info[route_item_index].netmask,p);
			p=strtok(NULL," ");
			route_info[route_item_index].interface=atoi(p);//change char to int
			route_item_index++;
		}
		memset(buf,0,100);//recover
		fgets(buf,100,fp);
	}
	return 1;
}
int read_arp_table_info()
{
	FILE *fp=fopen("arp_table_info","r");	/*open the arp_table_info*/
	if(fp==NULL)
	{
		printf("can't open the arp_table_info!\n");
		return -1;
	}
	char buf[50];
	memset(buf,0,50);
	char *p;
	fgets(buf,50,fp);
	while(!feof(fp))
	{
		if(arp_item_index<ARP_SIZE_MAX)
		{
			p=strtok(buf," ");
			strcpy(arp_table[arp_item_index].ip_addr,p);
			p=strtok(NULL," ");
			strcpy(arp_table[arp_item_index].mac_addr,p);
			arp_item_index++;
		}
		memset(buf,0,50);
		fgets(buf,50,fp);
	}
	return 1;
}

int read_device_info()
{
	FILE *fp=fopen("device_item_info","r");	
	if(fp==NULL)
	{
		printf("can't open the device_item_info\n");
		return -1;
	}
	char buf[100];
	char *p;
	memset(buf,0,100);
	fgets(buf,100,fp);
	while(!feof(fp))	/*if not the end of file,continue read*/
	{
		if(device_index<DEVICE_MAX)	
		{
			p=strtok(buf," ");
			strcpy(device[device_index].mac,p);
			p=strtok(NULL," ");
			device[device_index].interface=atoi(p);
			device_index++;
		}
		memset(buf,0,100);
		fgets(buf,100,fp);
	}
	return 1;
}
int if_des_mac_in_device(char des_mac[18])//des_mac is local or not
{
	int index=0;
	while(index<device_index)
	{
		if(strcmp(device[index].mac,des_mac)==0)//equal
			return 1;
		index++;
	}
	return 0;
}
int check_and_get_in_route_table(char des_ip[16])
{
	int index=-1,i;
	for(i=0;i<route_item_index;i++)
	{
		if(strcmp(route_info[i].destination,des_ip)==0)//equal
		{
			index=i;
			break;
		}
	}
	return index;
}
int check_arp_get_next_hop_mac(int gateway_index)
{
	int index=-1;
	int i=0;
	while(i<arp_item_index)
	{
		if(strcmp(arp_table[i].ip_addr,route_info[gateway_index].gateway)==0)
		{	index=i;break;}
		i++;
	}
	return index;
}
void change_18_to_6(char mac[18],unsigned char mac_6[6])
{
	unsigned int temp[6];
	sscanf(mac,"%02x:%02x:%02x:%02x:%02x:%02x",&temp[0],&temp[1],&temp[2],&temp[3],&temp[4],&temp[5]);
	mac_6[0]=(unsigned char)temp[0];
	mac_6[1]=(unsigned char)temp[1];
	mac_6[2]=(unsigned char)temp[2];
	mac_6[3]=(unsigned char)temp[3];
	mac_6[4]=(unsigned char)temp[4];
	mac_6[5]=(unsigned char)temp[5];
}
int decide_eth(char des_ip[16])
{	
	char des1[16]="192.168.0",des2[16]="192.168.1",des3[16]="192.168.2";
	if(strncmp(des_ip,des1,9)==0)//equal
	{
			return 1;
	}
	else if((strncmp(des_ip,des2,9)==0)||(strncmp(des_ip,des3,9)==0))
	{		return 2;
	}
	else
	{return -1;}
}
int main(int argc, char* argv[])
{
	if(read_route_table_info()==-1)
		return -1;
	if(read_arp_table_info()==-1)
		return -1;
	if(read_device_info()==-1)
		return -1;
	int sock_fd;
	int n_read;
	char buffer[BUFFER_MAX];
	char *eth_head;//ethernet header
	char *ip_head;//ip header
	char *p;
	int index=-1;//gateway_index
	int arp_index=-1;//arp_next_hop_index
	char type[4];
	char des_ip[16];
	char des_mac[18];		//destination mac Address
	unsigned char des_mac6[6];
	char src_mac[18];	//source Mac Address
	unsigned char src_mac6[6];
	//int interface=-1;
	int dec_eth=-1;
	memset(des_ip,0,16);
	memset(des_mac,0,18);
	memset(src_mac,0,18);
	if ((sock_fd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_IP)))<0)
	{
		printf("create raw socket error!\n");
		return -1;
	}
	while (1)
	{
		n_read = recvfrom(sock_fd,buffer,BUFFER_MAX, 0, NULL, NULL);//buffer:( 0~11:addres   12~13:type   14~33:IP head   34~41:tcp,udp )
		if (n_read < 42)
		{
			printf("error when recv msg\n");
			return -1;
		}
		eth_head = buffer;
		p = eth_head;
		int n = 0xff;
		sprintf(des_mac,"%02x:%02x:%02x:%02x:%02x:%02x",p[0]&n,p[1]&n,p[2]&n,p[3]&n,p[4]&n,p[5]&n);
		printf("the destination mac(the next hop)is %s\n ",des_mac);
		printf("check the destination mac in device \n ");
		if(if_des_mac_in_device(des_mac)==1)
		{	
			printf("check the des_mac,find that the des_mac is in device,so recv data...\n ");
			sprintf(type,"%02x%02x",p[12]&n,p[13]&n);
			printf("TYPE:  %s      ",type);
			if(strncmp(type,"0800",4)==0)//==right
			{	printf("packet is IP protocol\n");
				//get ip
				ip_head = eth_head+14;
				p = ip_head+12;
				sprintf(des_ip,"%d.%d.%d.%d",(256+p[4])%256,(256+p[5])%256,(256+p[6])%256,(256+p[7])%256);//unsign
				printf("the des_ip is: %s\n",des_ip);
				 //get interface
				dec_eth = decide_eth(des_ip);//get eth
					
				//check and get the des_ip's gateway
				index = check_and_get_in_route_table(des_ip);
				if(index!=-1)
				{      
					printf("Check and find the des_ip is in the route item table. index=%d\n",index);
					//check the arp to get the next hop mac
					arp_index=check_arp_get_next_hop_mac(index);
					if(arp_index != -1)
					{
						printf("check and find that next_hop is in the arp table. index=%d\n",arp_index);
						strcpy(src_mac,des_mac);//modify src_mac
						strcpy(des_mac,arp_table[arp_index].mac_addr);
						//preprocess!!!!!!!
						change_18_to_6(src_mac,src_mac6);	
						change_18_to_6(des_mac,des_mac6);	
						memcpy(&(eth_head[6]),src_mac6,6);
						printf("resend data src_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",eth_head[6]&n,eth_head[7]&n,eth_head[8]&n,eth_head[9]&n,eth_head[10]&n,eth_head[11]&n);										
						memcpy(eth_head,des_mac6,6);
						printf("resend data des_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",eth_head[0]&n,eth_head[1]&n,eth_head[2]&n,eth_head[3]&n,eth_head[4]&n,eth_head[5]&n);										
						
						memset(&des_addr,0,sizeof(des_addr));
						memset(&src_addr,0,sizeof(src_addr));
						struct ifreq ifrq0,ifrq1;
						strcpy(ifrq0.ifr_name,"eth2");
						ioctl(sock_fd,SIOCGIFINDEX,&ifrq0);
						des_addr.sll_ifindex=ifrq0.ifr_ifindex;
						des_addr.sll_family=PF_PACKET;
						
						strcpy(ifrq1.ifr_name,"eth1");
						ioctl(sock_fd,SIOCGIFINDEX,&ifrq1);
						src_addr.sll_ifindex=ifrq1.ifr_ifindex;
						src_addr.sll_family=PF_PACKET;
						printf("the interface is eth%d\n",dec_eth);
						printf("bgein to send data to next_hop.....\n");	
						if(dec_eth ==2)//eth2
						{
							if((sendto(sock_fd,buffer,n_read,0,(struct sockaddr*)&des_addr,sizeof(des_addr)))<0)
							{
								printf("resend data error! errno==%d\n",errno);
								//fprintf(stderr,"error...",strerror(errno));
							}
							else
							{
								printf("success!!!!!!!!!!\n");
							}
						}	
						else if(dec_eth == 1)//eth1
						{
							if((sendto(sock_fd,buffer,n_read,0,(struct sockaddr*)&src_addr,sizeof(src_addr)))<0)
							{
								printf("Re-send data error! errno==%d\n",errno);
							}
							else
							{
								printf("success!!!!!!!!!!\n");
							}
						}	
						else
						{
							printf("no such interface eth\n");
						}
					}
					else
					{
						printf("can not find arp info\n");
					}
				}
				else
				{
					printf("can not find route table info\n");
				}
			}
		}
		else
		{
			printf("can not find device info\n");
		}
		printf("***one packet process end ,get next...***\n\n");
	}	
				
	return 0;
}
