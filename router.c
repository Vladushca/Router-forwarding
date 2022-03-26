#include <queue.h>
#include "skel.h"

//structurile de route table si arp table si dimensiunile lor 
//ce vor fi modificate la parsare
struct route_table_entry *rtable;
int rtable_size;

struct arp_entry *arp_table;
int arp_table_entries;

//functia de parsare a tabelei de rutare, care primeste un nume de fisier
//si citeste din el datele: prefix next_hope mask interface
void parse_rtable(char *str){
	FILE * f;
	f = fopen (str, "r"); //deschiderea fisierului in modul read
	DIE(f == NULL, "Smth wrong opening rtable.txt");
	char linie[200]; //stringul in care voi scrie fiecare linie din tabela
	int i; //iterator prin liniile tabelei

	
	for(i = 0; fgets(linie, sizeof (linie), f); i++) {
		char pr[100], n_h[100],  m[100], in[50];
		
// citirea de pe linii si completarea campurilor structurilor route_table_entry
		sscanf (linie, "%s %s %s %s", pr, n_h, m, in);
		
		rtable[i].prefix = inet_addr(pr);
		rtable[i].next_hop = inet_addr(n_h);
		rtable[i].mask = inet_addr(m);
		rtable[i].interface = atoi(in);
		
	}

	rtable_size = i;
	fclose(f);
}



//functia de comparare pentru sortarea ulterioara
int comparator (const void *p, const void *q) {
	uint32_t a = ((struct route_table_entry *)p)->prefix;
    uint32_t b = ((struct route_table_entry *)q)->prefix;
    return b - a ;
}


//functia de aflare a longest-prefix-match-ului
//folosind binary search pe tabela
struct route_table_entry *get_best_route (int l, int r, __u32 dest_ip) {
	struct route_table_entry * best = NULL;
	uint32_t ippp = dest_ip;

	if (r >= l) {
		int mid = l + (r - l) / 2;

		if ((rtable[mid].mask & dest_ip) == rtable[mid].prefix) {
			best = &rtable[mid];
			return best;
		}

		//daca e in 1 jumatate
		 if ((rtable[mid].mask & dest_ip) > rtable[mid].prefix) {
		 	return get_best_route (l, mid - 1, ippp);
		 }
		 //daca e in 2 jum
		 return get_best_route (mid + 1, r, ippp);
	}
	return NULL;
}


//aflarea adresei din arp table ce contine ip din parametru
struct arp_entry *get_arp_entry(__u32 ip) {
    int i;
    
    for(i = 0; i < arp_table_entries; i++)
    	if (arp_table[i].ip == ip)
    		return &arp_table[i];
    
    return NULL;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;


	//alocarea si parsarea tabelei de rutare
	rtable = malloc(80000 * sizeof(struct route_table_entry));
	parse_rtable (argv[1]);
	//sortarea tabelei de rutare
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), comparator);
	//alocarea tabelei arp
	arp_table = malloc(80000 * sizeof(struct  arp_entry));
	
	struct arp_header *arp_hdr = NULL;
	queue q = queue_create();
	
	init(argc - 2, argv + 2);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		//headerele eth si ip ale pachetului primit
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
		
		arp_hdr = parse_arp(m.payload);

		if (arp_hdr != NULL) {
			if (arp_hdr->tpa != htonl(inet_network(get_interface_ip(m.interface)))) { // ARP not for me
					continue;
			}
			arp_table[arp_table_entries].ip = arp_hdr->spa;
			memcpy(arp_table[arp_table_entries].mac, arp_hdr->sha, 6);
			arp_table_entries++;

			if (ntohs(arp_hdr->op) == 1) { // ARP request
				get_interface_mac(m.interface, eth_hdr->ether_shost);
				memcpy(eth_hdr->ether_dhost, arp_hdr->sha, 6);
				send_arp(arp_hdr->spa, arp_hdr->tpa, eth_hdr, m.interface, htons(2));
				continue;
			} else if (ntohs(arp_hdr->op) == 2) { // ARP reply
				while (!queue_empty(q)) { // daca coada nu e goala
					packet *m2 = (packet*)queue_deq(q);
					eth_hdr = (struct ether_header*)m2->payload;
					memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
					memcpy(eth_hdr->ether_dhost, arp_hdr->sha, 6);
					send_packet(m.interface, m2);
					free(m2);
				}
				continue;
			}
		}
		/* Check the checksum */
		if(ip_checksum (ip_hdr, sizeof(struct iphdr)) != 0) {
			continue;
		}

		//daca e pentru router
		char * inter_ip = get_interface_ip (m.interface);
		struct in_addr my_ip;
		inet_aton(inter_ip, &my_ip);

		if (my_ip.s_addr == ip_hdr->daddr) {
			send_icmp (ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_shost, eth_hdr->ether_dhost, 0, 0, m.interface, 0 , 0);
			continue;
		}


		/*Check TTL >= 1 */
		if(ip_hdr->ttl <= 1) {
			send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_shost, eth_hdr->ether_dhost, 11, 0, m.interface);
			continue;
		}


		/* Find best matching route  */
		struct route_table_entry *best_route = get_best_route (0, (rtable_size - 1), ip_hdr->daddr);
		if(!best_route) {
			send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_shost, eth_hdr->ether_dhost, 3, 0, m.interface);
			continue;
		}


		/* Update TTL and recalculate the checksum */
		ip_hdr->ttl--;
		ip_hdr->check = htons(0);
		ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));



		/* Find matching ARP entry and update Ethernet addresses */
		get_interface_mac(best_route->interface, eth_hdr->ether_shost);
		
		struct arp_entry *next_hop_addr = get_arp_entry(best_route->next_hop);
		if(!next_hop_addr) {
			packet *m2 = malloc(sizeof(packet));
			memcpy(m2, &m, sizeof(packet));
			queue_enq(q, m2);
			eth_hdr->ether_type = htons(0x0806);
			int i;
			for (i = 0; i < 6; i++) {
				eth_hdr->ether_dhost[i] = 0xff;
			}
			send_arp(best_route->next_hop, htonl(inet_network(get_interface_ip(best_route->interface))), eth_hdr, best_route->interface, htons(1));
			continue;
		}

		memcpy(eth_hdr->ether_dhost, next_hop_addr->mac, sizeof(next_hop_addr->mac));

		/* Forward the pachet to best_route->interface */
		send_packet(best_route->interface, &m);
	} 
	free(rtable);
	free(arp_table);
}
