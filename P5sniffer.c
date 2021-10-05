//PRACTICA 5B 
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <features.h>
#include <pthread.h>
#include <net/if.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <errno.h>
//ESTRUCTURAS
typedef struct{
  unsigned char buff[2048];
  int ln;
  int vl;
}frames;
struct addresses{
	struct sockaddr_in dir;	
	int env;
    int rec;
};
struct sockaddr_in  A,B;
struct sockaddr trama;
struct addresses *dir;
struct iphdr *header;
frames *tram;
FILE *file;
//Variables GLOBALES
int sock,conTramas=0,conTramasAux=0;
int tam1=0,tam2=0,tam3=0,tam4=0,tam5=0;
int ICMPv4=0,IGMP=0,IP=0,TCP=0,UDP=0,IPv6=0,OSPF=0,XD=0;
unsigned char frame[2048];
//Funciones - Hilo
void *Capturador(void *arg);
void *Analizador(void *arg);
//Funcion Principal
int main(int argc, char *argv[]){
    //HILOS y SOCKETS
    pthread_t h1,h2;
    pthread_attr_t h;
    pthread_attr_init(&h);
    pthread_attr_setdetachstate(&h, PTHREAD_CREATE_JOINABLE);
    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0)
    {
        perror("\nFallo en el socket\n");
        exit(1);
    }
    struct ifreq eth;    
    bzero(&eth, sizeof(eth));
    strncpy((char *)eth.ifr_name, argv[1], IFNAMSIZ); 
    ioctl(sock, SIOCGIFFLAGS, &eth);
    eth.ifr_flags |= IFF_PROMISC; 
    ioctl(sock, SIOCSIFFLAGS, &eth);
    if(sock < 0)
    {
        perror("\nFallo modo promiscuo\n");
        exit(1);
    }
    //Reserva de TRAMAS
    conTramas = atoi(argv[2]);
    conTramasAux = conTramas;
    tram = malloc(conTramas*sizeof(frames));
    if(tram == NULL){
        printf("\nFallo de memoria\n");
        exit(1);
    }
    //ARCHIVO
    file = fopen("Sniffer.txt","w+");
    if(file == NULL){
        printf("\nFallo del fichero\n");
        exit(1);
    }
    fprintf(file, "\n==============================================\n");
    fprintf(file, "\nPractica 5: SNIFFER IPv4\nElizondo Herrera Miguel Angel\n");
    fprintf(file, "\n==============================================\n");

    printf( "\nAnalizando Tramas . . .\n");
    pthread_create(&h1, &h, Capturador, (void *)&sock);
    pthread_create(&h2, &h, Analizador, (void *)&sock);
    pthread_join(h1, NULL);
    pthread_join(h2, NULL);
    printf( "\nTramas analizadas.\n\n");

    fprintf(file, "\n==============================================\n");
    fprintf(file, "\nResultados Finales\n");
    fprintf(file, "\n==============================================\n");
    fprintf(file, "\n* Numero de paquetes capturados de cada uno de\n los protocolos de capa superior:\n");
    fprintf(file, "\nICMPv4: %d",ICMPv4);
    fprintf(file, "\nIGMP: %d",IGMP);
    fprintf(file, "\nIP: %d",IP);
    fprintf(file, "\nTCP: %d",TCP);
    fprintf(file, "\nUDP: %d",UDP);
    fprintf(file, "\nIPv6: %d",IPv6);

    unsigned char *dirAux = tram[0].buff;
    dir = malloc(conTramasAux*sizeof(struct addresses));
    int total = 0, check = 0;
    //Verificaicones
    for (int i=0;i<conTramasAux;i++)
    {
        dirAux = tram[i].buff;
        header = (struct iphdr*)(dirAux+sizeof(struct ethhdr));
        memset(&A, 0, sizeof(A));
        memset(&B, 0, sizeof(B));
        //A -> Fuente  // B-> Destino
        A.sin_addr.s_addr = header->saddr;
        B.sin_addr.s_addr = header->daddr;
        if(total > 0 )
        {
            for (int j=0;j<total;j++)
            {if(dir[j].dir.sin_addr.s_addr == A.sin_addr.s_addr)
            {
                dir[j].env++;   
                check = 1;                 
                break;
            }}
            if(check != 0)
            {check = 0;                
            }else{          
                dir[total].dir.sin_addr.s_addr = A.sin_addr.s_addr;                
                dir[total].env = 1;
                dir[total].rec = 0;
                total=total+1;
            }
            for (int i=0;i<total;i++)
            {if(dir[i].dir.sin_addr.s_addr == B.sin_addr.s_addr)
            {
                dir[i].rec++;   
                check = 1;                 
                break;
            }}          
            if(check != 0)
            {check = 0;                
            }else{          
                dir[total].dir.sin_addr.s_addr = B.sin_addr.s_addr;                
                dir[total].env = 0;
                dir[total].rec = 1;
                total=total+1;
            }}else{
            dir[0].dir.sin_addr.s_addr = A.sin_addr.s_addr;  
            dir[1].dir.sin_addr.s_addr = B.sin_addr.s_addr;
            dir[0].env = 1; 
            dir[1].env = 0;
            dir[0].rec = 0;
            dir[1].rec = 1; 
            total=total+2;
        }
    }
    int pak = 0;
    fprintf(file, "\n\n* Numero de paquetes por cada direccion IP diferente:\n");
    fprintf(file,"\nDirecciones capturadas: %d\n", total);
    while(pak < total)
    {
        fprintf(file, "\nDireccion IP: %s\n", inet_ntoa(dir[pak].dir.sin_addr));   
        fprintf(file, "Paquetes transmitidos: %d\n", dir[pak].env);
        fprintf(file, "Paquetes recibidos: %d\n", dir[pak].rec);
        pak++;
    }
    fprintf(file, "\n\n* Numero de paquetes segun su tamaño:\n");
    fprintf(file, "\n0 - 159: %d",tam1);
    fprintf(file, "\n160 - 639: %d",tam2);
    fprintf(file, "\n640 - 1279: %d",tam3);
    fprintf(file, "\n1280 - 5119: %d",tam4);
    fprintf(file, "\n5120 o mayor: %d",tam5);
    fclose(file);
    close(sock);
    return 0;
}
//CAPTURADOR DE TRAMAS
void *Capturador(void *arg){
    struct sockaddr_ll tramaAux;
    frames tram2;
    int check2;
    int sockAux = *(int *)arg;
    int tramaAux2 = sizeof(tramaAux);
    unsigned char buff2[2048];
    //Tramas recibidas
    while(conTramas--)
    {
        int n = recvfrom(sockAux, buff2, 2048, 0, (struct sockaddr*)&tramaAux, (socklen_t*)&tramaAux2);
        if(n < 0)
        {
            printf("\nFallo en la trama %d\n", conTramas);                
        }else{
            if(n > sizeof(struct ethhdr))
            {
                struct ethhdr *tram2;
                struct iphdr *ip;
                tram2 =  (struct ethhdr *)buff2;
                if(ntohs(tram2->h_proto) == ETH_P_IP)
                {
                    ip = (struct iphdr *)(buff2+sizeof(struct ethhdr));
                    if(ip->protocol == IPPROTO_TCP)
                    {check2 =  1;	
                    }			
                }
                if(check2 != 1){
                    conTramas=conTramas+1;
                }else{            
                    memcpy(tram[conTramas].buff, buff2, 2048);
                    tram[conTramas].ln = n;
                    tram[conTramas].vl = 1;
                }}}
  }pthread_exit(0);
}
//ANALIZADOR DE TRAMAS
void *Analizador(void *arg){
    int tamanio,fragmento,contador = 0,j=0;
    while(contador != conTramasAux)
    {
        struct ethhdr *tram2;
        struct iphdr *ip;
        if(tram[contador].vl == 1)
        {            
            fprintf(file, "\n\nTrama: %d\n\n", contador+1);
            int byte  = tram[contador].ln;
            unsigned char *k = tram[contador].buff;
            unsigned char *k2 = tram[contador].buff;
            byte = tram[contador].ln;                                    
            tram2 = (struct ethhdr *)k2;
            if(ntohs(tram2->h_proto) == ETH_P_IP)
            {
                if(byte >= (sizeof(struct ethhdr)+sizeof(struct iphdr)))
                {j=j+1;
                    ip = (struct iphdr*)(k2+sizeof(struct ethhdr));
                    int prot = ip->protocol;
                    fprintf(file, "Direccion IP fuente: %s\n", inet_ntoa(*(struct in_addr*)&ip->saddr));
                    fprintf(file, "Direccion IP destino: %s\n", inet_ntoa(*(struct in_addr*)&ip->daddr));
                    fprintf(file, "Longitud de cabecera en bytes: %d \n", (unsigned int)ip->ihl*4);
                    fprintf(file, "Longitud total del datagrama IP en bytes: %d \n", ntohs(ip->tot_len));
                    fprintf(file, "Identificador del datagrama: %d\n", ntohs(ip->id));
                    fprintf(file, "Tiempo de vida: %d\n", ip->ttl);
                    //Verificacion de PROTOCOLOS
                    if (prot==1)
                    {ICMPv4++;
                        fprintf(file, "Protocolo de capa superior: ICMPv4 \n", (unsigned int)ip->protocol);
                    }else{
                        if (prot==2)
                        {IGMP++;
                            fprintf(file, "Protocolo de capa superior: ICMPv4 (0x%.2X)\n", (unsigned int)ip->protocol);
                        }else{
                            if (prot==4)
                            {IP++;
                                fprintf(file, "Protocolo de capa superior: IP (0x%.2X)\n", (unsigned int)ip->protocol);
                            }else{
                                if (prot==6)
                                {TCP++;
                                    fprintf(file, "Protocolo de capa superior: TCP (0x%.2X)\n", (unsigned int)ip->protocol);
                                }else{
                                    if (prot==11)
                                    {UDP++;                  
                                        fprintf(file, "Protocolo de capa superior: UDP (0x%.2X)\n", (unsigned int)ip->protocol);
                                    }else{
                                        if (prot==29)
                                        {IPv6++;
                                            fprintf(file, "Protocolo de capa superior: IPv6 (0x%.2X)\n", (unsigned int)ip->protocol);
                                        }else{
                                            if (prot==59)
                                            {OSPF++;                       
                                                fprintf(file, "Protocolo de capa superior: OSPF (0x%.2X)\n", (unsigned int)ip->protocol);
                                            }else{
                                                XD++;                
                                                fprintf(file, "Protocolo de capa superior: Desconocido (0x%.2X)\n", (unsigned int)ip->protocol);
                                            }}}}}}}
                    tamanio = ntohs(ip->tot_len)-(unsigned int)ip->ihl*4;  
                    fprintf(file,"\n");                
                    fprintf(file, "Longitud de carga util: %d Bytes \n", tamanio);   
                    //Verificacion TAMAÑO
                    if(tamanio >= 0 && tamanio <= 159){
                        tam1++;
                        }
                    if(tamanio > 159 && tamanio <= 639){
                        tam2++;
                        }
                    if(tamanio > 639 && tamanio <= 1279){
                        tam3++;
                        }
                    if(tamanio > 1279 && tamanio <= 5119){
                        tam4++;
                        }
                    if(tamanio >= 5120){
                        tam5++;
                        }
                    int iptos = ip->tos;
                    int *service = malloc(sizeof(int)*(3));
                    for(int i = 0; i < 3; i++){
                        int x = 1<<i;
                        int y = iptos&x;
                        int bit = y>>i;
                        service[i] = bit;                        
                    }
                    //Verificacion de SERVICIO
                    if (*service==0)
                    {
                        fprintf(file,"Tipo de servicio utilizado; Rutina\n");
                    }else{
                        if (*service==1)
                        {
                            fprintf(file,"Tipo de servicio utilizado; Prioritario\n");
                        }else{
                            if (*service==2)
                            {
                                fprintf(file,"Tipo de servicio utilizado; Inmediato\n");
                            }else{
                                if (*service==3)
                                {
                                    fprintf(file,"Tipo de servicio utilizado; Relampago\n");
                                }else{
                                    if (*service==4)
                                    {
                                        fprintf(file,"Tipo de servicio utilizado; Invalidacion Relampago\n");
                                    }else{
                                        if (*service==5)
                                        {
                                            fprintf(file,"Tipo de servicio utilizado; Critico\n");
                                        }else{
                                            if (*service==6)
                                            {
                                                fprintf(file,"Tipo de servicio utilizado; Control de Inter-Red\n");
                                            }else{
                                                if (*service==7)
                                                {
                                                    fprintf(file,"Tipo de servicio utilizado; Control de Red\n");
                                                }}}}}}}}                    
                    //Fragmentacion
                    fragmento = ntohs(ip->frag_off)&&IP_DF;
                    if (fragmento == 1){
                        fprintf(file, "Datagrama fragmentado?: 0\n");
                    }else{
                        if (fragmento == 0){
                            fprintf(file, "Datagrama fragmentado?: 1\n");
                        }}
                    if (ntohs(ip->frag_off & 0x2000) > 0)
                    {
                        if (ntohs(ip->frag_off & 0x1FFF) == 0)
                        {                       
                            fprintf(file, "Numero de fragmento: primero\n");
                        }else{       
                            fprintf(file, "Numero de fragmento: intermedio\n");    
                        }}else{
                            if (ntohs(ip->frag_off & 0x1FFF) > 0)
                            {                         
                                fprintf(file, "Numero de fragmento: ultimo\n");  
                            }else{           
                                fprintf(file, "Numero de fragmento: unico\n");
                            }}                
                    fprintf(file, "Primer byte que contiene el datagrama: %.2X\n", (unsigned char)k2[ntohs(ip->tot_len)*4+1]);                
                    fprintf(file, "Ultimo byte que contiene el datagrama: %.2X\n", (unsigned char)k2[byte]);  
                }else{
                    printf("Fallo el analisis de la trama\n");
                    fprintf(file, "Fallo el analisis de la trama\n");
                }
            }else{ 
                fprintf(file,"Paquete descartado alno ser IPv4 (0x800)\n");
            }
        fprintf(file,"\n");
        for(int i=0;i<byte;i++)
        {
            fprintf(file, "%.2X ", *k);
            k++;
        }
        contador=contador+1;
        fprintf(file,"\n");
        }
    }
    pthread_exit(0);
}


