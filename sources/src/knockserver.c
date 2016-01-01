#include <stdio.h> //For standard things
#include <stdlib.h>    //malloc
#include <string.h>    //memset
#include <netinet/ip_icmp.h>   //Provides declarations for icmp header
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <netinet/if_ether.h>  //For ETH_P_ALL
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <linux/limits.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>

#include "log.h"
#include "config.h"

struct Knocker;

void print_clients();
void print_knocker();

void find_knockers_ip(int dport);
void knock_on_door(Config_knocker kn, int dport);
int run_command(char * cmd);
int contain_knocker_port(Config_knocker kn, int dport);


void add_knocker(Config_knocker kn);
void delete_knocker(int index);

int create_conn_client(Config_knocker kn);
void exit_conn_client(int index);
void set_exit_cmd(char * cmd);

void process_packet(unsigned char*, int);
void set_ip_header(unsigned char * BUffer, int Size);
void get_tcp_packet(unsigned char* Buffer, int Size);
void get_udp_packet(unsigned char* Buffer, int Size);

void * check_connected_clients(void * arg);
void stop(int signum);
void reload(int signum);


char message[PATH_MAX];

struct sockaddr_in source, dest;

/** Detail of knocker, which knocking on ports */
typedef struct Knocker {
    char name[PATH_MAX];
    char ip_addr[IP_MAX];
    int time_out;
    int stage;
    time_t time_end;
} Knocker;

/** Detail of client, which is now connected on server */
typedef struct Conn_client {
    char name[PATH_MAX];
    char ip_addr[IP_MAX];
    time_t time_end;
    int time;
    char exit_cmd[PATH_MAX];
} Conn_client;

typedef struct arg_struct {
    int running;
    int sighup;
} arg_struct;

// Actual knockers
Knocker knockers[CLIENTS_MAX];
// Actual connected clients
Conn_client conn_clients[CLIENTS_MAX];
int num_knockers = 0;

int num_conn_clients;
int conn_locked = TRUE;

void stop(int signum) {
    if (num_conn_clients > 0) {
        write_log("Stopping actual connected clients:.");
        int i;
        for (i = 0; i < num_conn_clients; i++) {
            exit_conn_client(i);
        }
    }
    sprintf(message, "Stopping listening on %s...", local_ip_addr);
    write_log(message);

    write_log("===================== S T O P ====================");
    close_log();
    exit(signum);
}

void reload(int signum) {
    write_log("--------------------------------------------------");
    sprintf(message, "Stopping listening on %s...", local_ip_addr);
    write_log(message);
    write_log("Reloading configuration...");
    num_clients = 0;
    if (load_configuration() == 2) {
        stop(2);
    }

    sprintf(message, "Starting listening on %s...", local_ip_addr);
    write_log(message);
}

int running = 1, sighup = 0;

int main(int argc, char **argv) {
    while (1) {
        static struct option long_options[] = {
            {"logfile", 1, 0, 'l'},
            {"configfile", 1, 0, 'c'},
            {"testconf", 0, 0, 't'},
            {0, 0, 0, 0}
        };
        int option_index = 0;
        int c = getopt_long(argc, argv, "l:c:t", long_options, &option_index);
        if (c == -1) {
            break;
        }
        switch (c) {
            case 'l':
                strncpy(log_path, optarg, strlen(optarg));
                log_path[strlen(optarg)] = '\0';
                break;

            case 'c':
                strncpy(cnf_path, optarg, strlen(optarg));
                cnf_path[strlen(optarg)] = '\0';
                break;

            case 't':
                return load_configuration();

            default: break;
        }
    }

    unsigned char *buffer = (unsigned char *) malloc(65536); //Its Big!

    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    //setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 );

    if (sock_raw < 0) {
        perror("This program must run with root privileges.\n");
        return 1;
    }

    int ret = open_log();
    if (ret == 2) {
        perror("knockserver - cannot open logfile");
    }
    write_log("==================== S T A R T====================");
    write_log("Loading configuration...");
    if (load_configuration() == 2) {
        stop(2);
    }

    signal(SIGINT, stop); // kill program
    signal(SIGHUP, reload); // reload configuration
    sprintf(message, "Starting listening on %s...", local_ip_addr);
    write_log(message);
    // Thread for checking exitinf of clients
    pthread_t chech_thread;
    pthread_create(&chech_thread, NULL, check_connected_clients, NULL);

    int saddr_size, data_size;
    struct sockaddr saddr;
    while (1) {
        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t*) & saddr_size);
        process_packet(buffer, data_size);
    }
    close(sock_raw);
    return 0;
}

void * check_connected_clients(void * arg) {
    while (1) {
        if (!conn_locked) {
            struct tm * tm = get_actual_time();
            int i;
            for (i = 0; i < num_conn_clients; i++) {
                int diff_interval = difftime(mktime(tm), conn_clients[i].time_end);
                if (diff_interval > 0) {
                    exit_conn_client(i);
                }
            }
        }
        sleep(1);
    }
}

/* ----------------- These next 4 function was used from -----------
 * http://www.binarytides.com/packet-sniffer-code-c-linux/ -------- */

void process_packet(unsigned char * buffer, int size) {
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*) (buffer + sizeof (struct ethhdr));
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 6: //TCP Protocol
            get_tcp_packet(buffer, size);
            break;

        case 17: //UDP Protocol
            get_udp_packet(buffer, size);
            break;

        default:
            break;
    }
}

void set_ip_header(unsigned char * buffer, int Size) {

    struct iphdr *iph = (struct iphdr *) (buffer + sizeof (struct ethhdr));

    memset(&source, 0, sizeof (source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof (dest));
    dest.sin_addr.s_addr = iph->daddr;
}

void get_tcp_packet(unsigned char* Buffer, int Size) {
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *) (Buffer + sizeof (struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct tcphdr *tcph = (struct tcphdr*) (Buffer + iphdrlen + sizeof (struct ethhdr));

    set_ip_header(Buffer, Size);

    int dport = ntohs(tcph->dest);

    if (strcmp(inet_ntoa(dest.sin_addr), local_ip_addr) != 0)
        return;
    find_knockers_ip(dport);
}

void get_udp_packet(unsigned char *Buffer, int Size) {

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *) (Buffer + sizeof (struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct udphdr *udph = (struct udphdr*) (Buffer + iphdrlen + sizeof (struct ethhdr));

    set_ip_header(Buffer, Size);

    int dport = ntohs(udph->dest);

    if (strcmp(inet_ntoa(dest.sin_addr), local_ip_addr) != 0)
        return;
    find_knockers_ip(dport);
}

/* ----------------- These last 4 function was used from -----------
 * http://www.binarytides.com/packet-sniffer-code-c-linux/ -------- */

void find_knockers_ip(int dport) {
    Config_knocker actual_clients[CLIENTS_MAX];
    int find_ip = 0;
    int i;
    for (i = 0; i < num_clients; i++) {
        if (strcmp(inet_ntoa(source.sin_addr), clients[i].ip_addr) == 0 && contain_knocker_port(clients[i], dport)) {
            actual_clients[find_ip++] = clients[i];
        }
    }
    if (find_ip == 0)
        return;
    for (i = 0; i < find_ip; i++) {
        knock_on_door(actual_clients[i], dport);
    }
}

void knock_on_door(Config_knocker actual_client, int dport) {
    int find_knocker = FALSE;
    int index;
    for (index = 0; index < num_knockers; index++) {
        if (strcmp(knockers[index].name, actual_client.name) == 0) {
            find_knocker = TRUE;
            break;
        }
    }
    struct tm * tm = get_actual_time();
    if (!find_knocker && actual_client.ports[0] == dport) {
        add_knocker(actual_client);

        sprintf(message, "%s NAME:%s - Stage1", actual_client.ip_addr, actual_client.name);
        write_log(message);

    } else if (find_knocker) {
        if (actual_client.ports[knockers[index].stage] == dport) {

            int diff_interval = difftime(mktime(tm), knockers[index].time_end);

            if (diff_interval > actual_client.time_interval) {
                delete_knocker(index);

                sprintf(message, "%s NAME:%s - TIME_OUT", actual_client.ip_addr, actual_client.name);
                write_log(message);
                knock_on_door(actual_client, dport);
                return;
            }

            knockers[index].stage++;

            sprintf(message, "%s NAME:%s - Stage%d", actual_client.ip_addr, actual_client.name, knockers[index].stage);
            write_log(message);

            if (knockers[index].stage == actual_client.num_ports) {
                int is_old = create_conn_client(actual_client);
                int run_ret = 1;
                if (is_old == 0)
                    run_ret = run_command(actual_client.command);
                if (run_ret == 0 || is_old == 1) {
                    sprintf(message, "%s NAME:%s - OK: Connection for %d sec", actual_client.ip_addr, actual_client.name, actual_client.time_out);
                } else {
                    sprintf(message, "%s NAME:%s - Fail: Invalid iptables command", actual_client.ip_addr, actual_client.name);
                }
                write_log(message);

                delete_knocker(index);
            }
        } else {
            delete_knocker(index);

            sprintf(message, "%s NAME:%s - TIME_OUT", actual_client.ip_addr, actual_client.name);
            write_log(message);

            knock_on_door(actual_client, dport);
        }
    } else {
        return;
    }
}

int contain_knocker_port(Config_knocker kn, int dport) {
    int i;
    for (i = 0; i < kn.num_ports; i++)
        if (kn.ports[i] == dport)
            return TRUE;
    return FALSE;
}

void add_knocker(Config_knocker kn) {
    Knocker knock;
    strcpy(knock.ip_addr, kn.ip_addr);
    knock.ip_addr[strlen(kn.ip_addr)] = '\0';
    strcpy(knock.name, kn.name);
    knock.name[strlen(kn.name)] = '\0';
    knock.stage = 1;
    knock.time_out = kn.time_out;
    struct tm * tm = get_actual_time();
    tm->tm_sec += kn.time_interval;
    knock.time_end = mktime(tm);
    knockers[num_knockers++] = knock;
}

void delete_knocker(int index) {
    memmove(knockers + index, knockers + index + 1, (num_knockers - (index + 1)) * sizeof (Knocker));
    num_knockers--;
}

int create_conn_client(Config_knocker kn) {
    conn_locked = TRUE;
    int i;
    int find = FALSE;
    for (i = 0; i < num_conn_clients; i++)
        if (strcmp(conn_clients[i].name, kn.name) == 0) {
            find = TRUE;
            break;
        }
    if (!find) {
        Conn_client conn_cl;
        strcpy(conn_cl.ip_addr, kn.ip_addr);
        conn_cl.ip_addr[strlen(kn.ip_addr)] = '\0';
        strcpy(conn_cl.name, kn.name);
        conn_cl.name[strlen(kn.name)] = '\0';
        conn_cl.time = kn.time_out;
        struct tm * tm = get_actual_time();
        tm->tm_sec += kn.time_out;
        conn_cl.time_end = mktime(tm);

        strcpy(conn_cl.exit_cmd, kn.command);
        int len = strlen(kn.command);
        conn_cl.exit_cmd[len] = '\0';
        int i;
        for (i = 1; i < len; i++) {
            if (conn_cl.exit_cmd[i - 1] == '-' && conn_cl.exit_cmd[i] == 'A') {
                conn_cl.exit_cmd[i] = 'D';
                break;
            }
        }

        conn_clients[num_conn_clients++] = conn_cl;
        conn_locked = FALSE;
        return 0;
    } else {
        struct tm * tm = get_actual_time();
        tm->tm_sec += kn.time_out;
        conn_clients[i].time_end = mktime(tm);
        conn_locked = FALSE;
        return 1;
    }
}

void set_exit_cmd(char * cmd) {
    int len = strlen(cmd);
    int i;
    for (i = 0; i + 1 < len; i++) {
        if (cmd[i] == '-' && cmd[i + 1] == 'A') {
            cmd[i + 1] = 'D';
            return;
        }
    }
}

void exit_conn_client(int index) {
    conn_locked = TRUE;
    run_command(conn_clients[index].exit_cmd);

    sprintf(message, "%s NAME:%s - Stopping connection", conn_clients[index].ip_addr, conn_clients[index].name);
    write_log(message);

    memmove(conn_clients + index, conn_clients + index + 1, (num_conn_clients - (index + 1)) * sizeof (Conn_client));
    num_conn_clients--;
    if (num_conn_clients > 0)
        conn_locked = FALSE;
}

int run_command(char* cmd) {
    int is_ok;
    is_ok = system(cmd);
    return is_ok;
}

void print_clients() {
    int i;
    for (i = 0; i < num_clients; i++) {
        printf("[%s]\n", clients[i].name);
        printf("|--IP: %s\n", clients[i].ip_addr);
        printf("|--Ports sequency(%d):", clients[i].num_ports);
        int x;
        for (x = 0; x + 1 < clients[i].num_ports; x++)
            printf("%d,", clients[i].ports[x]);
        printf("%d\n", clients[i].ports[clients[i].num_ports - 1]);
        printf("|--Interval: %d [s]\n", clients[i].time_interval);
        printf("|--Time: %d [s]\n", clients[i].time_out);
        printf("|--Command: \'%s\'\n", clients[i].command);
    }
}

void print_knocker() {
    int x;
    for (x = 0; x < num_knockers; x++) {
        printf("[%s]\n", knockers[x].name);
        printf("|--IP: %s\n", knockers[x].ip_addr);
        printf("Stage: %d\n", knockers[x].stage);
    }
}
