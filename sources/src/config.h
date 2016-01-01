#ifndef CONFIG_H
#define	CONFIG_H

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>

#include "log.h"

#define PORTS_MAX 20
#define PORTS_MIN 2
#define CLIENTS_MAX 1000
#define IP_MAX 16
#define MIN_INTERVAL 3
#define MAX_INTERVAL 30
#define MIN_TIME_CONN 5

#define NO_CONF_FILE 2
#define INVALID_IP 1
#define NO_VALID_CLIENT 3

#define FALSE 0
#define TRUE 1


struct Config_knocker;
FILE * configfile;
char cnf_path[PATH_MAX] = "/etc/knockserver.conf"; // default configuration file
int num_clients = 0;
char local_ip_addr[IP_MAX] = "0.0.0.0";

/** Detail of client, which can use port knocking */
typedef struct Config_knocker {
    char name[PATH_MAX];
    char ip_addr[IP_MAX];
    int ports[PORTS_MAX];
    int num_ports;
    int time_interval;
    int time_out;
    char command[PATH_MAX];
} Config_knocker;

// Configurated connection specification
Config_knocker clients[CLIENTS_MAX];


int cmpIp(const Config_knocker addr1, const Config_knocker addr2);
int load_configuration();
void insertSortedByIP(Config_knocker info);
char* trim(char * str);
void set_alternative_name(char * name, int id);
int is_valid_ip(const char * ip);
int contains(char * name);
int load_line(char * line, int num_line, int id_create_name);

int contains(char * name) {
    int i; 
    for (i = 0; i < num_clients; i++) {
        if (strcmp(name, clients[i].name) == 0)
            return TRUE;
    }
    return FALSE;
}

int is_valid_ip(const char * ip) {
    int int_addr[4];
    int scan = sscanf(ip, "%d.%d.%d.%d", &int_addr[0], &int_addr[1], &int_addr[2], &int_addr[3]);
    if (scan != 4)
        return FALSE;
    int i;
    for (i = 0; i < 4; i++) {
        if (int_addr[i] < 0 || int_addr[i] > 255)
            return FALSE;
    }

    return TRUE;
}

int load_configuration() {
    int id_create_name = 0;
    configfile = fopen(cnf_path, "r");
    if (configfile == NULL) {
        write_log("Cannot open config file");
        return NO_CONF_FILE;
    }
    char line[PATH_MAX + 1];
    int num_line = 0;

    while (fgets(line, PATH_MAX, configfile)) {
        int ret = load_line(line, num_line, id_create_name);
        num_line++;
        if (ret == 2) {
            write_log("Invalid server IP address.");
            return INVALID_IP;
        }

    }
    fclose(configfile);
    if (num_clients == 0) {
        write_log("No configurated clients.");
        return NO_VALID_CLIENT;
    }
    return 0;
}

int load_line(char * line, int num_line, int id_create_name) {
    char * ptr = line;
    trim(line);
    int len = strlen(line);

    if (num_line == 0) {
        if (len >= 10 + 7) {
            strncpy(local_ip_addr, line + 10, sizeof (char) * (len - 10));
            local_ip_addr[len - 10] = '\0';
        }
        if (len < 17 || !is_valid_ip(local_ip_addr)) {
            return 2;
        }
        return 0;
    }

    if (len == 0 || line[0] == '#' || line[0] == '\n')
        return 0;

    char portArray[PATH_MAX];
    Config_knocker inf;
    inf.num_ports = 0;
    int indexStart = 0, indexEnd = 0;

    // Name of port knocking
    while (line[indexEnd] != ';' && indexEnd < len) indexEnd++;
    if (indexEnd == len || indexEnd == indexStart) return 1;

    strncpy(inf.name, ptr, indexEnd);
    inf.name[indexEnd] = '\0';
    indexStart = ++indexEnd;
    // If exists same name, skip loading configuration of client
    if (contains(inf.name)) {
        set_alternative_name(inf.name, id_create_name);
    }
    while (line[indexEnd] != ';' && indexEnd < len) indexEnd++;
    if (indexEnd == len || indexEnd + 1 == indexStart) return 1;

    // IP address - source
    strncpy(inf.ip_addr, ptr + indexStart, indexEnd - indexStart);
    inf.ip_addr[indexEnd - indexStart] = '\0';
    indexStart = ++indexEnd;
    if (!is_valid_ip(inf.ip_addr))
        return 1;

    // Sequence of ports
    while (line[indexEnd] != ';' && indexEnd < len) indexEnd++;
    if (indexEnd == len || indexEnd + 1 == indexStart) return 1;

    strncpy(portArray, ptr + indexStart, indexEnd - indexStart);
    portArray[indexEnd - indexStart] = '\0';
    indexStart = ++indexEnd;

    int numOfComma = 0;
    int inStart = 0, inEnd = 0;
    char * ptrPort = portArray;
    int indexNull = 0;
    while (portArray[indexNull] != '\0') indexNull++;
    int i;
    for (i = 0; i < indexNull; i++) {
        if (portArray[i] == ',')
            numOfComma++;
    }
    int z;
    if (numOfComma < PORTS_MIN - 1 || numOfComma > PORTS_MAX - 1)
        return 1;
    for (z = 0; z < numOfComma; z++) {
        while (portArray[inEnd] != ',') inEnd++;
        int scan = sscanf(ptrPort + inStart, "%d", &inf.ports[inf.num_ports++]);
        if (scan != 1)
            return 1;
        inStart = ++inEnd;
    }
    int scan = sscanf(ptrPort + inStart, "%d", &inf.ports[inf.num_ports++]);
    if (scan != 1)
        return 1;

    // Max time interval between 1st and last port
    while (line[indexEnd] != ';' && indexEnd < len) indexEnd++;
    if (indexEnd == len || indexEnd + 1 == indexStart) return 1;

    char nArray[PATH_MAX];
    strncpy(nArray, ptr + indexStart, indexEnd - indexStart);
    nArray[indexEnd - indexStart] = '\0';
    indexStart = ++indexEnd;
    if (sscanf(nArray, "%d", &inf.time_interval) != 1 || inf.time_interval < MIN_INTERVAL || inf.time_interval > MAX_INTERVAL)
        return 1;

    // Time after accessed port knocking
    while (line[indexEnd] != ';' && indexEnd < len) indexEnd++;
    if (indexEnd == len || indexEnd + 1 == indexStart) return 1;

    char numArray[PATH_MAX];
    strncpy(numArray, ptr + indexStart, indexEnd - indexStart);
    numArray[indexEnd - indexStart] = '\0';
    indexStart = ++indexEnd;
    if (sscanf(numArray, "%d", &inf.time_out) != 1 || inf.time_out < MIN_TIME_CONN)
        return 1;

    // Command in iptables format
    if (indexEnd >= len) return 1;
    strncpy(inf.command, ptr + indexEnd, len - indexEnd);
    inf.command[(len - indexEnd)] = '\0';

    insertSortedByIP(inf);
    return 0;
}

void insertSortedByIP(Config_knocker info) {
    int index = 0;
    int endWith = 1;
    while (index < num_clients) {
        endWith = cmpIp(info, clients[index]);
        if (endWith <= 0)
            break;
        index++;
    }
    if (endWith >= 1)
        clients[index] = info;
    else {

        memmove(clients + index + 1, clients + index, (num_clients - index) * sizeof (Config_knocker));
        clients[index] = info;
    }
    num_clients++;
}

char* trim(char * str) {
    char *pch = str;
    while (isspace(*pch)) {
        pch++;
    }
    if (pch != str) {
        memmove(str, pch, (strlen(pch) + 1));
    }
    pch = (char*) (str + (strlen(str) - 1));
    while (isspace(*pch)) {
        pch--;
    }
    *++pch = '\0';

    return str;
}

void set_alternative_name(char * name, int id) {
    int len = 1;
    int max_num = 1;
    int len_name = strlen(name);
    name[len_name] = '_';

    if (id == 0) {
        len = 2;
        max_num = 0;
    } else {
        int i;
        for (i = id; i > 0; i /= 10) {
            len++;
            max_num *= 10;
        }
    }
    max_num /= 10;

    int id_cp = id;
    int i;
    for (i = 1; i < len; i++) {
        if (max_num != 0) {
            name[len_name + i] = (id_cp / max_num) + 48;
            id_cp -= (id_cp / max_num) * max_num;
        } else
            name[len_name + i] = id_cp + 48;
        max_num /= 10;
    }
    name[len_name + len] = '\0';
    id++;
}

int cmpIp(const Config_knocker addr1, const Config_knocker addr2) {
    int int_addr1[4];
    int int_addr2[4];
    sscanf(addr1.ip_addr, "%d.%d.%d.%d", &int_addr1[0], &int_addr1[1], &int_addr1[2], &int_addr1[3]);
    sscanf(addr2.ip_addr, "%d.%d.%d.%d", &int_addr2[0], &int_addr2[1], &int_addr2[2], &int_addr2[3]);
    int i;
    for (i = 0; i < 4; i++) {
        if (int_addr1[i] < int_addr2[i])
            return -1;
        else if (int_addr1[i] > int_addr2[i])
            return 1;
    }
    return strcmp(addr1.name, addr2.name);
}

#endif	/* CONFIG_H */

