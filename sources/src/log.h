
#ifndef LOG_H
#define	LOG_H

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#define TIME_CONST 20

static FILE * logfile;
char log_path[PATH_MAX] = "/var/log/knockserver.log"; // default log file
static char time_char[TIME_CONST];
int is_open = 0;

int open_log();
int close_log();
int write_log(const char * message);
struct tm * get_actual_time();

int open_log() {
    logfile = fopen(log_path, "a");
    if (logfile == NULL) {
        is_open = 0;
        return 2;
    }
    is_open = 1;
    return 1;
}

int close_log() {
    if (is_open) {
        fclose(logfile);
    }
    return 0;
}

int write_log(const char * message) {
    if (is_open) {
        struct tm * tm = get_actual_time();
        sprintf(time_char, "[%04d-%02d-%02d %02d:%02d]", tm->tm_year + 1900,
                tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min);
        fprintf(logfile, "%s %s\n", time_char, message);
        return fflush(logfile);
    }
    return 0;
}

struct tm * get_actual_time() {
    time_t t;
    struct tm * tm;
    t = time(NULL);
    tm = localtime(&t);
    return tm;
}


#endif	/* LOG_H */

