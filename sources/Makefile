#
# Makefile
#
CC=gcc
LD=gcc
CFLAGS=-g -Wall -pthread
LFLAGS=-pthread
PROGRAM=knockserver
PROGRAM_DIR=/usr/sbin/
CONFFILE=others/$(PROGRAM).conf
LOGFILE=others/$(PROGRAM).log

IP_SERVER_CONF="IP_SERVER=192.168.1.100"
CLIENT_CONF="default;1.1.1.1;1000,2000,3000,4000;10;120;iptables -A INPUT -s 1.1.1.1 -j ACCEPT"

src/log.o: src/log.h
	$(CC) $< $(CFLAGS) -c -o $@

src/config.o: src/config.h src/log.h
	$(CC) $< $(CFLAGS) -c -o $@

src/knockserver.o: src/knockserver.c src/log.h src/config.h 
	$(CC) $< $(CFLAGS) -c -o $@

$(PROGRAM): src/knockserver.o
	$(LD) $(LFLAGS) -o ./$(PROGRAM) $^

compile: $(PROGRAM)

run:
	mkdir -p ./others
	touch $(CONFFILE)
	echo $(IP_SERVER_CONF) > $(CONFFILE)
	echo $(CLIENT_CONF) >> $(CONFFILE)
	sudo ./$(PROGRAM) -c $(CONFFILE) -l $(LOGFILE)

make: compile

clean:
	rm -f ./knockserver ./src/*.o
	rm -rf ./others
