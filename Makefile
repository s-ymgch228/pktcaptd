PROG =	pktcaptd
CTRL =	pktcaptdctl

SRCS =	pktcaptd.c	\
	pidfile.c	\
	config.c	\
	interface.c	\
	analyze.c	\
	control.c	\
	log.c

CTRL_SRCS =	pktcaptdctl.c	\
		log.c


CPPFLAGS =	-D_GNU_SOURCE	\
		-DLOG_STDERR

LIBS =	-levent


OBJ =		$(SRCS:%.c=%.o)
CTRL_OBJ =	$(CTRL_SRCS:%.c=%.o)


all:$(PROG) $(CTRL)

$(PROG): $(OBJ)
	gcc -o $@ $(OBJ) $(LIBS)

$(CTRL): $(CTRL_OBJ)
	gcc -o $@ $(CTRL_OBJ) $(LIBS)

.c.o:
	gcc $(CPPFLAGS) -Wall -c $<

clean:
	@rm -rf $(PROG) $(OBJ) $(CTRL) $(CTRL_OBJ)
.PHONY: clean
