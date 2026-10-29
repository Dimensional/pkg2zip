ifeq ($(OS),Windows_NT)
#  RM := del /q
  EXE := .exe
else
  EXE :=
endif

DESTDIR =
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

BIN = pkg2zip${EXE}
SRC := ${wildcard pkg2zip*.c} miniz_tdef.c puff.c

# Host arch/OS detection. The x86 AES-NI/SSE units are built only on x86; on other arches
# (e.g. Apple Silicon arm64) pkg2zip_aes.c / pkg2zip_crc32.c use their portable C fallback, so
# those intrinsic units -- and their -maes/-mssse3/-mpclmul/-msse4 flags -- are left out.
# An empty ARCH (no uname, e.g. some Windows setups) keeps the x86 path, matching the default.
ARCH := $(shell uname -m 2>/dev/null)
UNAME_S := $(shell uname -s 2>/dev/null)
ifneq (,$(ARCH))
ifeq (,$(filter x86_64 amd64 i386 i486 i586 i686,$(ARCH)))
  SRC := $(filter-out pkg2zip_aes_x86.c pkg2zip_crc32_x86.c,$(SRC))
endif
endif

OBJ = ${SRC:.c=.o}
DEP = ${SRC:.c=.d}

CFLAGS = -std=c99 -pipe -fvisibility=hidden -Wall -Wextra -Werror -DNDEBUG -D_GNU_SOURCE -O2
# macOS ld rejects the obsolete -s strip flag; skip it there and strip separately if wanted.
ifneq ($(UNAME_S),Darwin)
${BIN}: LDFLAGS += -s
endif
debug: CFLAGS += -g
debug: LDFLAGS += -g

.PHONY: all clean

all: ${BIN}

install:
	install -D -m 0755 ${BIN} $(DESTDIR)$(BINDIR)/${BIN}
	install -D -m 0755 rif2zrif.py $(DESTDIR)$(BINDIR)/rif2zrif
	install -D -m 0755 zrif2rif.py $(DESTDIR)$(BINDIR)/zrif2rif

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/${BIN}
	rm -f $(DESTDIR)$(BINDIR)/rif2zrif
	rm -f $(DESTDIR)$(BINDIR)/zrif2rif

clean:
	@${RM} ${BIN} ${OBJ} ${DEP}

${BIN}: ${OBJ}
	@echo [L] $@
	@${CC} ${LDFLAGS} -o $@ $^

debug: ${OBJ}
	@echo [L] ${BIN}
	@${CC} ${LDFLAGS} -o ${BIN} $^

%aes_x86.o: %aes_x86.c
	@echo [C] $<
	@${CC} ${CFLAGS} -maes -mssse3 -MMD -c -o $@ $<

%crc32_x86.o: %crc32_x86.c
	@echo [C] $<
	@${CC} ${CFLAGS} -mpclmul -msse4 -MMD -c -o $@ $<

%.o: %.c
	@echo [C] $<
	@${CC} ${CFLAGS} -MMD -c -o $@ $<

-include ${DEP}
