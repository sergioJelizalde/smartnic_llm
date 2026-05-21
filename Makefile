# Makefile — builds smtp_extract against an installed DPDK (pkg-config libdpdk)
APP = smtp_extract
SRCS = smtp_extract.c

PKGCONF ?= pkg-config
ifeq ($(shell $(PKGCONF) --exists libdpdk && echo 0),)
$(error "DPDK not found via pkg-config. Install DPDK and/or set PKG_CONFIG_PATH \
to point at libdpdk.pc (e.g. /usr/local/lib/x86_64-linux-gnu/pkgconfig).")
endif

CFLAGS  += -O3 -g -Wall -Wextra $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS += $(shell $(PKGCONF) --libs libdpdk)

BUILD = build

all: $(BUILD)/$(APP)

$(BUILD)/$(APP): $(SRCS) | $(BUILD)
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS)

$(BUILD):
	@mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD) message_*.eml

.PHONY: all clean

