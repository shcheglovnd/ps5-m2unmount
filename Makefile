# m2unmount - PS5 payload that keeps the M.2 unmounted on the console.
#
# Requires the ps5-payload-dev SDK (https://github.com/ps5-payload-dev/sdk)
# and a system clang that knows the x86_64-sie-ps5 target (clang 19 works).
#
#   make                       build m2unmount.elf
#   make send PS5_HOST=<ip>    load it through the ELF loader on :9021

PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
PS5_HOST        ?= ps5
CC      := $(PS5_PAYLOAD_SDK)/bin/prospero-clang
CFLAGS  := -O2 -Wall -Wextra -Werror
TARGET  := m2unmount.elf

$(TARGET): src/m2unmount.c
	$(CC) $(CFLAGS) -o $@ $<

send: $(TARGET)
	$(PS5_PAYLOAD_SDK)/bin/prospero-deploy -h $(PS5_HOST) -p 9021 $<

clean:
	rm -f $(TARGET)

.PHONY: send clean
