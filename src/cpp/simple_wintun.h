#pragma once

#include "wintun.h"

typedef void *EVENT;
typedef unsigned char CODE;
typedef unsigned char BYTE;

const CODE SUCCESS_CODE = 0;
const CODE OS_ERROR_CODE = 1;
const CODE NOT_ENOUGH_SIZE_CODE = 2;
const CODE PARSE_GUID_ERROR_CODE = 3;
const CODE IP_ADDRESS_ERROR_CODE = 4;

extern "C" {
CODE initialize_wintun();

CODE delete_driver();

CODE create_adapter(
        const char *pool_name,
        const char *adapter_name,
        const char *guid_str,
        WINTUN_ADAPTER_HANDLE *adapter
);

CODE open_adapter(const char *adapter_name, WINTUN_ADAPTER_HANDLE *adapter);

void close_adapter(WINTUN_ADAPTER_HANDLE adapter);

NET_LUID get_adapter_luid(WINTUN_ADAPTER_HANDLE adapter);

CODE get_drive_version(unsigned long *version);

CODE start_session(
        WINTUN_ADAPTER_HANDLE adapter,
        unsigned long capacity,
        WINTUN_SESSION_HANDLE *session
);

void end_session(WINTUN_SESSION_HANDLE session);

EVENT get_read_wait_event(WINTUN_SESSION_HANDLE session);

CODE read_packet(
        WINTUN_SESSION_HANDLE session,
        EVENT read_wait,
        BYTE *buff,
        unsigned long *size
);

CODE write_packet(
        WINTUN_SESSION_HANDLE session,
        BYTE *buff,
        unsigned long size
);

CODE set_ipaddr(
        WINTUN_ADAPTER_HANDLE adapter,
        const char *ipaddr,
        BYTE subnet_mask
);
}