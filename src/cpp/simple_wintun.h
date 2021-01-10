#pragma once

typedef void *ADAPTER;
typedef void *SESSION;
typedef void *EVENT;
typedef unsigned char CODE;

const CODE SUCCESS_CODE = 0;
const CODE OS_ERROR_CODE = 1;
const CODE NOT_ENOUGH_SIZE_CODE = 2;
const CODE PARSE_GUID_ERROR_CODE = 3;
const CODE IP_ADDRESS_ERROR_CODE = 4;
const CODE STRING_COPY_ERROR_CODE = 5;

extern "C" {
CODE initialize_wintun();

CODE create_adapter(
        const char *pool_name,
        const char *adapter_name,
        const char *guid_str,
        ADAPTER *adapter
);

CODE delete_adapter(ADAPTER adapter);

CODE delete_pool(const char *pool_name);

CODE get_adapter(const char *pool_name, const char *adapter_name, ADAPTER *adapter);

CODE get_adapter_name(ADAPTER adapter, char *adapter_name, unsigned char size);

CODE set_adapter_name(ADAPTER adapter, const char *adapter_name);

CODE set_ipaddr(ADAPTER adapter, const char *ipaddr, unsigned char subnet_mask);

CODE open_adapter(ADAPTER adapter, unsigned long capacity, SESSION *session);

void close_adapter(SESSION session);

EVENT get_read_wait_event(SESSION session);

CODE read_packet(SESSION session, EVENT read_wait, unsigned char *buff, unsigned long *size);

CODE write_packet(SESSION session, const unsigned char *buff, unsigned long size);

unsigned long get_drive_version();
}

