#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <string>
#include "simple_wintun.h"
#include "wintun.h"

#pragma comment(lib, "Ws2_32")
#pragma comment(lib, "iphlpapi")
#pragma comment(lib, "ole32")

static WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter;
static WINTUN_DELETE_ADAPTER_FUNC WintunDeleteAdapter;
static WINTUN_DELETE_POOL_DRIVER_FUNC WintunDeletePoolDriver;
static WINTUN_ENUM_ADAPTERS_FUNC WintunEnumAdapters;
static WINTUN_FREE_ADAPTER_FUNC WintunFreeAdapter;
static WINTUN_OPEN_ADAPTER_FUNC WintunOpenAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC WintunGetAdapterLUID;
static WINTUN_GET_ADAPTER_NAME_FUNC WintunGetAdapterName;
static WINTUN_SET_ADAPTER_NAME_FUNC WintunSetAdapterName;
static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC WintunGetRunningDriverVersion;
static WINTUN_SET_LOGGER_FUNC WintunSetLogger;
static WINTUN_START_SESSION_FUNC WintunStartSession;
static WINTUN_END_SESSION_FUNC WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC WintunSendPacket;

std::wstring get_ws(const char *c) {
    std::string str = c;
    std::wstring wstr = std::wstring(str.begin(), str.end());
    return wstr;
}

HMODULE initialize() {
    HMODULE Wintun = LoadLibraryExW(
            L"wintun.dll",
            NULL,
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32
    );

    if (!Wintun)
        return NULL;
#define X(Name, Type) ((Name = (Type)GetProcAddress(Wintun, #Name)) == NULL)
    if (X(WintunCreateAdapter, WINTUN_CREATE_ADAPTER_FUNC) || X(WintunDeleteAdapter, WINTUN_DELETE_ADAPTER_FUNC) ||
        X(WintunDeletePoolDriver, WINTUN_DELETE_POOL_DRIVER_FUNC) || X(WintunEnumAdapters, WINTUN_ENUM_ADAPTERS_FUNC) ||
        X(WintunFreeAdapter, WINTUN_FREE_ADAPTER_FUNC) || X(WintunOpenAdapter, WINTUN_OPEN_ADAPTER_FUNC) ||
        X(WintunGetAdapterLUID, WINTUN_GET_ADAPTER_LUID_FUNC) ||
        X(WintunGetAdapterName, WINTUN_GET_ADAPTER_NAME_FUNC) ||
        X(WintunSetAdapterName, WINTUN_SET_ADAPTER_NAME_FUNC) ||
        X(WintunGetRunningDriverVersion, WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC) ||
        X(WintunSetLogger, WINTUN_SET_LOGGER_FUNC) || X(WintunStartSession, WINTUN_START_SESSION_FUNC) ||
        X(WintunEndSession, WINTUN_END_SESSION_FUNC) || X(WintunGetReadWaitEvent, WINTUN_GET_READ_WAIT_EVENT_FUNC) ||
        X(WintunReceivePacket, WINTUN_RECEIVE_PACKET_FUNC) ||
        X(WintunReleaseReceivePacket, WINTUN_RELEASE_RECEIVE_PACKET_FUNC) ||
        X(WintunAllocateSendPacket, WINTUN_ALLOCATE_SEND_PACKET_FUNC) || X(WintunSendPacket, WINTUN_SEND_PACKET_FUNC))
#undef X
    {
        DWORD LastError = GetLastError();
        FreeLibrary(Wintun);
        SetLastError(LastError);
        return NULL;
    }
    return Wintun;
}

CODE initialize_wintun() {
    HMODULE wintun = initialize();

    if (wintun) {
        return SUCCESS_CODE;
    } else {
        return OS_ERROR_CODE;
    }
}

CODE create_adapter(
        const char *pool_name,
        const char *adapter_name,
        const char *guid_str,
        ADAPTER *adapter) {
    auto wc_pool_name = get_ws(pool_name);
    auto wc_adapter_name = get_ws(adapter_name);
    auto wc_guid = get_ws(guid_str);
    const wchar_t *pguid = wc_guid.c_str();

    GUID guid;
    auto res = CLSIDFromString(pguid, (LPCLSID) & guid);

    if (res != S_OK) {
        return PARSE_GUID_ERROR_CODE;
    }

    WINTUN_ADAPTER_HANDLE inner_adapter = WintunCreateAdapter(wc_pool_name.c_str(), wc_adapter_name.c_str(), &guid,
                                                              nullptr);

    if (!inner_adapter) {
        return OS_ERROR_CODE;
    }

    *adapter = inner_adapter;
    return SUCCESS_CODE;
}

CODE delete_adapter(ADAPTER adapter) {
    BOOL res = WintunDeleteAdapter(adapter, FALSE, nullptr);

    if (res == 0) {
        return OS_ERROR_CODE;
    }

    WintunFreeAdapter(adapter);
    return SUCCESS_CODE;
}

CODE delete_pool(const char *pool_name) {
    auto wc_pool_name = get_ws(pool_name);
    auto res = WintunDeletePoolDriver(wc_pool_name.c_str(), nullptr);

    if (res == 0) {
        return OS_ERROR_CODE;
    } else {
        return SUCCESS_CODE;
    }
}

CODE get_adapter(const char *pool_name, const char *adapter_name, ADAPTER *adapter) {
    auto wc_pool_name = get_ws(pool_name);
    auto wc_adapter_name = get_ws(adapter_name);

    auto inner_adapter = WintunOpenAdapter(wc_pool_name.c_str(), wc_adapter_name.c_str());

    if (inner_adapter) {
        *adapter = inner_adapter;
        return SUCCESS_CODE;
    } else {
        return OS_ERROR_CODE;
    }
}

CODE set_ipaddr(ADAPTER adapter, const char *ipaddr, unsigned char subnet_mask) {
    MIB_UNICASTIPADDRESS_ROW AddressRow;
    InitializeUnicastIpAddressEntry(&AddressRow);
    WintunGetAdapterLUID(adapter, &AddressRow.InterfaceLuid);
    AddressRow.Address.Ipv4.sin_family = AF_INET;
    AddressRow.OnLinkPrefixLength = subnet_mask;
    auto res = inet_pton(AF_INET, ipaddr, &(AddressRow.Address.Ipv4.sin_addr));

    if (res != 1) {
        return IP_ADDRESS_ERROR_CODE;
    }

    auto res2 = CreateUnicastIpAddressEntry(&AddressRow);

    if (res2 != ERROR_SUCCESS && res2 != ERROR_OBJECT_ALREADY_EXISTS) {
        return IP_ADDRESS_ERROR_CODE;
    }
    return SUCCESS_CODE;
}

CODE open_adapter(ADAPTER adapter, unsigned long capacity, SESSION *session) {
    SESSION inner_session = WintunStartSession(adapter, capacity);

    if (!inner_session) {
        return OS_ERROR_CODE;
    }

    *session = inner_session;
    return SUCCESS_CODE;
}

void close_adapter(SESSION session) {
    WintunEndSession(session);
}

EVENT get_read_wait_event(SESSION session) {
    return WintunGetReadWaitEvent(session);
}

CODE read_packet(SESSION session, EVENT read_wait, unsigned char *buff, unsigned long *size) {
    unsigned long packet_size;
    unsigned char *packet = WintunReceivePacket(session, &packet_size);

    if (packet) {
        if (*size >= packet_size) {
            memcpy(buff, packet, packet_size);
            *size = packet_size;
            WintunReleaseReceivePacket(session, packet);

            return SUCCESS_CODE;
        } else {
            WintunReleaseReceivePacket(session, packet);
            *size = packet_size;
            return NOT_ENOUGH_SIZE_CODE;
        }
    } else {
        DWORD last_error = GetLastError();

        if (last_error == ERROR_NO_MORE_ITEMS) {
            if (WaitForSingleObject(read_wait, INFINITE) == WAIT_OBJECT_0) {
                return read_packet(session, read_wait, buff, size);
            } else {
                return OS_ERROR_CODE;
            }
        } else {
            return OS_ERROR_CODE;
        }
    }
}

CODE write_packet(SESSION session, const unsigned char *buff, unsigned long size) {
    unsigned char *data = WintunAllocateSendPacket(session, size);

    if (data) {
        memcpy(data, buff, size);
        WintunSendPacket(session, data);
        return SUCCESS_CODE;
    } else {
        return OS_ERROR_CODE;
    }
}

CODE get_adapter_name(ADAPTER adapter, char *adapter_name, unsigned char size) {
    wchar_t name[128];
    auto res = WintunGetAdapterName(adapter, name);

    if (res == 0) {
        return OS_ERROR_CODE;
    }

    std::wstring t = name;
    std::string tn = std::string(t.begin(), t.end());

    auto res2 = strcpy_s(adapter_name, size, tn.c_str());

    if (res2 != 0) {
        return STRING_COPY_ERROR_CODE;
    }
    return SUCCESS_CODE;
}

CODE set_adapter_name(ADAPTER adapter, const char *adapter_name) {
    std::wstring an = get_ws(adapter_name);
    auto res = WintunSetAdapterName(adapter, an.c_str());

    if (res == 0) {
        return OS_ERROR_CODE;
    }
    return SUCCESS_CODE;
}

unsigned long get_drive_version() {
    return WintunGetRunningDriverVersion();
}
