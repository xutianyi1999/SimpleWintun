#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <string>
#include "simple_wintun.h"

#pragma comment(lib, "Ws2_32")
#pragma comment(lib, "iphlpapi")
#pragma comment(lib, "ole32")

static WINTUN_CREATE_ADAPTER_FUNC *WintunCreateAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC *WintunCloseAdapter;
static WINTUN_OPEN_ADAPTER_FUNC *WintunOpenAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC *WintunGetAdapterLUID;
static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *WintunGetRunningDriverVersion;
static WINTUN_DELETE_DRIVER_FUNC *WintunDeleteDriver;
static WINTUN_SET_LOGGER_FUNC *WintunSetLogger;
static WINTUN_START_SESSION_FUNC *WintunStartSession;
static WINTUN_END_SESSION_FUNC *WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC *WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC *WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC *WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC *WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC *WintunSendPacket;

std::wstring get_ws(const char *c) {
    std::string str = c;
    std::wstring wstr = std::wstring(str.begin(), str.end());
    return wstr;
}

static HMODULE
initialize() {
    HMODULE Wintun = LoadLibraryExW(L"wintun.dll", nullptr,
                                    LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!Wintun)
        return nullptr;
#define X(Name) ((*(FARPROC *)&Name = GetProcAddress(Wintun, #Name)) == NULL)
    if (X(WintunCreateAdapter) || X(WintunCloseAdapter) || X(WintunOpenAdapter) || X(WintunGetAdapterLUID) ||
        X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver) || X(WintunSetLogger) || X(WintunStartSession) ||
        X(WintunEndSession) || X(WintunGetReadWaitEvent) || X(WintunReceivePacket) || X(WintunReleaseReceivePacket) ||
        X(WintunAllocateSendPacket) || X(WintunSendPacket))
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

CODE delete_driver() {
    BOOL res = WintunDeleteDriver();

    if (res == 0) {
        return OS_ERROR_CODE;
    }
    return SUCCESS_CODE;
}

CODE create_adapter(
        const char *adapter_name,
        const char *tunnel_type,
        const char *guid_str,
        WINTUN_ADAPTER_HANDLE *adapter
) {
    auto wc_adapter_name = get_ws(adapter_name);
    auto wc_tunnel_type = get_ws(tunnel_type);
    auto wc_guid = get_ws(guid_str);
    const wchar_t *pguid = wc_guid.c_str();

    GUID guid;
    auto res = CLSIDFromString(pguid, (LPCLSID) &guid);

    if (res != S_OK) {
        return PARSE_GUID_ERROR_CODE;
    }

    WINTUN_ADAPTER_HANDLE inner_adapter = WintunCreateAdapter(
            wc_adapter_name.c_str(),
            wc_tunnel_type.c_str(),
            &guid
    );

    if (!inner_adapter) {
        return OS_ERROR_CODE;
    }

    *adapter = inner_adapter;
    return SUCCESS_CODE;
}

CODE open_adapter(const char *adapter_name, WINTUN_ADAPTER_HANDLE *adapter) {
    auto wc_adapter_name = get_ws(adapter_name);
    auto inner_adapter = WintunOpenAdapter(wc_adapter_name.c_str());

    if (inner_adapter) {
        *adapter = inner_adapter;
        return SUCCESS_CODE;
    } else {
        return OS_ERROR_CODE;
    }
}

void close_adapter(WINTUN_ADAPTER_HANDLE adapter) {
    WintunCloseAdapter(adapter);
}

NET_LUID get_adapter_luid(WINTUN_ADAPTER_HANDLE adapter) {
    NET_LUID luid = NET_LUID{};
    WintunGetAdapterLUID(adapter, &luid);
    return luid;
}

CODE get_drive_version(unsigned long *version) {
    *version = WintunGetRunningDriverVersion();

    if (*version == 0) {
        return OS_ERROR_CODE;
    }
    return SUCCESS_CODE;
}

CODE start_session(
        WINTUN_ADAPTER_HANDLE adapter,
        unsigned long capacity,
        WINTUN_SESSION_HANDLE *session
) {
    WINTUN_SESSION_HANDLE inner_session = WintunStartSession(adapter, capacity);

    if (!inner_session) {
        return OS_ERROR_CODE;
    }

    *session = inner_session;
    return SUCCESS_CODE;
}

void end_session(WINTUN_SESSION_HANDLE session) {
    WintunEndSession(session);
}

EVENT get_read_wait_event(WINTUN_SESSION_HANDLE session) {
    return WintunGetReadWaitEvent(session);
}

CODE read_packet(
        WINTUN_SESSION_HANDLE session,
        EVENT read_wait,
        BYTE *buff,
        unsigned long *size
) {
    unsigned long packet_size;
    BYTE *packet = WintunReceivePacket(session, &packet_size);

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

CODE write_packet(
        WINTUN_SESSION_HANDLE session,
        BYTE *buff,
        unsigned long size
) {
    BYTE *data = WintunAllocateSendPacket(session, size);

    if (data) {
        memcpy(data, buff, size);
        WintunSendPacket(session, data);
        return SUCCESS_CODE;
    } else {
        return OS_ERROR_CODE;
    }
}

CODE set_ipaddr(
        WINTUN_ADAPTER_HANDLE adapter,
        const char *ipaddr,
        BYTE subnet_mask
) {
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