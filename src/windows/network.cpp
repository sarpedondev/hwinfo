#include "hwinfo/platform.h"

#ifdef HWINFO_WINDOWS

// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
// clang-format on

#include <hwinfo/network.h>
#include <hwinfo/utils/stringutils.h>

#include <cstdio>
#include <string>
#include <vector>

#ifndef __MINGW32__
#pragma comment(lib, "iphlpapi.lib")
#endif

namespace {

// Win32_NetworkAdapterConfiguration also lists software adapters (WAN Miniports, Wi-Fi Direct, VPN and Hyper-V
// switches) whose MAC address appears and disappears at runtime. Only adapters backed by hardware are reported.
bool isHardwareAdapter(const IP_ADAPTER_ADDRESSES& adapter) {
  if (adapter.IfType == IF_TYPE_SOFTWARE_LOOPBACK || adapter.IfType == IF_TYPE_TUNNEL ||
      adapter.PhysicalAddressLength == 0) {
    return false;
  }
  MIB_IF_ROW2 row = {};
  row.InterfaceLuid = adapter.Luid;
  if (GetIfEntry2(&row) != NO_ERROR) {
    return false;
  }
  return row.InterfaceAndOperStatusFlags.HardwareInterface && !row.InterfaceAndOperStatusFlags.FilterInterface;
}

std::string formatMac(const IP_ADAPTER_ADDRESSES& adapter) {
  std::string mac;
  char octet[4];
  for (ULONG i = 0; i < adapter.PhysicalAddressLength; ++i) {
    std::snprintf(octet, sizeof(octet), i == 0 ? "%02X" : ":%02X", adapter.PhysicalAddress[i]);
    mac += octet;
  }
  return mac;
}

std::string formatAddress(const SOCKET_ADDRESS& address) {
  char buffer[INET6_ADDRSTRLEN] = {};
  const sockaddr* sa = address.lpSockaddr;
  if (sa == nullptr) return {};
  if (sa->sa_family == AF_INET) {
    inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(sa)->sin_addr, buffer, sizeof(buffer));
  } else if (sa->sa_family == AF_INET6) {
    inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(sa)->sin6_addr, buffer, sizeof(buffer));
  }
  return buffer;
}

}  // namespace

namespace hwinfo {

// _____________________________________________________________________________________________________________________
std::vector<Network> getAllNetworks() {
  constexpr ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
  ULONG size = 16 * 1024;
  std::vector<unsigned char> buffer;
  ULONG result = ERROR_BUFFER_OVERFLOW;
  // The adapter list can grow between the size query and the actual call, so retry a few times.
  for (int attempt = 0; attempt < 4 && result == ERROR_BUFFER_OVERFLOW; ++attempt) {
    buffer.resize(size);
    result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()),
                                  &size);
  }
  if (result != NO_ERROR) {
    return {};
  }

  std::vector<Network> networks;
  for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); adapter != nullptr;
       adapter = adapter->Next) {
    if (!isHardwareAdapter(*adapter)) continue;

    Network network;
    network._index = std::to_string(adapter->IfIndex);
    if (adapter->Description != nullptr) {
      network._description = utils::wstring_to_std_string(adapter->Description);
    }
    network._mac = formatMac(*adapter);
    // Same selection as before: the IPv4 address and the link-local IPv6 address.
    for (auto* unicast = adapter->FirstUnicastAddress; unicast != nullptr; unicast = unicast->Next) {
      const std::string ip = formatAddress(unicast->Address);
      if (ip.empty()) continue;
      if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
        if (network._ip4.empty()) network._ip4 = ip;
      } else if (ip.rfind("fe80::", 0) == 0 && network._ip6.empty()) {
        network._ip6 = ip;
      }
    }
    networks.push_back(std::move(network));
  }
  return networks;
}

}  // namespace hwinfo

#endif  // HWINFO_WINDOWS
