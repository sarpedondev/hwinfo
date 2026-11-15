// Copyright Leon Freist
// Author Leon Freist <freist@informatik.uni-freiburg.de>

#include "hwinfo/platform.h"

#ifdef HWINFO_WINDOWS

#include <hwinfo/disk.h>
#include <hwinfo/utils/stringutils.h>
#include <windows.h>
// clang-format off
#include <cfgmgr32.h>
#include <setupapi.h>
// clang-format on
#include <winioctl.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace {

hwinfo::Disk::Interface mapBusType(STORAGE_BUS_TYPE busType) {
  switch (busType) {
    case BusTypeNvme:
      return hwinfo::Disk::Interface::NVME;
    case BusTypeUsb:
      return hwinfo::Disk::Interface::USB;
    case BusTypeSata:
      return hwinfo::Disk::Interface::SATA;
    case BusTypeScsi:  // fall through
    case BusTypeSas:
      return hwinfo::Disk::Interface::SCSI;
    default:
      return hwinfo::Disk::Interface::UNKNOWN;
  }
}

std::map<uint32_t, std::vector<std::string>> getDiskToVolumeMap() {
  std::map<uint32_t, std::vector<std::string>> mapping;
  char logicalDrives[MAX_PATH] = {};
  GetLogicalDriveStringsA(sizeof(logicalDrives), logicalDrives);

  char* currentDrive = logicalDrives;
  while (*currentDrive) {
    std::string rootPath = currentDrive;  // e.g., "C:\"
    UINT driveType = GetDriveTypeA(rootPath.c_str());

    if (driveType == DRIVE_FIXED || driveType == DRIVE_REMOVABLE) {
      std::string volumePath = "\\\\.\\" + rootPath.substr(0, 2);
      HANDLE hVolume =
          CreateFileA(volumePath.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);

      if (hVolume != INVALID_HANDLE_VALUE) {
        STORAGE_DEVICE_NUMBER sdn;
        DWORD bytesReturned;
        if (DeviceIoControl(hVolume, IOCTL_STORAGE_GET_DEVICE_NUMBER, nullptr, 0, &sdn, sizeof(sdn), &bytesReturned,
                            nullptr)) {
          mapping[sdn.DeviceNumber].push_back(rootPath);
        }
        CloseHandle(hVolume);
      }
    }
    currentDrive += strlen(currentDrive) + 1;
  }
  return mapping;
}

// Returns true only if PhysicalDrive<diskNumber> sits directly on a controller driven by the Microsoft inbox NVMe
// driver (stornvme). Vendor and RAID stacks (Intel RST/VMD iaStorVD, AMD rcraid, Samsung secnvme, ...) implement the
// protocol specific pass-through themselves, and some of them corrupt the kernel pool when asked for Identify
// Controller (seen as KERNEL_MODE_HEAP_CORRUPTION 0x13A with iaStorVD). Any lookup failure counts as "not inbox".
bool isInboxNvmeController(DWORD diskNumber) {
  // GUID_DEVINTERFACE_DISK, declared locally to avoid depending on INITGUID / libuuid.
  static const GUID kDiskInterface = {0x53f56307, 0xb6bf, 0x11d0, {0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b}};

  HDEVINFO devInfo = SetupDiGetClassDevsW(&kDiskInterface, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
  if (devInfo == INVALID_HANDLE_VALUE) {
    return false;
  }

  bool inbox = false;
  SP_DEVICE_INTERFACE_DATA interfaceData = {};
  interfaceData.cbSize = sizeof(interfaceData);
  for (DWORD index = 0; SetupDiEnumDeviceInterfaces(devInfo, nullptr, &kDiskInterface, index, &interfaceData); ++index) {
    DWORD required = 0;
    SetupDiGetDeviceInterfaceDetailW(devInfo, &interfaceData, nullptr, 0, &required, nullptr);
    if (required < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)) {
      continue;
    }
    std::vector<BYTE> detailBuffer(required);
    auto* detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(detailBuffer.data());
    detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
    SP_DEVINFO_DATA devData = {};
    devData.cbSize = sizeof(devData);
    if (!SetupDiGetDeviceInterfaceDetailW(devInfo, &interfaceData, detail, required, nullptr, &devData)) {
      continue;
    }

    HANDLE hDisk =
        CreateFileW(detail->DevicePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDisk == INVALID_HANDLE_VALUE) {
      continue;
    }
    STORAGE_DEVICE_NUMBER sdn = {};
    DWORD bytesReturned = 0;
    const BOOL gotNumber =
        DeviceIoControl(hDisk, IOCTL_STORAGE_GET_DEVICE_NUMBER, nullptr, 0, &sdn, sizeof(sdn), &bytesReturned, nullptr);
    CloseHandle(hDisk);
    if (!gotNumber || sdn.DeviceType != FILE_DEVICE_DISK || sdn.DeviceNumber != diskNumber) {
      continue;
    }

    DEVINST parent = 0;
    if (CM_Get_Parent(&parent, devData.DevInst, 0) == CR_SUCCESS) {
      wchar_t service[64] = {};
      ULONG size = sizeof(service);
      if (CM_Get_DevNode_Registry_PropertyW(parent, CM_DRP_SERVICE, nullptr, service, &size, 0) == CR_SUCCESS) {
        service[(sizeof(service) / sizeof(service[0])) - 1] = L'\0';
        inbox = _wcsicmp(service, L"stornvme") == 0;
      }
    }
    break;
  }

  SetupDiDestroyDeviceInfoList(devInfo);
  return inbox;
}

// Reads the serial number from the NVMe Identify Controller data (bytes 4-23).
//
// STORAGE_DEVICE_DESCRIPTOR::SerialNumber is not the controller serial for NVMe: the inbox driver derives it from the
// namespace EUI-64 / NGUID ("0025_3854_01B1_2F3A.") whenever the namespace has one, while vendor drivers report the
// real serial. Identify Controller yields the same value on every driver, matching /sys/block/<dev>/device/serial.
//
// The protocol specific query types are declared locally, as older MinGW headers do not provide them.
std::string getNvmeControllerSerial(HANDLE hDevice) {
  struct ProtocolSpecificData {
    DWORD ProtocolType;
    DWORD DataType;
    DWORD ProtocolDataRequestValue;
    DWORD ProtocolDataRequestSubValue;
    DWORD ProtocolDataOffset;
    DWORD ProtocolDataLength;
    DWORD FixedProtocolReturnData;
    DWORD ProtocolDataRequestSubValue2;
    DWORD ProtocolDataRequestSubValue3;
    DWORD ProtocolDataRequestSubValue4;
  };
  struct ProtocolQuery {
    DWORD PropertyId;
    DWORD QueryType;
    ProtocolSpecificData ProtocolSpecific;
    BYTE IdentifyData[4096];
  };
  constexpr DWORD kStorageAdapterProtocolSpecificProperty = 49;
  constexpr DWORD kStorageDeviceProtocolSpecificProperty = 50;
  constexpr DWORD kPropertyStandardQuery = 0;
  constexpr DWORD kProtocolTypeNvme = 3;
  constexpr DWORD kNVMeDataTypeIdentify = 1;
  constexpr DWORD kIdentifyCnsController = 1;
  constexpr std::size_t kSerialOffset = 4;
  constexpr std::size_t kSerialLength = 20;

  // Identify Controller is addressed to the adapter; some drivers only answer the device scoped property.
  ProtocolQuery query;
  bool succeeded = false;
  for (const DWORD propertyId : {kStorageAdapterProtocolSpecificProperty, kStorageDeviceProtocolSpecificProperty}) {
    query = {};
    query.PropertyId = propertyId;
    query.QueryType = kPropertyStandardQuery;
    query.ProtocolSpecific.ProtocolType = kProtocolTypeNvme;
    query.ProtocolSpecific.DataType = kNVMeDataTypeIdentify;
    query.ProtocolSpecific.ProtocolDataRequestValue = kIdentifyCnsController;
    query.ProtocolSpecific.ProtocolDataOffset = sizeof(ProtocolSpecificData);
    query.ProtocolSpecific.ProtocolDataLength = sizeof(query.IdentifyData);

    DWORD bytesReturned = 0;
    if (DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), &query, sizeof(query),
                        &bytesReturned, nullptr)) {
      succeeded = true;
      break;
    }
  }
  if (!succeeded) {
    return {};
  }

  // On return the buffer holds a STORAGE_PROTOCOL_DATA_DESCRIPTOR, whose Version / Size header has the same size as
  // the PropertyId / QueryType header of the request. ProtocolDataOffset is relative to the protocol specific data.
  const std::size_t dataOffset = offsetof(ProtocolQuery, ProtocolSpecific) + query.ProtocolSpecific.ProtocolDataOffset;
  if (query.ProtocolSpecific.ProtocolDataLength < kSerialOffset + kSerialLength ||
      dataOffset + kSerialOffset + kSerialLength > sizeof(query)) {
    return {};
  }

  const char* data = reinterpret_cast<const char*>(&query) + dataOffset + kSerialOffset;
  std::string serial(data, kSerialLength);
  serial.erase(std::find(serial.begin(), serial.end(), '\0'), serial.end());
  for (const char c : serial) {
    if (c < 0x20 || c > 0x7e) return {};
  }
  hwinfo::utils::strip(serial);
  return serial;
}

}  // namespace

namespace hwinfo {

// _____________________________________________________________________________________________________________________
std::vector<Disk> getAllDisks() {
  std::vector<Disk> disks;

  auto diskToVolumes = getDiskToVolumeMap();

  for (uint32_t i = 0; i < 16; ++i) {
    std::string devicePath = "\\\\.\\PhysicalDrive" + std::to_string(i);

    HANDLE hDevice =
        CreateFileA(devicePath.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hDevice == INVALID_HANDLE_VALUE) continue;

    Disk disk;
    disk._id = i;

    STORAGE_PROPERTY_QUERY query = {StorageDeviceProperty, PropertyStandardQuery, 0};
    char buffer[1024];
    DWORD bytesReturned;
    if (DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), &buffer, sizeof(buffer),
                        &bytesReturned, nullptr)) {
      auto* desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buffer);

      disk._interface = mapBusType(desc->BusType);
      if (desc->ProductIdOffset) {
        disk._model = buffer + desc->ProductIdOffset;
      }
      if (desc->VendorIdOffset) {
        disk._vendor = buffer + desc->VendorIdOffset;
      } else {
        static const std::vector<std::string> known_vendors = {"KIOXIA",  "SAMSUNG", "WESTERN DIGITAL", "WD",
                                                               "SEAGATE", "INTEL",   "CRUCIAL",         "KINGSTON"};
        std::string upper_model(disk._model);
        std::transform(disk._model.begin(), disk._model.end(), upper_model.begin(),
                       [](const char c) { return static_cast<char>(std::toupper(static_cast<int>(c))); });
        for (const auto& vendor : known_vendors) {
          if (upper_model.find(vendor) != std::string::npos) {
            disk._vendor = vendor;
            break;
          }
        }
      }
      // _serial_number defaults to "<unknown>", so the NVMe result is kept in a local to decide on the fallback.
      // Identify Controller is only sent through the inbox driver; vendor drivers already report the real serial in the
      // descriptor, and some of them crash the kernel on the pass-through (see isInboxNvmeController).
      const std::string nvmeSerial = desc->BusType == BusTypeNvme && isInboxNvmeController(i)
                                         ? getNvmeControllerSerial(hDevice)
                                         : std::string();
      if (!nvmeSerial.empty()) {
        disk._serial_number = nvmeSerial;
      } else if (desc->SerialNumberOffset) {
        disk._serial_number = buffer + desc->SerialNumberOffset;
      }
    }

    DISK_GEOMETRY_EX geometry;
    if (DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, nullptr, 0, &geometry, sizeof(geometry),
                        &bytesReturned, nullptr)) {
      disk._size_bytes = geometry.DiskSize.QuadPart;
    }

    if (diskToVolumes.count(i)) {
      disk._mount_points = diskToVolumes[i];
    }

    CloseHandle(hDevice);
    disks.push_back(std::move(disk));
  }
  return disks;
}

}  // namespace hwinfo

#endif  // HWINFO_WINDOWS
