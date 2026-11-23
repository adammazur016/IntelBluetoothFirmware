//
//  IntelBTPatcher.cpp
//  IntelBTPatcher
//
//  Created by zxystd <zxystd@foxmail.com> on 2021/2/8.
//
#define __ACIDANTHERA_MAC_SDK 2600
#include <Headers/kern_api.hpp>
#include <Headers/kern_util.hpp>
#include <Headers/plugin_start.hpp>

#include <pexpert/pexpert.h>
#include <sys/sysctl.h>
#include <kern/clock.h>
#include <libkern/OSAtomic.h>
#include "IntelBTPatcher.hpp"

static CIntelBTPatcher ibtPatcher;
static CIntelBTPatcher *callbackIBTPatcher = nullptr;

static const char *bootargOff[] {
    "-ibtcompatoff"
};

static const char *bootargDebug[] {
    "-ibtcompatdbg"
};

static const char *bootargBeta[] {
    "-ibtcompatbeta"
};

PluginConfiguration ADDPR(config) {
    xStringify(PRODUCT_NAME),
    parseModuleVersion(xStringify(MODULE_VERSION)),
    LiluAPI::AllowNormal | LiluAPI::AllowInstallerRecovery | LiluAPI::AllowSafeMode,
    bootargOff,
    arrsize(bootargOff),
    bootargDebug,
    arrsize(bootargDebug),
    bootargBeta,
    arrsize(bootargBeta),
    KernelVersion::MountainLion,
    KernelVersion::Tahoe,
    []() {
        ibtPatcher.init();
    }
};

static const char *IntelBTPatcher_IOBluetoothFamily[] { "/System/Library/Extensions/IOBluetoothFamily.kext/Contents/MacOS/IOBluetoothFamily" };

static KernelPatcher::KextInfo IntelBTPatcher_IOBluetoothInfo {
    "com.apple.iokit.IOBluetoothFamily",
    IntelBTPatcher_IOBluetoothFamily,
    1,
    {true, true},
    {},
    KernelPatcher::KextInfo::Unloaded
};

static const char *IntelBTPatcher_IOUSBHostFamily[] {
    "/System/Library/Extensions/IOUSBHostFamily.kext/Contents/MacOS/IOUSBHostFamily" };

static KernelPatcher::KextInfo IntelBTPatcher_IOUsbHostInfo {
    "com.apple.iokit.IOUSBHostFamily",
    IntelBTPatcher_IOUSBHostFamily,
    1,
    {true, true},
    {},
    KernelPatcher::KextInfo::Unloaded
};

void *CIntelBTPatcher::_hookPipeInstance = nullptr;
bool CIntelBTPatcher::_randomAddressInit = false;

// PEM-PRIV: optional masking of LE feature bits reported by LE Read Local Supported Features (0x2003).
// macOS (THIRD_PARTY_DONGLE path) never loads IRKs into the controller resolving list, but when the
// controller advertises LL Privacy it still connects through the filter accept list using the peer's
// identity address -> connections to RPA-only peers (iPhone, Watch) always time out.
// Boot-arg ibtpriv=<mask> clears these bits in LE features byte 0 (64 = LL Privacy, 128 = Ext Scanner Filter Policies).
static uint8_t pemPrivacyMask = 0;
static volatile int leFeatRewrite = 0;

// ---------------------------------------------------------------------------------------------
// PEM-RPA: connect to RPA-only peers (iPhone / Watch) without controller address resolution.
// bluetoothd (THIRD_PARTY_DONGLE path) adds the peer *identity* address to the filter accept list
// and issues LE Create Connection with initiator filter policy 1, expecting the controller to
// resolve the peer RPA. The Intel controller never gets the IRKs, so it never matches.
// bluetoothd logs the current peer RPA ("connectingAddress=Random:XX:..") - a small root helper
// (log stream) writes it to sysctl debug.ibtp_rpa. When the next LE Create Connection targets the
// identity in the accept list, we rewrite it into a direct connection to that RPA, and rewrite the
// resulting LE Connection Complete back to the identity address bluetoothd expects.
// Disable with boot-arg -ibtrpaoff.
// ---------------------------------------------------------------------------------------------
static bool     pemRpaEnabled = true;
static uint8_t  pemAclAddr[6];          // HCI byte order (LSB first)
static uint8_t  pemAclType = 0;
static volatile int pemAclCount = 0;
static uint8_t  pemRpa[6];              // HCI byte order
static volatile uint64_t pemRpaTime = 0;   // seconds (uptime), 0 = none
static uint8_t  pemRpaBound[6];
static volatile bool pemRpaIsBound = false;
static uint8_t  pemPendRpa[6];
static uint8_t  pemPendId[6];
static uint8_t  pemPendIdType = 0;
static volatile bool pemPending = false;
static volatile uint32_t pemCntHint = 0, pemCntRewrite = 0, pemCntFixed = 0, pemCntConnFail = 0;
static char     pemLast[96] = "none";
static char     pemRpaStr[24] = "";

static uint64_t pemNowSec()
{
    clock_sec_t secs = 0; clock_usec_t usecs = 0;
    clock_get_system_microtime(&secs, &usecs);
    return (uint64_t)secs;
}

static int pemHex(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// "4B:30:BF:BB:4D:EF" (MSB first) -> HCI order (LSB first)
static bool pemParseMac(const char *s, uint8_t out[6])
{
    for (int i = 0; i < 6; i++) {
        int h = pemHex(s[i * 3]), l = pemHex(s[i * 3 + 1]);
        if (h < 0 || l < 0) return false;
        if (i < 5 && s[i * 3 + 2] != ':') return false;
        out[5 - i] = (uint8_t)((h << 4) | l);
    }
    return true;
}

static void pemFmtMac(char *dst, size_t len, const uint8_t a[6])
{
    snprintf(dst, len, "%02X:%02X:%02X:%02X:%02X:%02X", a[5], a[4], a[3], a[2], a[1], a[0]);
}

static int pemSysctlRpa SYSCTL_HANDLER_ARGS
{
    char buf[24];
    strlcpy(buf, pemRpaStr, sizeof(buf));
    int err = sysctl_handle_string(oidp, buf, sizeof(buf), req);
    if (err || !req->newptr)
        return err;
    uint8_t a[6];
    if (!pemParseMac(buf, a))
        return EINVAL;
    memcpy(pemRpa, a, 6);
    if (pemAclCount == 1) {
        memcpy(pemRpaBound, pemAclAddr, 6);
        pemRpaIsBound = true;
    } else {
        pemRpaIsBound = false;
    }
    strlcpy(pemRpaStr, buf, sizeof(pemRpaStr));
    OSMemoryBarrier();
    pemRpaTime = pemNowSec();
    pemCntHint++;
    return 0;
}

static int pemSysctlStat SYSCTL_HANDLER_ARGS
{
    char buf[256], id[20] = "-";
    if (pemRpaIsBound) pemFmtMac(id, sizeof(id), pemRpaBound);
    uint64_t age = pemRpaTime ? pemNowSec() - pemRpaTime : 0;
    snprintf(buf, sizeof(buf), "enabled=%d hints=%u rewrites=%u fixed=%u connfail=%u acl=%d rpa=%s bound=%s age=%llus last=%s",
             pemRpaEnabled, pemCntHint, pemCntRewrite, pemCntFixed, pemCntConnFail, pemAclCount,
             pemRpaStr[0] ? pemRpaStr : "-", id, age, pemLast);
    return sysctl_handle_string(oidp, buf, strlen(buf) + 1, req);
}

SYSCTL_PROC(_debug, OID_AUTO, ibtp_rpa, CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_LOCKED, nullptr, 0, pemSysctlRpa, "A", "PEM: current peer RPA hint");
SYSCTL_PROC(_debug, OID_AUTO, ibtp_stat, CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_LOCKED, nullptr, 0, pemSysctlStat, "A", "PEM: RPA rewrite status");

#define HCI_OP_LE_CREATE_CONN            0x200D
#define HCI_OP_LE_CLEAR_ACCEPT_LIST      0x2010
#define HCI_OP_LE_ADD_ACCEPT_LIST        0x2011
#define HCI_OP_LE_DEL_ACCEPT_LIST        0x2012

// Inspect / rewrite an outgoing HCI command. Returns true if the buffer was modified.
static bool pemHandleCommand(uint8_t *buf, uint32_t len)
{
    if (!pemRpaEnabled || len < 3)
        return false;
    uint16_t op = (uint16_t)(buf[0] | (buf[1] << 8));
    uint8_t *p = buf + 3;
    switch (op) {
        case HCI_OP_LE_CLEAR_ACCEPT_LIST:
            pemAclCount = 0;
            break;
        case HCI_OP_LE_ADD_ACCEPT_LIST:
            if (len >= 3 + 7) {
                pemAclType = p[0];
                memcpy(pemAclAddr, p + 1, 6);
                pemAclCount++;
                // hint arrived before the accept list entry: bind it now if fresh
                if (!pemRpaIsBound && pemRpaTime && pemNowSec() - pemRpaTime <= 3) {
                    memcpy(pemRpaBound, pemAclAddr, 6);
                    pemRpaIsBound = true;
                }
            }
            break;
        case HCI_OP_LE_DEL_ACCEPT_LIST:
            if (pemAclCount > 0) pemAclCount--;
            break;
        case HCI_OP_LE_CREATE_CONN:
            // params: scanInt(2) scanWin(2) filterPolicy(1) peerType(1) peerAddr(6) ownType(1) ...
            if (len >= 3 + 25 && p[4] == 0x01 && pemAclCount == 1 && pemRpaIsBound &&
                memcmp(pemRpaBound, pemAclAddr, 6) == 0 && pemRpaTime &&
                pemNowSec() - pemRpaTime <= 15) {
                memcpy(pemPendRpa, pemRpa, 6);
                memcpy(pemPendId, pemAclAddr, 6);
                pemPendIdType = pemAclType;
                p[4] = 0x00;                 // no filter accept list
                p[5] = 0x01;                 // peer address type: random
                memcpy(p + 6, pemRpa, 6);    // peer address: current RPA
                pemPending = true;
                pemCntRewrite++;
                char a[20], b[20];
                pemFmtMac(a, sizeof(a), pemPendId); pemFmtMac(b, sizeof(b), pemPendRpa);
                snprintf(pemLast, sizeof(pemLast), "conn %s via %s", a, b);
                return true;
            }
            break;
        default:
            break;
    }
    return false;
}

bool CIntelBTPatcher::init()
{
    DBGLOG(DRV_NAME, "%s", __PRETTY_FUNCTION__);
    callbackIBTPatcher = this;
    {
        uint32_t m = 0;
        if (PE_parse_boot_argn("ibtpriv", &m, sizeof(m)))
            pemPrivacyMask = (uint8_t)(m & 0xFF);
        SYSLOG(DRV_NAME, "PEM-PRIV: LE feature mask=0x%02x (boot-arg ibtpriv)", pemPrivacyMask);
        if (checkKernelArgument("-ibtrpaoff"))
            pemRpaEnabled = false;
        sysctl_register_oid(&sysctl__debug_ibtp_rpa);
        sysctl_register_oid(&sysctl__debug_ibtp_stat);
    }
    if (getKernelVersion() < KernelVersion::Monterey) {
        lilu.onKextLoadForce(&IntelBTPatcher_IOBluetoothInfo, 1,
        [](void *user, KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size) {
            callbackIBTPatcher->processKext(patcher, index, address, size);
        }, this);
    } else {
        lilu.onKextLoadForce(&IntelBTPatcher_IOUsbHostInfo, 1,
        [](void *user, KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size) {
            callbackIBTPatcher->processKext(patcher, index, address, size);
        }, this);
    }
    return true;
}

void CIntelBTPatcher::free()
{
    DBGLOG(DRV_NAME, "%s", __PRETTY_FUNCTION__);
}

void CIntelBTPatcher::processKext(KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size)
{
    DBGLOG(DRV_NAME, "%s", __PRETTY_FUNCTION__);
    if (getKernelVersion() < KernelVersion::Monterey) {
        if (IntelBTPatcher_IOBluetoothInfo.loadIndex == index) {
            DBGLOG(DRV_NAME, "%s", IntelBTPatcher_IOBluetoothInfo.id);
            
            KernelPatcher::RouteRequest findQueueRequestRequest {
                "__ZN25IOBluetoothHostController17FindQueuedRequestEtP22BluetoothDeviceAddresstbPP21IOBluetoothHCIRequest",
                newFindQueueRequest,
                oldFindQueueRequest
            };
            patcher.routeMultiple(index, &findQueueRequestRequest, 1, address, size);
            if (patcher.getError() == KernelPatcher::Error::NoError) {
                DBGLOG(DRV_NAME, "routed %s", findQueueRequestRequest.symbol);
            } else {
                SYSLOG(DRV_NAME, "failed to resolve %s, error = %d", findQueueRequestRequest.symbol, patcher.getError());
                patcher.clearError();
            }
            
        }
    } else {
        if (IntelBTPatcher_IOUsbHostInfo.loadIndex == index) {
            SYSLOG(DRV_NAME, "%s", IntelBTPatcher_IOUsbHostInfo.id);
            
            KernelPatcher::RouteRequest hostDeviceRequest {
            "__ZN15IOUSBHostDevice13deviceRequestEP9IOServiceRN11StandardUSB13DeviceRequestEPvP18IOMemoryDescriptorRjP19IOUSBHostCompletionj",
                newHostDeviceRequest,
                oldHostDeviceRequest
            };
            patcher.routeMultiple(index, &hostDeviceRequest, 1, address, size);
            if (patcher.getError() == KernelPatcher::Error::NoError) {
                SYSLOG(DRV_NAME, "routed %s", hostDeviceRequest.symbol);
            } else {
                SYSLOG(DRV_NAME, "failed to resolve %s, error = %d", hostDeviceRequest.symbol, patcher.getError());
                patcher.clearError();
            }

            KernelPatcher::RouteRequest asyncIORequest {
            "__ZN13IOUSBHostPipe2ioEP18IOMemoryDescriptorjP19IOUSBHostCompletionj",
                newAsyncIO,
                oldAsyncIO
            };
            patcher.routeMultiple(index, &asyncIORequest, 1, address, size);
            if (patcher.getError() == KernelPatcher::Error::NoError) {
                SYSLOG(DRV_NAME, "routed %s", asyncIORequest.symbol);
            } else {
                SYSLOG(DRV_NAME, "failed to resolve %s, error = %d", asyncIORequest.symbol, patcher.getError());
                patcher.clearError();
            }

            // macOS 26.5+: third parameter became ConfigurationDescriptor (was SuperSpeedEndpointCompanionDescriptor)
            KernelPatcher::RouteRequest initPipeConfigRequest {
            "__ZN13IOUSBHostPipe28initWithDescriptorsAndOwnersEPKN11StandardUSB18EndpointDescriptorEPKNS0_23ConfigurationDescriptorEP22AppleUSBHostControllerP15IOUSBHostDeviceP18IOUSBHostInterfaceht",
                newInitPipeConfig,
                oldInitPipeConfig
            };
            patcher.routeMultiple(index, &initPipeConfigRequest, 1, address, size);
            if (patcher.getError() == KernelPatcher::Error::NoError) {
                SYSLOG(DRV_NAME, "routed %s", initPipeConfigRequest.symbol);
            } else {
                SYSLOG(DRV_NAME, "failed to resolve %s, error = %d", initPipeConfigRequest.symbol, patcher.getError());
                patcher.clearError();
            }

            KernelPatcher::RouteRequest initPipeRequest {
            "__ZN13IOUSBHostPipe28initWithDescriptorsAndOwnersEPKN11StandardUSB18EndpointDescriptorEPKNS0_37SuperSpeedEndpointCompanionDescriptorEP22AppleUSBHostControllerP15IOUSBHostDeviceP18IOUSBHostInterfaceht",
                newInitPipe,
                oldInitPipe
            };
            patcher.routeMultiple(index, &initPipeRequest, 1, address, size);
            if (patcher.getError() == KernelPatcher::Error::NoError) {
                SYSLOG(DRV_NAME, "routed %s", initPipeRequest.symbol);
            } else {
                SYSLOG(DRV_NAME, "failed to resolve %s, error = %d", initPipeRequest.symbol, patcher.getError());
                patcher.clearError();
            }
        }
    }
}

#pragma mark - For Bigsur-, patch unhandled 0x2019 opcode

#define HCI_OP_LE_START_ENCRYPTION 0x2019

IOReturn CIntelBTPatcher::newFindQueueRequest(void *that, unsigned short arg1, void *addr, unsigned short arg2, bool arg3, void **hciRequestPtr)
{
    IOReturn ret = FunctionCast(newFindQueueRequest, callbackIBTPatcher->oldFindQueueRequest)(that, arg1, addr, arg2, arg3, hciRequestPtr);
    if (ret != 0 && arg1 == HCI_OP_LE_START_ENCRYPTION) {
        ret = FunctionCast(newFindQueueRequest, callbackIBTPatcher->oldFindQueueRequest)(that, arg1, addr, 0xffff, arg3, hciRequestPtr);
        DBGLOG(DRV_NAME, "%s ret: %d arg1: 0x%04x arg2: 0x%04x arg3: %d ptr: %p", __FUNCTION__, ret, arg1, arg2, arg3, *hciRequestPtr);
    }
    return ret;
}

#pragma mark - For Monterey+ patch for intercept HCI REQ and RESP

StandardUSB::DeviceRequest randomAddressRequest;
// Hardcoded Random Address HCI Command
const uint8_t randomAddressHci[9] = {0x05, 0x20, 0x06, 0x94, 0x50, 0x64, 0xD0, 0x78, 0x6B}; 
IOBufferMemoryDescriptor *writeHCIDescriptor = nullptr;

#define MAX_HCI_BUF_LEN                 255
#define HCI_OP_RESET                    0x0c03
#define HCI_OP_LE_SET_SCAN_PARAM        0x200B
#define HCI_OP_LE_SET_SCAN_ENABLE       0x200C
#define HCI_OP_LE_READ_REMOTE_FEATURES  0x2016
#define HCI_OP_LE_READ_LOCAL_FEATURES   0x2003

int remoteReadSCount = 0;
IOReturn CIntelBTPatcher::newHostDeviceRequest(void *that, IOService *provider, StandardUSB::DeviceRequest &request, void *data, IOMemoryDescriptor *descriptor, unsigned int &length, IOUSBHostCompletion *completion, unsigned int timeout)
{
    HciCommandHdr *hdr = nullptr;
    uint32_t hdrLen = 0;
    char hciBuf[MAX_HCI_BUF_LEN] = {0};
    
    if (data == nullptr) {
        if (descriptor != nullptr &&
            (getKernelVersion() < KernelVersion::Sequoia || !descriptor->prepare(kIODirectionOut))) {
            if (descriptor->getLength() > 0) {
                descriptor->readBytes(0, hciBuf, min(descriptor->getLength(), MAX_HCI_BUF_LEN));
                hdrLen = (uint32_t)min(descriptor->getLength(), MAX_HCI_BUF_LEN);
            }
            if (getKernelVersion() >= KernelVersion::Sequoia)
                descriptor->complete(kIODirectionOut);
            if (hdrLen && pemHandleCommand((uint8_t *)hciBuf, hdrLen)) {
                bool prepared = getKernelVersion() < KernelVersion::Sequoia || descriptor->prepare(kIODirectionInOut) == kIOReturnSuccess;
                if (prepared) {
                    descriptor->writeBytes(0, hciBuf, hdrLen);
                    if (getKernelVersion() >= KernelVersion::Sequoia)
                        descriptor->complete(kIODirectionInOut);
                }
            }
        }
        hdr = (HciCommandHdr *)hciBuf;
        if (hdr->opcode == HCI_OP_LE_SET_SCAN_PARAM && hdr->data[5] == 0x1) {
            if (!_randomAddressInit) {
                randomAddressRequest.bmRequestType = makeDeviceRequestbmRequestType(kRequestDirectionOut, kRequestTypeClass, kRequestRecipientInterface);
                randomAddressRequest.bRequest = 0xE0;
                randomAddressRequest.wIndex = 0;
                randomAddressRequest.wValue = 0;
                randomAddressRequest.wLength = 9;
                length = 9;
                if (writeHCIDescriptor == nullptr)
                    writeHCIDescriptor = IOBufferMemoryDescriptor::withBytes(randomAddressHci, 9, kIODirectionInOut);
                writeHCIDescriptor->prepare(kIODirectionInOut);
                IOReturn ret = FunctionCast(newHostDeviceRequest, callbackIBTPatcher->oldHostDeviceRequest)(that, provider, randomAddressRequest, nullptr, writeHCIDescriptor, length, nullptr, timeout);
                writeHCIDescriptor->complete(kIODirectionInOut);
                const char *randAddressDump = _hexDumpHCIData((uint8_t *)randomAddressHci, 9);
                if (randAddressDump) {
                    SYSLOG(DRV_NAME, "[PATCH] Sending Random Address HCI %d %s", ret, randAddressDump);
                    IOFree((void *)randAddressDump, 9 * 3 + 1);
                }
                _randomAddressInit = true;
                SYSLOG(DRV_NAME, "[PATCH] Resend LE SCAN PARAM HCI %d", ret);
            }
        } else if (hdr->opcode == HCI_OP_LE_READ_REMOTE_FEATURES) {
            // #514: send TWO extra reads -> two duplicate 0x04 events to rewrite
            // (1st dup -> fake PHY Update Complete, 2nd dup -> fake LE Data Length Change).
            remoteReadSCount += 2;
            FunctionCast(newHostDeviceRequest, callbackIBTPatcher->oldHostDeviceRequest)(that, provider, request, nullptr, descriptor, length, nullptr, timeout);
            FunctionCast(newHostDeviceRequest, callbackIBTPatcher->oldHostDeviceRequest)(that, provider, request, nullptr, descriptor, length, nullptr, timeout);
        }
    } else {
        hdr = (HciCommandHdr *)data;
        hdrLen = request.wLength - 3;
        if (request.wLength >= 3)
            pemHandleCommand((uint8_t *)data, request.wLength);
    }
    if (hdr) {
        // HCI reset, we need to send Random address again
        if (hdr->opcode == HCI_OP_RESET)
            _randomAddressInit = false;
        if (pemPrivacyMask && hdr->opcode == HCI_OP_LE_READ_LOCAL_FEATURES) {
            leFeatRewrite++;
            SYSLOG(DRV_NAME, "PEM-PRIV: LE Read Local Supported Features sent, will mask 0x%02x", pemPrivacyMask);
        }
#if DEBUG
        DBGLOG(DRV_NAME, "[%s] bRequest: 0x%x direction: %s type: %s recipient: %s wValue: 0x%02x wIndex: 0x%02x opcode: 0x%04x len: %d length: %d async: %d", provider->getName(), request.bRequest, requestDirectionNames[(request.bmRequestType & kDeviceRequestDirectionMask) >> kDeviceRequestDirectionPhase], requestRecipientNames[(request.bmRequestType & kDeviceRequestRecipientMask) >> kDeviceRequestRecipientPhase], requestTypeNames[(request.bmRequestType & kDeviceRequestTypeMask) >> kDeviceRequestTypePhase], request.wValue, request.wIndex, hdr->opcode, hdr->len, request.wLength, completion != nullptr);
        if (hdrLen) {
            const char *dump = _hexDumpHCIData((uint8_t *)hdr, hdrLen);
            if (dump) {
                DBGLOG(DRV_NAME, "[Request]: %s", dump);
                IOFree((void *)dump, hdrLen * 3 + 1);
            }
        }
#endif
    }
    return FunctionCast(newHostDeviceRequest, callbackIBTPatcher->oldHostDeviceRequest)(that, provider, request, data, descriptor, length, completion, timeout);
}

#define HCI_EVT_LE_META                               0x3E
#define HCI_EVT_LE_META_READ_REMOTE_FEATURES_COMPLETE 0x04

uint8_t fakePhyUpdateCompleteEvent[8] = {0x3E, 0x06, 0x0C, 0x00, 0x00, 0x00, 0x02, 0x02};
// #514: LE Data Length Change (LE Meta subevent 0x07, no status byte -> handle at [3][4]).
// bluetoothd stalls at LE_READY_WAIT_FOR_LENGTH after PHY until it sees this. 27 octets / 328us tx+rx.
// Made by Claude.
uint8_t fakeDataLengthChangeEvent[13] = {0x3E, 0x0B, 0x07, 0x00, 0x00, 0x1B, 0x00, 0x48, 0x01, 0x1B, 0x00, 0x48, 0x01};
//uint8_t remoteFeaturesStatus[6] = {0x0F, 0x04, 0x00, 0x01, 0x16, 0x20};

static void asyncIOCompletion(void* owner, void* parameter, IOReturn status, uint32_t bytesTransferred)
{
    AsyncOwnerData *asyncOwner = (AsyncOwnerData *)owner;
    IOMemoryDescriptor* dataBuffer = asyncOwner->dataBuffer;
    // #514 3-stage rewrite of the repeated LE Read Remote Features Complete (0x04) events:
    //   stage 0 = the real one (pass through), 1 = rewrite to fake PHY Update Complete,
    //   2 = rewrite to fake LE Data Length Change (clears bluetoothd's LE_READY_WAIT_FOR_LENGTH).
    static int leMetaStage = 0;
    uint32_t allocLen = bytesTransferred;

    if (dataBuffer && bytesTransferred) {
        void *buffer = IOMalloc(allocLen);
        if (buffer) {
            if (dataBuffer->getLength() > 0 && (getKernelVersion() < KernelVersion::Sequoia || !dataBuffer->prepare(kIODirectionInOut))) {
                dataBuffer->readBytes(0, buffer, allocLen);
                HciEventHdr *hdr = (HciEventHdr *)buffer;
                if (remoteReadSCount > 0 && hdr->evt == HCI_EVT_LE_META && hdr->data[0] == HCI_EVT_LE_META_READ_REMOTE_FEATURES_COMPLETE) {
                    if (leMetaStage == 0) {
                        leMetaStage = 1;            // real features complete -> pass through
                    } else if (leMetaStage == 1) {  // 1st duplicate -> fake PHY Update Complete
                        fakePhyUpdateCompleteEvent[4] = hdr->data[2];
                        fakePhyUpdateCompleteEvent[5] = hdr->data[3];
                        dataBuffer->writeBytes(0, fakePhyUpdateCompleteEvent, 8);
                        bytesTransferred = 8;
                        leMetaStage = 2;
                        remoteReadSCount--;
                    } else {                        // 2nd duplicate -> fake LE Data Length Change
                        fakeDataLengthChangeEvent[3] = hdr->data[2];
                        fakeDataLengthChangeEvent[4] = hdr->data[3];
                        dataBuffer->writeBytes(0, fakeDataLengthChangeEvent, 13);
                        bytesTransferred = 13;
                        leMetaStage = 0;
                        remoteReadSCount--;
                    }
                }
                // PEM-RPA: LE Connection Complete [0]=0x3E [1]=len [2]=0x01 [3]=status [4..5]=handle
                // [6]=role [7]=peerType [8..13]=peerAddr
                else if (pemPending && hdr->evt == HCI_EVT_LE_META && allocLen >= 14 && hdr->data[0] == 0x01) {
                    pemPending = false;
                    if (hdr->data[1] == 0x00 && hdr->data[5] == 0x01 && memcmp(&hdr->data[6], pemPendRpa, 6) == 0) {
                        uint8_t fix[7];
                        fix[0] = pemPendIdType;
                        memcpy(fix + 1, pemPendId, 6);
                        dataBuffer->writeBytes(7, fix, 7);
                        pemCntFixed++;
                        strlcat(pemLast, " -> OK", sizeof(pemLast));
                    } else {
                        pemCntConnFail++;
                        char st[16]; snprintf(st, sizeof(st), " -> st=0x%02x", hdr->data[1]);
                        strlcat(pemLast, st, sizeof(pemLast));
                    }
                }
                // PEM-PRIV: Command Complete for LE Read Local Supported Features:
                // [0]=0x0E [1]=len [2]=ncmd [3..4]=opcode 0x2003 [5]=status [6..13]=features
                else if (pemPrivacyMask && hdr->evt == 0x0E && allocLen >= 14 &&
                         hdr->data[1] == 0x03 && hdr->data[2] == 0x20) {
                    if (leFeatRewrite > 0) leFeatRewrite--;
                    if (hdr->data[3] == 0x00) {
                        uint8_t oldF = hdr->data[4];
                        uint8_t newF = oldF & (uint8_t)~pemPrivacyMask;
                        dataBuffer->writeBytes(6, &newF, 1);
                        SYSLOG(DRV_NAME, "PEM-PRIV: LE features byte0 0x%02x -> 0x%02x", oldF, newF);
                    }
                }
                if (getKernelVersion() >= KernelVersion::Sequoia) dataBuffer->complete(kIODirectionInOut);
            }
            IOFree(buffer, allocLen);
        }
    }
    if (asyncOwner->action)
        asyncOwner->action(asyncOwner->owner, parameter, status, bytesTransferred);
    delete asyncOwner;
}

IOReturn CIntelBTPatcher::
newAsyncIO(void *that, IOMemoryDescriptor* dataBuffer, uint32_t bytesTransferred, IOUSBHostCompletion* completion, uint32_t completionTimeoutMs)
{
    if ((remoteReadSCount > 0 || pemPrivacyMask || pemPending) && that == _hookPipeInstance && completion) {
        AsyncOwnerData *ownerData = new AsyncOwnerData;
        ownerData->action = completion->action;
        ownerData->owner = completion->owner;
        ownerData->dataBuffer = dataBuffer;
        completion->action = asyncIOCompletion;
        completion->owner = ownerData;
    }
    return FunctionCast(newAsyncIO, callbackIBTPatcher->oldAsyncIO)(that, dataBuffer, bytesTransferred, completion, completionTimeoutMs);
}

#define VENDOR_USB_INTEL 0x8087

void CIntelBTPatcher::captureIntelInterruptPipe(void *that, StandardUSB::EndpointDescriptor const *descriptor, IOUSBHostDevice *device)
{
    if (!device)
        return;
    const StandardUSB::DeviceDescriptor *deviceDescriptor = device->getDeviceDescriptor();
    if (deviceDescriptor && deviceDescriptor->idVendor == VENDOR_USB_INTEL) {
        uint8_t epType = StandardUSB::getEndpointType(descriptor);
        if (epType == kIOUSBEndpointTypeInterrupt)
            CIntelBTPatcher::_hookPipeInstance = that;
    }
}

int CIntelBTPatcher::
newInitPipe(void *that, StandardUSB::EndpointDescriptor const *descriptor, StandardUSB::SuperSpeedEndpointCompanionDescriptor const *superDescriptor, AppleUSBHostController *controller, IOUSBHostDevice *device, IOUSBHostInterface *interface, unsigned char a7, unsigned short a8)
{
    int ret = FunctionCast(newInitPipe, callbackIBTPatcher->oldInitPipe)(that, descriptor, superDescriptor, controller, device, interface, a7, a8);
    captureIntelInterruptPipe(that, descriptor, device);
    return ret;
}

int CIntelBTPatcher::
newInitPipeConfig(void *that, StandardUSB::EndpointDescriptor const *descriptor, StandardUSB::ConfigurationDescriptor const *configDescriptor, AppleUSBHostController *controller, IOUSBHostDevice *device, IOUSBHostInterface *interface, unsigned char a7, unsigned short a8)
{
    int ret = FunctionCast(newInitPipeConfig, callbackIBTPatcher->oldInitPipeConfig)(that, descriptor, configDescriptor, controller, device, interface, a7, a8);
    captureIntelInterruptPipe(that, descriptor, device);
    return ret;
}
