//
//  IntelBluetoothFirmware.cpp
//  IntelBluetoothFirmware
//
//  Created by zxystd on 2019/11/17.
//  Copyright © 2019 zxystd. All rights reserved.
//

#include "BtIntel.h"

#include "IntelBluetoothFirmware.hpp"
#include <libkern/libkern.h>
#include <libkern/OSKextLib.h>
#include <libkern/version.h>
#include <libkern/OSTypes.h>
#include <IOKit/usb/StandardUSB.h>
#include <libkern/OSAtomic.h>
#include <pexpert/pexpert.h>
#include <stdarg.h>
#include "Hci.h"
#include "linux.h"
#include "Log.h"

#include "IntelBluetoothOpsGen1.hpp"
#include "IntelBluetoothOpsGen2.hpp"
#include "IntelBluetoothOpsGen3.hpp"

#define super IOService
OSDefineMetaClassAndStructors(IntelBluetoothFirmware, IOService)

/* ------------------------------------------------------------------ */
/* PEM: in-memory trace published to IORegistry                       */
/* ------------------------------------------------------------------ */

#define IBT_LOG_CAP 16384
static char gIbtLog[IBT_LOG_CAP];
static volatile SInt32 gIbtLogLen = 0;
static volatile SInt32 gIbtTotalAttempts = 0;

extern "C" void ibtLogAppend(const char *fmt, ...)
{
    char line[256];
    uint64_t abs, ns;
    clock_get_uptime(&abs);
    absolutetime_to_nanoseconds(abs, &ns);
    int n = snprintf(line, sizeof(line), "[%llu] ", (unsigned long long)(ns / 1000000ULL));
    if (n < 0) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    int m = vsnprintf(line + n, sizeof(line) - (size_t)n, fmt, ap);
    va_end(ap);
    if (m < 0) {
        return;
    }
    size_t len = (size_t)n + (size_t)m;
    if (len > sizeof(line) - 1) {
        len = sizeof(line) - 1;
    }
    if (len == 0) {
        return;
    }
    SInt32 off = OSAddAtomic((SInt32)len, &gIbtLogLen);
    if (off < 0 || (size_t)off + len >= IBT_LOG_CAP - 1) {
        return;
    }
    memcpy(gIbtLog + off, line, len);
}

static void ibtPublish(IOService *dev, const char *status)
{
    gIbtLog[IBT_LOG_CAP - 1] = '\0';
    OSString *logStr = OSString::withCString(gIbtLog);
    OSString *stStr = OSString::withCString(status);
    OSNumber *att = OSNumber::withNumber((unsigned long long)gIbtTotalAttempts, 32);
    IOService *res = IOService::getResourceService();
    if (res) {
        if (logStr) res->setProperty("IBTLog", logStr);
        if (stStr) res->setProperty("IBTStatus", stStr);
        if (att) res->setProperty("IBTAttempts", att);
    }
    if (dev) {
        if (stStr) dev->setProperty("IBTStatus", stStr);
        if (att) dev->setProperty("IBTAttempts", att);
    }
    OSSafeReleaseNULL(logStr);
    OSSafeReleaseNULL(stStr);
    OSSafeReleaseNULL(att);
}

//com.apple.iokit.IOBluetoothHostControllerUSBTransport

enum { kMyOffPowerState = 0, kMyOnPowerState = 1 };

#define kIOPMPowerOff 0

static IOPMPowerState myTwoStates[2] =
{
    {1, kIOPMPowerOff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {1, kIOPMPowerOn, kIOPMPowerOn, kIOPMPowerOn, 0, 0, 0, 0, 0, 0, 0, 0}
};

bool IntelBluetoothFirmware::init(OSDictionary *dictionary)
{
    XYLog("Driver init()\n");
    return super::init(dictionary);
}

void IntelBluetoothFirmware::free() {
    XYLog("Driver free()\n");
    super::free();
}

bool IntelBluetoothFirmware::start(IOService *provider)
{
    XYLog("Driver Start() [PEM robust loader]\n");
    char fwName[64];
    m_pDevice = OSDynamicCast(IOUSBHostDevice, provider);
    if (m_pDevice == NULL) {
        XYLog("Driver Start fail, not usb device\n");
        return false;
    }
    PMinit();
    registerPowerDriver(this, myTwoStates, 2);
    provider->joinPMtree(this);
    makeUsable();
    
    if (!super::start(provider)) {
        return false;
    }
    
    if (!m_pDevice->open(this)) {
        XYLog("start fail, can not open device\n");
        ibtPublish(provider, "fail: cannot open device");
        cleanUp();
        stop(this);
        return false;
    }
    
    /* PEM: optional delay (ms) before the first attempt, boot-arg ibtdelay=N.
     * Intel combo cards are known to break the BT firmware download when
     * the Wi-Fi firmware is being loaded at the same moment.
     */
    uint32_t delayMs = 0;
    if (PE_parse_boot_argn("ibtdelay", &delayMs, sizeof(delayMs)) && delayMs > 0) {
        if (delayMs > 30000) {
            delayMs = 30000;
        }
        XYLog("ibtdelay: sleeping %u ms before first attempt\n", delayMs);
        IOSleep(delayMs);
    }
    
    uint32_t maxAttempts = 5;
    PE_parse_boot_argn("ibtretries", &maxAttempts, sizeof(maxAttempts));
    if (maxAttempts < 1) {
        maxAttempts = 1;
    }
    if (maxAttempts > 10) {
        maxAttempts = 10;
    }
    
    bool ok = false;
    for (uint32_t attempt = 1; attempt <= maxAttempts; attempt++) {
        SInt32 total = OSIncrementAtomic(&gIbtTotalAttempts) + 1;
        if (total > 15) {
            XYLog("global attempt limit reached (%d), giving up\n", (int)total);
            break;
        }
        if (m_pDevice->isInactive()) {
            XYLog("device went away (USB re-enumeration), a new instance will continue\n");
            break;
        }
        XYLog("=== attempt %u/%u (global %d) ===\n", attempt, maxAttempts, (int)total);
        
        if (currentType == kTypeGen1) {
            m_pBTIntel = new IntelBluetoothOpsGen1();
        } else {
            m_pBTIntel = new IntelBluetoothOpsGen3();
        }
        if (!m_pBTIntel || !m_pBTIntel->initWithDevice(this, m_pDevice)) {
            XYLog("attempt %u: can not init device\n", attempt);
        } else {
            XYLog("BT init succeed\n");
            if (m_pBTIntel->setup()) {
                ok = true;
                break;
            }
            XYLog("attempt %u: setup failed\n", attempt);
        }
        OSSafeReleaseNULL(m_pBTIntel);
        IOSleep(500 * attempt);
    }
    
    if (!ok) {
        XYLog("all attempts failed\n");
        ibtPublish(m_pDevice, "fail: firmware not loaded");
        cleanUp();
        stop(this);
        return false;
    }
    
    m_pBTIntel->getFirmwareName(fwName, sizeof(fwName));
    XYLog("firmware loaded OK: %s\n", fwName);
    publishReg(true, fwName);
    ibtPublish(m_pDevice, "ok");
    cleanUp();
    return true;
}

void IntelBluetoothFirmware::publishReg(bool isSucceed, const char *fwName)
{
    m_pDevice->setProperty("FirmwareLoaded", isSucceed);
    if (isSucceed)
        setProperty("fw_name", OSString::withCString(fwName));
    // Monterey+
    if (version_major >= 21) {
        m_pDevice->setName("Bluetooth USB Host Controller");
        /* PEM: bluetoothd (bm3_usb GetProductAndVendorID) only accepts a USB
         * device as the internal controller when its "USB Product Name"
         * property is exactly "Bluetooth USB Host Controller". Intel cards
         * report no product string, so set it explicitly.
         */
        if (isSucceed) {
            m_pDevice->setProperty("USB Product Name", "Bluetooth USB Host Controller");
            m_pDevice->setProperty("kUSBProductString", "Bluetooth USB Host Controller");
            if (!m_pDevice->getProperty("USB Vendor Name")) {
                m_pDevice->setProperty("USB Vendor Name", "Intel Corp.");
            }
        }
    }
}

void IntelBluetoothFirmware::cleanUp()
{
    XYLog("Clean up...\n");
    OSSafeReleaseNULL(m_pBTIntel);
    if (m_pDevice) {
        if (m_pDevice->isOpen(this)) {
            m_pDevice->close(this);
        }
        m_pDevice = NULL;
    }
}

IOReturn IntelBluetoothFirmware::setPowerState(unsigned long powerStateOrdinal, IOService *whatDevice)
{
//    XYLog("setPowerState powerStateOrdinal=%lu\n", powerStateOrdinal);
    return IOPMAckImplied;
}

void IntelBluetoothFirmware::stop(IOService *provider)
{
    XYLog("Driver Stop()\n");
    PMstop();
    super::stop(provider);
}

IOService * IntelBluetoothFirmware::probe(IOService *provider, SInt32 *score)
{
    XYLog("Driver Probe()\n");
    if (!super::probe(provider, score)) {
        XYLog("super probe failed\n");
        return NULL;
    }
    m_pDevice = OSDynamicCast(IOUSBHostDevice, provider);
    if (!m_pDevice) {
        XYLog("is not usb device\n");
        return NULL;
    }
    UInt16 vendorID = USBToHost16(m_pDevice->getDeviceDescriptor()->idVendor);
    UInt16 productID = USBToHost16(m_pDevice->getDeviceDescriptor()->idProduct);
    XYLog("name=%s, class=%s, vendorID=0x%04X, productID=0x%04X\n", m_pDevice->getName(), provider->metaClass->getClassName(), vendorID, productID);
    if (productID == 0x07dc || productID == 0x0a2a || productID == 0x0aa7) {
        currentType = kTypeGen1;
    } else if (productID == 0x0032 || productID == 0x0033 || productID == 0x0035
               || productID == 0x0036 || productID == 0x0038) {
        currentType = kTypeGen3;
    } else {
        currentType = kTypeGen2;
    }
    m_pDevice = NULL;
    return this;
}
