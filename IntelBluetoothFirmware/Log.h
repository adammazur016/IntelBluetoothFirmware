/** @file
  Copyright (c) 2020 zxystd. All rights reserved.
  SPDX-License-Identifier: GPL-3.0-only
**/

//
//  Log.h
//  IntelBluetoothFirmware
//
//  Created by zxystd on 2019/12/3.
//  Copyright © 2019 zxystd. All rights reserved.
//
//  PEM patch: every log line is also kept in an in-memory ring that is
//  published to the IORegistry (IOResources -> "IBTLog"), so the whole
//  firmware-loading trace can be read with ioreg after boot, without
//  depending on dmesg / unified log.
//

#ifndef Log_h
#define Log_h

#include <IOKit/IOLib.h>

#ifdef __cplusplus
extern "C" {
#endif
void ibtLogAppend(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
#ifdef __cplusplus
}
#endif

#define XYLog(fmt, x...)\
do\
{\
IOLog("%s: " fmt, "IntelFirmware", ##x);\
ibtLogAppend(fmt, ##x);\
}while(0)

#endif /* Log_h */
