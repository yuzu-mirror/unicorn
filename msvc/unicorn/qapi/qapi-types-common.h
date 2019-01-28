/* AUTOMATICALLY GENERATED, DO NOT MODIFY */

/*
 * Schema-defined QAPI types
 *
 * Copyright IBM, Corp. 2011
 * Copyright (c) 2013-2018 Red Hat Inc.
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 */

#ifndef QAPI_TYPES_COMMON_H
#define QAPI_TYPES_COMMON_H

#include "qapi/qapi-builtin-types.h"

typedef enum QapiErrorClass {
    QAPI_ERROR_CLASS_GENERICERROR,
    QAPI_ERROR_CLASS_COMMANDNOTFOUND,
    QAPI_ERROR_CLASS_DEVICEENCRYPTED,
    QAPI_ERROR_CLASS_DEVICENOTACTIVE,
    QAPI_ERROR_CLASS_DEVICENOTFOUND,
    QAPI_ERROR_CLASS_KVMMISSINGCAP,
    QAPI_ERROR_CLASS__MAX,
} QapiErrorClass;

extern const char *const QapiErrorClass_lookup[];

#endif /* QAPI_TYPES_COMMON_H */
