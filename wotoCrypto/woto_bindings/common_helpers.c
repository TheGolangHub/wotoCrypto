// wotoCrypto Project
// Copyright (C) 2022 ALiwoto
// This file is subject to the terms and conditions defined in
// file 'LICENSE', which is part of the source code.

#ifndef _WOTO_BINDINGS_COMMON_HELPERS_C
#define _WOTO_BINDINGS_COMMON_HELPERS_C

#include <stdio.h>
#include <string.h>

static int compute_signature_real_length(const char *sig, int alg) 
{
    return strlen(sig)|alg;
}


#endif /* _WOTO_BINDINGS_COMMON_HELPERS_C */

