/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_tae_service.h"
#include "string.h"

void ecall_trusted_time_primitives(void)
{
    uint32_t ret = 0;
    int busy_retry_times = 2;
    sgx_time_source_nonce_t nonce = {0};
    sgx_time_t current_timestamp;
    
    do{
        ret = sgx_create_pse_session();
    }while (ret == SGX_ERROR_BUSY && busy_retry_times--);
    if(ret != SGX_SUCCESS)
    {
        goto_error(ret);
    } else {
        printf("pse session successfully created\n");
    }

    ret = sgx_get_trusted_time(&current_timestamp, &nonce);
    if(ret != SGX_SUCCESS)
    {
        goto_error(ret);
    } else {
        printf("trusted time successfully received and timestamp value is %d\n", current_timestamp);
    }
}

void ecall_monotonic_counter_primitives(void)
{
    uint32_t ret = 0;
    uint32_t mc_value = 0;
    sgx_mc_uuid_t mc;
    memset(&mc, 0, sizeof(mc));
    int busy_retry_times = 2;

    do{
        ret = sgx_create_pse_session();
    }while (ret == SGX_ERROR_BUSY && busy_retry_times--);
    if(ret != SGX_SUCCESS)
    {
        goto_error(ret);
    } else {
        printf("pse session successfully created\n");
    }

    ret = sgx_create_monotonic_counter(&mc,&mc_value);
    if(ret != SGX_SUCCESS)
    {
        goto_error(ret);
    } else {
        printf("monotonic_counter successfully created and counter value is %d\n",mc_value);
    }

    ret = sgx_increment_monotonic_counter(&mc,&mc_value);
    if(ret != SGX_SUCCESS)
    {
        goto_error(ret);
    } else {
        printf("monotonic_counter successfully incremented and counter value is %d\n",mc_value);
    }

    ret = sgx_read_monotonic_counter(&mc,&mc_value);
    if(ret != SGX_SUCCESS)
    {
        goto_error(ret);
    } else {
        printf("monotonic_counter successfully read and counter value is %d\n",mc_value);
    }

    ret = sgx_destroy_monotonic_counter(&mc);
    if(ret != SGX_SUCCESS)
    {
        goto_error(ret);
    } else {
        printf("monotonic_counter successfully destroyed\n");
    }
}

void goto_error(int ret)
{
    switch(ret)
    {
    case SGX_ERROR_SERVICE_UNAVAILABLE:
        /* Architecture Enclave Service Manager is not installed or not
        working properly.*/
            break;
    case SGX_ERROR_SERVICE_TIMEOUT:
        /* retry the operation later*/
            break;
    case SGX_ERROR_BUSY:
        /* retry the operation later*/
            break;
    case SGX_ERROR_MC_NOT_FOUND:
        /* the the Monotonic Counter ID is invalid.*/
            break;
    default:
        /*other errors*/
        break;
    }
}

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}
