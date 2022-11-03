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
#include "sgx_tcrypto.h"
#include "string.h"

void goto_error(int ret);

void ecall_sgx_rsa3072_sign(void)
{
    sgx_rsa3072_key_t rsa_key;
    mod = 0x9F4F55E4C564B45CDD7E78868258633AE0FF1BF7359FE1EA0EB4C0068AC3EDB95A2D02355CA6B4DAC19EBAB53F273655F1194748D6043F58763FDE127B5E908F90BCFFF5C9CC0E2A3307D1DCA01440925FC188B5348D1FC446527430FEEC44183831568EBA9738457952C8F6EFEB061D19772A7EBC4BFC4179AC308F7D00DB45C3C734E6B226DDE83440E7741AC25EBDBA5FEA2B518BDDE43909BC5DCA829A85EE19EA1E3EC0413104CD38ACE584C0088E3DECC380595209BA8494CA542E508A3F152DE25EC1AF0BBB2BA4AC14E71D159738AC9AD86B05EE534A79356B0CC0C8EEF607FD52D6B51CB0B18F7A4F77834AA4BF042F1A58652DEE7D2671BEECA7C5313C4F7F5EDAC841063440E0BD921287B5868D508ACF7C5F701923F604ABF19899489277941E6B34C1807427494DDB13444ABE08C248FC6D7A0F79DD7DB2543A92B74AF2D27896451BD3705E797E0E8318EA6F9C26067839BFBE510D369C1E08746460D6CB5BA250C24C106F5FE7BDDE00BB1A450D43C3CDB4525D9CCB4D19CD;
    memcpy(&(rsa_key.mod), &mod, sizeof(rsa_key.mod);
    d = 0x6B16756383552AF0C2C605EE798886E71CBBD0143514BD9143075E2195C83A04F1CABE6C554CE5F501B3BDC49CD2267505334AC9F54909816FAE96283482076C31A1AB20E2A3EB0AD6A23EB4AFD1508CA29706096844DFFE55FD3CCEF2353E83BA005A5582082128BB76D4EF7CC27F9A12C7EA0E99F3AF900236A5B50CCCF818C41395708794839FBEA01CB109E7C4ED2811953F9824EAFD160C32DFC17A402B5110CA77E79B392AA39E666A4436ABD953E82770C0FBA042E5CEE86F10ADCF7E7E6373413FD61F5D271D1873B84469630F7B1D6790F258498D31A623F2B22ADB494F05FEE18ECEBDCACB5FFC34FAAC3118D5AD741190431EF453C4A029F36F2E21288AFF3E3CDB2B0478D5EAD3610C5ACE595EE0063553EA4A6617A458C74BBBBB8561FA6214F222D655F8C430DE3C0DD886295B8130A89E510AA693FE76387C617ADCF6E1A5B98367374B94FBFE5E57109C4A68C4AEFAD0D429E108246814B0A2EDEA8E323D6CE0D6DD0A4AEA44293FAB7CBCD80882D73323373E683289BB88;
    memcpy(&(rsa_key.d), &d, sizeof(rsa_key.d));
    e = 0x03000000;
    memcpy(&(rsa_key.e), &e, sizeof(rsa_key.e));

    sgx_rsa3072_signature_t sig;
    uint8_t private_data = 0xf;
    sgx_status_t ret = sgx_rsa3072_sign( &private_data, 1, &rsa_key, &sig);

    if (ret != SGX_SUCCESS)
    {
        goto_error(ret);
    } else {
        printf("sgx_rsa3072_sign successed, the sig is: ");
        for (int i = 0; i < 384; i++)
        {
            printf("%02X", sig[i]);
        }
        printf("\n");
    }
}

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

    ret = sgx_close_pse_session();
    if(ret != SGX_SUCCESS)
    {
        goto_error(ret);
    } else {
        printf("pse session successfully closed\n");
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
        printf("monotonic_counter id created is %d %d %d, nonce is a length 13 array of uint8_t\n",mc.counter_id[0],mc.counter_id[1],mc.counter_id[2]);
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
    
    ret = sgx_close_pse_session();
    if(ret != SGX_SUCCESS)
    {
        goto_error(ret);
    } else {
        printf("pse session successfully closed\n");
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
