#include "common_def.h"
#include "soc_osal.h"
#include "app_init.h"
#include "securec.h"
#include "sle_common.h"
#include "sle_device_discovery.h"
#include "sle_connection_manager.h"
#include "nearlink_common.h"

void sle_enable_cb(errcode_t status)
{
    osal_printk("sle_enable_cb: %d\r\n", status);

    sle_addr_t addr = {.type = SLE_ADDRESS_TYPE_PUBLIC, .addr = NULL};
    memcpy(addr.addr, SLE_SERVER_ADDR, SLE_ADDR_LEN);
    sle_setlocal_addr(&addr);

    if (status == ERRCODE_SUCC) {
        if (sle_init_adv() == ERRCODE_SUCC) {
            sle_start_adv();
        }
    }
}

void sle_announce_enable_cb(errcode_t status)
{
    osal_printk("sle_announce_enable_cb: %d\r\n", status);
}