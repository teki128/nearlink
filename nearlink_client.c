#include "common_def.h"
#include "soc_osal.h"
#include "app_init.h"
#include "securec.h"
#include "sle_common.h"
#include "sle_ssap_stru.h"
#include "sle_device_discovery.h"
#include "sle_connection_manager.h"
#include "nearlink_common.h"
#include "sle_ssap_client.h"

uint8_t client_id;

static void sle_enable_cb(errcode_t status)
{
    // 注册client身份
    sle_uuid_t app_uuid = {.uuid = SLE_APP_UUID, .len = 2};
    ssapc_register_client(&app_uuid, &client_id);

    // 设置本地地址
    sle_addr_t addr = {.type = SLE_ADDRESS_TYPE_PUBLIC};
    memcpy(addr.addr, SLE_CLIENT_ADDR, SLE_ADDR_LEN);
    sle_set_local_addr(&addr);

    // 设置连接参数
    sle_default_connect_param_t para = {

    };
}

static int sle_client_task(void)
{
    sle_announce_seek_callbacks_t seek_cbs = {0};
    sle_connection_callbacks_t conn_cbs = {0};

    seek_cbs.sle_enable_cb = sle_enable_cb;

    enable_sle();
    return 0;
}

static void sle_entry(void)
{
    osal_task *task_handle = NULL;
    osal_kthread_lock();
    task_handle = osal_kthread_create(sle_client_task, NULL, "sle_client_task", SLE_ENTRY_STACK_SIZE);
    if (task_handle != NULL) {
        osal_kthread_set_priority(task_handle, SLE_ENTRY_PRIORITY);
        osal_kfree(task_handle);
    }
    osal_kthread_unlock();
}

app_run(sle_entry);
