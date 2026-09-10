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

uint16_t conn_handle;
uint16_t prop_handle;

uint8_t client_id;

sle_addr_t server_addr;

static void sle_start_scan(void)
{
    sle_seek_param_t para = {.own_addr_type = 0,
                             .filter_duplicates = 1,
                             .seek_filter_policy = SLE_SEEK_FILTER_ALLOW_ALL,
                             .seek_phys = SLE_SEEK_PHY_1M,
                             .seek_type[0] = SLE_SEEK_ACTIVE,
                             .seek_interval[0] = 100,
                             .seek_window[0] = 100};

    sle_set_seek_param(&para);
    sle_start_seek();
}

static void sle_enable_cb(errcode_t status)
{
    if (status != ERRCODE_SUCC) {
        return;
    }
    // 注册client身份
    sle_uuid_t app_uuid = {.uuid = {0x00, 0xA0}, .len = 2};
    ssapc_register_client(&app_uuid, &client_id);

    // 设置本地地址
    sle_addr_t addr = {.type = SLE_ADDRESS_TYPE_PUBLIC};
    memcpy(addr.addr, SLE_CLIENT_ADDR, SLE_ADDR_LEN);
    sle_set_local_addr(&addr);

    // 设置连接参数
    sle_default_connect_param_t para = {.enable_filter_policy = 0,
                                        .initiate_phys = 1,
                                        .gt_negotiate = SLE_ANNOUNCE_ROLE_G_CAN_NEGO,
                                        .scan_interval = 200,
                                        .scan_window = 20,
                                        .min_interval = SLE_CONN_INTERVAL,
                                        .max_interval = SLE_CONN_INTERVAL,
                                        .timeout = 500};

    sle_default_connection_param_set(&para);

    // 扫描server
    sle_start_scan();
}

static void sle_seek_result_cb(sle_seek_result_info_t *result)
{
    if (result == NULL) {
        osal_printk("seek result is null!");
        return;
    }

    // 寻找特定地址的server
    if (memcmp(result->addr.addr, SLE_SERVER_ADDR, SLE_ADDR_LEN) == 0) {
        server_addr = result->addr;
        sle_stop_seek();
    }
}

static void sle_stop_seek_cb(errcode_t status)
{
    if (status == ERRCODE_SUCC) {
        sle_connect_remote_device(&server_addr);
    }
}

static void sle_connect_state_changed_cb(uint16_t conn_id,
                                         const sle_addr_t *addr,
                                         sle_acb_state_t conn_state,
                                         sle_pair_state_t pair_state,
                                         sle_disc_reason_t disc_reason)
{
    unused(addr);
    unused(pair_state);
    unused(disc_reason);
    if (conn_state == SLE_ACB_STATE_CONNECTED) {
        osal_printk("sle_connect_state_changed_cb: connected, conn_id=0x%02x\r\n", conn_id);
        conn_handle = conn_id;
        // 首次连接尝试配对
        if (pair_state == SLE_PAIR_NONE) {
            osal_printk("start pairing...\r\n");
            sle_pair_remote_device(&server_addr);
        }
    } else if (conn_state == SLE_ACB_STATE_DISCONNECTED) {
        osal_printk("sle_connect_state_changed_cb: disconnected, restart scan\r\n");
        conn_handle = 0;
        sle_remove_paired_remote_device(&server_addr);
        sle_start_scan();
    }
}

static void sle_pair_complete_cb(uint16_t conn_id, const sle_addr_t *addr, errcode_t status)
{
    unused(conn_id);
    unused(addr);

    if (status == ERRCODE_SUCC) {
        // 设置MTU大小
        ssap_exchange_info_t para = {0};
        para.mtu_size = SLE_MTU_SIZE;
        para.version = 1;
        ssapc_exchange_info_req(client_id, conn_id, &para);
    } else {
        sle_remove_paired_remote_device(addr);
    }
    osal_printk("sle_pair_complete_cb: %d\r\n", status);
}

static void sle_exchange_info_cb(uint8_t client_id, uint16_t conn_id, ssap_exchange_info_t *param, errcode_t status)
{
    osal_printk("exchange mtu: %d, status: %d\r\n", param->mtu_size, status);

    // MTU 协商完成，开始服务发现
    ssapc_find_structure_param_t find = {.type = SSAP_FIND_TYPE_PROPERTY, .start_hdl = 1, .end_hdl = 0xFFFF};
    ssapc_find_structure(client_id, conn_id, &find);
}

static int sle_client_task(void)
{
    sle_announce_seek_callbacks_t seek_cbs = {0};
    sle_connection_callbacks_t conn_cbs = {0};

    seek_cbs.sle_enable_cb = sle_enable_cb;
    seek_cbs.seek_result_cb = sle_seek_result_cb;
    seek_cbs.seek_disable_cb = sle_stop_seek_cb;

    conn_cbs.connect_state_changed_cb = sle_connect_state_changed_cb;
    conn_cbs.pair_complete_cb = sle_pair_complete_cb;

    sle_announce_seek_register_callbacks(&seek_cbs);
    sle_connection_register_callbacks(&conn_cbs);

    enable_sle();
    return 0;
}

static void sle_entry(void)
{
    osal_task *task_handle = NULL;
    osal_kthread_lock();
    task_handle =
        osal_kthread_create((osal_kthread_handler)sle_client_task, NULL, "sle_client_task", SLE_ENTRY_STACK_SIZE);
    if (task_handle != NULL) {
        osal_kthread_set_priority(task_handle, SLE_ENTRY_PRIORITY);
        osal_kfree(task_handle);
    }
    osal_kthread_unlock();
}

app_run(sle_entry);
