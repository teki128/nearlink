#include "common_def.h"
#include "soc_osal.h"
#include "app_init.h"
#include "securec.h"
#include "sle_common.h"
#include "sle_ssap_stru.h"
#include "sle_device_discovery.h"
#include "sle_connection_manager.h"
#include "nearlink_common.h"
#include "sle_ssap_server.h"

uint16_t service_handle;
uint16_t prop_handle;
uint16_t g_conn_id;

uint8_t prop_value[SLE_PROP_VALUE_MAX_LEN] = "hello sle";
uint8_t prop_len;

uint8_t server_id;

static errcode_t sle_start_service(void)
{
    // 注册server身份
    sle_uuid_t app_uuid = {.uuid = {0x00, 0xA0}, .len = 2};
    ssaps_register_server(&app_uuid, &server_id);

    // 添加service
    sle_uuid_t server_uuid = {.uuid = {0x01, 0xA0}, .len = 2};
    ssaps_add_service_sync(server_id, &server_uuid, true, &service_handle);

    // 添加service内的property
    prop_len = sizeof("hello sle") - 1;
    ssaps_property_info_t prop = {.uuid = {.uuid = {0x02, 0xA0}, .len = 2},
                                  .permissions = SSAP_PERMISSION_READ | SSAP_PERMISSION_WRITE,
                                  .operate_indication = SSAP_OPERATE_INDICATION_BIT_READ |
                                                        SSAP_OPERATE_INDICATION_BIT_WRITE |
                                                        SSAP_OPERATE_INDICATION_BIT_NOTIFY,
                                  .value_len = prop_len,
                                  .value = prop_value};
    ssaps_add_property_sync(server_id, service_handle, &prop, &prop_handle);

    // 添加property的配置(descriptor)
    uint8_t desc_value[] = {1, 0};
    ssaps_desc_info_t desc = {.permissions = SSAP_PERMISSION_READ | SSAP_PERMISSION_WRITE,
                              .operate_indication =
                                  SSAP_OPERATE_INDICATION_BIT_READ | SSAP_OPERATE_INDICATION_BIT_WRITE,
                              .type = SSAP_DESCRIPTOR_USER_DESCRIPTION,
                              .value_len = 2,
                              .value = desc_value};
    ssaps_add_descriptor_sync(server_id, service_handle, prop_handle, &desc);

    ssaps_start_service(server_id, service_handle);

    return ERRCODE_SUCC;
}

static void sle_start_service_cb(uint8_t server_id, uint16_t handle, errcode_t status)
{
    unused(server_id);
    unused(handle);
    osal_printk("sle_start_service_cb stauts=0x%x\r\n", status);
}

static void sle_announce_enable_cb(uint32_t announce_id, errcode_t status)
{
    unused(announce_id);
    osal_printk("sle_announce_enable_cb status=0x%x\r\n", status);
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
        g_conn_id = conn_id;
        osal_printk("sle_connect_state_changed_cb: connected, conn_id=0x%02x\r\n", conn_id);
    } else if (conn_state == SLE_ACB_STATE_DISCONNECTED) {
        osal_printk("sle_connect_state_changed_cb: disconnected, restart announce\r\n");
        g_conn_id = 0;
        sle_start_announce(1);
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
        ssaps_set_info(server_id, &para);
    } else {
        sle_remove_paired_remote_device(addr);
    }
    osal_printk("sle_pair_complete_cb status=0x%x\r\n", status);
}

// 收到client的读属性req，发送resp
static void sle_read_request_cb(uint8_t server_id,
                                uint16_t conn_id,
                                ssaps_req_read_cb_t *read_cb_para,
                                errcode_t status)
{
    unused(status);
    ssaps_send_rsp_t rsp = {0};
    rsp.request_id = read_cb_para->request_id;
    rsp.status = 0;
    rsp.value_len = prop_len;
    rsp.value = prop_value; // 直接返回属性值

    ssaps_send_response(server_id, conn_id, &rsp);
}

// 收到client的写属性req，发送resp
static void sle_write_request_cb(uint8_t server_id,
                                 uint16_t conn_id,
                                 ssaps_req_write_cb_t *write_cb_para,
                                 errcode_t status)
{
    unused(status);
    osal_printk("write req: len=%d, value=%s\r\n", write_cb_para->length, write_cb_para->value);

    // 修改prop值
    if (write_cb_para->length <= SLE_PROP_VALUE_MAX_LEN) {
        memcpy(prop_value, write_cb_para->value, write_cb_para->length);
        prop_len = write_cb_para->length;
    }

    // req要求必须回复
    if (write_cb_para->need_rsp == true) {
        uint8_t rsp_value[] = "OK!";
        ssaps_send_rsp_t rsp = {
            .request_id = write_cb_para->request_id, .status = 0, .value = rsp_value, .value_len = 3};
        ssaps_send_response(server_id, conn_id, &rsp);
    }

    // 将新值notify给client
    ssaps_ntf_ind_t ntf = {0};
    ntf.handle = prop_handle;
    ntf.type = SSAP_PROPERTY_TYPE_VALUE;
    ntf.value_len = prop_len;
    ntf.value = prop_value;
    ssaps_notify_indicate(server_id, conn_id, &ntf);
}

static errcode_t sle_init_adv(void)
{
    sle_announce_param_t param = {0}; // 广播参数
    param.announce_mode = SLE_ANNOUNCE_MODE_CONNECTABLE_SCANABLE;
    param.announce_handle = 1; // 只用1路广播，自分配句柄1
    param.announce_gt_role = SLE_ANNOUNCE_ROLE_T_CAN_NEGO;
    param.announce_level = SLE_ANNOUNCE_LEVEL_NORMAL;
    param.announce_channel_map = SLE_ADV_CHANNEL_MAP_DEFAULT;
    param.announce_interval_min = 200; // 以25ms间隔广播, time=N*0.125ms
    param.announce_interval_max = 200;
    param.conn_interval_min = SLE_CONN_INTERVAL; // 连接后期望以12.5ms间隔同步
    param.conn_interval_max = SLE_CONN_INTERVAL;
    param.conn_max_latency = 499;         // 最大休眠连接间隔
    param.conn_supervision_timeout = 500; // 连接超时时间
    param.announce_tx_power = 18;
    param.own_addr.type = SLE_ADDRESS_TYPE_PUBLIC;
    memcpy(param.own_addr.addr, SLE_SERVER_ADDR, SLE_ADDR_LEN); // 设置本端server地址

    sle_set_announce_param(1, &param);

    struct sle_adv_common_value adv_disc_level = {.length = 2, .type = 1, .value = SLE_ANNOUNCE_LEVEL_NORMAL};

    struct sle_adv_common_value adv_access_mode = {.length = 2, .type = 2, .value = 0};

    struct sle_adv_common_value tx_power_level = {.length = 2, .type = 12, .value = 10};

    struct sle_adv_common_value adv_name = {.length = 5, .type = 11};

    uint8_t announce_data[] = {adv_disc_level.length,  adv_disc_level.type,  adv_disc_level.value,
                               adv_access_mode.length, adv_access_mode.type, adv_access_mode.value}; // 广播数据
    uint8_t seek_rsp_data[] = {tx_power_level.length,
                               tx_power_level.type,
                               tx_power_level.value,
                               adv_name.length,
                               adv_name.type,
                               'W',
                               'S',
                               '6',
                               '3'}; // 扫描响应数据

    sle_announce_data_t data = {
        .announce_data_len = sizeof(announce_data),
        .seek_rsp_data_len = sizeof(seek_rsp_data),
        .announce_data = announce_data,
        .seek_rsp_data = seek_rsp_data,
    };

    return sle_set_announce_data(1, &data);
}

static errcode_t sle_start_adv(void)
{
    errcode_t ret = sle_start_announce(1); // 启动句柄为1的广播
    return ret;
}

static errcode_t sle_server_task(void)
{
    sle_announce_seek_callbacks_t adv_cbs = {0};
    sle_connection_callbacks_t conn_cbs = {0};
    ssaps_callbacks_t ssaps_cbs = {0};

    adv_cbs.announce_enable_cb = sle_announce_enable_cb;

    conn_cbs.connect_state_changed_cb = sle_connect_state_changed_cb;
    conn_cbs.pair_complete_cb = sle_pair_complete_cb;

    ssaps_cbs.start_service_cb = sle_start_service_cb;
    ssaps_cbs.read_request_cb = sle_read_request_cb;
    ssaps_cbs.write_request_cb = sle_write_request_cb;

    sle_announce_seek_register_callbacks(&adv_cbs);
    sle_connection_register_callbacks(&conn_cbs);
    ssaps_register_callbacks(&ssaps_cbs);

    errcode_t status = enable_sle(); // 使能SLE协议栈
    if (status != ERRCODE_SUCC) {
        osal_printk("enable_sle failed status=0x%x\r\n", status);
        return status;
    }

    // 设定本地地址
    sle_addr_t addr = {.type = SLE_ADDRESS_TYPE_PUBLIC};
    memcpy(addr.addr, SLE_SERVER_ADDR, SLE_ADDR_LEN);
    sle_set_local_addr(&addr);

    // 开始启动服务并广播
    if (status == ERRCODE_SUCC) {
        sle_start_service();
        if (sle_init_adv() == ERRCODE_SUCC) {
            sle_start_adv();
        }
    }

    return ERRCODE_SUCC;
}

static void sle_entry(void)
{
    osal_task *task_handle = NULL;
    osal_kthread_lock();
    task_handle =
        osal_kthread_create((osal_kthread_handler)sle_server_task, NULL, "sle_server_task", SLE_ENTRY_STACK_SIZE);
    if (task_handle != NULL) {
        osal_kthread_set_priority(task_handle, SLE_ENTRY_PRIORITY);
        osal_kfree(task_handle);
    }
    osal_kthread_unlock();
}

app_run(sle_entry);
