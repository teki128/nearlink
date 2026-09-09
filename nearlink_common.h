#ifndef NEARLINK_COMMON_H
#define NEARLINK_COMMON_H

#define SLE_ENTRY_PRIORITY 25
#define SLE_ENTRY_STACK_SIZE 4096

#define SLE_ADV_CHANNEL_MAP_DEFAULT 0x07

#define SLE_SERVER_ADDR "12:34:56:78:9A:BC"

#define SLE_APP_UUID 0xA000
#define SLE_SERVICE_UUID 0xA001
#define SLE_SERVER_ID 1
#define SLE_CLIENT_ID 2

typedef struct sle_adv_common_value {
    uint8_t length;
    uint8_t type;
    uint8_t value;
} sle_adv_common_t; // 广播包每块数据结构

#endif