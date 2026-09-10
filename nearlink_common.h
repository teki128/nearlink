#ifndef NEARLINK_COMMON_H
#define NEARLINK_COMMON_H

#define SLE_ENTRY_PRIORITY 25
#define SLE_ENTRY_STACK_SIZE 4096

#define SLE_ADV_CHANNEL_MAP_DEFAULT 0x07

#define SLE_MTU_SIZE 512

static const uint8_t SLE_APP_UUID[SLE_UUID_LEN] = {0x00, 0xA0};
static const uint8_t SLE_SERVICE_UUID[SLE_UUID_LEN] = {0x01, 0xA0};

static const uint8_t SLE_SERVER_ADDR[SLE_ADDR_LEN] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
static const uint8_t SLE_CLIENT_ADDR[SLE_ADDR_LEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

typedef struct sle_adv_common_value {
    uint8_t length;
    uint8_t type;
    uint8_t value;
} sle_adv_common_t; // 广播包每块数据结构

#endif