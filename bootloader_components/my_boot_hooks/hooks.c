#include <string.h>

#include "esp_log.h"
#include "esp_flash_partitions.h"
#include "esp_partition.h"

#include "bootloader_config.h"
#include "bootloader_common.h"

static const char *TAG = "bl_hooks";

esp_err_t bootloader_flash_erase_range(uint32_t start_addr, uint32_t size);
const void *bootloader_mmap(uint32_t src_addr, uint32_t size);
void bootloader_munmap(const void *mapping);

/* Function used to tell the linker to include this file
 * with all its symbols.
 */
void bootloader_hooks_include(void){
}

// from esp_ota_ops.c
static esp_err_t read_otadata(const esp_partition_pos_t *ota_info, esp_ota_select_entry_t *two_otadata)
{
    const esp_ota_select_entry_t *ota_select_map;
    if (ota_info->offset == 0) {
        return ESP_ERR_NOT_FOUND;
    }

    // partition table has OTA data partition
    if (ota_info->size < 2 * SPI_SEC_SIZE) {
        ESP_LOGE(TAG, "ota_info partition size %d is too small (minimum %d bytes)", ota_info->size, (2 * SPI_SEC_SIZE));
        return ESP_FAIL; // can't proceed
    }

    ESP_LOGD(TAG, "OTA data offset 0x%x", ota_info->offset);
    ota_select_map = bootloader_mmap(ota_info->offset, ota_info->size);
    if (!ota_select_map) {
        ESP_LOGE(TAG, "bootloader_mmap(0x%x, 0x%x) failed", ota_info->offset, ota_info->size);
        return ESP_FAIL; // can't proceed
    }

    memcpy(&two_otadata[0], ota_select_map, sizeof(esp_ota_select_entry_t));
    memcpy(&two_otadata[1], (uint8_t *)ota_select_map + SPI_SEC_SIZE, sizeof(esp_ota_select_entry_t));
    bootloader_munmap(ota_select_map);

    return ESP_OK;
}

static int get_otadata_info(const esp_partition_pos_t *otadata_pos, esp_ota_select_entry_t *two_otadata)
{
    memset(two_otadata, 0, sizeof(esp_ota_select_entry_t) * 2);
    if(ESP_OK != read_otadata(otadata_pos, two_otadata))
    {
        abort();
    }
    return bootloader_common_get_active_otadata(two_otadata);
}

static esp_err_t get_otadata_part(esp_partition_pos_t *otadata_pos)
{
    // naive function to grab otadata partition, check serial output
    const esp_partition_info_t *partition_table = bootloader_mmap(ESP_PARTITION_TABLE_OFFSET, ESP_PARTITION_TABLE_MAX_LEN);
    assert(partition_table);

    const esp_partition_info_t *partition = partition_table;
    while(partition->magic == ESP_PARTITION_MAGIC)
    {
        ESP_LOGI(TAG, "Partition %s @ 0x%X", partition->label, partition->pos.offset);
        if(partition->type == ESP_PARTITION_TYPE_DATA && partition->subtype == ESP_PARTITION_SUBTYPE_DATA_OTA)
        {
            *otadata_pos = partition->pos;
            bootloader_munmap(partition_table);
            return ESP_OK;
        }
        ++partition;
    }
    bootloader_munmap(partition_table);
    return ESP_ERR_NOT_FOUND;
}

void bootloader_after_init(void) {
    esp_partition_pos_t ota_data_partition;
    esp_ota_select_entry_t otadata[2];
    int active_otadata;

    ESP_LOGI(TAG, "Patched ROM Driver: %s",
#ifdef CONFIG_SPI_FLASH_ROM_DRIVER_PATCH
        "Enabled"
#else
        "Disabled"
#endif
    );
    // 1. Read partition table to get otadata partition
    if(ESP_OK != get_otadata_part(&ota_data_partition))
    {
        abort();
    }
    ESP_LOGI(TAG, "OTA Data Partition: 0x%X @ 0x%X", ota_data_partition.offset, ota_data_partition.size);
    // 2. Print info about current otadata state
    active_otadata = get_otadata_info(&ota_data_partition, otadata);
    ESP_LOGI(TAG, "OTA Data before -> Active index: %d, seq[0]: 0x%X, seq[1]: 0x%X", active_otadata, otadata[0].ota_seq, otadata[1].ota_seq);
    // 3. "Erase" otadata partition
    bootloader_flash_erase_range(ota_data_partition.offset, ota_data_partition.size);
    // 4. Print info again
    // if patched functions is disabled, note the odd otadata sequence number
    active_otadata = get_otadata_info(&ota_data_partition, otadata);
    ESP_LOGI(TAG, "OTA Data after -> Active index: %d, seq[0]: 0x%X, seq[1]: 0x%X", active_otadata, otadata[0].ota_seq, otadata[1].ota_seq);
    if(active_otadata != -1 || otadata[0].ota_seq != 0xFFFFFFFF || otadata[1].ota_seq != 0xFFFFFFFF)
    {
        /*
        The delay in this block appears to mitigate the issue, however if the following lines are skipped (so the bootloader immediately reads
        partition table) then the app fails to boot due to a partition table verification error:

        I (112) bl_hooks: OTA Data after -> Active index: -1, seq[0]: 0xFF070000, seq[1]: 0xFF070000
        E (121) flash_parts: partition 0 invalid magic number 0x0
        E (127) boot: Failed to verify partition table
        E (133) boot: load partition table error!

        */
        ESP_LOGE(TAG, "Erase appears to have failed");
        ESP_LOGE(TAG, "Comment this block to read corrupted partition table");
        ets_delay_us(1000000);
    }
}
