#ifndef _STRUCTS_H
#define _STRUCTS_H

// 802.11 related structs

typedef struct ieee80211_radiotap_header
{
  u_int8_t it_version;
  u_int8_t it_pad;
  u_int16_t it_len;
  u_int32_t it_present;
} radiotap_header;

typedef struct frame_control
{
  uint8_t version : 2;
  uint8_t type : 2;
  uint8_t subtype : 4;
  uint8_t to_ds : 1;
  uint8_t from_ds : 1;
  uint8_t more_frag : 1;
  uint8_t retry : 1;
  uint8_t pwr_mgt : 1;
  uint8_t more_data : 1;
  uint8_t wep : 1;
  uint8_t order : 1;
} frame_control;

typedef struct mac_header
{
  uint8_t frame_control[2];
  uint8_t duration_id[2];
  uint8_t address1[6];
  uint8_t address2[6];
  uint8_t address3[6];
  uint8_t sequence_control[2];
} mac_header;

typedef struct beacon_frame_body_ssid
{
  uint8_t element_id;
  uint8_t length;
  uint8_t ssid[32];
} beacon_frame_body_ssid;

typedef struct beacon_frame_body
{
  uint8_t timestamp[8];
  uint8_t beacon_interval[2];
  uint8_t capability_info[2];
  beacon_frame_body_ssid ssid;
} beacon_frame_body;


// Saving communication info structs

typedef struct centry
{
  uint8_t addr_1[6];
  uint8_t addr_2[6];
  int ttl;
} centry;

typedef struct com_ap_data
{
  centry **entries;
  int size;
  int cap;
  uint8_t bssid[6];
  char ssid[32];
} com_ap_data;

typedef struct com_ap_data_list {
  com_ap_data **data;
  int size;
  int cap;
} com_ap_data_list;

// Handling communication structs

#define START_TTL 100

com_ap_data *com_ap_data_new(uint8_t *bssid, char *ssid)
{
  com_ap_data *data = malloc(sizeof(com_ap_data));
  data->entries = NULL;
  data->size = 0;
  memcpy(data->bssid, bssid, 6);
  strcpy(data->ssid, ssid);
  return data;
}

void com_ap_data_add_entry(com_ap_data *data, uint8_t *addr_1, uint8_t *addr_2, int ttl)
{
  if (data->entries == NULL)
  {
    data->entries = malloc(10 * sizeof(centry));
    data->cap = 10;
  }
  else if (data->size == data->cap)
  {
    data->cap *= 2;
    data->entries = realloc(data->entries, (data->cap) * sizeof(centry));
  }

  centry *entry = data->entries[data->size];
  memcpy(entry->addr_1, addr_1, 6);
  memcpy(entry->addr_2, addr_2, 6);
  entry->ttl = ttl;
  data->size++;
}

com_ap_data_list *com_ap_data_list_new()
{
  com_ap_data_list *list = malloc(sizeof(com_ap_data_list));
  list->data = NULL;
  list->size = 0;
  list->cap = 0;
  return list;
}

void com_ap_data_list_add(com_ap_data_list *list, com_ap_data *data)
{
  if (list->data == NULL)
  {
    list->data = malloc(10 * sizeof(com_ap_data *));
    list->cap = 10;
  }
  else if (list->size == list->cap)
  {
    list->cap *= 2;
    list->data = realloc(list->data, (list->cap) * sizeof(com_ap_data *));
  }

  list->data[list->size] = data;
  list->size++;
}

void remove_old_entries(com_ap_data *data)
{
  for (int j = 0; j < data->size; j++)
  {
    if (data->entries[j]->ttl <= 0)
    {
      for (int k = j; k < data->size - 1; k++)
      {
        data->entries[k] = data->entries[k + 1];
      }
      data->size--;
      j--;
    }
  }
}

#endif