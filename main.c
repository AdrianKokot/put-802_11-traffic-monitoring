/*
 * Compilation: gcc -Wall ./main.c -o ./main -lpcap
 */

#include <pcap.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stdint.h>
#include <unistd.h>

char *errbuf;
pcap_t *handle;

#define START_TTL 100

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

void main_loop(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void cleanup();
void stop(int signum);



typedef struct centry {
  uint8_t addr_1[6];
  uint8_t addr_2[6];
  int ttl;
} centry;

typedef struct com_ap_data {
  centry *entries;
  int size;
  int cap;
  uint8_t bssid[6];
  char ssid[32];
} com_ap_data;

com_ap_data *com_ap_data_new(uint8_t *bssid, char *ssid) {
  com_ap_data *data = malloc(sizeof(com_ap_data));
  data->entries = NULL;
  data->size = 0;
  memcpy(data->bssid, bssid, 6);
  strcpy(data->ssid, ssid);
  return data;
}

void com_ap_data_add_entry(com_ap_data *data, uint8_t *addr_1, uint8_t *addr_2, int ttl) {
  if (data->entries == NULL) {
    data->entries = malloc(10 * sizeof(centry));
    data->cap = 10;
  } else if (data->size == data->cap) {
    data->cap *= 2;
    data->entries = realloc(data->entries, (data->cap) * sizeof(centry));
  }

  centry *entry = &data->entries[data->size];
  memcpy(entry->addr_1, addr_1, 6);
  memcpy(entry->addr_2, addr_2, 6);
  entry->ttl = ttl;
  data->size++;
}

void com_ap_data_free(com_ap_data *data) {
  free(data->entries);
  free(data);
}

typedef struct com_ap_data_list {
  com_ap_data **data;
  int size;
  int cap;
} com_ap_data_list;

com_ap_data_list *com_ap_data_list_new() {
  com_ap_data_list *list = malloc(sizeof(com_ap_data_list));
  list->data = NULL;
  list->size = 0;
  list->cap = 0;
  return list;
}

void com_ap_data_list_add(com_ap_data_list *list, com_ap_data *data) {
  if (list->data == NULL) {
    list->data = malloc(10 * sizeof(com_ap_data *));
    list->cap = 10;
  } else if (list->size == list->cap) {
    list->cap *= 2;
    list->data = realloc(list->data, (list->cap) * sizeof(com_ap_data *));
  }

  list->data[list->size] = data;
  list->size++;
}






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

int mac_equal(const uint8_t *mac1, const uint8_t *mac2)
{
  return memcmp(mac1, mac2, 6) == 0;
}

#define clear() printf("\033[H\033[J")

mac_header parse_mac_header(const uint8_t *mac_header_bytes)
{
  mac_header hdr;
  memcpy(hdr.frame_control, mac_header_bytes, 2);
  memcpy(hdr.duration_id, mac_header_bytes + 2, 2);
  memcpy(hdr.address1, mac_header_bytes + 4, 6);
  memcpy(hdr.address2, mac_header_bytes + 10, 6);
  memcpy(hdr.address3, mac_header_bytes + 16, 6);
  memcpy(hdr.sequence_control, mac_header_bytes + 24, 2);
  // Copy other fields as needed
  return hdr;
}

frame_control parse_frame_control(const uint8_t *frame_control_byte)
{
  frame_control fc;
  fc.version = (*frame_control_byte) & 0x03;
  fc.type = ((*frame_control_byte) >> 2) & 0x03;
  fc.subtype = ((*frame_control_byte) >> 4) & 0x0F;
  fc.to_ds = ((*frame_control_byte) >> 8) & 0x01;
  fc.from_ds = ((*frame_control_byte) >> 9) & 0x01;
  fc.more_frag = ((*frame_control_byte) >> 10) & 0x01;
  fc.retry = ((*frame_control_byte) >> 11) & 0x01;
  fc.pwr_mgt = ((*frame_control_byte) >> 12) & 0x01;
  fc.more_data = ((*frame_control_byte) >> 13) & 0x01;
  fc.wep = ((*frame_control_byte) >> 14) & 0x01;
  fc.order = ((*frame_control_byte) >> 15) & 0x01;
  return fc;
}

typedef struct ieee80211_radiotap_header
{
  u_int8_t it_version;
  u_int8_t it_pad;
  u_int16_t it_len;
  u_int32_t it_present;
} radiotap_header;

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

com_ap_data_list *ap_list;

void main_loop(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
  radiotap_header *rdiohdr;
  rdiohdr = (radiotap_header *)(bytes);

  const uint8_t *frame_control_byte = bytes + rdiohdr->it_len;
  frame_control fc = parse_frame_control(frame_control_byte);

  uint8_t *source_address, *destination_address, *bssid;
  mac_header hdr = parse_mac_header(frame_control_byte);

  if (fc.to_ds == 0)
  {
    destination_address = hdr.address1;

    if (fc.from_ds == 0)
    {
      source_address = hdr.address2;
      bssid = hdr.address3;
    }
    else
    {
      source_address = hdr.address3;
      bssid = hdr.address2;
    }
  }
  else
  {
    destination_address = hdr.address3;

    if (fc.from_ds == 0)
    {
      source_address = hdr.address2;
      bssid = hdr.address1;
    }
    else
    {
      source_address = hdr.address1;
      bssid = hdr.address2;
    }
  }

  if (fc.type == 0 && fc.subtype == 0b1000)
  {
    beacon_frame_body *beacon_frame = (beacon_frame_body *)(bytes + rdiohdr->it_len + sizeof(mac_header));

    char ssid[33];
    memcpy(ssid, beacon_frame->ssid.ssid, beacon_frame->ssid.length);
    ssid[beacon_frame->ssid.length] = '\0';

    int found = 0;

    for (int i = 0; i < ap_list->size; i++)
    {
      if (mac_equal(ap_list->data[i]->bssid, bssid))
      {
        found = 1;
        break;
      }
    }

    if (!found)
    {
      com_ap_data *data = com_ap_data_new(bssid, ssid);
      com_ap_data_list_add(ap_list, data);
    }

    return;
  }

  if (!(fc.type == 0b10 && fc.subtype == 0b0000)) {
    return;
  }

  com_ap_data *current_ap = NULL;

  for (int i = 0; i < ap_list->size; i++)
  {
    if (mac_equal(ap_list->data[i]->bssid, bssid))
    {
      current_ap = ap_list->data[i];
      break;
    }
  }

  if (current_ap == NULL)
  {
    return;
  }

  int found = 0;

  for (int i = 0; i < current_ap->size; i++)
  {
    centry *entry = &current_ap->entries[i];
    if ((mac_equal(entry->addr_1, source_address) && mac_equal(entry->addr_2, destination_address))
    || (mac_equal(entry->addr_2, source_address) && mac_equal(entry->addr_1, destination_address)))
    {
      entry->ttl = START_TTL;
      found = 1;
      break;
    }
  }

  if (!found)
  {
    com_ap_data_add_entry(current_ap, source_address, destination_address, START_TTL);
  }

  clear();

  for (int i = 0; i < ap_list->size; i++)
  {
    com_ap_data *data = ap_list->data[i];
    printf("BSSID: " MACSTR " SSID: %s\n", MAC2STR(data->bssid), data->ssid);
    for (int j = 0; j < data->size; j++)
    {
      centry *entry = &data->entries[j];
      printf("  %d. " MACSTR " <-> " MACSTR " TTL: %d", j + 1, MAC2STR(entry->addr_1), MAC2STR(entry->addr_2), entry->ttl);
      entry->ttl--;
      if (entry->ttl <= 0)
      {
        data->size--;
        for (int k = j; k < data->size; k++)
        {
          data->entries[k] = data->entries[k + 1];
        }
        j--;
      }

      free(entry);
    }
    printf("\n");
  }
}

int main(int argc, char *argv[])
{
  atexit(cleanup);
  signal(SIGINT, stop);

  if (argc != 2)
  {
    printf("Usage: %s <interface>\n", argv[0]);
    return 1;
  }

  bpf_u_int32 netp, maskp;
  struct bpf_program fp;

  char *interface = argv[1];

  errbuf = malloc(PCAP_ERRBUF_SIZE);
  handle = pcap_create(interface, errbuf);

  if (pcap_set_promisc(handle, 1) != 0)
  {
    printf("Failed to set monitor mode.\n");
    exit(EXIT_FAILURE);
  }

  if (pcap_set_rfmon(handle, 1) != 0)
  {
    printf("Failed to set monitor mode.\n");
    exit(EXIT_FAILURE);
  }

  pcap_set_snaplen(handle, 65535);
  pcap_set_timeout(handle, 1000);

  if (pcap_activate(handle) != 0)
  {
    printf("pcap_activate() failed\n");
    exit(EXIT_FAILURE);
  }

  pcap_lookupnet(interface, &netp, &maskp, errbuf);
  pcap_compile(handle, &fp, "type mgt subtype beacon || type data subtype data", 0, maskp);

  if (pcap_setfilter(handle, &fp) < 0)
  {
    pcap_perror(handle, "pcap_setfilter()");
    exit(EXIT_FAILURE);
  }

  if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO)
  {
    printf("Wrong datalink type\n");
    exit(EXIT_FAILURE);
  }

  ap_list = com_ap_data_list_new();

  pcap_loop(handle, -1, main_loop, NULL);

  return 0;
}

void cleanup()
{
  if (handle != NULL)
  {
    pcap_close(handle);
  }

  if (errbuf != NULL)
  {
    free(errbuf);
  }

  if (ap_list != NULL)
  {
    for (int i = 0; i < ap_list->size; i++)
    {
      com_ap_data_free(ap_list->data[i]);
    }
    free(ap_list->data);
    free(ap_list);
  }
}

void stop(int signum)
{
  exit(EXIT_SUCCESS);
}