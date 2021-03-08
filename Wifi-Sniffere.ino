#include "esp_wifi.h"

String maclist[64][3]; 
int listcount = 0;

typedef struct
{
  unsigned interval:16;
  unsigned capability:16;
  unsigned tag_number:8;
  unsigned tag_length:8;
  char ssid[0];
  uint8_t rates[1];
} wifi_mgmt_beacon_t;

typedef enum
{
    ASSOCIATION_REQ,
    ASSOCIATION_RES,
    REASSOCIATION_REQ,
    REASSOCIATION_RES,
    PROBE_REQ,
    PROBE_RES,
    NU1,  /* ......................*/
    NU2,  /* 0110, 0111 not used */
    BEACON,
    ATIM,
    DISASSOCIATION,
    AUTHENTICATION,
    DEAUTHENTICATION,
    ACTION,
    ACTION_NACK,
} wifi_mgmt_subtypes_t;

//Parses 802.11 packet type-subtype pair into a human-readable string
const char* wifi_pkt_type2str(wifi_promiscuous_pkt_type_t type, wifi_mgmt_subtypes_t subtype)
{
    switch(type)
    {
        case WIFI_PKT_MGMT:
            switch(subtype)
            {
                case ASSOCIATION_REQ:
                    return "Mgmt: Association request";
                case ASSOCIATION_RES:
                    return "Mgmt: Association response";
                case REASSOCIATION_REQ:
                    return "Mgmt: Reassociation request";
                case REASSOCIATION_RES:
                    return "Mgmt: Reassociation response";
                case PROBE_REQ:
                    return "Mgmt: Probe request";
                case PROBE_RES:
                    return "Mgmt: Probe response";
                case BEACON:
                    return "Mgmt: Beacon frame";
                case ATIM:
                    return "Mgmt: ATIM";
                case DISASSOCIATION:
                    return "Mgmt: Dissasociation";
                case AUTHENTICATION:
                    return "Mgmt: Authentication";
                case DEAUTHENTICATION:
                    return "Mgmt: Deauthentication";
                case ACTION:
                    return "Mgmt: Action";
                case ACTION_NACK:
                    return "Mgmt: Action no ack";
                default:
                    return "Mgmt: Unsupported/error";
            }

        case WIFI_PKT_CTRL:
            return "Control";

        case WIFI_PKT_DATA:
            return "Data";

        default:
            return "Unsupported/error";
    }
}


typedef struct
{
    unsigned protocol:2;
    unsigned type:2;
    unsigned subtype:4;
    unsigned to_ds:1;
    unsigned from_ds:1;
    unsigned more_frag:1;
    unsigned retry:1;
    unsigned pwr_mgmt:1;
    unsigned more_data:1;
    unsigned wep:1;
    unsigned strict:1;
} wifi_header_frame_control_t;

typedef struct
{
    wifi_header_frame_control_t frame_ctrl;
    uint8_t addr1[6]; /* receiver address */
    uint8_t addr2[6]; /* sender address */
    uint8_t addr3[6]; /* filtering address */
    unsigned sequence_ctrl:16;
    uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct
{
    wifi_ieee80211_mac_hdr_t hdr;
    uint8_t payload[2]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

String defaultTTL = "60"; // Maximum time (Apx seconds) elapsed before device is consirded offline

const wifi_promiscuous_filter_t filt={ //Idk what this does
    //.filter_mask=WIFI_PROMIS_FILTER_MASK_MGMT|WIFI_PROMIS_FILTER_MASK_DATA
    .filter_mask=WIFI_PROMIS_FILTER_MASK_CTRL|WIFI_PROMIS_FILTER_MASK_DATA
};

void mac2str(const uint8_t* ptr, char* string)
{
  sprintf(string, "%02x:%02x:%02x:%02x:%02x:%02x", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
  return;
}

#define maxCh 11 //max Channel -> US = 11, EU = 13, Japan = 14

int curChannel = 1;

void sniffer(void* buff, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
  const uint8_t *data = ipkt->payload;
  const wifi_header_frame_control_t *frame_ctrl = (wifi_header_frame_control_t *)&hdr->frame_ctrl;
  
  char addr1[] = "00:00:00:00:00:00\0";
  char addr2[] = "00:00:00:00:00:00\0";
  char addr3[] = "00:00:00:00:00:00\0";

  mac2str(hdr->addr1, addr1);
  mac2str(hdr->addr2, addr2);
  mac2str(hdr->addr3, addr3);

  // Output info to serial
  Serial.printf("\n%s | %s | %s | %2u | %02d | %u | %u(%-2u) | %-28s | %u | %u | %u | %u | %u | %u | %u | %u | ",
    addr1,
    addr2,
    addr3,
    curChannel,
    ppkt->rx_ctrl.rssi,
    frame_ctrl->protocol,
    frame_ctrl->type,
    frame_ctrl->subtype,
    wifi_pkt_type2str((wifi_promiscuous_pkt_type_t)frame_ctrl->type, (wifi_mgmt_subtypes_t)frame_ctrl->subtype),
    frame_ctrl->to_ds,
    frame_ctrl->from_ds,
    frame_ctrl->more_frag,
    frame_ctrl->retry,
    frame_ctrl->pwr_mgmt,
    frame_ctrl->more_data,
    frame_ctrl->wep,
    frame_ctrl->strict);

  // Print ESSID if beacon
  if (frame_ctrl->type == WIFI_PKT_MGMT && frame_ctrl->subtype == BEACON)
  {
    const wifi_mgmt_beacon_t *beacon_frame = (wifi_mgmt_beacon_t*) ipkt->payload;
    char ssid[32] = {0};

    if (beacon_frame->tag_length >= 32)
    {
      strncpy(ssid, beacon_frame->ssid, 31);
    }
    else
    {
      strncpy(ssid, beacon_frame->ssid, beacon_frame->tag_length);
    }

    Serial.printf("%s", ssid);
  }
}



//===== SETUP =====//
void setup() {

  /* start Serial */
  Serial.begin(115200);

  /* setup wifi */
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
  esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);

  delay(5000);
  Serial.printf("\n\n     MAC Address 1|      MAC Address 2|      MAC Address 3|  Ch| RSSI| Pr| T(S)  |           Frame type         |TDS|FDS| MF|RTR|PWR| MD|ENC|STR|   SSID");
}


//===== LOOP =====//
void loop() {
    if(curChannel > maxCh){ 
      curChannel = 1;
    }
    esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
    delay(100);
    curChannel++;
}
