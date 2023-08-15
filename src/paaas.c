#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bsp/board.h"
#include "tusb.h"

#include "hardware/gpio.h"

#include "pico/cyw43_arch.h"
#include "pico/stdio.h"

#include "lwip/pbuf.h"
#include "lwip/udp.h"

#include "config.h"

// These IDs are bogus. If you want to distribute any hardware using this,
// you will have to get real ones.
#define USB_VID 0xCAFE
#define USB_PID 0xBABA

#define PIN_UP 2
#define PIN_DOWN 3
#define PIN_LEFT 5
#define PIN_RIGHT 4
#define PIN_CROSS 6
#define PIN_CIRCLE 7
#define PIN_TRIANGLE 11
#define PIN_SQUARE 10
#define PIN_L1 13
#define PIN_L2 9
#define PIN_R1 12
#define PIN_R2 8
#define PIN_SELECT 16
#define PIN_START 17
#define PIN_L3 18
#define PIN_R3 19
#define PIN_PS 20
#define PIN_TOUCHPAD 21

uint32_t pin_mask = 1 << PIN_UP | 1 << PIN_DOWN | 1 << PIN_LEFT | 1 << PIN_RIGHT | 1 << PIN_CROSS | 1 << PIN_CIRCLE | 1 << PIN_TRIANGLE | 1 << PIN_SQUARE | 1 << PIN_L1 | 1 << PIN_L2 | 1 << PIN_R1 | 1 << PIN_R2 | 1 << PIN_SELECT | 1 << PIN_START | 1 << PIN_L3 | 1 << PIN_R3 | 1 << PIN_PS;

struct udp_pcb* pcb;
ip_addr_t server_address;

uint8_t nonce_id;
uint8_t nonce[280];
uint8_t signature[1064];
uint8_t signature_part = 0;
uint8_t signature_ready = 0;
uint8_t nonce_ready = 0;

int stickMode = 0;  // 0 = dpad, 1 = left stick

tusb_desc_device_t const desc_device = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bDeviceClass = 0x00,
    .bDeviceSubClass = 0x00,
    .bDeviceProtocol = 0x00,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,

    .idVendor = USB_VID,
    .idProduct = USB_PID,
    .bcdDevice = 0x0100,

    .iManufacturer = 0x01,
    .iProduct = 0x02,
    .iSerialNumber = 0x00,

    .bNumConfigurations = 0x01
};

// Razer Raion
uint8_t const desc_hid_report[] = {
    0x05, 0x01,        // Usage Page (Generic Desktop Ctrls)
    0x09, 0x05,        // Usage (Game Pad)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0x01,        //   Report ID (1)
    0x09, 0x30,        //   Usage (X)
    0x09, 0x31,        //   Usage (Y)
    0x09, 0x32,        //   Usage (Z)
    0x09, 0x35,        //   Usage (Rz)
    0x15, 0x00,        //   Logical Minimum (0)
    0x26, 0xFF, 0x00,  //   Logical Maximum (255)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x04,        //   Report Count (4)
    0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x09, 0x39,        //   Usage (Hat switch)
    0x15, 0x00,        //   Logical Minimum (0)
    0x25, 0x07,        //   Logical Maximum (7)
    0x35, 0x00,        //   Physical Minimum (0)
    0x46, 0x3B, 0x01,  //   Physical Maximum (315)
    0x65, 0x14,        //   Unit (System: English Rotation, Length: Centimeter)
    0x75, 0x04,        //   Report Size (4)
    0x95, 0x01,        //   Report Count (1)
    0x81, 0x42,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,Null State)
    0x65, 0x00,        //   Unit (None)
    0x05, 0x09,        //   Usage Page (Button)
    0x19, 0x01,        //   Usage Minimum (0x01)
    0x29, 0x0E,        //   Usage Maximum (0x0E)
    0x15, 0x00,        //   Logical Minimum (0)
    0x25, 0x01,        //   Logical Maximum (1)
    0x75, 0x01,        //   Report Size (1)
    0x95, 0x0E,        //   Report Count (14)
    0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x06, 0x00, 0xFF,  //   Usage Page (Vendor Defined 0xFF00)
    0x09, 0x20,        //   Usage (0x20)
    0x75, 0x06,        //   Report Size (6)
    0x95, 0x01,        //   Report Count (1)
    0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x05, 0x01,        //   Usage Page (Generic Desktop Ctrls)
    0x09, 0x33,        //   Usage (Rx)
    0x09, 0x34,        //   Usage (Ry)
    0x15, 0x00,        //   Logical Minimum (0)
    0x26, 0xFF, 0x00,  //   Logical Maximum (255)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x02,        //   Report Count (2)
    0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x06, 0x00, 0xFF,  //   Usage Page (Vendor Defined 0xFF00)
    0x09, 0x21,        //   Usage (0x21)
    0x95, 0x36,        //   Report Count (54)
    0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x85, 0x05,        //   Report ID (5)
    0x09, 0x22,        //   Usage (0x22)
    0x95, 0x1F,        //   Report Count (31)
    0x91, 0x02,        //   Output (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0x85, 0x03,        //   Report ID (3)
    0x0A, 0x21, 0x27,  //   Usage (0x2721)
    0x95, 0x2F,        //   Report Count (47)
    0xB1, 0x02,        //   Feature (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0x06, 0x80, 0xFF,  //   Usage Page (Vendor Defined 0xFF80)
    0x85, 0xE0,        //   Report ID (-32)
    0x09, 0x57,        //   Usage (0x57)
    0x95, 0x02,        //   Report Count (2)
    0xB1, 0x02,        //   Feature (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0xC0,              // End Collection
    0x06, 0xF0, 0xFF,  // Usage Page (Vendor Defined 0xFFF0)
    0x09, 0x40,        // Usage (0x40)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0xF0,        //   Report ID (-16)
    0x09, 0x47,        //   Usage (0x47)
    0x95, 0x3F,        //   Report Count (63)
    0xB1, 0x02,        //   Feature (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0x85, 0xF1,        //   Report ID (-15)
    0x09, 0x48,        //   Usage (0x48)
    0x95, 0x3F,        //   Report Count (63)
    0xB1, 0x02,        //   Feature (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0x85, 0xF2,        //   Report ID (-14)
    0x09, 0x49,        //   Usage (0x49)
    0x95, 0x0F,        //   Report Count (15)
    0xB1, 0x02,        //   Feature (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0x85, 0xF3,        //   Report ID (-13)
    0x0A, 0x01, 0x47,  //   Usage (0x4701)
    0x95, 0x07,        //   Report Count (7)
    0xB1, 0x02,        //   Feature (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0xC0,              // End Collection
};

#define CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_HID_DESC_LEN)
#define EPNUM_HID 0x81

uint8_t const desc_configuration[] = {
    // Config number, interface count, string index, total length, attribute, power in mA
    TUD_CONFIG_DESCRIPTOR(1, 1, 0, CONFIG_TOTAL_LEN, 0, 100),

    // Interface number, string index, protocol, report descriptor len, EP In address, size & polling interval
    TUD_HID_DESCRIPTOR(0, 0, HID_ITF_PROTOCOL_NONE, sizeof(desc_hid_report), EPNUM_HID, CFG_TUD_HID_EP_BUFSIZE, 1)
};

char const* string_desc_arr[] = {
    (const char[]){ 0x09, 0x04 },  // 0: is supported language is English (0x0409)
    "Hosaka",                      // 1: Manufacturer
    "PAAAS POC",                   // 2: Product
};

// Razer Raion
const uint8_t output_0x03[] = {
    0x21, 0x27, 0x04, 0xc0, 0x07, 0x2c, 0x56,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x0d, 0x0d, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

const uint8_t output_0xf3[] = { 0x0, 0x38, 0x38, 0, 0, 0, 0 };

// HID report
typedef struct __attribute__((packed)) {
    uint8_t leftStickXAxis;
    uint8_t leftStickYAxis;
    uint8_t rightStickXAxis;
    uint8_t rightStickYAxis;
    uint32_t dpadHat : 4;
    uint32_t square : 1;
    uint32_t cross : 1;
    uint32_t circle : 1;
    uint32_t triangle : 1;
    uint32_t L1 : 1;
    uint32_t R1 : 1;
    uint32_t L2 : 1;
    uint32_t R2 : 1;
    uint32_t select : 1;
    uint32_t start : 1;
    uint32_t L3 : 1;
    uint32_t R3 : 1;
    uint32_t PS : 1;
    uint32_t touchpad : 1;
    uint32_t counter : 6;
    uint8_t L2Axis;
    uint8_t R2Axis;

    uint8_t whatever[54];
} hid_report_t;

hid_report_t report;
hid_report_t prevReport;

void dpad(bool up, bool down, bool left, bool right) {
    if (up && down) {
        up = down = false;
    }
    if (left && right) {
        left = right = false;
    }

    switch (stickMode) {
        case 0:
            if (up && !right && !left)
                report.dpadHat = 0;
            else if (up && right)
                report.dpadHat = 1;
            else if (right && !up && !down)
                report.dpadHat = 2;
            else if (right && down)
                report.dpadHat = 3;
            else if (down && !right && !left)
                report.dpadHat = 4;
            else if (down && left)
                report.dpadHat = 5;
            else if (left && !down && !up)
                report.dpadHat = 6;
            else if (left && up)
                report.dpadHat = 7;
            else
                report.dpadHat = 0x0f;
            break;
        case 1:
            report.leftStickXAxis = left ? 0x00 : (right ? 0xFF : 0x80);
            report.leftStickYAxis = up ? 0x00 : (down ? 0xFF : 0x80);
            break;
    }
}

void send_hid_report() {
    if (!tud_hid_ready()) {
        return;
    }

    if (memcmp(&prevReport, &report, sizeof(report))) {
        tud_hid_report(1, &report, sizeof(report));
        memcpy(&prevReport, &report, sizeof(report));
    }
}

void hid_task(void) {
    memset(&report, 0, sizeof(report));

    uint32_t pins = ~gpio_get_all() & pin_mask;

    report.leftStickXAxis = 0x80;
    report.leftStickYAxis = 0x80;
    report.rightStickXAxis = 0x80;
    report.rightStickYAxis = 0x80;

    dpad(pins & (1 << PIN_UP),
        pins & (1 << PIN_DOWN),
        pins & (1 << PIN_LEFT),
        pins & (1 << PIN_RIGHT));

//    report.dpadHat = ((time_us_64() / 1000000) % 2) ? 2 : 6;

    report.square = !!(pins & (1 << PIN_SQUARE));
    report.cross = !!(pins & (1 << PIN_CROSS));
    report.circle = !!(pins & (1 << PIN_CIRCLE));
    report.triangle = !!(pins & (1 << PIN_TRIANGLE));
    report.L1 = !!(pins & (1 << PIN_L1));
    report.R1 = !!(pins & (1 << PIN_R1));
    report.L2 = !!(pins & (1 << PIN_L2));
    report.R2 = !!(pins & (1 << PIN_R2));
    report.L2Axis = report.L2 ? 0xff : 0;
    report.R2Axis = report.R2 ? 0xff : 0;
    report.select = !!(pins & (1 << PIN_SELECT));
    report.start = !!(pins & (1 << PIN_START));
    report.L3 = !!(pins & (1 << PIN_L3));
    report.R3 = !!(pins & (1 << PIN_R3));
    report.PS = !!(pins & (1 << PIN_PS));
    report.touchpad = !!(pins & (1 << PIN_TOUCHPAD));

    send_hid_report();
}

void pin_init(uint pin) {
    gpio_init(pin);
    gpio_set_dir(pin, GPIO_IN);
    gpio_pull_up(pin);
}

void pins_init(void) {
    pin_init(PIN_UP);
    pin_init(PIN_DOWN);
    pin_init(PIN_LEFT);
    pin_init(PIN_RIGHT);
    pin_init(PIN_CROSS);
    pin_init(PIN_CIRCLE);
    pin_init(PIN_TRIANGLE);
    pin_init(PIN_SQUARE);
    pin_init(PIN_L1);
    pin_init(PIN_L2);
    pin_init(PIN_R1);
    pin_init(PIN_R2);
    pin_init(PIN_SELECT);
    pin_init(PIN_START);
    pin_init(PIN_L3);
    pin_init(PIN_R3);
    pin_init(PIN_PS);
    pin_init(PIN_TOUCHPAD);

    // if left is held when plugged in, switch to left stick emulation mode
    if (!gpio_get(PIN_LEFT)) {
        stickMode = 1;
    }
}

void report_init(void) {
    memset(&report, 0, sizeof(report));
    memcpy(&prevReport, &report, sizeof(report));
}

void net_recv(void* arg, struct udp_pcb* pcb, struct pbuf* p, const ip_addr_t* addr, u16_t port) {
    printf("Received signature from server.\n");
    /*
        for (int i = 0; i < 1064; i++) {
            printf("%02x ", pbuf_get_at(p, i));
        }
        printf("\n");
    */
    for (int i = 0; i < sizeof(signature); i++) {
        signature[i] = pbuf_get_at(p, i);
    }
    signature_part = 0;
    signature_ready = 1;
    pbuf_free(p);
}

void net_init() {
    ipaddr_aton(SERVER_IP_ADDRESS, &server_address);
    pcb = udp_new();
    udp_recv(pcb, net_recv, NULL);
}

void net_send() {
    printf("Sending nonce to server...\n");
    struct pbuf* p = pbuf_alloc(PBUF_TRANSPORT, 257, PBUF_RAM);
    uint8_t* req = (uint8_t*) p->payload;
    req[0] = nonce_id;
    memcpy(&req[1], nonce, 256);
    udp_sendto(pcb, p, &server_address, 6969);
    pbuf_free(p);
}

void net_task() {
    if (nonce_ready) {
        net_send();
        nonce_ready = 0;
    }
}

int main(void) {
    board_init();
    pins_init();
    report_init();
    stdio_init_all();

    printf("Connecting to wifi... ");

    cyw43_arch_init();
    cyw43_arch_enable_sta_mode();
    if (cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 10000)) {
        printf("failed\n");
        return 1;
    }

    printf("OK\n");
    cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);

    net_init();

    tusb_init();

    while (1) {
        tud_task();
        hid_task();
        cyw43_arch_poll();
        net_task();
    }

    return 0;
}

uint8_t const* tud_descriptor_device_cb(void) {
    return (uint8_t const*) &desc_device;
}

uint8_t const* tud_hid_descriptor_report_cb(uint8_t itf) {
    return desc_hid_report;
}

uint16_t tud_hid_get_report_cb(uint8_t itf, uint8_t report_id, hid_report_type_t report_type, uint8_t* buffer, uint16_t reqlen) {
    switch (report_id) {
        case 0x03:
            memcpy(buffer, output_0x03, reqlen);
            return reqlen;
        case 0xF3:
            memcpy(buffer, output_0xf3, reqlen);
            signature_ready = false;
            return reqlen;
        case 0xF1: {  // GET_SIGNATURE_NONCE
            buffer[0] = nonce_id;
            buffer[1] = signature_part;
            buffer[2] = 0;
            if (signature_part == 0) {
                printf("Sending signature to PS5");
            }
            printf(".");
            memcpy(&buffer[3], &signature[signature_part * 56], 56);
            signature_part++;
            if (signature_part == 19) {
                signature_part = 0;
                printf("\n");
            }
            return reqlen;
        }
        case 0xF2: {  // GET_SIGNING_STATE
            printf("PS5 asks if signature ready (%s).\n", signature_ready ? "yes" : "no");
            buffer[0] = nonce_id;
            buffer[1] = signature_ready ? 0 : 16;
            memset(&buffer[2], 0, 9);
            return reqlen;
        }
    }
    return reqlen;
}

void tud_hid_set_report_cb(uint8_t itf, uint8_t report_id, hid_report_type_t report_type, uint8_t const* buffer, uint16_t bufsize) {
    if (report_id == 0xF0) {  // SET_AUTH_PAYLOAD
        nonce_id = buffer[0];
        uint8_t part = buffer[1];
        if (part == 0) {
            printf("Getting nonce from PS5");
        }
        printf(".");
        if (part > 4) {
            return;
        }
        memcpy(&nonce[part * 56], &buffer[3], 56);
        if (part == 4) {
            nonce_ready = 1;
            printf("\n");
        }
    }
}

uint8_t const* tud_descriptor_configuration_cb(uint8_t index) {
    return desc_configuration;
}

static uint16_t _desc_str[32];

// Invoked when received GET STRING DESCRIPTOR request
// Application return pointer to descriptor, whose contents must exist long enough for transfer to complete
uint16_t const* tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    uint8_t chr_count;

    if (index == 0) {
        memcpy(&_desc_str[1], string_desc_arr[0], 2);
        chr_count = 1;
    } else {
        // Note: the 0xEE index string is a Microsoft OS 1.0 Descriptors.
        // https://docs.microsoft.com/en-us/windows-hardware/drivers/usbcon/microsoft-defined-usb-descriptors

        if (!(index < sizeof(string_desc_arr) / sizeof(string_desc_arr[0])))
            return NULL;

        const char* str = string_desc_arr[index];

        // Cap at max char
        chr_count = strlen(str);
        if (chr_count > 31)
            chr_count = 31;

        // Convert ASCII string into UTF-16
        for (uint8_t i = 0; i < chr_count; i++) {
            _desc_str[1 + i] = str[i];
        }
    }

    // first byte is length (including header), second byte is string type
    _desc_str[0] = (TUSB_DESC_STRING << 8) | (2 * chr_count + 2);

    return _desc_str;
}
