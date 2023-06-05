#ifndef HCIWRAP_H
#define HCIWRAP_H

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

int hci_open_socket();
int hci_get_devices(int ctl, struct hci_dev_list_req *dl);
int hci_get_device_info(int ctl, struct hci_dev_info *di);

#endif // HCIWRAP_H
