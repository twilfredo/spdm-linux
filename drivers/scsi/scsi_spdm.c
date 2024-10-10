// SPDX-License-Identifier: GPL-2.0
/*
 * Support for SPDM over SCSI Security In/Out commands as defined by the
 * DMTF DSP0286 and SCSI Primary Commands 6 (SPC-6)
 * Copyright (c) 2024, Western Digital Corporation or its affiliates.
 */
#include <scsi/scsi_device.h>
#include <scsi/scsi_driver.h>
#include <linux/spdm.h>

#include "sd.h"

static ssize_t scsi_security_spdm_transceive(void *priv, struct device *dev,
				 const void *request, size_t request_sz,
				 void *response, size_t response_sz)
{
	struct scsi_disk *sdkp = priv;
	ssize_t rc;
	uint16_t spsp;
	uint8_t conn_id = 0;

	/* The SPDM layer currently does not support secured messages */
	spsp = SPDM_STORAGE_OPERATION_CODE_MESSAGE << 2;
	spsp |= conn_id & 0x3;

	/* Submit SPDM Request */
	rc = sd_sec_submit(sdkp, spsp, SCSI_SECURITY_DMTF_SPDM, (void *)request,
			request_sz, true);
	if (rc)
		return -EIO;

	/* Receive SPDM Response */
	spsp = SPDM_STORAGE_OPERATION_CODE_MESSAGE << 2;
	rc = sd_sec_submit(sdkp, spsp, SCSI_SECURITY_DMTF_SPDM, response,
			response_sz, false);
	if (rc)
		return -EIO;

	return response_sz;
}

/*
 * scsi_spdm_reauthenticate() - Perform SCSI-SPDM authentication again
 *
 * Can be called by drivers after device identity has mutated,
 * e.g. after downloading firmware to an FPGA device.
 */
void scsi_spdm_reauthenticate(struct device *dev)
{
	struct scsi_disk *sdkp = dev_get_drvdata(dev);

	if (sdkp->spdm_state)
		spdm_authenticate(sdkp->spdm_state);
}

void scsi_spdm_destroy(struct device *dev)
{
	struct scsi_disk *sdkp = dev_get_drvdata(dev);

	if (sdkp->spdm_state)
		spdm_destroy(sdkp->spdm_state);

	if (sdkp->spdm_keyring) {
		key_revoke(sdkp->spdm_keyring);
		key_put(sdkp->spdm_keyring);
		sdkp->spdm_keyring = NULL;
	}
	scsi_spdm_disable(dev);
}

void scsi_spdm_init(struct device *dev)
{
	struct scsi_disk *sdkp = dev_get_drvdata(dev);
	char keyring_name[32];
	bool keyring_empty = false;

	if (!sdkp->security_spdm)
		return;
	/*
	 * TODO CHECK!: Can scsi be over PCI? in which case if CMA is enabled and
	 * a session exists, we don't want to do another. Double check this
	 * case!
	 */
	snprintf(keyring_name, 32, ".scsi_spdm_%s", sdkp->disk->disk_name);

	/*
	 * We could be here from a controller reset context so the keyring already
	 * exists.
	 */
	if (!sdkp->spdm_keyring) {
		sdkp->spdm_keyring = keyring_alloc(keyring_name, KUIDT_INIT(0),
								KGIDT_INIT(0), current_cred(),
								(KEY_POS_ALL & ~KEY_POS_SETATTR) |
								KEY_USR_VIEW | KEY_USR_READ |
								KEY_USR_WRITE | KEY_USR_SEARCH,
								KEY_ALLOC_NOT_IN_QUOTA |
								KEY_ALLOC_SET_KEEP, NULL, NULL);
		keyring_empty = true;
	}

	if (IS_ERR(sdkp->spdm_keyring)) {
		sdkp->spdm_keyring = NULL;
		sd_printk(KERN_ERR, sdkp, "Could not allocate %s keyring\n", keyring_name);
		return;
	}

	sdkp->spdm_state = spdm_create(dev, scsi_security_spdm_transceive,
					sdkp, SPDM_STORAGE_MAX_SIZE_IN_BYTE, sdkp->spdm_keyring,
					NULL);
	if (!sdkp->spdm_state) {
		sd_printk(KERN_ERR, sdkp, "Failed to allocate an SPDM session\n");
		return;
	}

	/*
	 * No reason to authenticate if the keyring is empty, this is only useful
	 * from a device reset context, where userspace has already poked
	 * certificates in.
	 */
	if (!keyring_empty)
		spdm_authenticate(sdkp->spdm_state);
}

bool dev_is_scsi(struct device *dev)
{
	if (dev && dev->parent->bus && !strcmp(dev->parent->bus->name, "scsi"))
		return true;

	return false;
}

struct spdm_state *scsi_dev_to_spdm_state(struct device *dev)
{
	struct scsi_disk *sdkp = dev_get_drvdata(dev);

	return sdkp ? sdkp->spdm_state : NULL;
}

#ifdef CONFIG_SYSFS
const struct attribute_group *scsi_spdm_attr_groups[] = {
	&spdm_attr_group,
	&spdm_certificates_group,
	&spdm_signatures_group,
	NULL,
};

/*
 * This function should be called only once an SPDM session has been established
 * using the SPDM over SCSI Storage transport
 */
int scsi_spdm_update_sysfs(struct device *dev)
{
	int rc;
	struct scsi_disk *sdkp = dev_get_drvdata(dev);

	rc = sysfs_update_group(&dev->kobj, &spdm_attr_group);
	if (rc) {
		sd_printk(KERN_ERR, sdkp, "failed to update sysfs spdm_attr_group: %d",
			rc);
		return rc;
	}

	rc = sysfs_update_group(&dev->kobj, &spdm_certificates_group);
	if (rc) {
		sd_printk(KERN_ERR, sdkp, "failed to update sysfs spdm_certificates_group: %d",
			rc);
		return rc;
	}

	rc = sysfs_update_group(&dev->kobj, &spdm_signatures_group);
	if (rc) {
		sd_printk(KERN_ERR, sdkp, "failed to update sysfs spdm_signatures_group: %d", rc);
		return rc;
	}

	return 0;
}

void scsi_spdm_publish(struct device *dev)
{
	struct scsi_disk *sdkp = dev_get_drvdata(dev);

	if (sdkp->spdm_state)
		spdm_publish_log(sdkp->spdm_state);
}
#endif
