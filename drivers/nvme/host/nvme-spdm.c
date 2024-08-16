// SPDX-License-Identifier: GPL-2.0
/*
 * Support for SPDM over NVMe Security Admin Commands
 * Copyright (c) 2024, Western Digital Corporation or its affiliates.
 */
#include "nvme.h"

static ssize_t nvme_security_spdm_transceive(void *priv, struct device *dev,
				 const void *request, size_t request_sz,
				 void *response, size_t response_sz)
{
	struct nvme_ctrl *ctrl = priv;
	ssize_t rc;
	uint16_t spsp;
	uint8_t conn_id = 0;

	/* The SPDM layer currently does not support secured messages */
	spsp = SPDM_STORAGE_OPERATION_CODE_MESSAGE << 2;
	spsp |= conn_id & 0x3;

	/* Submit SPDM Request */
	rc = nvme_sec_submit(ctrl, spsp, NVME_SECURITY_DMTF_SPDM, (void *)request,
			request_sz, true);
	if (rc)
		return -EIO;

	/* Receive SPDM Response */
	spsp = SPDM_STORAGE_OPERATION_CODE_MESSAGE << 2;
	rc = nvme_sec_submit(ctrl, spsp, NVME_SECURITY_DMTF_SPDM, response,
			response_sz, false);
	if (rc)
		return -EIO;

	return response_sz;
}

/*
 * nvme_spdm_reauthenticate() - Perform NVMe-SPDM authentication again
 * @ctrl: NVMe Controller to authenticate
 *
 * Can be called by drivers after device identity has mutated,
 * e.g. after downloading firmware to an FPGA device.
 */
void nvme_spdm_reauthenticate(struct device *dev)
{
	struct nvme_ctrl *ctrl = dev_get_drvdata(dev);

	if (ctrl->spdm_state)
		spdm_authenticate(ctrl->spdm_state);
}

void nvme_spdm_destroy(struct device *dev)
{
	struct nvme_ctrl *ctrl = dev_get_drvdata(dev);

	if (ctrl->spdm_state)
		spdm_destroy(ctrl->spdm_state);

	if (ctrl->spdm_keyring) {
		key_revoke(ctrl->spdm_keyring);
		key_put(ctrl->spdm_keyring);
		ctrl->spdm_keyring = NULL;
	}
	nvme_spdm_disable(dev);
}

/* Initialise an SPDM session using the SPDM over Storage transport protocol */
void nvme_spdm_init(struct device *dev)
{
	struct nvme_ctrl *ctrl = dev_get_drvdata(dev);

	if (!ctrl->security_spdm)
		return;

	/* Do not use the storage transport if PCI_CMA is utilized */
	if (dev_is_pci(ctrl->device->parent) &&
			(pci_dev_to_spdm_state(to_pci_dev(ctrl->device->parent)))) {
		dev_warn(ctrl->device,
			"PCI_CMA Configured already configured for SPDM");
		return;
	}

	/*
	 * We could be here from a controller reset context so the keyring already
	 * exists.
	 */
	if (!ctrl->spdm_keyring) {
		ctrl->spdm_keyring = keyring_alloc(".nvme_spdm", KUIDT_INIT(0),
						KGIDT_INIT(0), current_cred(),
						(KEY_POS_ALL & ~KEY_POS_SETATTR) |
						KEY_USR_VIEW | KEY_USR_READ |
						KEY_USR_WRITE | KEY_USR_SEARCH,
						KEY_ALLOC_NOT_IN_QUOTA |
						KEY_ALLOC_SET_KEEP, NULL, NULL);
	}

	if (IS_ERR(ctrl->spdm_keyring)) {
		ctrl->spdm_keyring = NULL;
		dev_err(ctrl->device, "NVMe: Could not allocate .nvme_spdm keyring\n");
		return;
	}

	ctrl->spdm_state = spdm_create(ctrl->device, nvme_security_spdm_transceive,
					   ctrl, SPDM_STORAGE_MAX_SIZE_IN_BYTE, ctrl->spdm_keyring,
					   NULL);

	if (!ctrl->spdm_state) {
		return;
	}

	/*
	 * Keep spdm_state allocated even if initial authentication fails
	 * to allow for provisioning of certificates and re-authentication.
	 */
	spdm_authenticate(ctrl->spdm_state);
}

#ifdef CONFIG_SYSFS
const struct attribute_group *spdm_attr_groups[] = {
	&spdm_attr_group,
	&spdm_certificates_group,
	&spdm_signatures_group,
	NULL,
};

/*
 * This function should be called only once an SPDM session has been established
 * using the SPDM over NVMe Storage transport
 */
 int nvme_spdm_update_sysfs(struct device *dev)
{
	int rc;

	rc = sysfs_update_group(&dev->kobj, &spdm_attr_group);
	if (rc) {
		dev_err(dev, "failed to update sysfs spdm_attr_group: %d", rc);
		return rc;
	}

	rc = sysfs_update_group(&dev->kobj, &spdm_certificates_group);
	if (rc) {
		dev_err(dev, "failed to update sysfs spdm_certificates_group: %d", rc);
		return rc;
	}

	rc = sysfs_update_group(&dev->kobj, &spdm_signatures_group);
	if (rc) {
		dev_err(dev, "failed to update sysfs spdm_signatures_group: %d", rc);
		return rc;
	}

	return 0;
}

void nvme_spdm_publish(struct device *dev)
{
	struct nvme_ctrl *ctrl = dev_get_drvdata(dev);

	if (ctrl->spdm_state)
		spdm_publish_log(ctrl->spdm_state);
}
#endif
