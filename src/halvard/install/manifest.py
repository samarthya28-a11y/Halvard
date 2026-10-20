"""Install and update manifests. Data only: no MSI, no service, no driver.

Decoys come off only when the product's remove command runs. A configure step that fails rolls the laid-down files back.
"""

SERVICE_NAME = "HalvardGuard"
# The WiX file installs the service executable. The service writes service.json when it is configured.
# halvard.conf is not laid down by that installer and is not named here.
LAID_DOWN = ["halvard-svc.exe"]

INSTALL_MANIFEST = {
    "kind": "install",
    "service_name": SERVICE_NAME,
    "files": list(LAID_DOWN),
    "decoys_removed_by": "remove",
    "configure_failure": "rollback",
    "built": False,
}

UPDATE_MANIFEST = {
    "kind": "update",
    "service_name": SERVICE_NAME,
    "files": list(LAID_DOWN),
    "decoys_removed_by": "remove",
    "configure_failure": "rollback",
    "built": False,
}
