"""Install and update manifests. Data only: no MSI, no service, no driver.

Decoys come off only when the product's remove command runs. A configure step that fails rolls the laid-down files back.
"""

SERVICE_NAME = "HalvardSvc"
LAID_DOWN = ["halvard-svc.exe", "halvard.conf"]

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
