"""Install and update manifests. Data only: no MSI, no service, no driver.

Decoys come off only when the product's remove command runs. A configure step that fails rolls the laid-down files back.
"""

SERVICE_NAME = "HalvardGuard"
LAID_DOWN = ["halvard-svc.exe"]
CREATED_BY_CONFIGURE = ["service.json"]      # written to ProgramData by `halvard-svc configure`, not laid down by the installer

INSTALL_MANIFEST = {
    "kind": "install",
    "service_name": SERVICE_NAME,
    "files": list(LAID_DOWN),
    "created_by_configure": list(CREATED_BY_CONFIGURE),
    "decoys_removed_by": "remove",
    "configure_failure": "rollback",
    "built": False,
}

UPDATE_MANIFEST = {
    "kind": "update",
    "service_name": SERVICE_NAME,
    "files": list(LAID_DOWN),
    "created_by_configure": list(CREATED_BY_CONFIGURE),
    "decoys_removed_by": "remove",
    "configure_failure": "rollback",
    "built": False,
}
