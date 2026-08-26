"""Role-Based Access Control definitions for the payment gateway."""

# All permissions in the system as resource.action
ALL_PERMISSIONS = [
    "dashboard.read",
    "merchant.read", "merchant.create", "merchant.update", "merchant.approve", "merchant.suspend",
    "kyc.read", "kyc.review",
    "transaction.read",
    "payment.read", "payment.create", "payment.cancel",
    "refund.read", "refund.create", "refund.approve",
    "settlement.read", "settlement.approve",
    "withdrawal.read", "withdrawal.create", "withdrawal.approve",
    "fee.read", "fee.update",
    "ledger.read",
    "api.read", "api.create", "api.revoke",
    "webhook.read", "webhook.create", "webhook.update", "webhook.test",
    "fraud.read", "fraud.update",
    "report.read",
    "user.read", "user.create", "user.update", "user.delete",
    "settings.read", "settings.update",
    "audit.read",
]

# Roles mapped to permissions. super_admin implicitly has everything.
ROLE_PERMISSIONS = {
    "super_admin": ["*"],
    "admin": [
        "dashboard.read",
        "merchant.read", "merchant.create", "merchant.update", "merchant.approve", "merchant.suspend",
        "kyc.read", "kyc.review",
        "transaction.read",
        "payment.read",
        "refund.read", "refund.approve",
        "settlement.read", "settlement.approve",
        "withdrawal.read", "withdrawal.approve",
        "fee.read", "fee.update",
        "ledger.read",
        "api.read",
        "webhook.read", "webhook.test",
        "fraud.read", "fraud.update",
        "report.read",
        "user.read",
        "audit.read",
    ],
    "finance": [
        "dashboard.read", "transaction.read", "settlement.read", "settlement.approve",
        "withdrawal.read", "withdrawal.approve",
        "refund.read", "refund.approve", "ledger.read", "fee.read", "report.read",
        "merchant.read",
    ],
    "support": [
        "dashboard.read", "merchant.read", "transaction.read", "refund.read",
        "settlement.read", "withdrawal.read", "report.read", "kyc.read",
    ],
    "risk": [
        "dashboard.read", "transaction.read", "fraud.read", "fraud.update",
        "merchant.read", "kyc.read", "settlement.read",
    ],
    "merchant": [
        "dashboard.read", "merchant.read", "merchant.update",
        "payment.read", "payment.create", "payment.cancel",
        "transaction.read", "refund.read", "refund.create", "settlement.read",
        "withdrawal.read", "withdrawal.create",
        "ledger.read", "api.read", "api.create", "api.revoke",
        "webhook.read", "webhook.create", "webhook.update", "webhook.test",
        "kyc.read",
    ],
    "developer": [
        "dashboard.read", "merchant.read", "api.read", "api.create", "api.revoke",
        "webhook.read", "webhook.create", "webhook.update", "webhook.test",
        "transaction.read", "payment.read",
    ],
}

# Roles that belong to the admin/back-office portal
ADMIN_ROLES = {"super_admin", "admin", "finance", "support", "risk"}
# Roles that belong to the merchant portal
MERCHANT_ROLES = {"merchant", "developer"}

ROLE_LABELS = {
    "super_admin": "Super Admin",
    "admin": "Admin",
    "finance": "Finance",
    "support": "Support",
    "risk": "Risk / Fraud",
    "merchant": "Merchant",
    "developer": "Developer",
}


def permissions_for(role: str):
    perms = ROLE_PERMISSIONS.get(role, [])
    if perms == ["*"]:
        return list(ALL_PERMISSIONS)
    return perms


def has_permission(role: str, permission: str) -> bool:
    if role == "super_admin":
        return True
    return permission in ROLE_PERMISSIONS.get(role, [])


def portal_for(role: str) -> str:
    return "merchant" if role in MERCHANT_ROLES else "admin"
