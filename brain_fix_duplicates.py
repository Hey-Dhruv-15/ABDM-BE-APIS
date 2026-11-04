import re

with open('app/api/routes/abdm.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# List of duplicate decorators to remove (non-canonical /v3/ aliases when /abha/v3/ exists)
duplicates_to_remove = [
    '@router.post("/v3/enrollment/request/mobile-otp"',
    '@router.post("/v3/profile/account/abha/search"',
    '@router.post("/v3/profile/login/request/otp"',
    '@router.post("/v3/profile/login/verify"',
    '@router.get("/v3/profile/public/certificate"',
    '@router.post("/v3/enrollment/request/otp"',
    '@router.post("/v3/enrollment/enrol/byAadhaar"',
    '@router.post("/v3/enrollment/abha-address/suggestions"',
    '@router.post("/v3/enrollment/create/phrAddress"',
    '@router.get("/v3/address/suggestions/{txnId}"',
    '@router.get("/v3/address/suggestions"',
    '@router.get("/v3/card/{txnId}"',
    '@router.get("/v3/card"',
    '@router.get("/v3/profile/account/abha-card"',
    '@router.post("/v3/enrollment/auth/byAbdm"',
    '@router.get("/v3/profile/account"',
    '@router.get("/v3/profile/account/qrCode"',
    '@router.post("/hiecm/user-initiated-linking/v3/patient/care-context/discover"',
    '@router.post("/v3/hip/patient/care-context/discover"',
]

new_lines = []
removed_count = 0
for line in lines:
    should_remove = False
    for dup in duplicates_to_remove:
        if dup in line:
            should_remove = True
            removed_count += 1
            print(f"Removing duplicate line: {line.strip()}")
            break
    if not should_remove:
        new_lines.append(line)

print(f"Total duplicate decorator lines removed: {removed_count}")

with open('app/api/routes/abdm.py', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)
