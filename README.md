# add-rbcd fix

## Problem

The original `add-rbcd.c` writes a security descriptor to `msDS-AllowedToActOnBehalfOfOtherIdentity` that causes S4U2Proxy to fail with **KDC_ERR_BADOPTION (error 13)**, even though:

- The LDAP write succeeds
- The attribute is present on the target object
- The BOF's own verification reports the principal SID is in the DACL

RBCD appears configured but delegation never works.

## Root Cause

### 1. Wrong access mask — `GENERIC_ALL` vs specific rights

The original builds the ACE with:

```c
ACCESS_MASK accessMask = GENERIC_ALL;  // 0x10000000
AddAccessAllowedAceEx(newDacl, revision, 0, accessMask, trusteeSid);
```

`GENERIC_ALL (0x10000000)` is a generic right. In a standard Win32 `AccessCheck` it would be expanded to object-specific rights via the object type's generic mapping. The KDC's internal S4U2Proxy evaluation does not go through this expansion — it checks the SD directly against specific AD rights bits. `0x10000000` matches nothing, so the delegation check fails silently.

### 2. Dangling pointer when existing RBCD is present

When the target already has `msDS-AllowedToActOnBehalfOfOtherIdentity` set:

```c
ADVAPI32$GetSecurityDescriptorDacl(pSD, &daclPresent, &pOldDacl, ...);
// pOldDacl now points INTO values[0]->bv_val
WLDAP32$ldap_value_free_len(values);  // frees that buffer
// pOldDacl is dangling — passed to CreateNewDaclWithAce()
```

`GetSecurityDescriptorDacl` sets `pOldDacl` to a pointer inside the LDAP-managed buffer. Freeing `values` immediately after leaves a dangling pointer that is then used to copy existing ACEs into the new DACL — producing a corrupted security descriptor.

### 3. Dependency on broken `acl_common.c` / `ldap_common.c`

The shared common files have their own issues with the SD construction pipeline (`CreateNewDaclWithAce` → `MakeSelfRelativeSD`).

## Fix

This version is fully self-contained (no `ldap_common.c` / `acl_common.c` dependency) and builds the security descriptor via SDDL:

```c
MSVCRT$_snprintf(sddl, sizeof(sddl), "O:BAD:(A;;0xF01FF;;;%s)", sidStr);
ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl, SDDL_REVISION_1, &pSD, &sdLen);
```

`0xF01FF` is the full set of specific AD rights:
- Bits 0–8 (`0x1FF`): all nine DS-specific rights including `ADS_RIGHT_DS_CONTROL_ACCESS (0x100)` — the right the KDC actually evaluates
- Bits 16–20 (`0xF0000`): DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER, SYNCHRONIZE

`ConvertStringSecurityDescriptorToSecurityDescriptorA` produces a well-formed self-relative SD in a single API call, bypassing the broken manual pipeline entirely. This is the same approach used by Impacket's `rbcd.py`.

**Note:** This version uses `LDAP_MOD_REPLACE`, so it overwrites any existing RBCD entries on the target. If the target already has delegations you want to preserve, read the existing attribute first and merge.

## Build

From the `LDAP-BOF` root (requires `x86_64-w64-mingw32-gcc`):

```bash
x86_64-w64-mingw32-gcc -I _include -Os -masm=intel -fno-stack-protector -mno-stack-arg-probe -DBOF -c add-rbcd.c -o add-rbcd.x64.o
x86_64-w64-mingw32-strip --strip-unneeded add-rbcd.x64.o
```

## Usage (Adaptix)

```
ldap add-rbcd <target> <principal> [searchOU] <dc-fqdn> [ldaps]
```

- `target` — sAMAccountName, name, or full DN of the target computer
- `principal` — sAMAccountName, name, or full DN of the computer to grant delegation from
- `dc-fqdn` — fully qualified DC hostname (e.g. `dc01.corp.local`)
