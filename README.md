<!--
    Copyright 2022-2024 TII (SSRC) and the Ghaf contributors
    SPDX-License-Identifier: CC-BY-SA-4.0
-->

This document outlines systemd service configurations that significantly impact a service's exposure. These configurations can be utilized to enhance the security of a systemd service.

# Table Of Contents:

### Networking
- [PrivateNetwork](#PrivateNetwork)
- [IPAccounting](#IPAccounting)
- [IPAddressDeny](#IPAddressDeny)
- [RestrictAddressFamilies](#RestrictAddressFamilies)

### File system
- [ProtectHome](#ProtectHome)
- [ProtectSystem](#ProtectSystem)
- [ProtectProc](#ProtectProc)
- [ReadWritePaths](#ReadWritePaths);
- [PrivateTmp](#PrivateTmp)
- [PrivateMounts](#PrivateMounts)
- [ProcSubset](#ProcSubset)

### User separation
- [PrivateUsers](#PrivateUsers)
- [DynamicUser](#DynamicUser)

### Devices 

- [PrivateDevices](#PrivateDevices)
- [DeviceAllow](#DeviceAllow)

### Kernel 
- [ProtectKernelTunables](#ProtectKernelTunables)
- [ProtectKernelModules](#ProtectKernelModules)
- [ProtectKernelLogs](#ProtectKernelLogs)

### Misc 
- [Delegate](#Delegate)
- [KeyringMode](#KeyringMode)
- [NoNewPrivileges](#NoNewPrivileges)
- [UMask](#UMask)
- [ProtectHostname](#ProtectHostname)
- [ProtectClock](#ProtectClock)
- [ProtectControlGroups](#ProtectControlGroups)
- [RestrictNamespaces](#RestrictNamespaces)
- [LockPersonality](#LockPersonality)
- [MemoryDenyWriteExecute](#MemoryDenyWriteExecute)
- [RestrictRealtime](#RestrictRealtime)
- [RestrictSUIDSGID](#RestrictSUIDSGID)
- [RemoveIPC](#RemoveIPC)
- [SystemCallArchitectures](#SystemCallArchitectures)
- [NotifyAccess](#NotifyAccess)

### Capabilities 
- [AmbientCapabilities](#AmbientCapabilities)
- [CapabilityBoundingSet](#CapabilityBoundingSet)
  
### System calls
- [SystemCallFilter](#SystemCallFilter)

---

# Networking

### PrivateNetwork

Useful for preventing the service from accessing the network.

**Type**: *boolean*

**Default**: `false`

**Options**:

- `true` : Creates a new network namespace for the service. Only the loopback device "lo" is available in this namespace, other network devices are not accessible.

- `false` : The service will use the host's network namespace, it can access all the network devices available on host. It can communicate over the network like any other process running on host.

[PrivateNetwork](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateNetwork=)

---

### IPAccounting

Helps in detecting unusual or unexpected network activity by a service.

**Type**: *boolean*

**Default**: `false`

**Options**:
- `true`: Enables accounting for all IPv4 and IPv6 sockets created by the service, i.e. keeps track of the data sent and received by each socket in the service.\  
- `false`: Disables tracking of the sockets created by the service.

[IPAccounting](https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html#IPAccounting=)

---

### IPAddressAllow=ADDRESS[/PREFIXLENGTH]…,
### IPAddressDeny=ADDRESS[/PREFIXLENGTH]…

It enables packet filtering on all IPv4 and IPv6 sockets created by the service. Useful for restricting/preventing a service to communicate only with certain IP addresses or networks.

**Type**: *Space separated list of ip addresses and/or a symbloc name*

**Default**: All IP addresses are allowed and no IP addresses are explicitly denied.

**Options**: 
- *List of addresses*: Specify list of addresses allowed/denied e.g. `['192.168.1.8' '192.168.1.0/24']`. Any IP not explicitly allowed will be denied.
- *Symbolic Names*: Following symbolic names can also be used.\
    `any` :	Any host (i.e. '0.0.0.0/0 ::/0')\
    `localhost`: All addresses on the local loopback(i.e. '127.0.0.0/8 ::1/128')\
    `link-local`: All link-local IP addresses(i.e.'169.254.0.0/16 fe80::/64')\
    `multicast`: All IP multicasting addresses (i.e. 224.0.0.0/4 ff00::/8)\

[IPAddressAllow](https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html#IPAddressAllow=)
   
---

### RestrictNetworkInterfaces

Used to control which network interfaces a service has access to. This helps isolate services from the network or restrict them to specific network interfaces, enhancing security and reducing potential risk.

**Type**: *Space separated list of network interface names.*

**Default**: The service has access to all available network interfaces unless other network restrictions are in place. 

**Options**:
- Specify individual network interface names to restrict the service to using only those interfaces.
- Prefix an interface name with '~' to invert the restriction, i.e. denying access to that specific interface while allowing all others.

[RestrictNetworkInterfaces](https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html#RestrictNetworkInterfaces=)

---

### RestrictAddressFamilies

Used to control which address families a service can use. This setting restricts the service's ability to open sockets using specific address families, such as `'AF_INET'` for IPv4, `'AF_INET6'` for IPv6, or others. It is a security feature that helps limit the service's network capabilities and reduces its exposure to network-related vulnerabilities.

**Type**: List of address family names.

**Default**: If not configured, the service is allowed to use all available address families.

**Options**:
- **`none`**: Apply no restriction.
- **Specific Address Families**: Specify one or more address families that the service is allowed to use, e.g., `'AF_INET'`, `'AF_INET6'`, `'AF_UNIX'`.
- **Inverted Restriction**: Prepend character '~' to an address family name to deny access to it while allowing all others, e.g., `'~AF_INET'` would block IPv4 access.
   
[RestrictAddressFamilies](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictAddressFamilies=)

---

# File system

### ProtectHome

Used to restrict a service's access to home directories. This security feature can be used to either completely block access to `/home`, `/root`, and `/run/user` or make them appear empty to the service, thereby protecting user data from unauthorized access by system services.

**Type**: *Boolean or string.*

**Default**: `false` i.e. the service has full access to home directories unless restricted by some other mean.

**Options**:
- **`true`**: The service is completely denied access to home directories.
- **`false`**: The service has unrestricted access to home directories.
- **`read-only`**: The service can view the contents of home directories but cannot modify them.
- **`tmpfs`**: Mounts a temporary filesystem in place of home directories, ensuring the service cannot access or modify the actual user data. Adding the tmpfs option provides a flexible approach by creating a volatile in-memory filesystem where the service believes it has access to home but any changes it makes do not affect the actual data and are lost when the service stops. This is particularly useful for services that require a temporary space in home.
  
[ProtectHome](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectHome=)

---

### ProtectSystem

Controls access to the system's root directory (`/`) and other essential system directories. This setting enhances security by restricting a service's ability to modify or access critical system files and directories.

**Type**: *Boolean or string.*

**Default**: `full` (Equivalent to `true`). The service is restricted from modifying or accessing critical system directories.

**Options**:
- **`true`**: Mounts the directories `/usr/`, `/boot`, and `/efi` read-only for processes.
- **`full`**: Additionally mounts the `/etc/` directory read-only.
- **`strict`**: Mounts the entire file system hierarchy read-only, except for essential API file system subtrees like `/dev/`, `/proc/`, and `/sys/`.
- **`false`**: Allows the service unrestricted access to system directories.

Using `true` or `full` is recommended for services that do not require access to system directories to enhance security and stability.

[ProtectSystem](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectSystem=)

---

### ProtectProc

Controls access to the `/proc` filesystem for a service. This setting enhances security by restricting a service's ability to view or manipulate processes and kernel information in the `/proc` directory.

**Type**: *Boolean or string.*

**Default**: `default`. No restriction is imposed from viewing or manipulating processes and kernel information in `/proc`.

**Options**:
- **`noaccess`**: Restricts access to most process metadata of other users in `/proc`.
- **`invisible`**: Hides processes owned by other users from view in `/proc`.
- **`ptraceable`**: Hides processes that cannot be traced (`ptrace()`) by other processes.
- **`default`**: Imposes no restrictions on access or visibility to `/proc`.
  
[ProtectProc](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectProc=)

---

### ReadWritePaths, ReadOnlyPaths, InaccessiblePaths, ExecPaths, NoExecPaths

Creates a new file system namespace for executed processes, enabling fine-grained control over file system access.\
- **ReadWritePaths=**: Paths listed here are accessible with the same access modes from within the namespace as from outside it.
- **ReadOnlyPaths=**: Allows reading from listed paths only; write attempts are refused even if file access controls would otherwise permit it.
- **InaccessiblePaths=**: Makes listed paths and everything below them in the file system hierarchy inaccessible to processes within the namespace.
- **NoExecPaths=**: Prevents execution of files from listed paths, overriding usual file access controls. Nest `ExecPaths=` within `NoExecPaths=` to selectively allow execution within directories otherwise marked non-executable.

**Type**: *Space separated list of paths.*

**Default**: No restriction to file system access until unless restricted by some other mechanism.

**Options**:

**Space separated list of paths** : Space-separated list of paths relative to the host's root directory. Symlinks are resolved relative to the root directory specified by `RootDirectory=` or `RootImage=`.

[ReadWritePaths](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ReadWritePaths=)

---

### PrivateTmp

**Type**:

**Default**:

A boolean argument. Defaults to `false`.
If enabled, sets up a new file system namespace for executed processes and mounts private `/tmp/` and `/var/tmp/` directories inside it. These directories are not shared with processes outside of the namespace. This enhances security by isolating temporary files of the process, but prevents sharing between processes via `/tmp/` or `/var/tmp/`.

Additionally, when enabled, all temporary files created by a service in these directories will be automatically removed after the service is stopped.

[PrivateTmp](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateTmp=)

---

### PrivateMounts

**Type**:

**Default**:

A boolean parameter. Defaults to `off`.
If enabled, the processes of this unit will run in their own private file system (mount) namespace, where all mount propagation from the unit's processes to the host's main file system namespace is disabled. This setup ensures that any file system mount points created or removed by the unit's processes remain private to them and are not visible to the host.

However, mount points established or removed on the host will still be propagated to the unit's processes.

[PrivateMounts](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateMounts=)

---

### ProcSubset

**Type**:

**Default**:

**Options:** `all` (the default), `pid`
If set to `pid`, all files and directories that are not directly associated with process management and introspection are hidden in the `/proc` file system configured for the unit's processes. This setting controls the `subset=` mount option of the `procfs` instance for the unit.

[ProcSubset](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProcSubset=)

---

# User separation

**NOTE:** Not applicable for the service runs as root

### PrivateUsers

**Type**:

**Default**:

A boolean argument. When set to true, it establishes a new user namespace for the executed processes and configures minimal user and group mappings. This mapping includes the "root" user and group, as well as the unit's own user and group, mapping them to themselves, and mapping all other users and groups to the "nobody" user and group. This setup effectively isolates the user and group databases used by the unit from the rest of the system, creating a secure sandbox environment.

In this mode, all files, directories, processes, IPC objects, and other resources owned by users or groups other than `root` or the unit's own are visible from within the unit but appear as owned by the `nobody` user and group. Processes run without privileges in the host's user namespace, meaning they have zero process capabilities in the host's user namespace but retain full capabilities within the service's user namespace.

[PrivateUsers=](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateUsers=)

---

### DynamicUser

**Type**:

**Default**:

A boolean parameter. Defaults to off. When set to true, a UNIX user and group pair are dynamically allocated when the unit is started and released as soon as it is stopped. These user and group entries are managed transiently during runtime and are not added to `/etc/passwd` or `/etc/group`.

[DynamicUser](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#DynamicUser=)

---

# Devices 

### PrivateDevices

**Type**:

**Default**:

A boolean argument. Defaults to false. When set to true, it establishes a new `/dev/` mount for the executed processes and includes only API pseudo devices such as `/dev/null`, `/dev/zero`, or `/dev/random`. Physical devices such as `/dev/sda`, system memory `/dev/mem`, system ports `/dev/port`, and others are not added to this mount. This setup is useful for disabling physical device access by the executed process.

Enabling this option installs a system call filter that blocks low-level I/O system calls categorized in the `@raw-io` set.

[PrivateDevices](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateDevices=)
   
---

### DeviceAllow

**Type**:

**Default**:

Controls access to specific device nodes by the executed processes using eBPF filtering. It accepts two space-separated strings: a device node specifier followed by a combination of `r`, `w`, `m` to control reading, writing, or creating (mknod) operations on the specified device nodes by the unit.

To disallow access to all physical devices, consider using `PrivateDevices=` instead.

[DeviceAllow](https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html#DeviceAllow=)

---

# Kernel

### ProtectKernelTunables

**Type**:

**Default**:

A boolean argument. Defaults to `off`. When set to `true`, kernel variables accessible through paths like */proc/sys/*, */sys/*, */proc/sysrq-trigger*, */proc/latency_stats*, */proc/acpi*, */proc/timer_stats*, */proc/fs*, and */proc/irq* are made read-only to all processes of the unit. Typically, kernel variables that are tunable should be initialized only at boot-time. Few services require runtime modifications to these variables; therefore, it is recommended to enable this setting for most services.

This option is available only for system services.

[ProtectKernelTunables](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelTunables=)

---

### ProtectKernelModules

**Type**:

**Default**:

A boolean argument. Defaults to off. When set to true, explicit module loading is denied, effectively disabling module load and unload operations on modular kernels. This setting is recommended for most services that do not require special file systems or additional kernel modules to function.

Enabling this option removes `CAP_SYS_MODULE` from the capability bounding set for the unit and installs a system call filter to block module system calls. Additionally, `/usr/lib/modules` is made inaccessible.

This option is available only for system services.

[ProtectKernelModules](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelModules=)

---

### ProtectKernelLogs

**Type**:

**Default**:

A boolean argument. Default is off. When set to true, access to the kernel log ring buffer is denied, preventing read and write operations on the buffer. This setting is recommended for most services that do not require access to the kernel log ring buffer.

Enabling this option removes `CAP_SYSLOG` from the capability bounding set for the unit and installs a system call filter to block the syslog(2) system call. The kernel exposes its log buffer to userspace via */dev/kmsg* and */proc/kmsg*. If this setting is enabled, access to these interfaces is restricted for all processes within the unit.

[ProtectKernelLogs](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelLogs=)

---

# Misc

### Delegate

**Type**:

**Default**:

Enables delegation of further resource control partitioning to processes of the unit. When enabled, units can create and manage their own private subhierarchy of control groups below the unit's control group. For unprivileged services (i.e., those using the `User=` setting), the unit's control group is made accessible to the relevant user.

When this option is enabled:
- The service manager refrains from manipulating control groups or moving processes below the unit's control group, establishing a clear ownership concept.

This option takes either a boolean argument or a (possibly empty) list of control group controller names:
- `true`: Enables delegation and activates all supported controllers for the unit, allowing its processes to manage them.
- `false`: Disables delegation entirely.

[Delegate](https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html#Delegate=)

---

### KeyringMode

**Type**:

**Default**:

**Options:** `inherit`, `private`, `shared`.
**Default:** `private` for services of the system service manager and to inherit for non-service units and for services of the user service manager
Specifies the kernel session keyring behavior for the service. Three options are available:

- `inherit`: No special keyring setup is performed, and the kernel's default behavior is applied.
- `private`: Allocates a new session keyring when a service process is invoked, not linked with any user keyring. This is recommended for system services to prevent sharing key material among services running under the same system user ID.
- `shared`: Allocates a new session keyring as for private, but links the user keyring of the user configured with `User=` into it. This allows keys assigned to the user to be requested by the unit's processes.

[KeyringMode](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#KeyringMode=)

---
  
### NoNewPrivileges

**Type**:

**Default**:

A boolean argument. Defaults to `false`. When set to `true`, ensures that the service process and all its children cannot gain new privileges through *execve()* calls. This effectively prevents any process or its descendants from escalating privileges. However, certain configurations may override this setting and ignore its value.

[NoNewPrivileges](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#NoNewPrivileges=)

---

### UMask

**Type**:

**Default**:

Controls the file mode creation mask, specified in octal notation. 

- Defaults to 0022 for system units.
- For user units, the default value is inherited from the per-user service manager. To change the default mask for all user services, consider setting the `UMask=` setting of the user's `user@.service` system service instance.

[UMask](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#UMask=)

---

### ProtectHostname

**Type**:

**Default**:

A boolean argument. Defaults to off. When enabled, sets up a new UTS namespace for the executed processes. Additionally, it prevents changes to the hostname or domainname.

This option is available only for system services.

[ProtectHostname](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectHostname=)

---

### ProtectClock

**Type**:

**Default**:

A boolean argument. Defaults to off. When enabled, denies writes to the hardware clock or system clock.

Enabling this option:
- Removes `CAP_SYS_TIME` and `CAP_WAKE_ALARM` from the capability bounding set for this unit.
- Installs a system call filter to block calls that can set the clock.
- Implies `DeviceAllow=char-rtc r`.

It is recommended to enable this setting for most services that do not need to modify the clock or check its state.

This option is available only for system services.

[ProtectClock](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectClock=)

---

### ProtectControlGroups

**Type**:

**Default**:

A boolean argument. Defaults to off. When set to true, makes the Linux Control Groups (cgroups(7)) hierarchies accessible through `/sys/fs/cgroup/` read-only to all processes of the unit.

Enabling this option:
- Ensures that processes within the unit cannot modify cgroups hierarchies.
- Helps in maintaining system stability and resource control integrity.

It is recommended to enable this setting for most services.

This option is available only for system services.

[ProtectControlGroups](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectControlGroups=)

---

### RestrictNamespaces

**Type**:

**Default**:

A boolean argument, or a space-separated list of namespace type identifiers. Defaults to `false`.

Controls access to Linux namespace functionality for the processes of this unit:
- `false`: No restrictions on namespace creation and switching are imposed.
- `true`: Prohibits access to any kind of namespacing.
- Otherwise: Specifies a space-separated list of namespace type identifiers, which can include `cgroup`, `ipc`, `net`, `mnt`, `pid`, `user`, and `uts`.

[RestrictNamespaces](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictNamespaces=)

---

### LockPersonality

**Type**:

**Default**:

A boolean argument. Defaults to `false`.

When enabled, locks down the personality system call, preventing changes to the kernel execution domain from the default or from the personality selected with the `Personality=` directive. This restriction can enhance security as unusual personality emulations may be inadequately tested and could potentially introduce vulnerabilities.

If the service runs in user mode or in system mode without the `CAP_SYS_ADMIN` capability (e.g., setting `User=`), enabling this option implies `NoNewPrivileges=yes`.

[LockPersonality](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#LockPersonality=)
   
---

### MemoryDenyWriteExecute

**Type**:

**Default**:

A boolean argument. Defaults to `false`.

When enabled, prohibits attempts to create memory mappings that are writable and executable simultaneously, change existing memory mappings to become executable, or map shared memory segments as executable. This restriction is implemented by adding an appropriate system call filter.

[MemoryDenyWriteExecute](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#MemoryDenyWriteExecute=)

---

### RestrictRealtime

**Type**:

**Default**:

A boolean argument. Default is `false`.

When enabled, refuses any attempts to enable realtime scheduling in processes of the unit. This restriction prevents access to realtime task scheduling policies such as `SCHED_FIFO`, `SCHED_RR`, or `SCHED_DEADLINE`.

If the service runs in user mode or in system mode without the `CAP_SYS_ADMIN` capability, enabling this option implies `NoNewPrivileges=yes`.

[RestrictRealtime](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictRealtime=)

---

### RestrictSUIDSGID

**Type**:

**Default**:

A boolean argument. Defaults to `off`.

When enabled, denies any attempts to set the set-user-ID (SUID) or set-group-ID (SGID) bits on files or directories. These bits are used to elevate privileges and allow users to acquire the identity of other users.

If the service runs in user mode or in system mode without the `CAP_SYS_ADMIN` capability, enabling this option implies `NoNewPrivileges=yes`.

It is recommended to restrict the creation of SUID/SGID files to only those programs that absolutely require them due to the potential security risks associated with these mechanisms.

[RestrictSUIDSGID](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictSUIDSGID=)

---

### RemoveIPC

**Type**:

**Default**:

A boolean parameter. Defaults to `off`.

When enabled, all **System V** and **POSIX IPC** objects owned by the user and group under which the processes of this unit are executed are removed when the unit is stopped. This includes IPC objects such as message queues, semaphore sets, and shared memory segments.

This option is available only for system services.

[RemoveIPC](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RemoveIPC=)

---
 
### SystemCallArchitectures

**Type**:

**Default**:

Takes a space-separated list of architecture identifiers to include in the system call filter. Defaults to an empty list, meaning no filtering is applied by default.

When configured:
- Processes of this unit will only be allowed to call native system calls and system calls specific to the architectures specified in the list.

If the service runs in user mode or in system mode without the `CAP_SYS_ADMIN` capability, enabling this option implies `NoNewPrivileges=yes`.



[SystemCallArchitectures](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallArchitectures=)
  
---

### NotifyAccess

**Type**:

**Default**:

Controls access to the service status notification socket, as accessed via the `sd_notify()` call. Takes one of the following values:
- `none` (default): No daemon status updates are accepted from the service processes; all status update messages are ignored.
- `main`: Only service updates sent from the main process of the service are accepted.
- `exec`: Only service updates sent from any main or control processes originating from one of the `Exec*=` commands are accepted.
- `all`: All service updates from all members of the service's control group are accepted.

This option should be configured to grant appropriate access to the notification socket when using `Type=notify` or `Type=notify-reload`, or when setting `WatchdogSec=`. If these options are used without explicitly configuring `NotifyAccess=`, it defaults to `main`.

[NotifyAccess](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html#NotifyAccess=)

---

# Capabilities 

### AmbientCapabilities

**Type**:

**Default**:

Controls which capabilities to include in the ambient capability set for the executed process. Takes a whitespace-separated list of capability names, such as `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`, `CAP_SYS_PTRACE`. This option can be specified multiple times to merge capability sets.

- If capabilities are listed without a prefix, those capabilities are included in the ambient capability set.
- If capabilities are prefixed with "~", all capabilities except those listed are included (inverted effect).
- Assigning the empty string (`""`) resets the ambient capability set to empty, overriding all prior settings.



[AmbientCapabilities](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#AmbientCapabilities=)

---

### CapabilityBoundingSet

**Type**:

**Default**:

A whitespace-separated list of capability names, for example, `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`, `CAP_SYS_PTRACE`.

Specifies which capabilities to include in the capability bounding set for the executed process. 

- If capabilities are listed without a prefix, only those capabilities are included.
- If capabilities are prefixed with "~", all capabilities except those listed are included (inverted effect).

Note: This setting does not affect commands prefixed with "+".



[CapabilityBoundingSet](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=)

#### Available Options:
**Capability** | **Description**
--- | --
**CAP_AUDIT_CONTROL** | Allows processes to control kernel auditing behavior, including enabling and disabling auditing, and changing audit rules.
**CAP_AUDIT_READ** | Allows processes to read audit log via unicast netlink socket. 
**CAP_AUDIT_WRITE** | Allows processes to write records to kernel auditing log. 
**CAP_BLOCK_SUSPEND** | Allows processes to prevent the system from entering suspend mode.
**CAP_CHOWN** | Allows processes to change the ownership of files.
**CAP_DAC_OVERRIDE** | Allows processes to bypass file read, write, and execute permission checks.
**CAP_DAC_READ_SEARCH** | Allows processes to bypass file read permission checks and directory read and execute permission checks.
**CAP_FOWNER** | Allows processes to bypass permission checks on operations that normally require the filesystem UID of the file to match the calling process's UID.
**CAP_FSETID** | Allows processes to set arbitrary process and file capabilities.
**CAP_IPC_LOCK** | Allows processes to lock memory segments into RAM.
**CAP_IPC_OWNER** | Allows processes to perform various System V IPC operations, such as message queue management and shared memory management.
**CAP_KILL** | Allows processes to send signals to arbitrary processes.
**CAP_LEASE** | Allows processes to establish leases on open files.
**CAP_LINUX_IMMUTABLE** | Allows processes to modify the immutable and append-only flags of files.
**CAP_MAC_ADMIN** | Allows processes to perform MAC configuration changes.
**CAP_MAC_OVERRIDE** | Bypasses Mandatory Access Control (MAC) policies.
**CAP_MKNOD** | Allows processes to create special files using mknod().
**CAP_NET_ADMIN** | Allows processes to perform network administration tasks, such as configuring network interfaces, setting routing tables, etc.
**CAP_NET_BIND_SERVICE** | Allows processes to bind to privileged ports (ports below 1024).
**CAP_NET_BROADCAST** | Allows processes to transmit packets to broadcast addresses.
**CAP_NET_RAW** | Allows processes to use raw and packet sockets.
**CAP_SETGID** | Allows processes to change their GID to any value.
**CAP_SETFCAP** | Allows processes to set any file capabilities.
**CAP_SETPCAP** | Allows processes to set the capabilities of other processes.
**CAP_SETUID** | Allows processes to change their UID to any value.
**CAP_SYS_ADMIN** | Allows processes to perform a range of system administration tasks, such as mounting filesystems, configuring network interfaces, loading kernel modules, etc.
**CAP_SYS_BOOT** | Allows processes to reboot or shut down the system.
**CAP_SYS_CHROOT** | Allows processes to use chroot().
**CAP_SYS_MODULE** | Allows processes to load and unload kernel modules.
**CAP_SYS_NICE** | Allows processes to increase their scheduling priority.
**CAP_SYS_PACCT** | Allows processes to configure process accounting.
**CAP_SYS_PTRACE** | Allows processes to trace arbitrary processes using ptrace().
**CAP_SYS_RAWIO** | Allows processes to perform I/O operations directly to hardware devices.
**CAP_SYS_RESOURCE** | Allows processes to override resource limits.
**CAP_SYS_TIME** | Allows processes to set system time and timers.
**CAP_SYS_TTY_CONFIG** | Allows processes to configure tty devices.
**CAP_WAKE_ALARM** | Allows processes to use the RTC wakeup alarm.

---

# System calls 

### SystemCallFilter

**Type**:

**Default**:

A space-separated list of system call names. 

Specifies which system calls executed by unit processes are allowed. If a system call executed is not in this list, the process will be terminated with the `SIGSYS` signal (allow-listing).

- If the list begins with "~", the effect is inverted, meaning only the listed system calls will result in termination.
- Predefined sets of system calls are available, starting with "@" followed by the name of the set.



[SystemCallFilter](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=)

#### Set	Description:
**Filter Set** | **Description**
--- | ---
**@clock** | Allows clock and timer-related system calls, such as clock_gettime, nanosleep, etc. This is essential for time-related operations.
**@cpu-emulation** | Allows CPU emulation-related system calls, typically used by virtualization software.
**@debug** | Allows debug-related system calls, which are often used for debugging purposes and may not be necessary for regular operations.
**@keyring** | Allows keyring-related system calls, which are used for managing security-related keys and keyrings.
**@module** | Allows module-related system calls, which are used for loading and unloading kernel modules. This can be restricted to prevent module loading for security purposes.
**@mount** | Allows mount-related system calls, which are essential for mounting and unmounting filesystems.
**@network** | Allows network-related system calls, which are crucial for networking operations such as socket creation, packet transmission, etc.
**@obsolete** | Allows obsolete system calls, which are no longer in common use and are often deprecated.
**@privileged** | Allows privileged system calls, which typically require elevated privileges or are potentially risky if misused.
**@raw-io** | Allows raw I/O-related system calls, which provide direct access to hardware devices. This can be restricted to prevent unauthorized access to hardware.
**@reboot** | Allows reboot-related system calls, which are necessary for initiating system reboots or shutdowns.
**@swap** | Allows swap-related system calls, which are used for managing swap space.
**@syslog** | Allows syslog-related system calls, which are used for system logging.
**@system-service** | Allows system service-related system calls, which are used for managing system services.
**@timer** | Allows timer-related system calls, which are essential for setting and managing timers.


---
