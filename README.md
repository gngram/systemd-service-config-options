# Networking

### PrivateNetwork
A boolean argument. Defaults to false. If true, sets up a new network namespace for the executed processes and configures only the loopback network device "lo" inside it.
No other network devices will be available to the executed process. This is useful to turn off network access by the executed process.

[PrivateNetwork](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateNetwork=)

### IPAccounting
A boolean argument. Defaults to false. If true, turns on IPv4 and IPv6 network traffic accounting for packets sent or received by the unit.
When this option is turned on, all IPv4 and IPv6 sockets created by any process of the unit are accounted for.

[IPAccounting](https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html#IPAccounting=)

### IPAddressAllow=ADDRESS[/PREFIXLENGTH]…,
### IPAddressDeny=ADDRESS[/PREFIXLENGTH]…
Turn on network traffic filtering for IP packets sent and received over AF_INET and AF_INET6 sockets. Both directives take a space separated list of
IPv4 or IPv6 addresses, each optionally suffixed with an address prefix length in bits after a "/" character. If the suffix is omitted, the
address is considered a host address.

[IPAddressAllow](https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html#IPAddressAllow=)
   

### RestrictNetworkInterfaces
Takes a list of space-separated network interface names. This option restricts the network interfaces that processes of this unit can use.
By default processes can only use the network interfaces listed. If the first character of the rule is "~", the effect is inverted.
The loopback interface ("lo") is not treated in any special way, you have to configure it explicitly in the unit file.

[RestrictNetworkInterfaces](https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html#RestrictNetworkInterfaces=)
  
### RestrictAddressFamilies
**Options:** `none`, or a space-separated list of address family names to allow-list, such as `AF_UNIX`, `AF_PACKET`, `AF_INET`, `AF_NETLINK` or `AF_INET6`.
Restricts the set of socket address families accessible to the processes of this unit. When "none" is specified, then all address families will be denied.
When prefixed with "~" the listed address families will be applied as deny list, otherwise as allow list. Note that this restricts access to the socket(2) system call only.
By default, no restrictions apply, all address families are accessible to processes. This setting does not affect commands prefixed with "+".
   
[RestrictAddressFamilies](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictAddressFamilies=)
  
# File system

### ProtectHome
Takes a boolean argument or the special values "read-only" or "tmpfs".
**Default:**
If `true`, the directories */home/*, */root*, and */run/user* are made inaccessible and empty for processes invoked by this unit. If set to "read-only", the three
directories are made read-only instead. If set to *tmpfs*, temporary file systems are mounted on the three directories in read-only mode. The value "tmpfs" is useful
to hide home directories not relevant to the processes invoked by the unit, while still allowing necessary directories to be made visible when listed in `BindPaths=`
or `BindReadOnlyPaths=`.
It is recommended to enable this setting for all long-running services (in particular network-facing ones), to ensure they cannot get access to private user data,
unless the services actually require access to the user's private data. This setting is implied if `DynamicUser=` is set.
This option is only available for system services, or for services running in per-user instances of the service manager in which case `PrivateUsers=` is implicitly enabled.

[ProtectHome](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectHome=)


### ProtectSystem
A boolean argument or the special values "full" or "strict".
**Default:** `false`.
If `true`, mounts the /usr/ and the boot loader directories (*/boot* and */efi*) read-only for processes invoked by this unit. If set to `full`, the */etc/* directory
is mounted read-only, too. If set to "strict" the entire file system hierarchy is mounted read-only, except for the API file system subtrees */dev/*, */proc/* and
*/sys/*. It is recommended to enable this setting for all long-running services, unless they are involved with system updates or need to modify the operating system in
other ways. If this option is used, `ReadWritePaths=` may be used to exclude specific directories from being made read-only. This setting is implied if `DynamicUser=`
is set. This setting cannot ensure protection in all cases. In general it has the same limitations as `ReadOnlyPaths=`, see below. Defaults to `off`.

[ProtectSystem](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectSystem=)

### ProtectProc
**Options:** `noaccess`, `invisible`, `ptraceable` or `default` (which it defaults to).
This controls the "hidepid=" mount option of the "procfs" instance for the unit that controls which directories
with process metainformation (proc/PID*) are visible and accessible: when set to "noaccess" the ability to
access most of other users' process metadata in proc is taken away for processes of the service. When set to
"invisible" processes owned by other users are hidden from proc. If "ptraceable" all processes that cannot
be ptrace()'ed by a process are hidden to it. If "default" no restrictions on proc access or visibility are made.
This option is only available for system services.

[ProtectProc](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectProc=)

### ReadWritePaths, ReadOnlyPaths, InaccessiblePaths, ExecPaths, NoExecPaths
Sets up a new file system namespace for executed processes. These options may be used to limit access a process has to the file system. Each setting takes a space-separated
list of paths relative to the host's root directory (i.e. the system running the service manager). Note that if paths contain symlinks, they are resolved relative to
the root directory set with `RootDirectory=/RootImage=`.
Paths listed in `ReadWritePaths=` are accessible from within the namespace with the same access modes as from outside of it.
Paths listed in `ReadOnlyPaths=` are accessible for reading only, writing will be refused even if the usual file access controls would permit this.
Paths listed in `InaccessiblePaths=` will be made inaccessible for processes inside the namespace along with everything below them in the file system hierarchy.
Paths listed in  `NoExecPaths=` are not executable even if the usual file access controls would permit this. Nest `ExecPaths=` inside of `NoExecPaths=` in order to provide
executable content within non-executable directories.

[ReadWritePaths](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ReadWritePaths=)


### PrivateTmp

A boolean argument. Defaults to `false`.
If true, sets up a new file system namespace for the executed processes and mounts private /tmp/ and /var/tmp/ directories inside it that are not shared by processes outside
of the namespace. This is useful to secure access to temporary files of the process, but makes sharing between processes via /tmp/ or /var/tmp/ impossible.
If true, all temporary files created by a service in these directories will be removed after the service is stopped.

[PrivateTmp](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateTmp=)

### PrivateMounts
A boolean parameter. Defaults to `off`.
If set, the processes of this unit will be run in their own private file system (mount) namespace with all mount propagation from the processes towards the
host's main file system namespace turned off. This means any file system mount points established or removed by the unit's processes will be private to them and not be visible to the host.
However, file system mount points established or removed on the host will be propagated to the unit's processes.

[PrivateMounts](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateMounts=)

### ProcSubset
**Options:** `all` (the default), `pid`
If "pid", all files and directories not directly associated with process management and introspection are made
invisible in the proc file system configured for the unit's processes. This controls the `subset=` mount option
of the *procf*" instance for the unit.

[ProcSubset](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProcSubset=)


# User separation

**NOTE:** Not applicable for the service runs as root

### PrivateUsers
A boolean argument. If true, sets up a new user namespace for the executed processes and configures a minimal user and group mapping, that maps the "root" user and
group as well as the unit's own user and group to themselves and everything else to the "nobody" user and group. This is useful to securely detach the user and group databases u
sed by the unit from the rest of the system, and thus to create an effective sandbox environment. All files, directories, processes, IPC objects and other resources owned
by users/groups not equaling `root` or the unit's own will stay visible from within the unit but appear owned by the `nobody` user and group. If this mode is enabled,
all unit processes are run without privileges in the host user namespace. Specifically this means that the process will have zero process capabilities on the host's user namespace,
but full capabilities within the service's user namespace.

[PrivateUsers=](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateUsers=)

### DynamicUser
A boolean parameter. Defaults to off. If true, a UNIX user and group pair is allocated dynamically when the unit is started, and released as soon
as it is stopped. The user and group will not be added to /etc/passwd or /etc/group, but are managed transiently during runtime.

[DynamicUser](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#DynamicUser=)


# Devices 

### PrivateDevices

A boolean argument. Defaults to false. If true, sets up a new /dev/ mount for the executed processes and only adds API pseudo devices such as */dev/null*, */dev/zero* or
*/dev/random* to it, but no physical devices such as */dev/sda*, system memory */dev/mem*, system ports */dev/port* and others. This is useful to turn off physical device access
by the executed process. Enabling this option will install a system call filter to block low-level I/O system calls that are grouped in the @raw-io set.

[PrivateDevices](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateDevices=)
   

### DeviceAllow

Control access to specific device nodes by the executed processes. Takes two space-separated strings: a device node specifier followed by a combination of `r`, `w`, `m` to
control reading, writing, or creation of the specific device nodes by the unit (mknod), respectively. This functionality is implemented using eBPF filtering.
When access to all physical devices should be disallowed, `PrivateDevices=` may be used instead.

[DeviceAllow](https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html#DeviceAllow=)


# Kernel

### ProtectKernelTunables
A boolean argument. Defaults to `off`. If `true`, kernel variables accessible through */proc/sys/*, */sys/*, */proc/sysrq-trigger*, */proc/latency_stats*, */proc/acpi*, */proc/timer_stats*, */proc/fs* and */proc/irq* will be made read-only to all processes of the unit. Usually, tunable kernel variables should be initialized only at boot-time. Few services need to writeto these at runtime; it is hence recommended to turn this on for most services.
This option is only available for system services.

[ProtectKernelTunables](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelTunables=)


### ProtectKernelModules
A boolean argument. Defaults to off. If true, explicit module loading will be denied. This allows module load and unload operations to be turned off on modular kernels.
It is recommended to turn this on for most services that do not need special file systems or extra kernel modules to work.
Enabling this option removes `CAP_SYS_MODULE` from the capability bounding set for the unit, and installs a system call filter to block module system calls,
also `/usr/lib/modules` is made inaccessible.
This option is only available for system services.

[ProtectKernelModules](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelModules=)


### ProtectKernelLogs
A boolean argument. Default is off. If true, access to the kernel log ring buffer will be denied.
It is recommended to turn this on for most services that do not need to read from or write to the kernel log ring buffer. Enabling this option removes CAP_SYSLOG
from the capability bounding set for this unit, and installs a system call filter to block the syslog(2) system call. The kernel exposes its log buffer to userspace via
*/dev/kmsg* and */proc/kmsg*. If enabled, these are made inaccessible to all the processes in the unit.

[ProtectKernelLogs](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelLogs=)

# Misc

### Delegate
Turns on delegation of further resource control partitioning to processes of the unit. Units where this is enabled may create and manage their own
private subhierarchy of control groups below the control group of the unit itself. For unprivileged services (i.e. those using the User= setting)
the unit's control group will be made accessible to the relevant user.
When enabled the service manager will refrain from manipulating control groups or moving processes below the unit's control group, so that a
clear concept of ownership is established.
Takes either a boolean argument or a (possibly empty) list of control group controller names. If true, delegation is turned on, and all supported
controllers are enabled for the unit, making them available to the unit's processes for management. If false, delegation is turned off entirely.

[Delegate](https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html#Delegate=)

### KeyringMode
**Options:** `inherit`, `private`, `shared`.
**Default:** `private` for services of the system service manager and to inherit for non-service units and for services of the user service manager
Kernel session keyring for the service. If set to inherit no special keyring setup is done, and the kernel's default behaviour is applied.
If private is used a new session keyring is allocated when a service process is invoked, and it is not linked up with any user keyring.
This is the recommended setting for system services, as this ensures that multiple services running under the same system user ID do not share their
key material among each other. If shared is used a new session keyring is allocated as for private, but the user keyring of the user configured
with `User=` is linked into it, so that keys assigned to the user may be requested by the unit's processes.

[KeyringMode](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#KeyringMode=)
  
### NoNewPrivileges
A boolean argument. Defaults to `false`. If `true`, ensures that the service process and all its children can never gain new privileges through *execve()*. This is the
simplest and most effective way to ensure that a process and its children can never elevate privileges again. Certain settings override this and ignore the value
of this setting.

[NoNewPrivileges](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#NoNewPrivileges=)

### UMask
Controls the file mode creation mask. Takes an access mode in octal notation.  Defaults to 0022 for system units.
For user units the default value is inherited from the per-user service manager. In order to change the per-user mask for all user services,
consider setting the UMask= setting of the user's user@.service system service instance.

[UMask](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#UMask=)

### ProtectHostname
A boolean argument. Defaults to off. When set, sets up a new UTS namespace for the executed processes. In addition, changing hostname or domainname is prevented.
This option is only available for system services.

[ProtectHostname](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectHostname=)


### ProtectClock
A boolean argument. Defaults to off. If set, writes to the hardware clock or system clock will be denied.  Enabling this option removes `CAP_SYS_TIME` and `CAP_WAKE_ALARM` from
the capability bounding set for this unit, installs a system call filter to block calls that can set the clock, and `DeviceAllow=char-rtc r` is implied.
It is recommended to turn this on for most services that do not need modify the clock or check its state.
This option is only available for system services.

[ProtectClock](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectClock=)
  
### ProtectControlGroups
A boolean argument. Defaults to off. If true, the Linux Control Groups (cgroups(7)) hierarchies accessible through /sys/fs/cgroup/ will be made read-only to all processes of the unit.
It is hence recommended to turn this on for most services.
This option is only available for system services.

[ProtectControlGroups](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectControlGroups=)

### RestrictNamespaces
Boolean argument, or a space-separated list of namespace type identifiers. Defaults to `false`.
Restricts access to Linux namespace functionality for the processes of this unit. If false, no restrictions on namespace creation and switching are made.
If `true`, access to any kind of namespacing is prohibited. Otherwise, a space-separated list of namespace type identifiers must be specified, consisting of any combination
of: `cgroup`, `ipc`, `net`, `mnt`, `pid`, `user`, and `uts`.

[RestrictNamespaces](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictNamespaces=)

### LockPersonality
A boolean argument. Defaults to `false`.
If set, locks down the personality system call so that the kernel execution domain may not be changed from the default or the personality selected with `Personality=` directive.
This may be useful to improve security, because odd personality emulations may be poorly tested and source of vulnerabilities. If running in user mode, or in system mode,
but without the `CAP_SYS_ADMIN` capability (e.g. setting `User=`), `NoNewPrivileges=yes` is implied.

[LockPersonality](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#LockPersonality=)
   

### MemoryDenyWriteExecute
A boolean argument. Default is `false`,
If set, attempts to create memory mappings that are writable and executable at the same time, or to change existing memory mappings to become executable, or mapping shared
memory segments as executable, are prohibited. Specifically, appropriate system call filter is added.

[MemoryDenyWriteExecute](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#MemoryDenyWriteExecute=)

### RestrictRealtime
A boolean argument. Default is `false`.
If set, any attempts to enable realtime scheduling in a process of the unit are refused. This restricts access to realtime task scheduling policies such as `SCHED_FIFO`,
`SCHED_RR` or `SCHED_DEADLINE`. If running in user mode, or in system mode, but without the `CAP_SYS_ADMIN` capability, `NoNewPrivileges=yes` is implied.

[RestrictRealtime](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictRealtime=)


### RestrictSUIDSGID
A boolean argument. Defaults to `off`. If set, any attempts to set the set-user-ID (SUID) or set-group-ID (SGID) bits on files or directories will be denied. If running in user mode, or in system mode, but without the `CAP_SYS_ADMIN` capability, `NoNewPrivileges=yes` is implied. As the SUID/SGID bits are mechanisms to elevate privileges, and allow users to
acquire the identity of other users, it is recommended to restrict creation of SUID/SGID files to the few programs that actually require them.

[RestrictSUIDSGID](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictSUIDSGID=)

### RemoveIPC
A boolean parameter. Defaults to `off`. If set, all **System V** and **POSIX IPC** objects owned by the user and group the processes of this unit are run as are removed when the unit is stopped.
This option is only available for system services.

[RemoveIPC](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RemoveIPC=)
 
### SystemCallArchitectures
Takes a space-separated list of architecture identifiers to include in the system call filter. If running in user mode, or in system mode, but without the CAP_SYS_ADMIN capability, `NoNewPrivileges=yes` is implied. By default, this option is set to the empty list, i.e. no filtering is applied.
If this setting is used, processes of this unit will only be permitted to call native system calls, and system calls of the specified architectures.

[SystemCallArchitectures](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallArchitectures=)
  
### NotifyAccess
Controls access to the service status notification socket, as accessible via the `sd_notify()` call. Takes one of `none` (the default), `main`, `exec` or `all`. If `none`, no daemon status updates are accepted from the service processes, all status update messages are ignored. If `main`, only service updates sent from the main process of the service are accepted. If `exec`, only service updates sent from any of the main or control processes originating from one of the `Exec*=` commands are accepted. If `all`, all services updates from all members of the service's control group are accepted. This option should be set to open access to the notification socket when using `Type=notify/Type=notify-reload` or `WatchdogSec=`. If those options are used but `NotifyAccess=` is not configured, it will be implicitly set to main.

[NotifyAccess](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html#NotifyAccess=)


# Capabilities 

### AmbientCapabilities
Controls which capabilities to include in the ambient capability set for the executed process. Takes a whitespace-separated list of capability names,
e.g. `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`, `CAP_SYS_PTRACE`. This option may appear more than once, in which case the ambient capability sets are merged.
If the list of capabilities is prefixed with "~", all but the listed capabilities will be included, the effect of the assignment inverted.
If the empty string is assigned to this option, the ambient capability set is reset to the empty capability set, and all prior settings have no effect.

[AmbientCapabilities](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#AmbientCapabilities=)

### CapabilityBoundingSet
A whitespace-separated list of capability names, e.g. `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`, `CAP_SYS_PTRACE`.
Controls which capabilities to include in the capability bounding set for the executed process.
If the list of capabilities is prefixed with "~", all but the listed capabilities will be included, the effect of the assignment inverted.
This does not affect commands prefixed with "+".

[CapabilityBoundingSet](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=)

#### Available Options:

**CAP_AUDIT_CONTROL:** Allows processes to control kernel auditing behavior, including enabling and disabling auditing, and changing audit rules.

**CAP_AUDIT_READ:** Allows processes to read audit log via unicast netlink socket.

**CAP_AUDIT_WRITE:** Allows processes to write records to kernel auditing log.

**CAP_BLOCK_SUSPEND:** Allows processes to prevent the system from entering suspend mode.

**CAP_CHOWN:** Allows processes to change the ownership of files.

**CAP_DAC_OVERRIDE:** Allows processes to bypass file read, write, and execute permission checks.

**CAP_DAC_READ_SEARCH:** Allows processes to bypass file read permission checks and directory read and execute permission checks.

**CAP_FOWNER:** Allows processes to bypass permission checks on operations that normally require the filesystem UID of the file to match the calling process's UID.

**CAP_FSETID:** Allows processes to set arbitrary process and file capabilities.

**CAP_IPC_LOCK:** Allows processes to lock memory segments into RAM.

**CAP_IPC_OWNER:** Allows processes to perform various System V IPC operations, such as message queue management and shared memory management.

**CAP_KILL:** Allows processes to send signals to arbitrary processes.

**CAP_LEASE:** Allows processes to establish leases on open files.

**CAP_LINUX_IMMUTABLE:** Allows processes to modify the immutable and append-only flags of files.

**CAP_MAC_ADMIN:** Allows processes to perform MAC configuration changes.

**CAP_MAC_OVERRIDE:** Bypasses Mandatory Access Control (MAC) policies.

**CAP_MKNOD:** Allows processes to create special files using mknod().

**CAP_NET_ADMIN:** Allows processes to perform network administration tasks, such as configuring network interfaces, setting routing tables, etc.

**CAP_NET_BIND_SERVICE:** Allows processes to bind to privileged ports (ports below 1024).

**CAP_NET_BROADCAST:** Allows processes to transmit packets to broadcast addresses.

**CAP_NET_RAW:** Allows processes to use raw and packet sockets.

**CAP_SETGID:** Allows processes to change their GID to any value.

**CAP_SETFCAP:** Allows processes to set any file capabilities.

**CAP_SETPCAP:** Allows processes to set the capabilities of other processes.

**CAP_SETUID:** Allows processes to change their UID to any value.

**CAP_SYS_ADMIN:** Allows processes to perform a range of system administration tasks, such as mounting filesystems, configuring network interfaces, loading kernel modules, etc.

**CAP_SYS_BOOT:** Allows processes to reboot or shut down the system.

**CAP_SYS_CHROOT:** Allows processes to use chroot().

**CAP_SYS_MODULE:** Allows processes to load and unload kernel modules.

**CAP_SYS_NICE:** Allows processes to increase their scheduling priority.

**CAP_SYS_PACCT:** Allows processes to configure process accounting.

**CAP_SYS_PTRACE:** Allows processes to trace arbitrary processes using ptrace().

**CAP_SYS_RAWIO:** Allows processes to perform I/O operations directly to hardware devices.

**CAP_SYS_RESOURCE:** Allows processes to override resource limits.

**CAP_SYS_TIME:** Allows processes to set system time and timers.

**CAP_SYS_TTY_CONFIG:** Allows processes to configure tty devices.

**CAP_WAKE_ALARM:** Allows processes to use the RTC wakeup alarm.

# System calls 

### SystemCallFilter
A space-separated list of system call names. If this setting is used, all system calls executed by the unit processes except for the listed ones will result in immediate process terminationwith the `SIGSYS` signal (allow-listing). If the first character of the list is "~", the effect is inverted.
As the number of possible system calls is large, predefined sets of system calls are provided. A set starts with "@" character, followed by name of the set.
Predefined system call sets:

[SystemCallFilter](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=)

#### Set	Description:

**@clock:** Allows clock and timer-related system calls, such as clock_gettime, nanosleep, etc. This is essential for time-related operations.

**@cpu-emulation:** Allows CPU emulation-related system calls, typically used by virtualization software.

**@debug:** Allows debug-related system calls, which are often used for debugging purposes and may not be necessary for regular operations.

**@keyring:** Allows keyring-related system calls, which are used for managing security-related keys and keyrings.

**@module:** Allows module-related system calls, which are used for loading and unloading kernel modules. This can be restricted to prevent module loading for security purposes.

**@mount:** Allows mount-related system calls, which are essential for mounting and unmounting filesystems.

**@network:** Allows network-related system calls, which are crucial for networking operations such as socket creation, packet transmission, etc.

**@obsolete:** Allows obsolete system calls, which are no longer in common use and are often deprecated.

**@privileged:** Allows privileged system calls, which typically require elevated privileges or are potentially risky if misused.

**@raw-io:** Allows raw I/O-related system calls, which provide direct access to hardware devices. This can be restricted to prevent unauthorized access to hardware.

**@reboot:** Allows reboot-related system calls, which are necessary for initiating system reboots or shutdowns.

**@swap:** Allows swap-related system calls, which are used for managing swap space.

**@syslog:** Allows syslog-related system calls, which are used for system logging.

**@system-service:** Allows system service-related system calls, which are used for managing system services.

**@timer:** Allows timer-related system calls, which are essential for setting and managing timers.

**@whiteout:** Allows whiteout-related system calls, which are used for managing overlay filesystems.
