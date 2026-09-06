package syslog

// The FreeBSD console multiplexes boot inventory and rc-script progress under
// kernel. These complete informational grammars have no useful event extraction.
// Hardware faults, panics and new diagnostics must NOT match the inventory list.
// Prefixes are optional because syslog paths differ in retaining kernel PRI and
// uptime. No severity or whole-program exemption is used.
func init() {
	for _, pattern := range []string{
		`---<<BOOT>>---`,
		`Copyright \(c\) \d{4}-\d{4} The FreeBSD Project\.`,
		`Copyright \(c\) \d{4}(?:, \d{4})*`,
		`\tThe Regents of the University of California\. All rights reserved\.`,
		`The Regents of the University of California\. All rights reserved\.`,
		`FreeBSD is a registered trademark of The FreeBSD Foundation\.`,
		`FreeBSD [^\r\n]+ (?:SMP|GENERIC) amd64`,
		`FreeBSD clang version [\w.]+ \(https://github\.com/llvm/llvm-project\.git [\w.-]+\)`,
		`VT\(efifb\): resolution \d+x\d+`,
		`CPU: [^\r\n]+ \(\d+\.\d+-MHz K8-class CPU\)`,
		` +Origin="[\w]+" +Id=0x[0-9a-f]+ +Family=0x[0-9a-f]+ +Model=0x[0-9a-f]+ +Stepping=\d+`,
		` +(?:Features2?|AMD Features2?|Structured Extended Features[23]?|XSAVE Features)=0x[0-9a-f]+<[\w.,]+>`,
		` +VT-x: [\w,]+`,
		` +TSC: P-state invariant, performance statistics`,
		`(?:real|avail) memory += \d+ \(\d+ MB\)`,
		`Event timer "[\w-]+" quality \d+`,
		`ACPI APIC Table: <[\w ]+>`,
		`FreeBSD/SMP: Multiprocessor System Detected: \d+ CPUs`,
		`FreeBSD/SMP: \d+ package\(s\) x \d+ core\(s\) x \d+ hardware threads`,
		`random: (?:registering fast source Intel Secure Key (?:RNG|Seed)|fast provider: "Intel Secure Key (?:RNG|Seed)"|unblocking device\.|entropy device external interface)`,
		`ioapic\d+ <Version \d+\.\d+> irqs \d+-\d+`,
		`Launching APs: \d+(?: \d+)*`,
		`wlan: mac acl policy registered`,
		`kbd\d+ at kbdmux\d+`,
		`(?:[\w]+\d+|uart): <[^>\r\n]+>(?: (?:port|mem|iomem|irq|at|on|flags) [\w .,:()/+-]+)?`,
		`(?:efirtc|atrtc)\d+: registered as a time-of-day clock, resolution \d+(?:\.\d+)?(?:us|s)`,
		`smbios\d+: Entry point: v\d+ \(\d+-bit\), Version: \d+\.\d+(?:, BCD Revision: \d+\.\d+)?`,
		`acpi\d+: Power Button \(fixed\)`,
		`Timecounter "[\w-]+" frequency \d+ Hz quality -?\d+`,
		`Event timer "[\w-]+" frequency \d+ Hz quality -?\d+`,
		`Timecounters tick every \d+\.\d+ msec`,
		`(?:ixl|igb)\d+: fw [\w.]+ api [\w.]+ nvm [\w.]+ etid [0-9a-fA-F]+(?: oem [\w.]+)?`,
		`ixl\d+: PF-ID\[\d+\]: VFs \d+, MSI-X \d+, VF MSI-X \d+, QPs \d+, (?:I2C|(?:AV|RSS) [\w, ]+)`,
		`(?:ixl|igb)\d+: Using \d+ (?:TX descriptors and \d+ RX descriptors|RX queues \d+ TX queues)`,
		`(?:ixl|igb)\d+: Using MSI-X interrupts with \d+ vectors`,
		`(?:ixl|igb)\d+: Ethernet address: [0-9a-fA-F:]+`,
		`ixl\d+: Allocating \d+ queues for PF LAN VSI; \d+ queues active`,
		`ixl\d+: PCI Express Bus: Speed \d+\.\d+GT/s Width x\d+`,
		`ixl\d+: SR-IOV ready`,
		`(?:ixl|igb)\d+: netmap queues/slots: TX \d+/\d+, RX \d+/\d+`,
		`xhci\d+: \d+ bytes context size, \d+-bit DMA`,
		`xhci\d+: xECP capabilities <[\w(),]+>`,
		`usbus\d+ on xhci\d+`,
		`usbus\d+: \d+\.\d+Gbps Super Speed USB v\d+\.\d+`,
		`ahci\d+: AHCI v?\d+\.\d+ with \d+ \d+Gbps ports, Port Multiplier (?:not )?supported`,
		`igb\d+: EEPROM V\d+\.\d+-\d+ eTrack 0x[0-9a-fA-F]+`,
		`vgapci\d+: Boot video device`,
		`atrtc\d+: <AT realtime clock> at port 0x[0-9a-f]+ on isa\d+`,
		`ZFS filesystem version: \d+`,
		`ZFS storage pool version: features support \(\d+\)`,
		`Trying to mount root from zfs:[\w/-]+ \[\]\.\.\.`,
		`uhub\d+ on usbus\d+`,
		`ada\d+ at ahcich\d+ bus \d+ scbus\d+ target \d+ lun \d+`,
		`ada\d+: Serial Number [\w-]+`,
		`ada\d+: \d+\.\d+MB/s transfers \(SATA \d+\.[\dx]+, UDMA\d+, PIO \d+bytes\)`,
		`ada\d+: Command Queueing enabled`,
		`ada\d+: \d+MB \(\d+ \d+ byte sectors\)`,
		`ada\d+: quirks=0x[0-9a-f]+<[\w,]+>`,
		`ses\d+ at ahciem\d+ bus \d+ scbus\d+ target \d+ lun \d+`,
		`ses\d+: SEMB SES Device`,
		`ses\d+: ada\d+,pass\d+ in 'Slot \d+', SATA Slot: scbus\d+ target \d+`,
		`uhub\d+: \d+ ports with \d+ removable, self powered`,
		`Mounting filesystems\.\.\.`,
		`no pools available to import`,
		`Setting hostuuid: [0-9a-fA-F-]+\.`,
		`Setting hostid: 0x[0-9a-fA-F]+\.`,
		`>>> Invoking (?:import|early) script '[\w.-]+'`,
		`Configuring crash dump device: /dev/[\w]+`,
		`swapon: adding /dev/[\w]+ as swap device`,
		`\.ELF ldconfig path: /lib(?: /[\w./-]+)*`,
		`ugen\d+\.\d+: <[^>\r\n]+> at usbus\d+`,
		`ada\d+: <[^>\r\n]+> ACS-\d+ ATA SATA \d+\.[\dx]+ device`,
		`ses\d+: <[^>\r\n]+> SEMB S-E-S \d+\.\d+ device`,
		`32-bit compatibility ldconfig path:`,
		`done\.`,
		`Starting configd\.`,
		`Generating configuration: templates\.\.\.done`,
		`CARP event system: OK`,
		// A console line containing only an optional PRI/uptime prefix.
		``,
		`Launching the init system\.\.\.done\.`,
		`Initializing\.{10}done\.`,
		`Starting device manager\.\.\.`,
		`ig4iic\d+: Using MSI`,
		`acpi_wmi\d+: Embedded MOF found`,
		`Configuring login behaviour\.\.\.done\.`,
		`Configuring loopback interface\.\.\.`,
		`Configuring kernel modules\.\.\.`,
		`Setting up extended sysctls\.\.\.done\.`,
		`Setting timezone: [\w/+-]+`,
		`Writing firmware settings: [\w ]+`,
		`Writing trust files\.\.\.done\.`,
		`Scanning /(?:usr/share/certs/(?:untrusted|trusted)|usr/local/share/certs) for certificates\.\.\.`,
		`certctl: No changes to trust store(?: were made\.)?`,
	} {
		knownMessage("kernel", "boot_inventory", `(?:<\d+>)?(?:\[\d+\] )?`+pattern)
	}
	// Faults encountered during boot are structured, never hidden as inventory.
	for _, pattern := range []string{
		`WARNING: Device "spkr" is Giant locked(?: and may be deleted before FreeBSD \d+\.\d+\.)?`,
		`atrtc\d+: Warning: Couldn't map I/O\.`,
		`atrtc\d+: Can't map interrupt\.`,
		`igb\d+: PHY reset is blocked due to SOL/IDER session\.`,
		`uart: ns8250: UART FCR is broken(?: \(0x[0-9a-f]+\))?`,
		`acpi_wmi\d+: cannot find EC device`,
	} {
		capturedEvent("kernel", "kernel_boot_diagnostic", `(?:<\d+>)?(?:\[\d+\] )?(`+pattern+`)`, "error.message")
	}
	capturedEvent("kernel", "interface_driver_link_up", `(?:<\d+>)?(?:\[\d+\] )?([\w.-]+): Link is up, (\d+) Gbps Full Duplex, Requested FEC: (\w+), Negotiated FEC: (\w+), Autoneg: (\w+), Flow Control: (\w+)`, "interface", "interface.speed_gbps", "interface.fec.requested", "interface.fec.negotiated", "interface.autoneg", "interface.flow_control")
	capturedEvent("kernel", "interface_renamed", `(?:<\d+>)?(?:\[\d+\] )?([\w.-]+): changing name to '([\w.-]+)'`, "interface.previous", "interface")
	capturedEvent("kernel", "ipv6_dad_diagnostic", `(?:<\d+>)?(?:\[\d+\] )?nd6_dad_timer: called with non-tentative address (\S+)`, "interface.address")
	capturedEvent("kernel", "process_signal_exit", `(?:<\d+>)?(?:\[\d+\] )?pid (\d+) \(([^)\r\n]+)\), jid (\d+), uid (\d+): exited on signal (\d+) \(no core dump - denied by ([\w.]+)\)`, "process.pid", "process.name", "process.jail_id", "process.uid", "process.signal", "process.core_policy")
	capturedEvent("kernel", "netmap_free_diagnostic", `(?:<\d+>)?(?:\[\d+\] )?\d+\.\d+ \[ *\d+\] netmap_extra_free +breaking with head ([0-9a-fA-F]+)`, "netmap.head")

}
