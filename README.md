WinMD v0.1
----------

WinMD is a driver allowing Windows to access MD RAID devices - software RAID
volumes created by `mdadm` on Linux. Bear in mind that you will still need a
filesystem driver: see, for instance, [WinBtrfs](https://github.com/maharmstone/btrfs) and [Ext2fsd](https://sourceforge.net/projects/ext2fsd/).

Everything here is released under the GNU Lesser General Public Licence (LGPL);
see the file LICENCE for more info. You are encouraged to play about with the
source code as you will, and I'd appreciate a note (mark@harmstone.com) if you
come up with anything nifty.

Donations
---------

I've been developing this driver for fun, and in the hopes that someone out there
will find it useful. But if you want to provide some pecuniary encouragement, it'd
be very much appreciated:

* [Paypal](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=3XQVCQ6YB55L2&lc=GB&item_name=WinMD%20donation&currency_code=GBP&bn=PP%2dDonationsBF%3abtn_donate_LG%2egif%3aNonHosted)

Features
--------

* RAID 0
* RAID 1
* RAID 4
* RAID 5
* RAID 6
* RAID 10 (near, far, offset)
* Linear
* Recognizes version 1 superblocks (1.0, 1.1, 1.2)
* Nested sets

Todo
----

* whole-disk RAID (i.e. recognizing partitions on MD device)
* reshaping
* rebuilding
* checking
* degraded mounts
* adding and removing devices
* creating new sets from Windows
* RAID4/5/6 journal
* write-intent bitmaps

Installation
------------

To install the driver, [download and extract the latest release](https://github.com/maharmstone/winmd/releases),
right-click winmd.inf, and choose Install. The driver is signed, so should work out
of the box on modern versions of Windows.

For the very latest versions of Windows 10, Microsoft introduced more onerous
requirements for signing, which are only available to corporations and not individuals.
If this affects you (i.e. you get a signing error when trying to install the driver),
try disabling Secure Boot in your BIOS settings.

Uninstalling
------------

From an elevated command prompt, run:

`RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultUninstall 132 winmd.inf`

You will probably need to give the full path to winmd.inf. Next time you reboot, Windows
will remove the driver from your system.

You can also disable it by opening regedit and setting the value of
HKLM\SYSTEM\CurrentControlSet\services\winmd\Start to 4.

Changelog
---------

v0.1 (2019-07-31):
* Initial release
