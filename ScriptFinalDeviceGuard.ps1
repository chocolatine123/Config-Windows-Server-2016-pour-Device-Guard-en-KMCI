################################################################################################################
############ Récupération des drivers utilisé lors d'un Boot d'un Windows Server 2016 sous Hyper-V  ############
################################################################################################################
###### Suppose que les logs de démarrage soient activées
## bcdedit /bootdebug on ou via System Configuration\ Boot puis cocher Boot Log
## bcdedit /debug on Si nécessaire.
###### Suppose également que Device Guard soit en place (VSM, Secure Boot et TPM).
## GPO Computer Configuration\ Policies\ Administrative Template\ System\ Device Guard\ Turn On VBS
## Secure Boot et DMA Protection + activer CCI et CG sans bloquer l'UEFI

###### Copie des drivers de C:\Windows\ntbtlog.txt dans un dossier de test à la racine de C:\
New-Item -Path "c:\" -Name "test" -ItemType "directory"
cp C:\Windows\ntbtlog.txt .\
$t = Get-Content .\ntbtlog.txt | where { $_ -like "*BOOTLOG*" } > .\test.txt
$t = Get-Content .\test.txt | Sort-Object | Get-Unique > .\test1.txt
$t = Get-Content .\test1.txt | foreach { $_ -replace "BOOTLOG_LOADED","cp" } > .\test2.txt
$t = Get-Content .\test2.txt | foreach { $_ -replace "\SystemRoot","C:\Windows" } > test3.txt
$t = Get-Content .\test3.txt | foreach { $_ -replace "BOOTLOG_NOT_LOADED","cp" } > test4.txt
$t = Get-Content .\test4.txt |foreach {$_ +  " C:\test"} > test5.txt
$t = Get-Content .\test5.txt 
$t = $t -replace('^(.{3}).', 'cp ') > FichiersACopier.ps1
rm .\ntbtlog.txt
rm .\test.txt
rm .\test1.txt
rm .\test2.txt
rm .\test3.txt
rm .\test4.txt
rm .\test5.txt
.\FichiersACopier.ps1
rm .\FichiersACopier.ps1

###### Copie des fichiers issus des logs  Application and services Logs\Microsoft\Windows\Boot-Kernel
cp C:\Windows\system32\apisetschema.dll c:\test
#cp C:\Windows\Boot\Resources\bootres.dll c:\test ## Optionnel
cp C:\Windows\system32\skci.dll c:\test
cp C:\Windows\system32\securekernel.exe c:\test

###### Copie des fichiers issus du tri manuel de System32
cp C:\Windows\system32\win32k.sys c:\test
cp C:\Windows\system32\win32kfull.sys c:\test
cp C:\Windows\system32\win32kbase.sys c:\test
#cp C:\Windows\system32\cca.dll c:\test
cp C:\Windows\system32\cdd.dll c:\test
cp C:\Windows\system32\workerdd.dll c:\test

###### Premier tri de System32\Drivers
### driversquery.exe
### Tri manuel
### Log kernel
### Bcdedit /debug
cp C:\Windows\system32\drivers\1394ohci.sys c:\test
cp C:\Windows\system32\drivers\3ware.sys c:\test
cp C:\Windows\system32\drivers\ACPI.sys c:\test
cp C:\Windows\system32\drivers\AcpiDev.sys c:\test
cp C:\Windows\system32\drivers\acpiex.sys c:\test
cp C:\Windows\system32\drivers\acpipagr.sys c:\test
cp C:\Windows\system32\drivers\AcpiPmi.sys c:\test
cp C:\Windows\system32\drivers\acpitime.sys c:\test
cp C:\Windows\system32\drivers\ADP80XX.sys c:\test
cp C:\Windows\system32\drivers\AFD.sys c:\test
cp C:\Windows\system32\drivers\AgileVpn.sys c:\test
cp C:\Windows\system32\drivers\ahcache.sys c:\test
cp C:\Windows\system32\drivers\AmdK8.sys c:\test
cp C:\Windows\system32\drivers\AmdPPM.sys c:\test
cp C:\Windows\system32\drivers\amdsata.sys c:\test
cp C:\Windows\system32\drivers\amdsbs.sys c:\test
cp C:\Windows\system32\drivers\amdxata.sys c:\test
cp C:\Windows\system32\drivers\AppID.sys c:\test
cp C:\Windows\system32\drivers\applockerfltr.sys c:\test
cp C:\Windows\system32\drivers\AppvStrm.sys c:\test
cp C:\Windows\system32\drivers\AppvVemgr.sys c:\test
cp C:\Windows\system32\drivers\AppvVfs.sys c:\test
cp C:\Windows\system32\drivers\arcsas.sys c:\test
cp C:\Windows\system32\drivers\AsyncMac.sys c:\test
cp C:\Windows\system32\drivers\atapi.sys c:\test
cp C:\Windows\system32\drivers\BasicDisplay.sys c:\test
cp C:\Windows\system32\drivers\BasicRender.sys c:\test
cp C:\Windows\system32\drivers\bcmfn.sys c:\test
cp C:\Windows\system32\drivers\bcmfn2.sys c:\test
cp C:\Windows\system32\drivers\Beep.sys c:\test
cp C:\Windows\system32\drivers\bfadfcoei.sys c:\test
cp C:\Windows\system32\drivers\bfadi.sys c:\test
cp C:\Windows\system32\DRIVERS\bowser.sys C:\test
cp C:\Windows\system32\drivers\bowser.sys c:\test
cp C:\Windows\system32\drivers\bridge.sys c:\test
cp C:\Windows\system32\drivers\buttonconverter.sys c:\test
cp C:\Windows\system32\drivers\bxfcoe.sys c:\test
cp C:\Windows\system32\drivers\bxois.sys c:\test
cp C:\Windows\system32\drivers\bxvbda.sys c:\test
cp C:\Windows\system32\drivers\CapImg.sys c:\test
cp C:\Windows\system32\drivers\cdfs.sys c:\test
cp C:\Windows\system32\drivers\cdrom.sys c:\test
cp C:\Windows\system32\drivers\CEA.sys C:\test
cp C:\Windows\system32\drivers\cht4sx64.sys c:\test
cp C:\Windows\system32\drivers\cht4vx64.sys c:\test
cp C:\Windows\System32\drivers\CLASSPNP.SYS C:\test
cp C:\Windows\system32\drivers\CLFS.sys c:\test
cp C:\Windows\System32\drivers\clipsp.sys C:\test
cp C:\Windows\system32\drivers\CmBatt.sys c:\test
cp C:\Windows\System32\drivers\cmimcext.sys C:\test
cp C:\Windows\system32\drivers\CNG.sys c:\test
cp C:\Windows\system32\drivers\cnghwassist.sys c:\test
cp C:\Windows\system32\drivers\condrv.sys c:\test
cp C:\Windows\system32\drivers\CSC.sys c:\test
cp C:\Windows\system32\drivers\dam.sys c:\test
cp C:\Windows\system32\drivers\dfs.sys C:\test
cp C:\Windows\system32\drivers\Dfsc.sys c:\test
cp C:\Windows\System32\Drivers\dfsc.sys C:\test
cp C:\Windows\system32\drivers\DfsrRo.sys c:\test
cp C:\Windows\system32\drivers\dfsrro.sys C:\test
cp C:\Windows\system32\drivers\Disk.sys c:\test
cp C:\Windows\system32\drivers\dmvsc.sys c:\test
cp C:\Windows\system32\drivers\DXGKrnl.sys c:\test
cp C:\Windows\system32\drivers\EhStorClass.sys c:\test
cp C:\Windows\system32\drivers\EhStorTcgDrv.sys c:\test
cp C:\Windows\system32\drivers\elxfcoe.sys c:\test
cp C:\Windows\system32\drivers\elxstor.sys c:\test
cp C:\Windows\system32\drivers\ErrDev.sys c:\test
cp C:\Windows\system32\drivers\evbda.sys c:\test
cp C:\Windows\system32\drivers\exfat.sys c:\test
cp C:\Windows\System32\Drivers\fastfat.SYS C:\test
cp C:\Windows\system32\drivers\fastfat.sys c:\test
cp C:\Windows\system32\drivers\fcvsc.sys c:\test
cp C:\Windows\system32\drivers\fdc.sys c:\test
cp C:\Windows\system32\drivers\filecrypt.sys C:\test
cp C:\Windows\system32\drivers\FileCrypt.sys c:\test
cp C:\Windows\system32\drivers\fileinfo.sys c:\test
cp C:\Windows\system32\drivers\FileInfo.sys c:\test
cp C:\Windows\system32\drivers\Filetrace.sys c:\test
cp C:\Windows\system32\drivers\flpydisk.sys c:\test
cp C:\Windows\System32\drivers\FLTMGR.SYS C:\test
cp C:\Windows\system32\drivers\FltMgr.sys c:\test
cp C:\Windows\System32\Drivers\Fs_Rec.sys C:\test
cp C:\Windows\system32\drivers\FsDepends.sys c:\test
cp C:\Windows\System32\drivers\fwpkclnt.sys C:\test
cp C:\Windows\system32\drivers\genericusbfn.sys c:\test
cp C:\Windows\system32\drivers\GpuEnergyDrv.sys c:\test
cp C:\Windows\system32\drivers\HDAudBus.sys c:\test
cp C:\Windows\system32\drivers\HidBatt.sys c:\test
cp C:\Windows\system32\drivers\HidBth.sys c:\test
cp C:\Windows\system32\drivers\hidinterrupt.sys c:\test
cp C:\Windows\system32\drivers\HidUsb.sys c:\test
cp C:\Windows\system32\drivers\HpSAMD.sys c:\test
cp C:\Windows\system32\drivers\HTTP.sys c:\test
cp C:\Windows\system32\drivers\hvservice.sys c:\test
cp C:\Windows\System32\drivers\hvsocket.sys C:\test
cp C:\Windows\system32\drivers\hwpolicy.sys c:\test
cp C:\Windows\system32\drivers\hyperkbd.sys c:\test
cp C:\Windows\system32\drivers\HyperVideo.sys c:\test
cp C:\Windows\system32\drivers\i8042prt.sys c:\test
cp C:\Windows\system32\drivers\iaLPSSi_GPIO.sys c:\test
cp C:\Windows\system32\drivers\iaLPSSi_I2C.sys c:\test
cp C:\Windows\system32\drivers\iaStorAV.sys c:\test
cp C:\Windows\system32\drivers\iaStorV.sys c:\test
cp C:\Windows\system32\drivers\ibbus.sys c:\test
cp C:\Windows\system32\drivers\IndirectKmd.sys c:\test
cp C:\Windows\system32\drivers\intelide.sys c:\test
cp C:\Windows\system32\drivers\intelpep.sys c:\test
cp C:\Windows\system32\drivers\intelppm.sys c:\test
cp C:\Windows\system32\drivers\ipfltdrv.sys c:\test
cp C:\Windows\system32\drivers\IPMIDRV.sys c:\test
cp C:\Windows\system32\drivers\IPNAT.sys c:\test
cp C:\Windows\system32\drivers\IPsecGW.sys c:\test
cp C:\Windows\system32\drivers\isapnp.sys c:\test
cp C:\Windows\system32\drivers\kbdclass.sys c:\test
cp C:\Windows\system32\drivers\kbdhid.sys c:\test
cp C:\Windows\system32\drivers\kdnic.sys c:\test
cp C:\Windows\system32\drivers\KSecDD.sys c:\test
cp C:\Windows\system32\drivers\KSecPkg.sys c:\test
cp C:\Windows\system32\drivers\ksthunk.sys c:\test
cp C:\Windows\system32\drivers\lltdio.sys c:\test
cp C:\Windows\system32\drivers\LSI_SAS.sys c:\test
cp C:\Windows\system32\drivers\LSI_SAS2i.sys c:\test
cp C:\Windows\system32\drivers\LSI_SAS3i.sys c:\test
cp C:\Windows\system32\drivers\LSI_SSS.sys c:\test
cp C:\Windows\system32\drivers\luafv.sys c:\test
cp C:\Windows\system32\drivers\luafv.sys C:\test
cp C:\Windows\system32\drivers\megasas.sys c:\test
cp C:\Windows\system32\drivers\megasas2i.sys c:\test
cp C:\Windows\system32\drivers\megasr.sys c:\test
cp C:\Windows\system32\drivers\mlx4_bus.sys c:\test
cp C:\Windows\system32\drivers\MMCSS.sys c:\test
cp C:\Windows\system32\drivers\Modem.sys c:\test
cp C:\Windows\system32\drivers\monitor.sys c:\test
cp C:\Windows\system32\drivers\mouclass.sys c:\test
cp C:\Windows\system32\drivers\mouhid.sys c:\test
cp C:\Windows\system32\drivers\mountmgr.sys c:\test
cp C:\Windows\system32\drivers\mpsdrv.sys c:\test
cp C:\Windows\system32\drivers\mrxsmb.sys c:\test
cp C:\Windows\system32\DRIVERS\mrxsmb.sys C:\test
cp C:\Windows\system32\DRIVERS\mrxsmb10.sys C:\test
cp C:\Windows\system32\drivers\mrxsmb10.sys c:\test
cp C:\Windows\system32\DRIVERS\mrxsmb20.sys C:\test
cp C:\Windows\system32\drivers\mrxsmb20.sys c:\test
cp C:\Windows\System32\Drivers\Msfs.SYS C:\test
cp C:\Windows\system32\drivers\Msfs.sys c:\test
cp C:\Windows\system32\drivers\msgpioclx.sys c:\test
cp C:\Windows\system32\drivers\msgpiowin32.sys c:\test
cp C:\Windows\system32\drivers\mshidkmdf.sys c:\test
cp C:\Windows\system32\drivers\mshidumdf.sys c:\test
cp C:\Windows\system32\drivers\msisadrv.sys c:\test
cp C:\Windows\system32\drivers\msiscsi.sys c:\test
cp C:\Windows\system32\drivers\MsLbfoProvider.sys c:\test
cp C:\Windows\system32\drivers\MsLldp.sys c:\test
cp C:\Windows\system32\drivers\MsRPC.sys c:\test
cp C:\Windows\system32\drivers\mssmbios.sys c:\test
cp C:\Windows\system32\drivers\MTConfig.sys c:\test
cp C:\Windows\system32\drivers\Mup.sys c:\test
cp C:\Windows\System32\Drivers\mup.sys C:\test
cp C:\Windows\system32\drivers\mvumis.sys c:\test
cp C:\Windows\system32\drivers\ndfltr.sys c:\test
cp C:\Windows\system32\drivers\NDIS.sys c:\test
cp C:\Windows\system32\drivers\NdisCap.sys c:\test
cp C:\Windows\system32\drivers\NdisImPlatform.sys c:\test
cp C:\Windows\system32\drivers\NdisTapi.sys c:\test
cp C:\Windows\system32\drivers\Ndisuio.sys c:\test
cp C:\Windows\system32\drivers\NdisVirtualBus.sys c:\test
cp C:\Windows\system32\drivers\NdisWan.sys c:\test
cp C:\Windows\system32\drivers\ndproxy.sys c:\test
cp C:\Windows\system32\drivers\netbios.sys C:\test
cp C:\Windows\system32\drivers\NetBIOS.sys c:\test
cp C:\Windows\system32\drivers\NetBT.sys c:\test
cp C:\Windows\system32\DRIVERS\NETIO.SYS C:\test
cp C:\Windows\system32\drivers\netvsc.sys c:\test
cp C:\Windows\system32\drivers\Npfs.sys c:\test
cp C:\Windows\System32\Drivers\Npfs.SYS C:\test
cp C:\Windows\system32\drivers\npsvctrig.sys c:\test
cp C:\Windows\system32\drivers\nsiproxy.sys c:\test
cp C:\Windows\system32\drivers\NTFS.sys c:\test
cp C:\Windows\System32\Drivers\NTFS.sys C:\test
cp C:\Windows\System32\drivers\ntosext.sys C:\test
cp C:\Windows\system32\drivers\Null.sys c:\test
cp C:\Windows\system32\drivers\nvraid.sys c:\test
cp C:\Windows\system32\drivers\nvstor.sys c:\test
cp C:\Windows\System32\drivers\pacer.sys C:\test
cp C:\Windows\system32\drivers\Parport.sys c:\test
cp C:\Windows\system32\drivers\partmgr.sys c:\test
cp C:\Windows\system32\drivers\pci.sys c:\test
cp C:\Windows\system32\drivers\pciide.sys c:\test
cp C:\Windows\system32\drivers\pcmcia.sys c:\test
cp C:\Windows\system32\drivers\pcw.sys c:\test
cp C:\Windows\system32\drivers\pdc.sys c:\test
cp C:\Windows\system32\drivers\PEAUTH.sys c:\test
cp C:\Windows\system32\drivers\percsas2i.sys c:\test
cp C:\Windows\system32\drivers\percsas3i.sys c:\test
cp C:\Windows\system32\drivers\Processr.sys c:\test
cp C:\Windows\system32\drivers\ql2300i.sys c:\test
cp C:\Windows\system32\drivers\ql40xx2i.sys c:\test
cp C:\Windows\system32\drivers\qlfcoei.sys c:\test
cp C:\Windows\system32\drivers\QWAVEdrv.sys c:\test
cp C:\Windows\system32\drivers\RasAcd.sys c:\test
cp C:\Windows\system32\drivers\RasGre.sys c:\test
cp C:\Windows\system32\drivers\Rasl2tp.sys c:\test
cp C:\Windows\system32\drivers\RasPppoe.sys c:\test
cp C:\Windows\system32\drivers\raspptp.sys c:\test
cp C:\Windows\system32\drivers\RasSstp.sys c:\test
cp C:\Windows\system32\drivers\rdbss.sys c:\test
cp C:\Windows\system32\DRIVERS\rdbss.sys C:\test
cp C:\Windows\system32\drivers\rdpbus.sys c:\test
cp C:\Windows\system32\drivers\RDPDR.sys c:\test
cp C:\Windows\system32\drivers\RdpVideoMiniport.sys c:\test
cp C:\Windows\system32\drivers\ReFS.sys c:\test
cp C:\Windows\system32\drivers\ReFSv1.sys c:\test
cp C:\Windows\System32\drivers\registry.sys C:\test
cp C:\Windows\system32\drivers\rspndr.sys c:\test
cp C:\Windows\system32\drivers\sacdrv.sys c:\test
cp C:\Windows\system32\drivers\sbp2port.sys c:\test
cp C:\Windows\system32\drivers\scfilter.sys c:\test
cp C:\Windows\system32\drivers\scmbus.sys c:\test
cp C:\Windows\system32\drivers\scmdisk0101.sys c:\test
cp C:\Windows\system32\drivers\sdbus.sys c:\test
cp C:\Windows\system32\drivers\sdstor.sys c:\test
cp C:\Windows\system32\drivers\SerCx.sys c:\test
cp C:\Windows\system32\drivers\SerCx2.sys c:\test
cp C:\Windows\system32\drivers\Serenum.sys c:\test
cp C:\Windows\system32\drivers\Serial.sys c:\test
cp C:\Windows\system32\drivers\sermouse.sys c:\test
cp C:\Windows\system32\drivers\sfloppy.sys c:\test
cp C:\Windows\system32\drivers\SiSRaid2.sys c:\test
cp C:\Windows\system32\drivers\SiSRaid4.sys c:\test
cp C:\Windows\system32\drivers\smbdirect.sys c:\test
cp C:\Windows\system32\drivers\spaceport.sys c:\test
cp C:\Windows\system32\drivers\SpbCx.sys c:\test
cp C:\Windows\System32\DRIVERS\srv.sys C:\test
cp C:\Windows\system32\drivers\srv.sys c:\test
cp C:\Windows\System32\DRIVERS\srv2.sys C:\test
cp C:\Windows\system32\drivers\srv2.sys c:\test
cp C:\Windows\system32\drivers\srvnet.sys c:\test
cp C:\Windows\System32\DRIVERS\srvnet.sys C:\test
cp C:\Windows\system32\drivers\stexstor.sys c:\test
cp C:\Windows\system32\drivers\storahci.sys c:\test
cp C:\Windows\system32\drivers\stornvme.sys c:\test
cp C:\Windows\System32\drivers\storport.sys C:\test
cp C:\Windows\system32\drivers\storqosflt.sys C:\test
cp C:\Windows\system32\drivers\storqosflt.sys c:\test
cp C:\Windows\system32\drivers\storufs.sys c:\test
cp C:\Windows\system32\drivers\storvsc.sys c:\test
cp C:\Windows\system32\drivers\swenum.sys c:\test
cp C:\Windows\system32\drivers\Synth3dVsc.sys c:\test
cp C:\Windows\system32\drivers\Tcpip.sys c:\test
cp C:\Windows\system32\drivers\tcpip.sys c:\test
cp C:\Windows\system32\drivers\tcpipreg.sys c:\test
cp C:\Windows\system32\drivers\tdx.sys c:\test
cp C:\Windows\system32\drivers\terminpt.sys c:\test
cp C:\Windows\System32\drivers\tm.sys C:\test
cp C:\Windows\system32\drivers\TPM.sys c:\test
cp C:\Windows\system32\drivers\TsUsbFlt.sys c:\test
cp C:\Windows\system32\drivers\TsUsbGD.sys c:\test
cp C:\Windows\system32\drivers\tsusbhub.sys c:\test
cp C:\Windows\system32\drivers\tunnel.sys c:\test
cp C:\Windows\system32\drivers\UASPStor.sys c:\test
cp C:\Windows\system32\drivers\UcmCx.sys c:\test
cp C:\Windows\system32\drivers\UcmTcpciCx.sys c:\test
cp C:\Windows\system32\drivers\UcmUcsi.sys c:\test
cp C:\Windows\system32\drivers\Ucx01000.sys c:\test
cp C:\Windows\system32\drivers\UdeCx.sys c:\test
cp C:\Windows\system32\DRIVERS\udfs.sys C:\test
cp C:\Windows\system32\drivers\udfs.sys c:\test
cp C:\Windows\system32\drivers\UEFI.sys c:\test
cp C:\Windows\system32\drivers\UevAgentDriver.sys c:\test
cp C:\Windows\system32\drivers\Ufx01000.sys c:\test
cp C:\Windows\system32\drivers\UfxChipidea.sys c:\test
cp C:\Windows\system32\drivers\ufxsynopsys.sys c:\test
cp C:\Windows\system32\drivers\umbus.sys c:\test
cp C:\Windows\system32\drivers\UmPass.sys c:\test
cp C:\Windows\system32\drivers\UrsChipidea.sys c:\test
cp C:\Windows\system32\drivers\UrsCx01000.sys c:\test
cp C:\Windows\system32\drivers\UrsSynopsys.sys c:\test
cp C:\Windows\system32\drivers\usbccgp.sys c:\test
cp C:\Windows\system32\drivers\usbehci.sys c:\test
cp C:\Windows\system32\drivers\usbhub.sys c:\test
cp C:\Windows\system32\drivers\USBHUB3.sys c:\test
cp C:\Windows\system32\drivers\usbohci.sys c:\test
cp C:\Windows\system32\drivers\usbprint.sys c:\test
cp C:\Windows\system32\drivers\usbser.sys c:\test
cp C:\Windows\system32\drivers\USBSTOR.sys c:\test
cp C:\Windows\system32\drivers\usbuhci.sys c:\test
cp C:\Windows\system32\drivers\USBXHCI.sys c:\test
cp C:\Windows\system32\drivers\vdrvroot.sys c:\test
cp C:\Windows\system32\drivers\VerifierExt.sys c:\test
cp C:\Windows\system32\drivers\vhdmp.sys c:\test
cp C:\Windows\system32\drivers\vhf.sys c:\test
cp C:\Windows\System32\drivers\vmbkmcl.sys C:\test
cp C:\Windows\system32\drivers\vmbus.sys c:\test
cp C:\Windows\system32\drivers\VMBusHID.sys c:\test
cp C:\Windows\System32\drivers\vmgencounter.sys C:\test
cp C:\Windows\system32\drivers\vmgencounter.sys c:\test
cp C:\Windows\system32\drivers\vmgid.sys c:\test
cp C:\Windows\system32\drivers\vms3cap.sys c:\test
cp C:\Windows\system32\drivers\vmstorfl.sys c:\test
cp C:\Windows\system32\drivers\volmgr.sys c:\test
cp C:\Windows\system32\drivers\volmgrx.sys c:\test
cp C:\Windows\system32\drivers\volsnap.sys c:\test
cp C:\Windows\system32\drivers\volume.sys c:\test
cp C:\Windows\system32\drivers\vpci.sys c:\test
cp C:\Windows\system32\drivers\vsmraid.sys c:\test
cp C:\Windows\system32\drivers\VSTXRAID.sys c:\test
cp C:\Windows\system32\drivers\WacomPen.sys c:\test
cp C:\Windows\system32\drivers\wanarp.sys c:\test
cp C:\Windows\system32\drivers\wcifs.sys C:\test
cp C:\Windows\system32\drivers\wcifs.sys c:\test
cp C:\Windows\system32\drivers\wcnfs.sys c:\test
cp C:\Windows\system32\drivers\WdBoot.sys c:\test
cp C:\Windows\system32\drivers\Wdf01000.sys c:\test
cp C:\Windows\system32\drivers\WdFilter.sys c:\test
cp C:\Windows\system32\drivers\WDFLDR.SYS C:\test
cp C:\Windows\system32\drivers\WdNisDrv.sys c:\test
cp C:\Windows\System32\drivers\werkernel.sys C:\test
cp C:\Windows\system32\drivers\WFPLWFS.sys c:\test
cp C:\Windows\system32\drivers\WIMMount.sys c:\test
cp C:\Windows\system32\drivers\WindowsTrustedRT.sys c:\test
cp C:\Windows\system32\drivers\WindowsTrustedRTProxy.sys c:\test
cp C:\Windows\System32\drivers\winhv.sys C:\test
cp C:\Windows\system32\drivers\WinMad.sys c:\test
cp C:\Windows\system32\drivers\WinNat.sys c:\test
cp C:\Windows\system32\drivers\WINUSB.sys c:\test
cp C:\Windows\system32\drivers\WinVerbs.sys c:\test
cp C:\Windows\system32\drivers\WmiAcpi.sys c:\test
cp C:\Windows\System32\drivers\WMILIB.SYS C:\test
cp C:\Windows\System32\Drivers\Wof.sys C:\test
cp C:\Windows\system32\drivers\Wof.sys c:\test
cp C:\Windows\system32\drivers\WpdUpFltr.sys c:\test
cp C:\Windows\System32\Drivers\WppRecorder.sys C:\test
cp C:\Windows\system32\drivers\ws2ifsl.sys c:\test
cp C:\Windows\system32\drivers\WudfPf.sys c:\test
cp C:\Windows\system32\drivers\WUDFRd.sys c:\test
cp C:\Windows\system32\drivers\xboxgip.sys c:\test
cp C:\Windows\system32\drivers\xinputhid.sys c:\test
cp C:\Windows\system32\drivers\dumpsdport.sys c:\test
cp C:\Windows\system32\drivers\dxgmms1.sys c:\test
cp C:\Windows\system32\drivers\dxgmms2.sys c:\test
cp C:\Windows\system32\drivers\hidclass.sys c:\test
cp C:\Windows\system32\drivers\hidparse.sys c:\test
cp C:\Windows\system32\drivers\stream.sys c:\test
cp C:\Windows\system32\drivers\tape.sys c:\test
cp C:\Windows\system32\drivers\tbs.sys c:\test
cp C:\Windows\system32\drivers\tdi.sys c:\test
cp C:\Windows\system32\drivers\vmbkmclr.sys c:\test
cp C:\Windows\system32\drivers\watchdog.sys c:\test
cp C:\Windows\system32\drivers\WfpCapture.sys c:\test
cp C:\Windows\system32\drivers\winhvr.sys c:\test

###### Génération de la Policy
cd C:\Windows\System32\CodeIntegrity\
New-CIPolicy -FilePath test.xml -Level FilePublisher -Fallback Hash -ScanPath C:\test\
Set-RuleOption -Option 0 -Delete -FilePath .\test.xml ## On enleve le mode UMCI pour passer en KMCI
Set-RuleOption -Option 3 -Delete -FilePath .\test.xml ## Ajouter un -Delete pour la mise en Prod
Set-RuleOption -Option 2 -FilePath .\test.xml
Set-RuleOption -Option 5 -FilePath .\test.xml
Set-RuleOption -Option 8 -FilePath .\test.xml
Set-RuleOption -Option 10 -FilePath .\test.xml
ConvertFrom-CIPolicy .\test.xml .\test.bin
rm -r C:\test\
#### Créer ensuite la GPO avec le chemin suivant :
## GPO : Computer Configuration\ Policies\ Administrative Template\ System\ Device Guard\Deploy CCI
## Valeur : C:\Windows\System32\CodeIntegrity\test.bin
#>