---
layout: post
title: captive-portal attack com eaphammer
date: 2024-02-15
description: recuperando psk ...
categories: wifi
---


## Ataque de Captive Portal com eaphammer

#### O ataque de captive-portal consiste em subir uma rede wifi falsa imitando a rede alvo (aka rogue ap, fake ap ou evil twin), para que os clientes da rede alvo se conectem na rede falsa, caiam em uma pagina phishing e assim passem a psk da rede legítima.

Para esse ataque você vai precisar de:

1 - a tool eaphammer (https://github.com/s0lst1c3/eaphammer)

2 - um adaptador wireless que suporte o modo AP(access point)

3 - um adaptador wireless que suporte o modo Monitor

4 - algum conhecimento basico de frontend


### 1 - escolhendo a pagina de phishing:

A pagina de phishing pode depender do cenario em que o ataque será feito, então fica a critério do atacante escolher a mais adequada.

Para esse tutorial vou usar uma pagina que é usada em outra tool de wifi hacking, a tool wifiphishing. Essa pagina simula uma atualização de firmware do roteador: https://wifiphisher.org/ps/firmware-upaginarade/


### 2 - clonando a pagina de phishing para a tool (adicionando template):

A tool eaphammer tem uma opção de clonar paginas para serem usadas nos ataques de captive portal. Então vamos clonar a pagina para usar no nosso ataque:

Nota: Tive problemas para clonar a pagina direto do link acima, então tive que fazer download dos arquivos e subila-la localmente pelo apache para assim clonar usando a tool. A pagina é feita de simples arquivos estaticos. A estrutura do dir deve ficar assim: 

```
/var/www/html
├── asus.png
├── bootstrap.min.css
├── bootstrap.min.js
├── jquery.min.js
└── index.html
```

Faça download dos arquivos da pagina, mova-os para /var/www/html, starte o serviço do apache e acesse o localhost (127.0.0.1) no navegador.


<div class="col-sm mt-3 mt-md-0">
    {% include figure.liquid loading="eager" path="assets/img/pihishrouterpg.png" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


Nessa parte você precisa ajustar os paths dos arquivos estaticos de css (no html) para a pagina ficar legivel (aqui que entra o conhecimento de frontend). Se a pagina estiver normal, rode o seguinte comando para clona-la:

```
└──╼ #./eaphammer --create-template --name firm-update --description "description..." --url http://127.0.0.1/
```

Para confirmar que a pagina foi clonada você pode listar os templates disponiveis:

```
└──╼ #./eaphammer --list-templates

[*] Listing available captive portal templates:

download         - Prompt targets to download an implant.
login            - Present user with a login page. Includes embedded realtime keylogger.
firm-update      - router firmware update page    <===========
```


### 3 - editando a pagina (template):

Durante meus testes com a pagina de phishing clonada tive problemas para receber a psk que é mandado pelo frontend para o backend da tool. Fazendo debugging nas requests enviadas e recebidas, percebi que quando a tool sobe a pagina ela injeta um código javascript que é usado para mandar os dados recebidos no frontend para o backend e assim mostrado nos logs do terminal... esse js espera receber um body mais ou menos assim ```{username: name, password: pass}```.

Então se você se deparar com esse problema, para resolver vá até os arquivos do template da pagina clonada em ```eaphammer/templates/seu-templete/``` e adicione um campo de "username" junto ao campo de "password" dessa forma(com os atributos html também):

``` 
<input type='text' name='username' value='TARGET-ESSID'/><br/>
<input type='password' name='password'/><br/>
```
Adicione também o atributo method='post' na tag do form, caso não tenha.

```
<form method='POST'>
```

(veja os templates default para mais exemplos)

Dica: Para colaborar com a pagina de phishing o campo username pode ser o essid da rede alvo como valor default (value='TARGET-ESSID'). 

Você tera que editar a pagina antes de subir a rede falsa. Fazendo isso o backend da tool vai receber os dados normalmente.

Depois de alterações o pagina deve ficar assim:

<div class="col-sm mt-3 mt-md-0">
    {% include figure.liquid loading="eager" path="assets/img/inputhtmledit.png" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


<div class="col-sm mt-3 mt-md-0">
    {% include figure.liquid loading="eager" path="assets/img/pgrendered.png" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


Nota: Você pode fazer o mesmo processo de editar o html para mudar outras partes, como o logo do vendor do roteador alvo, traduzir a pagina para portugues e etc. Isso para aumentar a credibilidade do phishing (fica critério do atacante).


### 4 - subindo o fake ap:

Agora é a hora que vamos precisar usar as duas placas de rede (adaptadores) ou só uma, se a placa suportar os modos necessarios. Para essa demonstração usei placas com os seguintes chipsets: RTL8812AU (suporta modo AP) e RTL8192EU (suporta modo Mon)


#### Starte o fake ap com a placa que suporta AP:

```
./eaphammer --captive-portal --portal-template seu-template --essid "TARGET-ESSID" --channel TARGET-CHANNEL --bssid 11:22:33:44:55:66 --interface INTERFACE-NAME
```

Dica: 
- em ```--essid``` deve ser o mesmo nome do alvo para ser convincente. 
- O ```--bssid``` deve ser parecido com o da rede alvo, alterando apenas um numero em qualquer lugar (de preferencia o ultimo), porque um mac igual ao da rede alvo pode conflitar na hora de mandar deauths. Ex: mac alvo = 1C:7E:E5:97:79:B1, mac fake ap = 1C:7E:E5:97:79:B2.

Se estiver tudo certo o fake ap vai ser iniciado como uma rede OPEN e você poderá ve-la igual qualquer outra rede (mas não se conecte a rede quando estiver fazendo o ataque). Você verá nos logs do terminal que o ap está ativo:


<div class="col-sm mt-3 mt-md-0">
    {% include figure.liquid loading="eager" path="assets/img/fakeapok.png" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


exemplo de visão do alvo

<div class="col-sm mt-3 mt-md-0">
    {% include figure.liquid loading="eager" path="assets/img/clientexample.png" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


#### Deauth na rede alvo:

Depois que o fake ap estiver up e esperando conexões você deve desautenticar os clientes da rede alvo para que eles possam se conectar no fake ap. Use o aireplay-ng pra isso:

```
aireplay-ng -0 0 -a TARGET-AP-MAC INTEFACE-NAME
```

Dica: o comando acima manda deauth para o broadcast da rede alvo, ou seja, todos os clientes vão receber os pacotes de deauth. Essa é a melhor forma porque não adianta muito você desautenticar apenas um cliente e os outros continuarem conectados normalmente, e você também corre o risco de ser percebido por causa das diferença da rede legitima e a falsa.


#### logs do fake ap:

Quando alguém se conectar ao fake ap, os logs vão aparecer na tela do terminal junto com os logs do DNS-spoofing funcionando e redirecionando os dispositivos conectados para a pagina de phishing:


<div class="col-sm mt-3 mt-md-0">
    {% include figure.liquid loading="eager" path="assets/img/clientconect.png" width="800" height="800" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


Conforme o client vai tentando acessar outras paginas pelo navegador o ataque de spoofing continua redirencionando para a pagina de phishing.


exemplo de visão do alvo em smartphone


<div class="col-sm mt-3 mt-md-0">
    {% include figure.liquid loading="eager" path="assets/img/phoneexample.png" width="300" height="300" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


O client conectado verá o pagina de atualização de firmware e se a sua eng-social der certo, ele digitara a senha pensando que há uma atualização de firmware do roteador... e a psk digitada vai aparecer nos logs do fake ap:

<div class="col-sm mt-3 mt-md-0">
    {% include figure.liquid loading="eager" path="assets/img/recvpsk.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


