#!/bin/bash

modprobe ip_tables
 

function LimpaRegras(){
    echo -n "Clear regras ........................................... "
     # clear Chains
     iptables -F INPUT
     iptables -F OUTPUT
     iptables -F FORWARD
     iptables -F -t filter
     iptables -F POSTROUTING -t nat
     iptables -F PREROUTING -t nat
     iptables -F OUTPUT -t nat
     iptables -F -t nat
     iptables -t nat -F
     iptables -t mangle -F
     iptables -X
     # clear count
     iptables -Z
     iptables -t nat -Z
     iptables -t mangle -Z
     # Define politicas padrao ACCEPT
     iptables -P INPUT ACCEPT
     iptables -P OUTPUT ACCEPT
     iptables -P FORWARD ACCEPT
}


#PING ____________________________________________________________________
function AtivaPing(){
    echo -n "Ativando resposta do ping ................................. "
    echo "0" > /proc/sys/net/ipv4/icmp_echo_ignore_all
}

#Protected _______________________________________________________________
function DesativaProtecao(){
    echo -n "Removendo regras de proteção .............................. "
    
    i=/proc/sys/net/ipv4
    
    echo "1" > /proc/sys/net/ipv4/ip_forward
    echo "0" > $i/tcp_syncookies
    echo "0" > $i/icmp_echo_ignore_broadcasts
    echo "0" > $i/icmp_ignore_bogus_error_responses
    
    for i in /proc/sys/net/ipv4/conf/*; do
        echo "1" > $i/accept_redirects
        echo "1" > $i/accept_source_route
        echo "0" > $i/log_martians
        echo "0" > $i/rp_filter
    done
}
function ativaprotecao(){
    echo -n "Ativando protecao ......................................... "
    # Ativando algumas coisas básicas do kernel
    # Abilitar o uso de syncookies (muito útil para evitar SYN flood attacks)
    echo 1 > /proc/sys/net/ipv4/tcp_syncookies                     
    # desabilita o "ping" (Mensagens ICMP) para sua máquina
    echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all               
    # Não aceite redirecionar pacotes ICMP
    echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects          
    # Ative a proteção contra respostas a mensagens de erro falsas
    echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses 
    # Evita a peste do Smurf Attack e alguns outros de redes locais
    echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts        
}

#Clear ___________________________________________________________________
function limpatabelas(){
    echo -n "Limpando regras ........................................... "
    
    # limpando tabelas
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
}

#Politics ________________________________________________________________
function politicaspadrao(){
    echo -n "Configurando padrao ....................................... "
    
    # Configurando as políticas padrões
    iptables -P INPUT DROP
    iptables -P OUTPUT DROP
    iptables -P FORWARD DROP

    # Loga/Adiciona/Descarta hosts da lista "SUSPEITO" 
    #(cuja conexão não cumpre nenhuma das regras acima) {deixe como última regra!}
    iptables -A INPUT -p tcp --dport=20 -j LOG --log-level warning --log-prefix "[firewall] [ftp]"
    iptables -A INPUT -p udp --dport=20 -j LOG --log-level warning --log-prefix "[firewall] [ftp]"
    iptables -A INPUT -p tcp --dport=21 -j LOG --log-level warning --log-prefix "[firewall] [ftp]"
    iptables -A INPUT -p udp --dport=21 -j LOG --log-level warning --log-prefix "[firewall] [ftp]"
    iptables -A INPUT -p tcp --dport=22 -j LOG --log-level warning --log-prefix "[firewall] [ssh]"
    iptables -A INPUT -p udp --dport=22 -j LOG --log-level warning --log-prefix "[firewall] [ssh]"
    iptables -A INPUT -p tcp --dport=23 -j LOG --log-level warning --log-prefix "[firewall] [telnet]"
    iptables -A INPUT -p udp --dport=23 -j LOG --log-level warning --log-prefix "[firewall] [telnet]"
    iptables -A INPUT -p icmp  -j LOG --log-level warning --log-prefix "[firewall] [ping]"
}

#Loopback ________________________________________________________________
function permitirloop(){
    echo -n "Permitindo loopback ....................................... "

    # Permitindo loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Permite o estabelecimento de novas conexões iniciadas por você // coração do firewall //
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED,NEW -j ACCEPT
}

#DNS
function dns(){
    echo -n "Ativando dns .............................................. "
    
    # Libera o acesso do DNS 
    #(troque pelo seu, caso não use o DNS do google. Caso não saiba exclua a opção -s apagando até antes do -j)
    iptables -A INPUT -p udp --sport 53  -j ACCEPT
    iptables -A INPUT -p udp --sport 53  -j ACCEPT

    # Liberando portas de serviços externos (descomente e altere conforme sua necessidade)
    #iptables -A INPUT -p tcp -m multiport --dport 21,22,53,80,443,3128,8080,1900 -j ACCEPT

    #--- Criando listas de bloqueios

    # Descarta pacotes reincidentes/persistentes da lista SUSPEITO 
    #(caso tenha 5 entradas ficará 1H em DROP / caso tenha 10 ficará 24H em DROP)
    iptables -A INPUT -m recent --update --hitcount 10 --name SUSPEITO --seconds 86400 -j DROP
    iptables -A INPUT -m recent --update --hitcount 5 --name SUSPEITO --seconds 3600 -j DROP

    # Descarta pacotes reincidentes/persistentes da lista SYN-DROP 
    #(caso tenha 5 entradas ficará 1H em DROP / caso tenha 10 ficará 24H em DROP)
    iptables -A INPUT -m recent --update --hitcount 10 --name SYN-DROP --seconds 86400 -j DROP
    iptables -A INPUT -m recent --update --hitcount 5 --name SYN-DROP --seconds 3600 -j DROP
}

#Chain _________________________________________________________________
function criachain(){
    echo -n "criando chains ............................................ "
    
    # Cria a CHAIN "SYN"
    iptables -N SYN
    iptables -A SYN -m limit --limit 10/min --limit-burst 3 -j LOG --log-level warning --log-prefix "[firewall] [SYN: DROP]"
    iptables -A SYN -m limit --limit 10/min --limit-burst 3 -m recent --set --name SYN-DROP -j DROP
    iptables -A SYN -m limit --limit 1/min --limit-burst 1 -j LOG --log-level warning --log-prefix "[firewall] [SYN: FLOOD!]"
    iptables -A SYN -j DROP

    # Cria a CHAIN "SCANNER"
    iptables -N SCANNER
    iptables -A SCANNER -m limit --limit 10/min --limit-burst 3 -j LOG --log-level warning --log-prefix "[firewall] [SCANNER: DROP]"
    iptables -A SCANNER -m limit --limit 10/min --limit-burst 3 -m recent --set --name SUSPEITO -j DROP
    iptables -A SCANNER -m limit --limit 1/min --limit-burst 1 -j LOG --log-level warning --log-prefix "[firewall] [SCANNER: FLOOD!]"
    iptables -A SCANNER -j DROP

    #--- Bloqueios

    # Rejeita os restos de pacotes após fechar o torrent (subistitua 12300 pela porta do seu torrent)
    #iptables -A INPUT -p tcp --dport 12300 -j REJECT
    #iptables -A INPUT -p udp --dport 12300 -j DROP

    # Manda os pacotes SYN suspeitos (não liberados acima) para a chain "SYN"
    iptables -A INPUT -p tcp --syn -m state --state NEW -j SYN

    # Adicionando regras para CHAIN "SCANNER"
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j SCANNER
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j SCANNER
    iptables -A INPUT -p tcp --tcp-flags ALL ACK -j SCANNER
    iptables -A INPUT -p tcp --tcp-flags ALL SYN,ACK -j SCANNER
    iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j SCANNER
    iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j SCANNER
    iptables -A INPUT -p tcp --tcp-flags ALL PSH,URG,FIN -j SCANNER
    iptables -A INPUT -p tcp --tcp-flags ALL URG,PSH,FIN -j SCANNER
    iptables -A INPUT -p tcp --tcp-flags ALL FIN,SYN -j SCANNER
    iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j SCANNER
    iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j SCANNER
    iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j SCANNER
    iptables -A INPUT -p tcp --tcp-flags ALL FIN -j SCANNER

    # Descarta pacotes inválidos
    iptables -A INPUT -m state --state INVALID -j DROP

    #bloqueia portas
    iptables -A INPUT -p tcp --dport=20 -j DROP
    iptables -A INPUT -p udp --dport=20 -j DROP
    iptables -A INPUT -p tcp --dport=21 -j DROP
    iptables -A INPUT -p udp --dport=21 -j DROP
    iptables -A INPUT -p tcp --dport=22 -j DROP
    iptables -A INPUT -p udp --dport=22 -j DROP
    iptables -A INPUT -p tcp --dport=23 -j DROP
    iptables -A INPUT -p udp --dport=23 -j DROP
    iptables -A INPUT -m recent --update --name SUSPEITO -m limit --limit 10/min --limit-burst 3 -j LOG --log-level warning --log-prefix "[firewall] [suspeito]"
    iptables -A INPUT -m limit --limit 10/min --limit-burst 3 -m recent --set --name SUSPEITO -j DROP
    iptables -A INPUT -j DROP
}

#LEGENDS _______________________________________________________________
function Backdoor(){
    echo -n "Backdoor Block ............................................ "
    iptables -A INPUT -j DROP
    iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
}

function ExternalBlock(){
    echo -n "External Block ............................................ "
    iptables -A INPUT -p tcp --syn -j DROP
    iptables -A INPUT -j REJECT
}

function Blacklist(){
    echo -n "Blacklist ................................................. "
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    #LOG
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix "[firewall> Null scan]" 
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -m recent --name blacklist_60 --set -m comment --comment "Drop Blacklist Null scan" -j DROP
}

function stopServices(){
    echo -n "Stop services ............................................. "
    service cups stop
}
#______________________________________________________________________




#______________________________firewall________________________________
function IniciaFirewall(){
clear
echo "========================================================================"
echo "|       lll                                    dd                      |"
echo "|       lll   eee   gggggg   eee  nn nnn       dd  sss                 |"
echo "|       lll ee   e gg   gg ee   e nnn  nn  dddddd s                    |"
echo "|------------------------------------------------------------------>   |"
echo "|       lll eeeee  ggggggg eeeee  nn   nn dd   dd  sss                 |"
echo "|       lll  eeeee      gg  eeeee nn   nn  dddddd     s                |"
echo "|                   ggggg                          sss                 |"
echo "========================================================================"
echo "                                                           Firewall 0.70"
echo "                                                    Adaptado de T4K3D0WN"


if limpatabelas
  then
   echo -e "[\033[01;32m  OK  \033[01;37m] "
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if ativaprotecao
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if politicaspadrao
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if permitirloop
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if dns
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if criachain
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if Backdoor
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi 
 if ExternalBlock
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi 
 if Blacklist
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if stopServices
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 
 
echo -n "iniciando firewall ........................................ "
echo -e  -n "[\033[01;32m  Firewall Ativo!  \033[01;37m]"
echo
}

function ParaFirewall(){
clear
echo "========================================================================"
echo "|       lll                                    dd                      |"
echo "|       lll   eee   gggggg   eee  nn nnn       dd  sss                 |"
echo "|       lll ee   e gg   gg ee   e nnn  nn  dddddd s                    |"
echo "|------------------------------------------------------------------>   |"
echo "|       lll eeeee  ggggggg eeeee  nn   nn dd   dd  sss                 |"
echo "|       lll  eeeee      gg  eeeee nn   nn  dddddd     s                |"
echo "|                   ggggg                          sss                 |"
echo "========================================================================"
echo "                                                           Firewall 0.70"
echo "                                                    Adaptado de T4K3D0WN"

 if LimpaRegras
  then
   echo -e "[\033[01;32m  OK  \033[01;37m] "
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi 
 if AtivaPing
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if DesativaProtecao
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 #Lista de Funções executadas
 #LimpaRegras
 #AtivaPing
 #DesativaProtecao
 echo
}  

case $1 in
  start)
   IniciaFirewall
   exit 0
  ;;

  stop)
   ParaFirewall
  ;;
 
  *)
   echo "Escolha uma opção válida { start | stop }"
   echo
esac


## LEGENDS...
#HONEYPOT
#REDIRECT CONEXÕES ESTABELECIDAS (BACKDOOR) PARA A POLICIA OU PARA O PROPRIO ATACANTE
#Comumento estou reirecionando para outra VPN cou máquna virtual com malware ou algo referente
# para outra subnet
#iptables -t nat -A PREROUTING -p tcp --dport 9020 -j DNAT --to 10.0.3.11:80
# para conexão local
#iptables -t nat -A OUTPUT -p tcp --dport 9020 -j DNAT --to 10.0.3.11:80

# Masquerade local subnet
#iptables -t nat -A POSTROUTING -s 10.0.3.0/16 -j MASQUERADE
#iptables -A FORWARD -o lxcbr0 -m state --state RELATED,ESTABLISHED -j ACCEPT
#iptables -A FORWARD -i lxcbr0 -o eth0 -j ACCEPT
#iptables -A FORWARD -i lxcbr0 -o lo -j ACCEPT



