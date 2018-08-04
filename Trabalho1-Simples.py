
from scapy.all import *
import  os

lista_ip_unicas = []

def listagem():
	os.system('clear')
	qtd = len(lista_ip_unicas)
	print 'Listagem de ips unicos (%s):\n' % str(qtd)
	for p1 in lista_ip_unicas:
		print p1
	
	print '\n-FIM-\n'

def monitorar(pkt):
	os.system('clear')
	print 'Monitoramento:\n'
        ip = str(pkt.sprintf(" %ARP.psrc%"))
	if ip not in lista_ip_unicas:
		lista_ip_unicas.append(ip)
	for y in lista_ip_unicas:
		print y
	print '\nPara cancelar o scan, aperte CTRL+C (algumas vezes e espere...)\n'

def recon():
	while True:
		try:
			sniff(prn=monitorar, filter="arp",store=0)
		except KeyboardInterrupt:
			listagem()
			break

recon()
