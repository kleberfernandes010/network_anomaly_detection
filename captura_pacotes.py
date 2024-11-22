# importando bibliotecas necessarias
from scapy.all import sniff, TCP, IP # Biblioteca para captura e manipulação de rede
import csv # Biblioteca para trabalhar com arquivos csv
from datetime import datetime # bibliotecas para trabalhar com datas e horas 
import logging # biblioteca para trabalhhar com logging
# Configurar logging para registrar anomalias localmente
logging.basicConfig(filename='anomalies.log', level=logging.INFO, format='%(asctime)s %(message)s')
# Lista para armazena anomalias detectadas
anomalies = []
# Função para detectar anomalias nos pacotes capturados
def detect_anomalies(packet):

    if packet.haslayer(TCP) and packet.haslayer(IP): #Verificar se o pacote tem camadas TCP e IP
        print(" packet captured:", packet.summary()) #Imprimir resumo do pacote capturado
        print("TCP Packet with IP layer captured") # Confirmação de pacote TCP capturado com camada IP
        print("TCP flags:", packet[TCP].flags) # Imprimir flags TCP para depuração
        # criar um dicionario de anomalia
        anomaly = {
            "source_ip": packet[IP].src, #endereço IP de origem
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), #Timestamp da anomalia
            "description": "Possible SYN scan detected" # Descrição da anomalia
        }
        # Adicionar anomalia à lista
        anomalies.append(anomaly)
        print(f"TCP packet from {packet[IP].src} with flags {packet[TCP].flags}") #Confirmação de captura
        logging.info(f"Anomaly detected: {anomaly}") # regristrar anomalia no arquivo de log
# Função para gerar relatorio CSV das anomalias
def generate_report(anomalies):
    with open('report.csv', 'w' , newline= '') as csvfile: #Abrir arquivo csv para escrita
        fieldnames = ['timestamp', 'source_ip', 'description'] # Definir cabeçalhos das colunas
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames) # criar escritor CSV
        writer.writeheader() # escrever cabeçalho no arquivo CSV
        for anomaly in anomalies: # escrever cada anomalia no arquivo CSV
           writer.writerow(anomaly)
    print("Report generated: report.csv") # Confirmação de geração do relatório
# Inicio da captura de pacotes
print("starting packet capture...")
# aplicar filtro para capturar apenas pacotes TCP
sniff(prn=detect_anomalies, filter="tcp", count=100) # Capturar 100 pacotes TCP
print("packet capture finished.")
# Gerar relatório das anomalias detectadas
generate_report(anomalies)


