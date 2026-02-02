# NetSpectre Pro - Professional Network Analyzer

![NetSpectre Pro](https://img.shields.io/badge/NetSpectre-Pro-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Platform](https://img.shields.io/badge/Platform-Windows%2FmacOS%2FLinux-lightgrey)

NetSpectre Pro es un analizador de red profesional escrito en Python, diseñado para análisis diario de tráfico de red con características avanzadas similares a Wireshark pero con mejoras significativas.

## ✨ Características Principales

### 🎯 Captura Avanzada
- Captura en tiempo real de paquetes de red
- Filtros BPF personalizables
- Soporte multihilo para alta performance
- Captura desde múltiples interfaces

### 🔍 Análisis Profundo
- Decodificación automática de protocolos (TCP, UDP, HTTP, DNS, ARP, ICMP)
- Visor hexadecimal con representación ASCII
- Reensamblaje de paquetes fragmentados
- Análisis de flujos y conversaciones

### 📊 Dashboard Estadístico
- Estadísticas en tiempo real (paquetes/seg, bytes/seg)
- Distribución por protocolos
- Top talkers (principales conversadores)
- Gráficos de actividad de red

### 🎨 Interfaz Moderna
- Interfaz tipo IDE dividida en paneles
- Temas oscuro/claro personalizables
- Vista detallada de paquetes en árbol
- Coloreado por protocolo
- Sistema de filtros intuitivo

### 💾 Gestión de Capturas
- Guardado en formatos PCAP y JSON
- Carga de capturas existentes
- Exportación a múltiples formatos
- Compresión automática

### 🛡️ Seguridad Avanzada
- Detección básica de amenazas
- Análisis de patrones sospechosos
- Alertas en tiempo real
- Registro de eventos de seguridad

## 🚀 Instalación Rápida

### Requisitos
- Python 3.8 o superior
- Privilegios de administrador/sudo para captura

### Instalación
```bash
# Clonar repositorio
git clone https://github.com/Doseuser/netspectre-pro.git
cd netspectre-pro

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar
python dosenalyser.py
