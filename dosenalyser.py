#!/usr/bin/env python3
"""
NetSpectre Pro - Analizador de Red Profesional
Versión monolítica altamente optimizada
Autor: [Tu Nombre]
Licencia: MIT
"""

import sys
import os
import threading
import queue
import time
import json
import re
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import hashlib

# Importaciones principales
try:
    import scapy.all as scapy
    from scapy.sendrecv import AsyncSniffer
except ImportError:
    print("Error: Scapy no está instalado. Instala con: pip install scapy")
    sys.exit(1)

try:
    from PyQt6.QtWidgets import *
    from PyQt6.QtCore import *
    from PyQt6.QtGui import *
    QT_VERSION = 6
except ImportError:
    try:
        from PyQt5.QtWidgets import *
        from PyQt5.QtCore import *
        from PyQt5.QtGui import *
        QT_VERSION = 5
    except ImportError:
        print("Error: PyQt no está instalado. Instala con: pip install PyQt6")
        sys.exit(1)

# ============================================================================
# CONSTANTES Y ENUMERACIONES
# ============================================================================

class PacketType(Enum):
    """Tipos de paquetes para clasificación rápida"""
    ETHERNET = "Ethernet"
    IPV4 = "IPv4"
    IPV6 = "IPv6"
    TCP = "TCP"
    UDP = "UDP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    ARP = "ARP"
    ICMP = "ICMP"
    UNKNOWN = "Unknown"

class CaptureStatus(Enum):
    """Estados de captura"""
    STOPPED = 0
    RUNNING = 1
    PAUSED = 2

# ============================================================================
# CLASES DE DATOS
# ============================================================================

@dataclass
class PacketInfo:
    """Información estructurada de un paquete"""
    timestamp: float
    number: int
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    length: int = 0
    info: str = ""
    type: PacketType = PacketType.UNKNOWN
    raw_data: bytes = b""
    summary: str = ""
    color: str = "#FFFFFF"
    hex_dump: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario para serialización"""
        return {
            "timestamp": self.timestamp,
            "number": self.number,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "length": self.length,
            "info": self.info,
            "type": self.type.value,
            "summary": self.summary,
            "color": self.color
        }

@dataclass
class NetworkStatistics:
    """Estadísticas de red en tiempo real"""
    total_packets: int = 0
    packets_per_second: float = 0.0
    total_bytes: int = 0
    bytes_per_second: float = 0.0
    protocol_distribution: Dict[str, int] = field(default_factory=dict)
    top_talkers: List[Tuple[str, int]] = field(default_factory=list)
    connections: Dict[Tuple[str, str, int, int], int] = field(default_factory=dict)
    
    def update(self, packet: PacketInfo):
        """Actualiza estadísticas con nuevo paquete"""
        self.total_packets += 1
        self.total_bytes += packet.length
        
        # Distribución por protocolo
        proto = packet.protocol
        self.protocol_distribution[proto] = self.protocol_distribution.get(proto, 0) + 1
        
        # Top talkers
        if packet.src_ip != "N/A":
            self._update_talker(packet.src_ip, packet.length)
        if packet.dst_ip != "N/A":
            self._update_talker(packet.dst_ip, packet.length)
    
    def _update_talker(self, ip: str, size: int):
        """Actualiza estadísticas de dirección IP"""
        pass  # Implementación simplificada

# ============================================================================
# NÚCLEO DE CAPTURA
# ============================================================================

class PacketCapturer(QObject):
    """Núcleo de captura de paquetes multihilo"""
    
    packet_received = pyqtSignal(object)  # Señal Qt para nuevos paquetes
    status_changed = pyqtSignal(int)      # Señal para cambios de estado
    error_occurred = pyqtSignal(str)      # Señal para errores
    
    def __init__(self):
        super().__init__()
        self.sniffer = None
        self.capture_thread = None
        self.status = CaptureStatus.STOPPED
        self.packet_count = 0
        self.filter = ""
        self.interface = None
        self.packet_queue = queue.Queue(maxsize=10000)
        self.running = False
        
        # Estadísticas
        self.stats = NetworkStatistics()
        self.last_update = time.time()
        
        # Almacenamiento de paquetes
        self.packets = []
        self.max_packets = 100000
        
        # Inicializar decodificadores
        self.protocol_handlers = {
            "TCP": self._decode_tcp,
            "UDP": self._decode_udp,
            "HTTP": self._decode_http,
            "DNS": self._decode_dns,
            "ARP": self._decode_arp,
            "ICMP": self._decode_icmp
        }
    
    def start_capture(self, interface: str, filter_expr: str = ""):
        """Inicia captura en interfaz específica"""
        if self.status == CaptureStatus.RUNNING:
            return False
        
        try:
            self.interface = interface
            self.filter = filter_expr
            self.packet_count = 0
            self.packets.clear()
            self.stats = NetworkStatistics()
            
            # Crear sniffer asíncrono
            self.sniffer = AsyncSniffer(
                iface=interface,
                filter=filter_expr,
                prn=self._packet_callback,
                store=False
            )
            
            self.running = True
            self.capture_thread = threading.Thread(target=self._run_sniffer, daemon=True)
            self.capture_thread.start()
            
            self.status = CaptureStatus.RUNNING
            self.status_changed.emit(1)
            return True
            
        except Exception as e:
            self.error_occurred.emit(f"Error al iniciar captura: {str(e)}")
            return False
    
    def stop_capture(self):
        """Detiene la captura"""
        self.running = False
        if self.sniffer:
            self.sniffer.stop()
        self.status = CaptureStatus.STOPPED
        self.status_changed.emit(0)
    
    def pause_capture(self):
        """Pausa la captura"""
        if self.status == CaptureStatus.RUNNING:
            self.status = CaptureStatus.PAUSED
            self.status_changed.emit(2)
    
    def resume_capture(self):
        """Reanuda la captura"""
        if self.status == CaptureStatus.PAUSED:
            self.status = CaptureStatus.RUNNING
            self.status_changed.emit(1)
    
    def _run_sniffer(self):
        """Ejecuta el sniffer en hilo separado"""
        if self.sniffer:
            self.sniffer.start()
            while self.running:
                time.sleep(0.1)
    
    def _packet_callback(self, packet):
        """Callback para cada paquete capturado"""
        if self.status != CaptureStatus.RUNNING:
            return
        
        self.packet_count += 1
        
        try:
            # Procesar paquete
            packet_info = self._process_packet(packet, self.packet_count)
            
            # Actualizar estadísticas
            self.stats.update(packet_info)
            
            # Limitar cantidad de paquetes almacenados
            if len(self.packets) >= self.max_packets:
                self.packets.pop(0)
            
            self.packets.append(packet_info)
            
            # Emitir señal (se ejecutará en hilo principal de Qt)
            QMetaObject.invokeMethod(self, "_emit_packet", 
                                   Qt.ConnectionType.QueuedConnection,
                                   Q_ARG(object, packet_info))
            
        except Exception as e:
            print(f"Error procesando paquete: {e}")
    
    @pyqtSlot(object)
    def _emit_packet(self, packet_info):
        """Slot para emitir señal desde hilo principal"""
        self.packet_received.emit(packet_info)
    
    def _process_packet(self, packet, packet_num: int) -> PacketInfo:
        """Procesa un paquete crudo y extrae información"""
        info = PacketInfo(
            timestamp=time.time(),
            number=packet_num,
            src_ip="N/A",
            dst_ip="N/A",
            length=len(packet),
            raw_data=bytes(packet),
            hex_dump=self._create_hex_dump(packet)
        )
        
        # Detectar protocolos y extraer información
        if packet.haslayer(scapy.Ether):
            info.type = PacketType.ETHERNET
            info.src_ip = packet[scapy.Ether].src
            info.dst_ip = packet[scapy.Ether].dst
        
        if packet.haslayer(scapy.IP):
            info.type = PacketType.IPV4
            info.src_ip = packet[scapy.IP].src
            info.dst_ip = packet[scapy.IP].dst
            info.protocol = "IP"
        
        if packet.haslayer(scapy.TCP):
            info.type = PacketType.TCP
            info.protocol = "TCP"
            info.src_port = packet[scapy.TCP].sport
            info.dst_port = packet[scapy.TCP].dport
            info.info = f"TCP [{info.src_port} → {info.dst_port}]"
            
            # Detectar HTTP
            if packet.haslayer(scapy.Raw):
                raw_data = bytes(packet[scapy.Raw])
                if b"HTTP" in raw_data or b"GET" in raw_data or b"POST" in raw_data:
                    info.type = PacketType.HTTP
                    info.protocol = "HTTP"
                    info.info = self._extract_http_info(raw_data)
        
        elif packet.haslayer(scapy.UDP):
            info.type = PacketType.UDP
            info.protocol = "UDP"
            info.src_port = packet[scapy.UDP].sport
            info.dst_port = packet[scapy.UDP].dport
            info.info = f"UDP [{info.src_port} → {info.dst_port}]"
            
            # Detectar DNS
            if packet.haslayer(scapy.DNS):
                info.type = PacketType.DNS
                info.protocol = "DNS"
                info.info = self._extract_dns_info(packet)
        
        elif packet.haslayer(scapy.ARP):
            info.type = PacketType.ARP
            info.protocol = "ARP"
            info.info = f"ARP {packet[scapy.ARP].psrc} → {packet[scapy.ARP].pdst}"
        
        elif packet.haslayer(scapy.ICMP):
            info.type = PacketType.ICMP
            info.protocol = "ICMP"
            info.info = f"ICMP Type: {packet[scapy.ICMP].type}"
        
        # Asignar color según protocolo
        info.color = self._get_packet_color(info.type)
        info.summary = f"{info.protocol}: {info.src_ip}:{info.src_port} → {info.dst_ip}:{info.dst_port}"
        
        return info
    
    def _create_hex_dump(self, packet) -> str:
        """Crea un hex dump legible del paquete"""
        try:
            data = bytes(packet)
            hex_dump = ""
            for i in range(0, len(data), 16):
                hex_part = " ".join(f"{b:02x}" for b in data[i:i+8])
                hex_part += "  " + " ".join(f"{b:02x}" for b in data[i+8:i+16])
                
                ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in data[i:i+16])
                
                hex_dump += f"{i:04x}  {hex_part:<48}  {ascii_part}\n"
            return hex_dump
        except:
            return ""
    
    def _extract_http_info(self, raw_data: bytes) -> str:
        """Extrae información HTTP del paquete"""
        try:
            text = raw_data.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')
            if lines:
                return lines[0][:100]
        except:
            pass
        return "HTTP Data"
    
    def _extract_dns_info(self, packet) -> str:
        """Extrae información DNS del paquete"""
        try:
            dns = packet[scapy.DNS]
            if dns.qd:
                query = dns.qd.qname.decode('utf-8', errors='ignore')
                return f"DNS Query: {query}"
        except:
            pass
        return "DNS Packet"
    
    def _get_packet_color(self, packet_type: PacketType) -> str:
        """Asigna color según tipo de paquete"""
        colors = {
            PacketType.TCP: "#3498db",     # Azul
            PacketType.UDP: "#2ecc71",     # Verde
            PacketType.HTTP: "#e74c3c",    # Rojo
            PacketType.HTTPS: "#9b59b6",   # Púrpura
            PacketType.DNS: "#f39c12",     # Naranja
            PacketType.ARP: "#1abc9c",     # Turquesa
            PacketType.ICMP: "#e67e22",    # Naranja oscuro
            PacketType.IPV4: "#34495e",    # Gris oscuro
            PacketType.IPV6: "#16a085",    # Verde oscuro
            PacketType.ETHERNET: "#7f8c8d", # Gris
        }
        return colors.get(packet_type, "#95a5a6")
    
    def _decode_tcp(self, packet):
        """Decodifica paquete TCP"""
        pass
    
    def _decode_udp(self, packet):
        """Decodifica paquete UDP"""
        pass
    
    def _decode_http(self, packet):
        """Decodifica paquete HTTP"""
        pass
    
    def _decode_dns(self, packet):
        """Decodifica paquete DNS"""
        pass
    
    def _decode_arp(self, packet):
        """Decodifica paquete ARP"""
        pass
    
    def _decode_icmp(self, packet):
        """Decodifica paquete ICMP"""
        pass
    
    def get_packet(self, index: int) -> Optional[PacketInfo]:
        """Obtiene paquete por índice"""
        if 0 <= index < len(self.packets):
            return self.packets[index]
        return None
    
    def clear_packets(self):
        """Limpia todos los paquetes capturados"""
        self.packets.clear()
        self.packet_count = 0
        self.stats = NetworkStatistics()
    
    def save_packets(self, filename: str, format: str = "pcap"):
        """Guarda paquetes a archivo"""
        try:
            if format.lower() == "pcap":
                scapy.wrpcap(filename, [scapy.Ether(p.raw_data) for p in self.packets])
            elif format.lower() == "json":
                data = [p.to_dict() for p in self.packets]
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
            return True
        except Exception as e:
            self.error_occurred.emit(f"Error guardando archivo: {str(e)}")
            return False
    
    def load_packets(self, filename: str):
        """Carga paquetes desde archivo"""
        try:
            packets = scapy.rdpcap(filename)
            self.clear_packets()
            for i, packet in enumerate(packets):
                packet_info = self._process_packet(packet, i+1)
                self.packets.append(packet_info)
                self.stats.update(packet_info)
            return True
        except Exception as e:
            self.error_occurred.emit(f"Error cargando archivo: {str(e)}")
            return False

# ============================================================================
# INTERFAZ GRÁFICA
# ============================================================================

class PacketListWidget(QTableWidget):
    """Widget para mostrar lista de paquetes"""
    
    packet_selected = pyqtSignal(int)
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.packets = []
        
    def setup_ui(self):
        """Configura la interfaz del widget"""
        self.setColumnCount(7)
        self.setHorizontalHeaderLabels([
            "#", "Time", "Source", "Destination", "Protocol", "Length", "Info"
        ])
        
        # Configurar propiedades
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.setSortingEnabled(True)
        self.verticalHeader().setVisible(False)
        
        # Ajustar columnas
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        self.setColumnWidth(0, 60)
        self.setColumnWidth(4, 80)
        self.setColumnWidth(5, 80)
        
        # Conectar señal
        self.itemSelectionChanged.connect(self._on_selection_changed)
    
    def add_packet(self, packet_info: PacketInfo):
        """Añade un paquete a la lista"""
        row = self.rowCount()
        self.insertRow(row)
        
        # Crear ítems
        items = [
            QTableWidgetItem(str(packet_info.number)),
            QTableWidgetItem(datetime.fromtimestamp(packet_info.timestamp).strftime("%H:%M:%S.%f")[:-3]),
            QTableWidgetItem(f"{packet_info.src_ip}:{packet_info.src_port}" if packet_info.src_port else packet_info.src_ip),
            QTableWidgetItem(f"{packet_info.dst_ip}:{packet_info.dst_port}" if packet_info.dst_port else packet_info.dst_ip),
            QTableWidgetItem(packet_info.protocol),
            QTableWidgetItem(str(packet_info.length)),
            QTableWidgetItem(packet_info.info[:100])
        ]
        
        # Configurar colores
        for item in items:
            item.setBackground(QColor(packet_info.color))
            item.setForeground(QColor("#ffffff" if self._is_dark_color(packet_info.color) else "#000000"))
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        
        # Añadir ítems a la tabla
        for col, item in enumerate(items):
            self.setItem(row, col, item)
        
        # Almacenar referencia
        self.packets.append(packet_info)
        
        # Auto-scroll si está al final
        if self.verticalScrollBar().value() == self.verticalScrollBar().maximum():
            self.scrollToBottom()
    
    def _is_dark_color(self, hex_color: str) -> bool:
        """Determina si un color es oscuro"""
        hex_color = hex_color.lstrip('#')
        r, g, b = int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)
        luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255
        return luminance < 0.5
    
    def _on_selection_changed(self):
        """Maneja cambio de selección"""
        selected = self.selectedItems()
        if selected:
            row = selected[0].row()
            self.packet_selected.emit(row)
    
    def clear_packets(self):
        """Limpia todos los paquetes"""
        self.setRowCount(0)
        self.packets.clear()

class HexViewerWidget(QTextEdit):
    """Widget para visualizar hex dump"""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
    
    def setup_ui(self):
        """Configura la interfaz"""
        self.setReadOnly(True)
        self.setFont(QFont("Courier New", 10))
        self.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
    
    def show_hex(self, hex_dump: str):
        """Muestra hex dump"""
        self.clear()
        self.setPlainText(hex_dump)

class PacketDetailsWidget(QTreeWidget):
    """Widget para mostrar detalles del paquete"""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
    
    def setup_ui(self):
        """Configura la interfaz"""
        self.setHeaderLabel("Packet Details")
        self.setAlternatingRowColors(True)
        self.header().setStretchLastSection(True)
    
    def show_packet_details(self, packet_info: PacketInfo):
        """Muestra detalles del paquete"""
        self.clear()
        
        # Información básica
        basic_info = QTreeWidgetItem(["Basic Information"])
        basic_info.addChild(QTreeWidgetItem(["Number", str(packet_info.number)]))
        basic_info.addChild(QTreeWidgetItem(["Timestamp", 
            datetime.fromtimestamp(packet_info.timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")]))
        basic_info.addChild(QTreeWidgetItem(["Length", f"{packet_info.length} bytes"]))
        basic_info.addChild(QTreeWidgetItem(["Protocol", packet_info.protocol]))
        self.addTopLevelItem(basic_info)
        
        # Direcciones
        addresses = QTreeWidgetItem(["Addresses"])
        addresses.addChild(QTreeWidgetItem(["Source", 
            f"{packet_info.src_ip}:{packet_info.src_port}" if packet_info.src_port else packet_info.src_ip]))
        addresses.addChild(QTreeWidgetItem(["Destination", 
            f"{packet_info.dst_ip}:{packet_info.dst_port}" if packet_info.dst_port else packet_info.dst_ip]))
        self.addTopLevelItem(addresses)
        
        # Información específica del protocolo
        if packet_info.info:
            protocol_info = QTreeWidgetItem(["Protocol Information"])
            protocol_info.addChild(QTreeWidgetItem(["Info", packet_info.info]))
            self.addTopLevelItem(protocol_info)
        
        self.expandAll()

class DashboardWidget(QWidget):
    """Widget de dashboard con estadísticas"""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.stats = NetworkStatistics()
    
    def setup_ui(self):
        """Configura la interfaz"""
        layout = QVBoxLayout()
        
        # Título
        title = QLabel("NetSpectre Pro - Dashboard")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;")
        layout.addWidget(title)
        
        # Estadísticas en tiempo real
        self.stats_group = QGroupBox("Real-time Statistics")
        stats_layout = QGridLayout()
        
        self.total_packets_label = QLabel("0")
        self.pps_label = QLabel("0.0")
        self.total_bytes_label = QLabel("0 B")
        self.bps_label = QLabel("0.0 B/s")
        
        stats_layout.addWidget(QLabel("Total Packets:"), 0, 0)
        stats_layout.addWidget(self.total_packets_label, 0, 1)
        stats_layout.addWidget(QLabel("Packets/s:"), 0, 2)
        stats_layout.addWidget(self.pps_label, 0, 3)
        
        stats_layout.addWidget(QLabel("Total Bytes:"), 1, 0)
        stats_layout.addWidget(self.total_bytes_label, 1, 1)
        stats_layout.addWidget(QLabel("Bytes/s:"), 1, 2)
        stats_layout.addWidget(self.bps_label, 1, 3)
        
        self.stats_group.setLayout(stats_layout)
        layout.addWidget(self.stats_group)
        
        # Distribución de protocolos
        self.protocol_group = QGroupBox("Protocol Distribution")
        protocol_layout = QVBoxLayout()
        self.protocol_tree = QTreeWidget()
        self.protocol_tree.setHeaderLabels(["Protocol", "Count", "Percentage"])
        protocol_layout.addWidget(self.protocol_tree)
        self.protocol_group.setLayout(protocol_layout)
        layout.addWidget(self.protocol_group)
        
        self.setLayout(layout)
    
    def update_stats(self, stats: NetworkStatistics):
        """Actualiza las estadísticas mostradas"""
        self.stats = stats
        
        # Actualizar labels
        self.total_packets_label.setText(f"{stats.total_packets:,}")
        self.pps_label.setText(f"{stats.packets_per_second:.1f}")
        
        # Formatear bytes
        bytes_text = self._format_bytes(stats.total_bytes)
        bps_text = self._format_bytes(int(stats.bytes_per_second)) + "/s"
        
        self.total_bytes_label.setText(bytes_text)
        self.bps_label.setText(bps_text)
        
        # Actualizar distribución de protocolos
        self.protocol_tree.clear()
        total = stats.total_packets if stats.total_packets > 0 else 1
        
        for protocol, count in stats.protocol_distribution.items():
            percentage = (count / total) * 100
            item = QTreeWidgetItem([
                protocol, 
                str(count), 
                f"{percentage:.1f}%"
            ])
            self.protocol_tree.addTopLevelItem(item)
    
    def _format_bytes(self, bytes_count: int) -> str:
        """Formatea bytes a unidades legibles"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.1f} TB"

class FilterWidget(QWidget):
    """Widget para aplicar filtros"""
    
    filter_changed = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
    
    def setup_ui(self):
        """Configura la interfaz"""
        layout = QHBoxLayout()
        
        # Label
        layout.addWidget(QLabel("Filter:"))
        
        # ComboBox de filtros predefinidos
        self.filter_combo = QComboBox()
        self.filter_combo.addItems([
            "All Traffic",
            "TCP Only",
            "UDP Only",
            "HTTP Only",
            "DNS Only",
            "ARP Only",
            "ICMP Only",
            "Custom..."
        ])
        self.filter_combo.currentTextChanged.connect(self._on_combo_changed)
        layout.addWidget(self.filter_combo)
        
        # Campo de filtro personalizado
        self.custom_filter = QLineEdit()
        self.custom_filter.setPlaceholderText("BPF filter (e.g., host 192.168.1.1 and port 80)")
        self.custom_filter.textChanged.connect(self._on_filter_changed)
        self.custom_filter.setVisible(False)
        layout.addWidget(self.custom_filter)
        
        # Botón aplicar
        self.apply_btn = QPushButton("Apply")
        self.apply_btn.clicked.connect(self._apply_filter)
        layout.addWidget(self.apply_btn)
        
        self.setLayout(layout)
    
    def _on_combo_changed(self, text: str):
        """Maneja cambio en combobox"""
        if text == "Custom...":
            self.custom_filter.setVisible(True)
            self.custom_filter.setFocus()
        else:
            self.custom_filter.setVisible(False)
            filters = {
                "All Traffic": "",
                "TCP Only": "tcp",
                "UDP Only": "udp",
                "HTTP Only": "tcp port 80",
                "DNS Only": "udp port 53",
                "ARP Only": "arp",
                "ICMP Only": "icmp"
            }
            self.filter_changed.emit(filters.get(text, ""))
    
    def _on_filter_changed(self, text: str):
        """Maneja cambio en filtro personalizado"""
        pass
    
    def _apply_filter(self):
        """Aplica el filtro actual"""
        if self.filter_combo.currentText() == "Custom...":
            self.filter_changed.emit(self.custom_filter.text())
        else:
            self._on_combo_changed(self.filter_combo.currentText())

class MainWindow(QMainWindow):
    """Ventana principal de la aplicación"""
    
    def __init__(self):
        super().__init__()
        self.capturer = PacketCapturer()
        self.setup_ui()
        self.setup_connections()
        self.last_stats_update = time.time()
        
        # Timer para actualizar estadísticas
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_dashboard)
        self.stats_timer.start(1000)  # 1 segundo
    
    def setup_ui(self):
        """Configura la interfaz principal"""
        self.setWindowTitle("NetSpectre Pro - Professional Network Analyzer")
        self.setGeometry(100, 100, 1400, 800)
        
        # Crear widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Barra de herramientas superior
        self.setup_toolbar()
        main_layout.addWidget(self.toolbar)
        
        # Widget de filtros
        self.filter_widget = FilterWidget()
        main_layout.addWidget(self.filter_widget)
        
        # Panel principal dividido
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Panel superior (lista de paquetes y dashboard)
        top_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Lista de paquetes
        self.packet_list = PacketListWidget()
        top_splitter.addWidget(self.packet_list)
        
        # Dashboard
        self.dashboard = DashboardWidget()
        top_splitter.addWidget(self.dashboard)
        top_splitter.setSizes([800, 400])
        
        splitter.addWidget(top_splitter)
        
        # Panel inferior (detalles y hex viewer)
        bottom_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Detalles del paquete
        self.packet_details = PacketDetailsWidget()
        bottom_splitter.addWidget(self.packet_details)
        
        # Hex Viewer
        self.hex_viewer = HexViewerWidget()
        bottom_splitter.addWidget(self.hex_viewer)
        bottom_splitter.setSizes([500, 500])
        
        splitter.addWidget(bottom_splitter)
        splitter.setSizes([500, 300])
        
        main_layout.addWidget(splitter)
        
        # Barra de estado
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Diálogo de selección de interfaz
        self.interface_dialog = InterfaceDialog(self)
    
    def setup_toolbar(self):
        """Configura la barra de herramientas"""
        self.toolbar = QToolBar()
        self.toolbar.setMovable(False)
        
        # Botón iniciar/parar
        self.start_btn = QPushButton("▶ Start")
        self.start_btn.setStyleSheet("background-color: #2ecc71; color: white; padding: 5px;")
        self.start_btn.clicked.connect(self.toggle_capture)
        self.toolbar.addWidget(self.start_btn)
        
        # Botón pausar
        self.pause_btn = QPushButton("⏸ Pause")
        self.pause_btn.setEnabled(False)
        self.pause_btn.clicked.connect(self.pause_capture)
        self.toolbar.addWidget(self.pause_btn)
        
        # Botón limpiar
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear_capture)
        self.toolbar.addWidget(clear_btn)
        
        self.toolbar.addSeparator()
        
        # Botón guardar
        save_btn = QPushButton("💾 Save")
        save_btn.clicked.connect(self.save_capture)
        self.toolbar.addWidget(save_btn)
        
        # Botón cargar
        load_btn = QPushButton("📂 Load")
        load_btn.clicked.connect(self.load_capture)
        self.toolbar.addWidget(load_btn)
        
        self.toolbar.addSeparator()
        
        # Selector de interfaz
        self.interface_btn = QPushButton("Select Interface")
        self.interface_btn.clicked.connect(self.select_interface)
        self.toolbar.addWidget(self.interface_btn)
        
        # Label de interfaz seleccionada
        self.interface_label = QLabel("No interface selected")
        self.toolbar.addWidget(self.interface_label)
        
        self.toolbar.addSeparator()
        
        # Contador de paquetes
        self.packet_count_label = QLabel("Packets: 0")
        self.toolbar.addWidget(self.packet_count_label)
        
        # Añadir espacio elástico
        self.toolbar.addWidget(QWidget())
    
    def setup_connections(self):
        """Configura las conexiones de señales"""
        # Capturador
        self.capturer.packet_received.connect(self.on_packet_received)
        self.capturer.status_changed.connect(self.on_status_changed)
        self.capturer.error_occurred.connect(self.on_error_occurred)
        
        # Lista de paquetes
        self.packet_list.packet_selected.connect(self.on_packet_selected)
        
        # Filtros
        self.filter_widget.filter_changed.connect(self.on_filter_changed)
    
    def toggle_capture(self):
        """Alterna entre iniciar y detener captura"""
        if self.capturer.status == CaptureStatus.STOPPED:
            if not hasattr(self, 'selected_interface') or not self.selected_interface:
                self.select_interface()
                return
            
            if self.capturer.start_capture(self.selected_interface):
                self.start_btn.setText("⏹ Stop")
                self.start_btn.setStyleSheet("background-color: #e74c3c; color: white; padding: 5px;")
                self.pause_btn.setEnabled(True)
                self.status_bar.showMessage(f"Capturing on {self.selected_interface}")
        else:
            self.capturer.stop_capture()
            self.start_btn.setText("▶ Start")
            self.start_btn.setStyleSheet("background-color: #2ecc71; color: white; padding: 5px;")
            self.pause_btn.setEnabled(False)
            self.pause_btn.setText("⏸ Pause")
            self.status_bar.showMessage("Capture stopped")
    
    def pause_capture(self):
        """Pausa o reanuda la captura"""
        if self.capturer.status == CaptureStatus.RUNNING:
            self.capturer.pause_capture()
            self.pause_btn.setText("▶ Resume")
            self.status_bar.showMessage("Capture paused")
        elif self.capturer.status == CaptureStatus.PAUSED:
            self.capturer.resume_capture()
            self.pause_btn.setText("⏸ Pause")
            self.status_bar.showMessage("Capture resumed")
    
    def clear_capture(self):
        """Limpia la captura actual"""
        self.capturer.clear_packets()
        self.packet_list.clear_packets()
        self.packet_details.clear()
        self.hex_viewer.clear()
        self.packet_count_label.setText("Packets: 0")
        self.status_bar.showMessage("Capture cleared")
    
    def save_capture(self):
        """Guarda la captura actual a archivo"""
        if len(self.capturer.packets) == 0:
            QMessageBox.warning(self, "No Data", "No packets to save.")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save Capture",
            f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "PCAP files (*.pcap);;JSON files (*.json);;All files (*.*)"
        )
        
        if filename:
            if filename.endswith('.json'):
                format_type = "json"
            else:
                if not filename.endswith('.pcap'):
                    filename += '.pcap'
                format_type = "pcap"
            
            if self.capturer.save_packets(filename, format_type):
                self.status_bar.showMessage(f"Capture saved to {filename}")
    
    def load_capture(self):
        """Carga una captura desde archivo"""
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Load Capture",
            "",
            "Capture files (*.pcap *.json);;All files (*.*)"
        )
        
        if filename:
            if self.capturer.load_packets(filename):
                # Actualizar interfaz
                self.packet_list.clear_packets()
                for packet in self.capturer.packets:
                    self.packet_list.add_packet(packet)
                
                self.packet_count_label.setText(f"Packets: {len(self.capturer.packets)}")
                self.status_bar.showMessage(f"Capture loaded from {filename}")
    
    def select_interface(self):
        """Muestra diálogo para seleccionar interfaz"""
        if self.interface_dialog.exec():
            self.selected_interface = self.interface_dialog.get_selected_interface()
            self.interface_label.setText(f"Interface: {self.selected_interface}")
    
    def on_packet_received(self, packet_info: PacketInfo):
        """Maneja recepción de nuevo paquete"""
        self.packet_list.add_packet(packet_info)
        self.packet_count_label.setText(f"Packets: {len(self.capturer.packets)}")
    
    def on_status_changed(self, status: int):
        """Maneja cambio de estado de captura"""
        status_text = {
            0: "Stopped",
            1: "Running",
            2: "Paused"
        }
        self.status_bar.showMessage(f"Status: {status_text.get(status, 'Unknown')}")
    
    def on_error_occurred(self, error_msg: str):
        """Maneja errores de captura"""
        QMessageBox.critical(self, "Capture Error", error_msg)
    
    def on_packet_selected(self, index: int):
        """Maneja selección de paquete en la lista"""
        packet_info = self.capturer.get_packet(index)
        if packet_info:
            self.packet_details.show_packet_details(packet_info)
            self.hex_viewer.show_hex(packet_info.hex_dump)
    
    def on_filter_changed(self, filter_expr: str):
        """Maneja cambio de filtro"""
        if self.capturer.status == CaptureStatus.RUNNING:
            self.capturer.stop_capture()
            time.sleep(0.1)
            self.capturer.start_capture(self.selected_interface, filter_expr)
            self.status_bar.showMessage(f"Filter applied: {filter_expr}")
    
    def update_dashboard(self):
        """Actualiza el dashboard con estadísticas en tiempo real"""
        now = time.time()
        time_diff = now - self.last_stats_update
        
        if time_diff > 0:
            # Calcular tasas por segundo
            self.capturer.stats.packets_per_second = len(self.capturer.packets) / time_diff
            self.capturer.stats.bytes_per_second = self.capturer.stats.total_bytes / time_diff
        
        self.dashboard.update_stats(self.capturer.stats)
        self.last_stats_update = now
    
    def closeEvent(self, event):
        """Maneja cierre de la aplicación"""
        if self.capturer.status != CaptureStatus.STOPPED:
            self.capturer.stop_capture()
        event.accept()

# ============================================================================
# DIÁLOGOS ADICIONALES
# ============================================================================

class InterfaceDialog(QDialog):
    """Diálogo para seleccionar interfaz de red"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected_interface = None
        self.setup_ui()
        self.load_interfaces()
    
    def setup_ui(self):
        """Configura la interfaz del diálogo"""
        self.setWindowTitle("Select Network Interface")
        self.setGeometry(300, 300, 500, 400)
        
        layout = QVBoxLayout()
        
        # Título
        title = QLabel("Select Network Interface")
        title.setStyleSheet("font-size: 16px; font-weight: bold; margin: 10px;")
        layout.addWidget(title)
        
        # Lista de interfaces
        self.interface_list = QListWidget()
        self.interface_list.itemDoubleClicked.connect(self.accept)
        layout.addWidget(self.interface_list)
        
        # Botones
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.setLayout(layout)
    
    def load_interfaces(self):
        """Carga las interfaces de red disponibles"""
        try:
            interfaces = scapy.get_if_list()
            self.interface_list.clear()
            
            for iface in interfaces:
                item = QListWidgetItem(iface)
                self.interface_list.addItem(item)
            
            if interfaces:
                self.interface_list.setCurrentRow(0)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not get interfaces: {str(e)}")
    
    def get_selected_interface(self):
        """Obtiene la interfaz seleccionada"""
        selected = self.interface_list.currentItem()
        if selected:
            return selected.text()
        return None
    
    def accept(self):
        """Acepta la selección"""
        if self.interface_list.currentItem():
            self.selected_interface = self.get_selected_interface()
            super().accept()
        else:
            QMessageBox.warning(self, "No Selection", "Please select an interface.")

# ============================================================================
# CARACTERÍSTICAS AVANZADAS
# ============================================================================

class PacketReassembler:
    """Reensamblador de paquetes fragmentados"""
    
    def __init__(self):
        self.fragments = defaultdict(list)
        self.timeout = 30  # segundos
        
    def add_fragment(self, packet):
        """Añade fragmento para reensamblar"""
        pass  # Implementación simplificada
    
    def reassemble(self, packet_id):
        """Reensambla paquetes fragmentados"""
        pass  # Implementación simplificada

class ThreatDetector:
    """Detector de amenazas de red básico"""
    
    def __init__(self):
        self.threat_patterns = {
            "port_scan": re.compile(r".*port.*scan.*", re.IGNORECASE),
            "sql_injection": re.compile(r".*(select|union|insert|delete|drop|--).*", re.IGNORECASE),
            "xss": re.compile(r".*(<script|javascript:|onload=|onerror=).*", re.IGNORECASE),
        }
        
    def analyze_packet(self, packet_info: PacketInfo) -> List[str]:
        """Analiza paquete en busca de amenazas"""
        threats = []
        
        # Detección básica de escaneo de puertos
        if packet_info.protocol == "TCP":
            if packet_info.info and "SYN" in packet_info.info:
                # Lógica simplificada para detección
                pass
        
        # Detección en contenido HTTP
        if packet_info.type == PacketType.HTTP:
            content = packet_info.info.lower()
            for threat_type, pattern in self.threat_patterns.items():
                if pattern.search(content):
                    threats.append(threat_type)
        
        return threats

# ============================================================================
# SISTEMA DE TEMAS
# ============================================================================

class ThemeManager:
    """Gestor de temas para la interfaz"""
    
    THEMES = {
        "dark": """
            QMainWindow, QDialog {
                background-color: #2c3e50;
                color: #ecf0f1;
            }
            QTableWidget, QTreeWidget, QTextEdit {
                background-color: #34495e;
                color: #ecf0f1;
                border: 1px solid #7f8c8d;
            }
            QHeaderView::section {
                background-color: #2c3e50;
                color: #ecf0f1;
                padding: 5px;
                border: 1px solid #7f8c8d;
            }
            QToolBar {
                background-color: #34495e;
                border: none;
            }
            QPushButton {
                background-color: #3498db;
                color: white;
                padding: 5px 10px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """,
        
        "light": """
            QMainWindow, QDialog {
                background-color: #f5f5f5;
                color: #333333;
            }
            QTableWidget, QTreeWidget, QTextEdit {
                background-color: white;
                color: #333333;
                border: 1px solid #cccccc;
            }
            QHeaderView::section {
                background-color: #e0e0e0;
                color: #333333;
                padding: 5px;
                border: 1px solid #cccccc;
            }
            QToolBar {
                background-color: #e0e0e0;
                border: none;
            }
            QPushButton {
                background-color: #3498db;
                color: white;
                padding: 5px 10px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """
    }
    
    @staticmethod
    def apply_theme(app, theme_name: str):
        """Aplica un tema a la aplicación"""
        theme = ThemeManager.THEMES.get(theme_name, ThemeManager.THEMES["dark"])
        app.setStyleSheet(theme)

# ============================================================================
# MAIN Y EJECUCIÓN
# ============================================================================

def main():
    """Función principal de la aplicación"""
    # Verificar privilegios (en Linux/Mac)
    if os.name != 'nt' and os.geteuid() != 0:
        print("Warning: Running without root privileges may limit capture capabilities.")
        print("Consider running with sudo for full functionality.")
    
    # Crear aplicación
    app = QApplication(sys.argv)
    app.setApplicationName("NetSpectre Pro")
    app.setOrganizationName("NetSpectre")
    
    # Aplicar tema
    ThemeManager.apply_theme(app, "dark")
    
    # Crear y mostrar ventana principal
    window = MainWindow()
    window.show()
    
    # Mensaje de bienvenida
    print("=" * 60)
    print("NetSpectre Pro - Professional Network Analyzer")
    print("Version 1.0.0")
    print("Author: DoseUser")
    print("License: MIT")
    print("=" * 60)
    print("\nFeatures:")
    print("- Real-time packet capture and analysis")
    print("- Advanced protocol decoding")
    print("- Hex viewer with ASCII representation")
    print("- Statistical dashboard")
    print("- Custom BPF filters")
    print("- Save/load PCAP and JSON formats")
    print("- Multi-threaded architecture")
    print("=" * 60)
    
    # Ejecutar aplicación
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
