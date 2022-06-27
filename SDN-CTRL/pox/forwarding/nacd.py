from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.util import str_to_bool
import time
import requests
import ipaddress
import datetime
from pox.lib.addresses import IPAddr, EthAddr

def search(list, element):
  for i in range(len(list)):
    if list[i] == element:
      return True
  return False

monitored_network = ipaddress.ip_network(unicode("192.168.25.0/24"))
excluded_address = ["192.168.25.1"]
controller_ip = "192.168.10.135"
adminuser = "IEUser"
adminpass = "Passw0rd!"
domain_controller = "192.168.10.139"

monitored_network_list = []
for x in monitored_network.hosts():
    monitored_network_list.append(str(x))

for x in range(len(excluded_address)):
    monitored_network_list.remove(excluded_address[x])

log = core.getLogger()

_flood_delay = 0

class LearningSwitch (object):

  def __init__ (self, connection, transparent):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent

    # Our table
    self.macToPort = {}

    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)

    # We just use this to know when to log a helpful message
    self.hold_down_expired = _flood_delay == 0

    #log.debug("Initializing LearningSwitch, transparent=%s",
    #          str(self.transparent))

  def _handle_PacketIn (self, event):

    packet = event.parsed

    def flood (message = None):
      """ Floods the packet """
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= _flood_delay:
        # Only flood if we've been connected for a little while...

        if self.hold_down_expired is False:
          # Oh yes it is!
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expired -- flooding",
              dpid_to_str(event.dpid))

        if message is not None: log.debug(message)
        #log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)
        # OFPP_FLOOD is optional; on some switches you may need to change
        # this to OFPP_ALL.
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        #log.info("Holding down flood for %s", dpid_to_str(event.dpid))
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):

      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    self.macToPort[packet.src] = event.port # 1

    if not self.transparent: # 2
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop() # 2a
        return

    if packet.dst.is_multicast:
      flood() # 3a
    else:
      if packet.dst not in self.macToPort: # 4
        flood("Port for %s unknown -- flooding" % (packet.dst,)) # 4a
      else:
        port = self.macToPort[packet.dst]
        if port == event.port: # 5
          # 5a
          log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
              % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
          drop(10)
          return
        # 6

        # Creacion de Match especifico que es indicado por paquete.
        from_packet = of.ofp_flow_mod()
        from_packet.match = of.ofp_match.from_packet(packet, event.port)
        print("\n")
        log.warning(str(datetime.datetime.now()) + " ------> Procesando un paquete")
        if(from_packet.match.dl_type == 0x806):
          log.debug("INSTALANDO FLUJO ARP %s.%i -> %s.%i\n" %
                    (packet.src, event.port, packet.dst, port))
          msg = of.ofp_flow_mod()
          msg.match = of.ofp_match.from_packet(packet, event.port)
          msg.idle_timeout = 10
          msg.hard_timeout = 30
          msg.actions.append(of.ofp_action_output(port = port))
          msg.data = event.ofp # 6a
          self.connection.send(msg)

        # Buscando si la IP origen del paquete coincide con la lista de la red monitoreada.
        log.warning(str(datetime.datetime.now()) + " ------> IP Origen: %s IP Destino: %s " % (str(from_packet.match.nw_src),str(from_packet.match.nw_dst)))
        if search(monitored_network_list, from_packet.match.nw_src):
          log.warning(str(datetime.datetime.now()) + " ------> La IP origen del paquete coincide con un host en la lista de los dispositivos monitoreados")

          # Instalacion de flujo que permite comunicacion desde la API hacia la Maquina
          log.warning(str(datetime.datetime.now()) + " ------> Instalando flujo de reverso")
          from_api_flow = of.ofp_flow_mod()
          from_api_flow.match = of.ofp_match(dl_type=0x800, nw_dst=IPAddr(from_packet.match.nw_src))
          from_api_flow.idle_timeout = 300
          from_api_flow.hard_timeout = 300
          from_api_flow.actions.append(of.ofp_action_output(port=event.port))
          self.connection.send(from_api_flow)

          # Creando URL de consulta
          url = "http://127.0.0.1:8000/compliance?host=" + str(from_packet.match.nw_src) + "&&user=" + \
                adminuser + "&&passwd=" + adminpass
          log.debug("Se creo URL para realizar request a compliance: %s" % (url))

          # Consulta de estado de dispositivo a la API
          r = requests.get(url)
          log.debug("\nEl resultado del request es: %s, inciando procesamiento de respuesta de la API..." % (r.text))

          # Procesamiento de Respuesta de la API

          if r.text == "1":
            log.warning(str(datetime.datetime.now()) + " ------> El dispositivo esta en cumplimiento, iniciando instalacion de flujo...")
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match(dl_type=0x800, dl_src=EthAddr(from_packet.match.dl_src), dl_dst=EthAddr(from_packet.match.dl_dst), nw_src=IPAddr(from_packet.match.nw_src))
            msg.idle_timeout = 300
            msg.hard_timeout = 300
            msg.actions.append(of.ofp_action_output(port = port))
            msg.data = event.ofp # 6a
            self.connection.send(msg)
            log.warning(str(datetime.datetime.now()) + " ------> El Flujo IP ORIGEN: %s hacia IP DESTINO: %s con PROTOCOLO: %s y PUERTO TCP/UDP: %s ha sido instalado\n" % (str(from_packet.match.nw_src),str(from_packet.match.nw_dst),
                        str(from_packet.match.nw_proto),str(from_packet.match.tp_dst)))
          elif r.text == "2":
            log.warning(str(datetime.datetime.now()) + " ------> El dispositivo no esta en cumplimiento, iniciando instalacion de drop...\n")
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match(dl_type=0x800, nw_src=IPAddr(from_packet.match.nw_src))
            msg.idle_timeout = 120
            msg.hard_timeout = 120
            msg.buffer_id = event.ofp.buffer_id
            self.connection.send(msg)
          elif r.text == "3":
            log.warning(str(datetime.datetime.now()) + " ------> El equipo aun no ha sido validado, instalando flujo de drop e iniciando validaciones...")
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match(dl_type=0x800, dl_src=EthAddr(from_packet.match.dl_src), nw_src=IPAddr(from_packet.match.nw_src))
            msg.idle_timeout = 10
            msg.hard_timeout = 10
            msg.buffer_id = event.ofp.buffer_id
            self.connection.send(msg)
        else:
          log.warning(str(datetime.datetime.now()) + " ------> El paquete lo origina un host no monitoreado, se procede a instalar flujos sin verificaciones")
          log.debug("Instalando flujo para host no monitoreado %s.%i -> %s.%i" %
                   (packet.src, event.port, packet.dst, port))
          msg = of.ofp_flow_mod()
          msg.match = of.ofp_match.from_packet(packet, event.port)
          msg.idle_timeout = 10
          msg.hard_timeout = 30
          msg.actions.append(of.ofp_action_output(port = port))
          msg.data = event.ofp # 6a
          self.connection.send(msg)

class l2_learning (object):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, transparent, ignore = None):
    """
    Initialize

    See LearningSwitch for meaning of 'transparent'
    'ignore' is an optional list/set of DPIDs to ignore
    """
    core.openflow.addListeners(self)
    self.transparent = transparent
    self.ignore = set(ignore) if ignore else ()

  def _handle_ConnectionUp (self, event):
    if event.dpid in self.ignore:
      log.debug("Ignoring connection %s" % (event.connection,))
      return
    log.warning(str(datetime.datetime.now()) + " ------> Se conecto switch %s" % (event.connection,))
    LearningSwitch(event.connection, self.transparent)
    # Instalacion de flujo que permite comunicacion desde todas las maquinas hacia la API.
    to_api_flow = of.ofp_flow_mod()
    to_api_flow.match = of.ofp_match(dl_type = 0x800, nw_dst = IPAddr(controller_ip))
    to_api_flow.actions.append(of.ofp_action_output(port = 1))
    event.connection.send(to_api_flow)
    log.warning(str(datetime.datetime.now()) + " ------> Preinstalando flujos del controlador")

def launch (transparent=False, hold_down=_flood_delay, ignore = None):
  """
  Starts an L2 learning switch.
  """
  try:
    global _flood_delay
    _flood_delay = int(str(hold_down), 10)
    assert _flood_delay >= 0
  except:
    raise RuntimeError("Expected hold-down to be a number")

  if ignore:
    ignore = ignore.replace(',', ' ').split()
    ignore = set(str_to_dpid(dpid) for dpid in ignore)

  core.registerNew(l2_learning, str_to_bool(transparent), ignore)
