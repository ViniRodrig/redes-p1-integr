'ca'
from iputils import *

IPV4_HEADER_DEF_SIZE = 20

#teste
def disable_nbits(orig_data, nbits):
    bits_str = bin(orig_data)[2:]
    nw_lst = []

    for i, bit in enumerate(bits_str):
        if i < len(bits_str) - nbits:
            nw_lst.append(int(bit))
        else:
            nw_lst.append(0)

    return int(''.join(str(num) for num in nw_lst), 2)


def get_checksum(header):
    return struct.pack("!H", calc_checksum(header))


def icmp_header(seg):
    header_struct = struct.pack('!BBHII', 11, 0, 0, 0, 0)  # 1, 1, 2, 4, 4 = 12

    datagram = bytearray(header_struct)
    datagram[8:12] = seg
    datagram[2:4] = get_checksum(datagram)

    return bytes(datagram)


def ipv4_header(seg, id_, protocol, src, dst):

    def get_int_from_addr(addr):
        int_lst = str2addr(addr)
        return int.from_bytes(int_lst, byteorder='big')

    header = struct.pack("!BBHHHBBHII", (4 << 4) | 5, 0, IPV4_HEADER_DEF_SIZE + len(seg), int(id_), 0, 64, protocol, 0, get_int_from_addr(src), get_int_from_addr(dst))

    datagram = bytearray(header)

    datagram[10:12] = get_checksum(datagram)

    return bytes(datagram) + seg


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self._count = -1

    @property
    def count(self):
        self._count += 1
        return self._count

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            next_hop = self._next_hop(dst_addr)
            if ttl < 2:
                seg = icmp_header(datagrama)

                datagram = ipv4_header(seg, self.count, IPPROTO_ICMP, self.meu_endereco, src_addr)

                return self.enlace.enviar(datagram, next_hop)
            else:
                # atua como roteador
                # TODO: Trate corretamente o campo TTL do datagrama
                nw_datagram = bytearray(datagrama)
                ttl -= 1
                nw_datagram[8] = ttl
                nw_datagram[10:12] = [0, 0]
                nw_datagram[10:12] = get_checksum(nw_datagram[:IPV4_HEADER_DEF_SIZE])

                self.enlace.enviar(bytes(nw_datagram), next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.

        # for item in self.tabela:
        #     if item['cidr'] == dest_addr:
        #         item['next_hop']

        # tabela_hash[dest_addr]
        hop = 0
        max_prefix = 0

        for cidr, next_hop in self.tabela_hash.items():
            net, prefix = cidr.split('/')

            var_bits = 32 - int(prefix)

            (net_,) = struct.unpack("!I", str2addr(net))
            (dest_,) = struct.unpack("!I", str2addr(dest_addr))

            if (disable_nbits(net_, var_bits) == disable_nbits(dest_, var_bits)) and int(prefix) >= int(max_prefix):
                max_prefix = prefix
                hop = next_hop

        return hop if hop != 0 else None

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.

        out_tbl = [
            {
                'cidr': cidr,
                'next_hop': next_hop,
            }, (...)
        ]
        """

        self.tabela = []
        for item in tabela:
            self.tabela.append({
                'cidr': item[0],
                'next_hop': item[1],
            })

        self.tabela_hash = {item[0]: item[1] for item in tabela}

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        self.enlace.enviar(
            ipv4_header(
                seg=segmento,
                id_=self.count,
                protocol=IPPROTO_TCP,
                src=self.meu_endereco,
                dst=dest_addr
            ),
            next_hop
        )
