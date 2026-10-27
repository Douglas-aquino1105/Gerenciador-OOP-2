from enum import Enum
import random

def gerador_id_random(ids_existentes) -> int:
    """Gera um ID numérico aleatório garantindo que ele seja único."""
    conjunto_ids = {int(i) for i in ids_existentes}

    while True:
        id_novo = random.randint(1, 9999)
        if id_novo not in conjunto_ids:
            return id_novo

class Setor(Enum):
    TI = "TI"
    FINANCEIRO = "Financeiro"
    RH = "RH"
    OPERACOES = "Comercial"

RESPONSAVEIS = ["Ana Souza", "Bruno Lima", "Carla Dias", "João da Silva"]

class TipoEquipamento(Enum):
    #NOTEBOOK = 1
    SERVIDOR = 1
    #ROTEADOR = 3
    BANCO_DADOS = 2
    APLICACAO_WEB = 3

class Vulnerabilidade:
    def __init__(self, id_vuln: str, descricao: str, categoria: str, severidade_cvss: float, status: str = "Aberta", nome: str = ""):
        self.id_vuln = id_vuln
        self.descricao = descricao
        self.categoria = categoria
        self.severidade_cvss = float(severidade_cvss)
        self.status = status  # Ex: Aberta, Em tratamento, Corrigida, Risco aceito

    def to_dict(self):
        return self.__dict__

class Equipamento:
    def __init__(self, id_equip: int, nome: str, responsavel: str, setor: str, tipo: TipoEquipamento):
        self.id_equip = int(id_equip)
        self.nome = nome
        self.responsavel = responsavel
        self.setor = setor
        self.tipo = tipo if isinstance(tipo, TipoEquipamento) else TipoEquipamento(tipo) #VERIFICA SE É ELEMENTO DA CLASSE ENUM E SE NÃO FOR ELE CONVERTE
        self.vulnerabilidades = []

    def fator_exposicao(self) -> float:
        """Fator polimórfico default de ponderação de risco próprio."""
        return 1.0

    def to_dict(self):
        return {
            "id_equip": self.id_equip,
            "nome": self.nome,
            "responsavel": self.responsavel,
            "setor": self.setor,
            "tipo": self.tipo.value,
            "vulnerabilidades": [v.to_dict() for v in self.vulnerabilidades] #CONVERTE CADA ELEMENTO PARA UM DICIONÁRIO
        }

# Polimorfismo: Subclasses ajustam o risco de acordo com o papel do ativo
class ServidorWeb(Equipamento):
    def fator_exposicao(self) -> float:
        return 1.5  # Ativo exposto à internet possui maior exposição

class BancoDados(Equipamento):
    def fator_exposicao(self) -> float:
        return 1.2

class Aplicativo(Equipamento):
    def fator_exposicao(self) -> float:
        return 1.3