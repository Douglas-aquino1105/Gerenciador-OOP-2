import json
import os
from typing import Dict, List, Optional
from Ativos import Equipamento, ServidorWeb, BancoDados, Vulnerabilidade, TipoEquipamento, Aplicativo


class InventarioRepository:
    def __init__(self, file_path="data/equipamentos.json", dep_file_path="data/dependencias.json"):
        self.file_path = file_path
        self.dep_file_path = dep_file_path
        # Indexação em memória usando Dicionários (O(1) para buscas)
        self.equipamentos_by_id: Dict[int, Equipamento] = {} #DICIONÁRIO DE TODOS OS EQUIPAMENTOS POR ID
        self.equipamentos_by_nome: Dict[str, Equipamento] = {}
        self.dependencias: Dict[str, float] = {}  # Chave: "id_origem->id_destino", Valor: peso
        self._carregar_dados()

    def salvar(self):
        lista_json = [eq.to_dict() for eq in self.equipamentos_by_id.values()]
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)

        with open(self.file_path, "w", encoding="utf-8") as f:
            json.dump(lista_json, f, indent=4, ensure_ascii=False)

        with open(self.dep_file_path, "w", encoding="utf-8") as f:
            json.dump(self.dependencias, f, indent=4, ensure_ascii=False)

    def _carregar_dados(self):
        if os.path.exists(self.file_path):
            with open(self.file_path, "r", encoding="utf-8") as f:
                dados = json.load(f)
                for item in dados:
                    # Instanciação dinâmica (POO)
                    tipo_enum = TipoEquipamento(item["tipo"]) #LÊ O ARQUIVO EM BUSCA DO TIPO DO EQUIPAMENTO
                    if tipo_enum == TipoEquipamento.APLICACAO_WEB:
                        eq = ServidorWeb(item["id_equip"], item["nome"], item["responsavel"], item["setor"],
                                         tipo_enum)
                    elif tipo_enum == TipoEquipamento.BANCO_DADOS:
                        eq = BancoDados(item["id_equip"], item["nome"], item["responsavel"], item["setor"],
                                        tipo_enum)
                    elif tipo_enum == TipoEquipamento.SERVIDOR:
                        eq = Aplicativo(item["id_equip"], item["nome"], item["responsavel"], item["setor"],
                                      tipo_enum)
                    else:
                        eq = Equipamento(item["id_equip"], item["nome"], item["responsavel"], item["setor"],
                                         tipo_enum)

                    for v in item.get("vulnerabilidades", []): #SE NÃO EXISTIR ELE RETORNA VAZIO EM VEZ DE CRASHAR
                        eq.vulnerabilidades.append(Vulnerabilidade(**v)) #** CONVERTE DICIONÁRIO EM OBJETO

                    self._adicionar_memoria(eq)

        if os.path.exists(self.dep_file_path):
            with open(self.dep_file_path, "r", encoding="utf-8") as f:
                self.dependencias = json.load(f)

    def _adicionar_memoria(self, eq: Equipamento): #PEGA OBJETO 'EQ' E GUARDA NO LOCAL APONTADO POR EQUIPAMENTOS_BY_ID
        self.equipamentos_by_id[eq.id_equip] = eq
        self.equipamentos_by_nome[eq.nome] = eq

    def adicionar(self, eq: Equipamento):
        self._adicionar_memoria(eq)
        self.salvar()

    def buscar_por_id(self, id_equip: int) -> Optional[Equipamento]: #OPTIONAL PREVINE ERRO PORQUE EQUIPAMENTO PODE SER NONE
        return self.equipamentos_by_id.get(id_equip)

    def deletar(self, id_equip: int) -> bool:
        eq = self.equipamentos_by_id.pop(id_equip, None)
        if eq:
            self.equipamentos_by_nome.pop(eq.nome, None)
            self.dependencias = {
                chave: peso for chave, peso in self.dependencias.items()
                if str(id_equip) not in chave.split("->")
            }
            self.salvar()
            return True
        return False