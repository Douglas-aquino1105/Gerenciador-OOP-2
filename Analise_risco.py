import numpy as np
from Arquivos import InventarioRepository


class AnalisadorDeRisco:
    def __init__(self, repo: InventarioRepository):
        self.repo = repo

    def calcular_riscos(self):
        equipamentos = list(self.repo.equipamentos_by_id.values())
        n = len(equipamentos)
        if n == 0:
            return {}, {} #DOIS VAZIOS PARA EVITAR ERRO DE MATRIZ TAMANHO 0

        # 1. Mapeamento de vulnerabilidades únicas para compor as colunas de M
        vulns_unicas = {}
        for eq in equipamentos:
            for v in eq.vulnerabilidades:
                if v.id_vuln not in vulns_unicas:
                    vulns_unicas[v.id_vuln] = v.severidade_cvss

        m = len(vulns_unicas)

        # Cada vulnerabilidade única recebe um número de coluna (0, 1, 2, ...)
        # Ex.: {"CVE-A": 0, "CVE-B": 1, "CVE-C": 2}
        coluna_da_vuln = {}
        proxima_coluna = 0
        for id_vuln in vulns_unicas:
            coluna_da_vuln[id_vuln] = proxima_coluna
            proxima_coluna += 1

        # 2. Construção da Matriz de Incidência M (n x m) e Vetor de Severidade v (m)
        M = np.zeros((n, m))
        v = np.zeros(m)

        # v[coluna] = severidade CVSS da vulnerabilidade daquela coluna
        for id_vuln, severidade in vulns_unicas.items():
            coluna = coluna_da_vuln[id_vuln]
            v[coluna] = severidade

        # M[linha, coluna] = 1 se o equipamento (linha) tem a vulnerabilidade (coluna)
        for linha, eq in enumerate(equipamentos):
            for vuln in eq.vulnerabilidades:
                coluna = coluna_da_vuln[vuln.id_vuln]
                M[linha, coluna] = 1.0

        # 3. Risco Próprio b = F * M * v (incorporando o polimorfismo do fator de exposição)
        F = np.diag([eq.fator_exposicao() for eq in equipamentos]) #DIAG CRIA MATRIZ DIAGONAL
        b = F @ (M @ v) #B É O RESULTADO FINAL DE RISCO BRUTO INDIVIDUAL

        # 4. Matriz de Dependência A (n x n)
        A = np.zeros((n, n))

        # Cada equipamento recebe um número de posição (0, 1, 2, ...)
        # que serve tanto de linha quanto de coluna em A
        # Ex.: {101: 0, 102: 1, 103: 2}
        posicao_do_equip = {}
        proxima_posicao = 0
        for eq in equipamentos:
            posicao_do_equip[eq.id_equip] = proxima_posicao
            proxima_posicao += 1

        for chave, peso in self.repo.dependencias.items(): #monta a matriz de pesos para interdependência
            id_origem, id_destino = map(int, chave.split("->")) #-> divide um valor do outro, split vai procurar isso
            if id_origem in posicao_do_equip and id_destino in posicao_do_equip: #verifica se pegou os ids corretamente e na ordem correta
                linha = posicao_do_equip[id_destino]  # Ativo que herda risco
                coluna = posicao_do_equip[id_origem]  # Ativo de onde o risco vem
                if linha != coluna:
                    A[linha, coluna] = peso

        # 5. Verificação de Invertibilidade da Matriz (I - A)
        I = np.eye(n)
        matriz_sistema = I - A

        # Teste 1: Regra da dominância diagonal estrita (Soma por linha < 1)
        soma_linhas = A.sum(axis=1)
        estritamente_dominante = np.all(soma_linhas < 1.0)

        # Teste 2: Número de Condição kappa(I - A) para evitar determinante "quase zero"
        kappa = np.linalg.cond(matriz_sistema)
        limite_estabilidade = 1 / np.finfo(float).eps

        if kappa >= limite_estabilidade or not estritamente_dominante:
            raise ValueError(
                f"Sistema não invertível ou mal-condicionado (kappa={kappa:.2e}). "
                "A soma dos pesos de dependência de uma linha deve ser estritamente menor que 1."
            )

        # 6. Resolução do Sistema Linear (I - A)x = b diretamente com solve
        x = np.linalg.solve(matriz_sistema, b)

        # Retorna resultados mapeados por hostname/ID
        risco_proprio = {eq.nome: float(b[i]) for i, eq in enumerate(equipamentos)}
        risco_efetivo = {eq.nome: float(x[i]) for i, eq in enumerate(equipamentos)}

        return risco_proprio, risco_efetivo