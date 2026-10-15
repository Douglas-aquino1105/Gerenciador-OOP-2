import numpy as np
from Arquivos import InventarioRepository


class AnalisadorDeRisco:
    def __init__(self, repo: InventarioRepository):
        self.repo = repo

    def calcular_riscos(self):
        equipamentos = list(self.repo.equipamentos_by_id.values())
        n = len(equipamentos)
        if n == 0:
            return {}, {}

        # 1. Mapeamento de vulnerabilidades únicas para compor as colunas de M
        vulns_unicas = {}
        for eq in equipamentos:
            for v in eq.vulnerabilidades:
                if v.id_vuln not in vulns_unicas:
                    vulns_unicas[v.id_vuln] = v.severidade_cvss

        m = len(vulns_unicas)
        id_vuln_to_idx = {id_v: idx for idx, id_v in enumerate(vulns_unicas.keys())}

        # 2. Construção da Matriz de Incidência M (n x m) e Vetor de Severidade v (m)
        M = np.zeros((n, m))
        v = np.zeros(m)

        for id_v, idx in id_vuln_to_idx.items():
            v[idx] = vulns_unicas[id_v]

        for i, eq in enumerate(equipamentos):
            for vuln in eq.vulnerabilidades:
                j = id_vuln_to_idx[vuln.id_vuln]
                M[i, j] = 1.0

        # 3. Risco Próprio b = F * M * v (incorporando o polimorfismo do fator de exposição)
        F = np.diag([eq.fator_exposicao() for eq in equipamentos])
        b = F @ (M @ v)

        # 4. Matriz de Dependência A (n x n)
        A = np.zeros((n, n))
        id_eq_to_idx = {eq.id_equip: idx for idx, eq in enumerate(equipamentos)}

        for chave, peso in self.repo.dependencias.items():
            id_origem, id_destino = map(int, chave.split("->"))
            if id_origem in id_eq_to_idx and id_destino in id_eq_to_idx:
                i = id_eq_to_idx[id_destino]  # Ativo que herda risco
                j = id_eq_to_idx[id_origem]  # Ativo de onde o risco vem
                if i != j:
                    A[i, j] = peso

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
        risco_proprio = {eq.hostname: float(b[i]) for i, eq in enumerate(equipamentos)}
        risco_efetivo = {eq.hostname: float(x[i]) for i, eq in enumerate(equipamentos)}

        return risco_proprio, risco_efetivo