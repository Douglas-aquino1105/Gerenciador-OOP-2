import sys
import unicodedata
import time
import pyfiglet

from Ativos import Equipamento, ServidorWeb, BancoDados, Aplicativo, Vulnerabilidade, TipoEquipamento, gerador_id_random
from Arquivos import InventarioRepository
from Analise_risco import AnalisadorDeRisco

VERMELHO = "\033[31m"
VERDE = "\033[32m"
AMARELO = "\033[33m"
AZUL = "\033[34m"
NEGRITO = "\033[1m"
ROXO = "\033[35m"
RESET = "\033[0m"

separador = "-" * 60

def normalizar_texto(texto):
    if not texto:
        return ""
    texto_limpo = "".join(str(texto).strip().split())
    sem_acento = "".join(
        c for c in unicodedata.normalize("NFD", texto_limpo) #NFD separa as letras e os acentos, á vira a+´
        if unicodedata.category(c) != "Mn" #Mn = acento solto
    ).lower()
    return sem_acento

def mostrar_ativos(self):
    print(f"{ROXO}Ativos disponíveis:{RESET}\n")
    for ativo in self.repo.equipamentos_by_nome.values():
        print(f"{AZUL}{ativo.id_equip}{RESET}.{ativo.nome.capitalize()}")

class CLI:
    def __init__(self):
        # Inicializa o repositório e o analisador de risco
        self.repo = InventarioRepository()
        self.analisador = AnalisadorDeRisco(self.repo)

    def executar(self):
        """Loop principal do menu interativo."""

        banner = pyfiglet.figlet_format("CYBER INVENTORY", font="slant")
        print(f"{VERDE}{banner}{RESET}")
        while True:
            print(f"\n{separador}")
            print(f"   {AZUL}SISTEMA DE INVENTÁRIO E ANÁLISE DE RISCO{RESET}")
            print(f"{separador}")
            print(F"1. {VERDE}Cadastrar{RESET} Novo Ativo")
            print(f"2. {AZUL}Buscar/Consultar{RESET} Ativo")
            print(f"3. {AZUL}Atualizar{RESET} Dados de um Ativo")
            print(f"4. {VERMELHO}Remover{RESET} Ativo")
            print(f"5. {VERDE}Cadastrar{RESET} Vulnerabilidade em Ativo")
            print(f"6. {AZUL}Visualizar{RESET} Vulnerabilidades de um Ativo")
            print(f"7. {AMARELO}Gerenciar{RESET} Dependências entre Ativos")
            print(f"8. {AMARELO}Calcular{RESET} e Consultar Riscos")
            print(f"9. {AZUL}Visualizar{RESET} Ativos Cadastrados")
            print(F"0. {VERMELHO}Sair{RESET}")
            print(f"{separador}")

            opcao = normalizar_texto(input(f"{AZUL}Escolha uma opção:{RESET} "))

            if opcao in ["1", "cadastrar", "cadastrarativo", "novoativo"]:
                self._cadastrar_ativo()
            elif opcao in ["2", "buscar", "consultar", "buscarativo", "consultarativo"]:
                self._buscar_ativo()
            elif opcao in ["3", "atualizar", "atualizarativo", "editar", "editarativo"]:
                self._atualizar_ativo()
            elif opcao in ["4", "remover", "deletar", "excluir", "removerativo", "excluirativo"]:
                self._remover_ativo()
            elif opcao in ["5", "cadastrarvulnerabilidade", "novavulnerabilidade", "vulnerabilidade"]:
                self._cadastrar_vulnerabilidade()
            elif opcao in ["6", "visualizarvulnerabilidades", "vervulnerabilidades", "listarvulnerabilidades"]:
                self._visualizar_vulnerabilidades()
            elif opcao in ["7", "gerenciardependencias", "dependencias", "verdependencias"]:
                self._gerenciar_dependencias()
            elif opcao in ["8", "calcularriscos", "riscos", "analisederisco", "calcularrisco"]:
                self._calcular_riscos()
            elif opcao in ["9", "visualizarativos", "verativos", "listarativos"]:
                mostrar_ativos(self)
                time.sleep(2)
            elif opcao in ["0", "sair", "encerrar", "exit", "fechar"]:
                print(f"\n{VERMELHO}ENCERRANDO A APLICAÇÃO!{RESET}")
                time.sleep(2)
                sys.exit(0)

            else:
                print(f"\n\n{VERMELHO}[Erro]{RESET} Opção inválida. Tente novamente.")

    # --- Métodos Auxiliares de Validação ---

    def _ler_int(self, mensagem: str) -> int:
        """Lê um número inteiro com tratamento de exceção."""
        while True:
            try:
                valor = int(input(mensagem).strip())
                return valor
            except ValueError:
                print(f"{VERMELHO}[Erro]{RESET} Entrada inválida. Por favor, digite um número inteiro.")

    def _ler_float(self, mensagem: str) -> float:
        """Lê um número flutuante com tratamento de exceção."""
        while True:
            try:
                valor = float(input(mensagem).strip())
                return valor
            except ValueError:
                print(f"{VERMELHO}[Erro]{RESET} Entrada inválida. Por favor, digite um número decimal.")

    def _ler_texto_nao_vazio(self, mensagem: str) -> str:
        """Lê uma string garantindo que não seja vazia."""
        while True:
            texto = input(mensagem).strip()
            if texto:
                return texto
            print(f"{VERMELHO}[Erro]{RESET} O campo não pode ficar vazio.")

    # --- Funcionalidades do Menu ---

    def _cadastrar_ativo(self):
        print(f"\n--- {VERDE}Cadastrar{RESET} Novo Ativo ---")
        print(f"\n{AMARELO}ID do ativo sendo gerado automaticamente!{RESET}")
        id_equip = gerador_id_random(self.repo.equipamentos_by_id.keys())
        print(f"{AZUL}ID gerado:{RESET} {VERDE}{id_equip}{RESET}")

        # if self.repo.buscar_por_id(id_equip):
        #     print(f"[Erro] Já existe um ativo cadastrado com o ID {id_equip}.")
        #     return

        hostname = normalizar_texto(self._ler_texto_nao_vazio(f"{AZUL}Nome:{RESET} "))
        responsavel = normalizar_texto(self._ler_texto_nao_vazio(f"{AZUL}Responsável:{RESET} "))
        setor = normalizar_texto(self._ler_texto_nao_vazio(f"{AZUL}Setor/Localização:{RESET} "))

        print(f"\n{AZUL}Tipos de Ativos disponíveis:{RESET}")
        for tipo in TipoEquipamento:
            print(f"{AZUL}{tipo.value}{RESET} - {tipo.name}")

        cod_tipo = self._ler_int(f"{AZUL}Código do Tipo de Ativo:{RESET} ")
        try:
            tipo_enum = TipoEquipamento(cod_tipo)
        except ValueError:
            print(f"{VERMELHO}[Erro]{RESET} Código de tipo inválido.")
            return

        # Instanciação com herança/polimorfismo
        if tipo_enum == TipoEquipamento.APLICACAO_WEB:
            novo_ativo = ServidorWeb(id_equip, hostname, responsavel, setor, tipo_enum)
        elif tipo_enum == TipoEquipamento.BANCO_DADOS:
            novo_ativo = BancoDados(id_equip, hostname, responsavel, setor, tipo_enum)
        else:
            novo_ativo = Equipamento(id_equip, hostname, responsavel, setor, tipo_enum)

        self.repo.adicionar(novo_ativo)
        print(f"\n{VERDE}[Sucesso]{RESET} Ativo '{AZUL}{hostname}{RESET}' cadastrado com sucesso!")

    def _buscar_ativo(self):

        mostrar_ativos(self)

        while True:
            print(f"\n--- {AZUL}Buscar Ativo{RESET} ---")
            termo = normalizar_texto(self._ler_texto_nao_vazio(f"{AZUL}Digite o ID ou nome do ativo:{RESET} "))
            if termo == "quit":
                break

            ativo = None
            if termo.isdigit():
                ativo = self.repo.buscar_por_id(int(termo))
            if not ativo:
                ativo = self.repo.equipamentos_by_nome.get(termo)

            if ativo:
                print(f"\n{VERDE}--- Dados do Ativo ---{RESET}")
                print(f"{AZUL}ID:{RESET} {ativo.id_equip}")
                print(f"{AZUL}Nome:{RESET} {ativo.nome}")
                print(f"{AZUL}Responsável:{RESET} {ativo.responsavel}")
                print(f"{AZUL}Setor:{RESET} {ativo.setor}")
                print(f"{AZUL}Tipo:{RESET} {ativo.tipo.name} (Código: {ativo.tipo.value})")
                print(f"{AZUL}Número Total de Vulnerabilidades:{RESET} {len(ativo.vulnerabilidades)}")
                time.sleep(4)
                break  # Encerra a busca e retorna ao menu principal

            # Caso o ativo não seja encontrado:
            print(f"\n{VERMELHO}[Aviso] Nenhum ativo encontrado com esse identificador.{RESET}")

            # Pergunta ao usuário se ele deseja tentar novamente
            opcao = input(f"\n{AZUL}Deseja tentar novamente? (S/N):{RESET} ").strip().lower()
            if opcao not in ["s", "sim", "1"]:
                print(f"{AMARELO}Retornando ao menu principal...{RESET}")
                time.sleep(1)
                break  # Sai do loop e volta ao menu principal

    def _atualizar_ativo(self):

        mostrar_ativos(self)
        print(f"\n--- {AMARELO}Atualizar Ativo{RESET} ---")
        id_equip = self._ler_int(f"{AZUL}ID do ativo a atualizar:{RESET} ")
        ativo = self.repo.buscar_por_id(id_equip)

        if not ativo:
            print(f"{VERMELHO}[Erro]{RESET} Ativo não encontrado.")
            return

        print(f"{AMARELO}Atualizando o ativo '{ativo.nome}'. Deixe em branco para manter o valor atual.{RESET}")

        novo_resp = input(f"{AZUL}Novo Responsável [{ativo.responsavel}]:{RESET} ").strip()
        if novo_resp:
            ativo.responsavel = novo_resp

        novo_setor = input(f"{AZUL}Novo Setor [{ativo.setor}]:{RESET} ").strip()
        if novo_setor:
            ativo.setor = novo_setor

        self.repo.salvar()
        print(f"\n{VERDE}[Sucesso]{RESET} Dados do ativo atualizados com sucesso!")

    def _remover_ativo(self):

        mostrar_ativos(self)

        print(f"\n--- {VERMELHO}Remover Ativo{RESET} ---")
        id_equip = self._ler_int(f"ID do ativo a {VERMELHO}remover:{RESET} ")
        ativo = self.repo.buscar_por_id(id_equip)

        if not ativo:
            print(f"\n{VERMELHO}[Erro]{RESET} Ativo não encontrado.")
            return

        while True:
            certeza = input(f"Tem certeza de que deseja {VERMELHO}remover{RESET} o ativo {AZUL}'{id_equip}.{ativo.nome.capitalize()}'{RESET}? Essa operação {VERMELHO}não{RESET} pode ser desfeita: Y/N\n-> ")
            certeza = normalizar_texto(certeza)
            if certeza in ["sim", "s", "yes", "y"]:
                if self.repo.deletar(id_equip):
                    print(f"\n{VERDE}[Sucesso]{RESET} Ativo e suas vulnerabilidades foram {VERMELHO}removidos{RESET} da base.")
                    time.sleep(1.5)
                else:
                    print(f"\n{VERMELHO}[Erro]{RESET} Ativo não encontrado.")
                break
            elif certeza in ["nao", "n", "no", "nope"]:
                print(f"Operação {VERMELHO}cancelada!{RESET}")
                time.sleep(1.5)
                break
            else:
                print("Escolha uma opção válida!")

    def _cadastrar_vulnerabilidade(self):
        print(f"\n--- {VERDE}Cadastrar Vulnerabilidade{RESET} ---")
        mostrar_ativos(self)
        id_equip = self._ler_int(f"{AZUL}ID do ativo afetado:{RESET} ")
        ativo = self.repo.buscar_por_id(id_equip)

        if not ativo:
            print(f"{VERMELHO}[Erro]{RESET} Ativo não encontrado.")
            return

        id_vuln = self._ler_texto_nao_vazio(f"{AZUL}ID da Vulnerabilidade (ex: CVE-2021-44228 ou V1):{RESET} ")
        descricao = self._ler_texto_nao_vazio(f"{AZUL}Descrição da falha:{RESET} ")
        categoria = self._ler_texto_nao_vazio(f"{AZUL}Categoria (ex: CWE-89, Configuração):{RESET} ")
        severidade = self._ler_float(f"{AZUL}Nota de Severidade CVSS (0.0 a 10.0):{RESET} ")
        status = self._ler_texto_nao_vazio(f"{AZUL}Status (Aberta, Em tratamento, Corrigida, Risco aceito):{RESET} ")

        vuln = Vulnerabilidade(id_vuln, descricao, categoria, severidade, status)
        ativo.vulnerabilidades.append(vuln)
        self.repo.salvar()
        print(f"\n{VERDE}[Sucesso]{RESET} Vulnerabilidade associada ao ativo com sucesso!")

    def _visualizar_vulnerabilidades(self):
        print(f"\n--- {AZUL}Visualizar Vulnerabilidades{RESET} ---")
        mostrar_ativos(self)
        id_equip = self._ler_int(f"{AZUL}ID do ativo:{RESET} ")
        ativo = self.repo.buscar_por_id(id_equip)

        if not ativo:
            print(f"{VERMELHO}[Erro]{RESET} Ativo não encontrado.")
            return

        if not ativo.vulnerabilidades:
            print(f"\n{AMARELO}[Informação]{RESET} O ativo '{ativo.nome}' não possui vulnerabilidades registradas.")
            return

        print(f"\n--- {AZUL}Vulnerabilidades do Ativo: {ativo.nome}{RESET} ---")
        for v in ativo.vulnerabilidades:
            print(f"- {AZUL}[{v.id_vuln}]{RESET} CVSS: {AMARELO}{v.severidade_cvss}{RESET} | Status: {AMARELO}{v.status}{RESET}")
            print(f"  {AZUL}Descrição:{RESET} {v.descricao} | {AZUL}Categoria:{RESET} {v.categoria}")

    def _gerenciar_dependencias(self):
        print(f"\n--- {AMARELO}Gerenciar Dependências (Pesos para Matriz A){RESET} ---")
        print(f"1. {VERDE}Adicionar/Atualizar{RESET} Dependência")
        print(f"2. {AZUL}Listar{RESET} Dependências Atuais")
        op = input(f"{AZUL}Escolha uma opção:{RESET} ").strip()

        if op == "1":
            mostrar_ativos(self)
            id_origem = self._ler_int(f"{AZUL}ID do Ativo de ORIGEM (de onde o risco vem):{RESET} ")
            id_destino = self._ler_int(f"{AZUL}ID do Ativo de DESTINO (que herda o risco):{RESET} ")

            if id_origem == id_destino:
                print(f"{VERMELHO}[Erro]{RESET} Um ativo não pode depender dele mesmo (diagonal A_ii = 0).")
                return

            peso = self._ler_float(f"{AZUL}Peso da dependência (fração entre 0.0 e 0.99):{RESET} ")
            if not (0.0 <= peso < 1.0):
                print(f"{VERMELHO}[Erro]{RESET} O peso deve estar no intervalo [0, 1).")
                return

            chave = f"{id_origem}->{id_destino}"
            self.repo.dependencias[chave] = peso
            self.repo.salvar()
            print(f"\n{VERDE}[Sucesso]{RESET} Dependência '{chave}' configurada com peso {peso}.")

        elif op == "2":
            print(f"\n--- {AZUL}Dependências Registradas{RESET} ---")
            if not self.repo.dependencias:
                print(f"{AMARELO}Nenhuma dependência cadastrada.{RESET}")
            for chave, peso in self.repo.dependencias.items():
                print(f"  {AZUL}{chave}{RESET} => Peso: {AMARELO}{peso}{RESET}")

    def _calcular_riscos(self):
        print(f"\n--- {AMARELO}Análise de Risco por Álgebra Linear{RESET} ---")
        try:
            risco_proprio, risco_efetivo = self.analisador.calcular_riscos()

            if not risco_proprio:
                print(f"{AMARELO}[Aviso]{RESET} Nenhum ativo cadastrado para realizar a análise.")
                return

            print(f"\n{AZUL}{'HOSTNAME':<20} | {'RISCO PRÓPRIO (b)':<18} | {'RISCO EFETIVO (x)':<18}{RESET}")
            print("-" * 62)
            for hostname in risco_proprio:
                b_val = risco_proprio[hostname]
                x_val = risco_efetivo[hostname]
                print(f"{hostname:<20} | {VERDE}{b_val:<18.2f}{RESET} | {AMARELO}{x_val:<18.2f}{RESET}")

        except ValueError as e:
            print(f"\n{VERMELHO}[ERRO MATEMÁTICO]{RESET} Não foi possível resolver o sistema:")
            print(f"  {VERMELHO}{e}{RESET}")


if __name__ == "__main__":
    app = CLI()
    app.executar()