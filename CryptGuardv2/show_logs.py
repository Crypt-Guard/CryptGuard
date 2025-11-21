#!/usr/bin/env python3
"""
Script para mostrar os logs do CryptGuard em tempo real
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_core.paths import LOG_PATH


def show_recent_logs(lines=50):
    """Mostra as últimas linhas do log"""
    try:
        if not LOG_PATH.exists():
            print(f"Arquivo de log não encontrado em: {LOG_PATH}")
            return

        print(f"=== Últimas {lines} linhas do log ({LOG_PATH}) ===\n")

        with open(LOG_PATH, encoding="utf-8") as f:
            all_lines = f.readlines()
            recent_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines

            for line in recent_lines:
                print(line.rstrip())

    except Exception as e:
        print(f"Erro ao ler arquivo de log: {e}")


def follow_logs():
    """Segue o log em tempo real (como tail -f)"""
    try:
        if not LOG_PATH.exists():
            print(f"Arquivo de log não encontrado em: {LOG_PATH}")
            return

        print(f"=== Seguindo logs em tempo real ({LOG_PATH}) ===")
        print("Pressione Ctrl+C para sair\n")

        with open(LOG_PATH, encoding="utf-8") as f:
            # Ir para o final do arquivo
            f.seek(0, 2)

            while True:
                line = f.readline()
                if line:
                    print(line.rstrip())
                else:
                    time.sleep(0.1)

    except KeyboardInterrupt:
        print("\nParando follow dos logs...")
    except Exception as e:
        print(f"Erro ao seguir logs: {e}")


def main():

    parser = argparse.ArgumentParser(description="Visualizar logs do CryptGuard")
    parser.add_argument(
        "-n",
        "--lines",
        type=int,
        default=50,
        help="Número de linhas recentes para mostrar (padrão: 50)",
    )
    parser.add_argument(
        "-f",
        "--follow",
        action="store_true",
        help="Seguir logs em tempo real (como tail -f)",
    )

    args = parser.parse_args()

    if args.follow:
        follow_logs()
    else:
        show_recent_logs(args.lines)


if __name__ == "__main__":
    main()
