
from .cli import HealthChecker
from .base import BaseCLI


def main():
    return BaseCLI().run_cli([HealthChecker])


if __name__ == '__main__':
    main()
