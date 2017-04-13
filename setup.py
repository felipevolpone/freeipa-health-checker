from setuptools import setup, find_packages

setup(
    name="freeipa-health-checker",
    description="freeipa-health-checker",
    url="http://github.com/felipevolpone/freeipa-health-checker",
    packages=find_packages(exclude=['tests']),
    install_requires=['PyYAML'],
    entry_points={
        'console_scripts': [
            'ipahc = freeipa_health_checker.__main__:main'
        ]
    },
)

