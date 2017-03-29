from setuptools import setup, find_packages

setup(
    name="freeipa-health-checker",
    description="freeipa-health-checker",
    url="http://github.com/felipevolpone/freeipa-health-checker",
    packages=find_packages(exclude=['tests']),
)

