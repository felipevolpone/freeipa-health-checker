from setuptools import setup, find_packages

setup(
    name="ipa-health-checker",
    description="ipa-health-checker",
    url="http://github.com/felipevolpone/ipa-health-checker",
    packages=find_packages(exclude=['tests']),
)

