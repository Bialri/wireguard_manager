from setuptools import setup, find_packages
import codecs
import os

here = os.path.abspath(os.path.dirname(__file__))

with codecs.open(os.path.join(here, "README.md"), encoding="utf-8") as fh:
    long_description = "\n" + fh.read()

VERSION = '0.0.2.1'
DESCRIPTION = 'Wireguard management tool'
LONG_DESCRIPTION = 'A package that allows to manage wireguard interfaces, peers and configs.'

# Setting up
setup(
    name="wireguard_manager",
    version=VERSION,
    author="Egor Kardasov",
    author_email="<egor@kardasov.ru>",
    description=DESCRIPTION,
    long_description_content_type="text/markdown",
    long_description=long_description,
    packages=find_packages(),
    install_requires=['cryptography'],
    keywords=['python', 'vpn', 'wireguard', 'server', 'manager'],
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Operating System :: Unix",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
    ]
)