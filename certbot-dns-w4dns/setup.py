from setuptools import setup
from setuptools import find_packages


version = '0.40.0.dev0'

# Remember to update local-oldest-requirements.txt when changing the minimum
# acme/certbot version.
install_requires = [
    'acme>=0.29.0',
    'certbot>=0.39.0',
    'mock',
    'setuptools',
    'zope.interface',
    'httplib2',
    'requests'
]

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
]

setup(
    name='certbot-dns-w4dns',
    version=version,
    description="W4DNS Authenticator plugin for Certbot",
    url='https://github.com/kgw4it/certbot',
    author="Klaus Gamauf",
    author_email='engineering@w4it.at',
    license='Apache License 2.0',
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        'docs': docs_extras,
    },
    entry_points={
        'certbot.plugins': [
            'dns-w4dns = certbot_dns_w4dns.dns_w4dns:Authenticator',
        ],
    },
    test_suite='certbot_dns_w4dns',
)
