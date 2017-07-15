#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='django-csp-advanced',
    version='0.0.1',
    description='Provides a powerful interface to CSP headers for Django applications.',
    author='Quantum',
    author_email='quantum@dmoj.ca',
    url='https://github.com/quantum5/django-csp-advanced',
    keywords='django csp security',
    packages=find_packages(),
    include_package_data=True,
    license='GNU AGPLv3',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    zip_safe=False,
)
