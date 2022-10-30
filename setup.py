#!/usr/bin/env python
import os

from setuptools import setup, find_packages

with open(os.path.join(os.path.dirname(__file__), 'README.md'), encoding='utf-8') as f:
    readme = f.read()

setup(
    name='django-csp-advanced',
    version='0.1.0',
    description='Provides a powerful interface to CSP headers for Django applications.',
    long_description=readme,
    long_description_content_type='text/markdown',
    author='Quantum',
    author_email='quantum@dmoj.ca',
    url='https://github.com/quantum5/django-csp-advanced',
    keywords='django csp security',
    packages=find_packages(),
    include_package_data=True,
    license='GNU AGPLv3',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 3.2',
        'Framework :: Django :: 4.0',
        'Framework :: Django :: 4.1',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    zip_safe=False,
)
