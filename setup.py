#!/usr/bin/env python

from setuptools import setup

setup(name='brubeck',
      version='0.5.0',
      description='Python Library for building Mongrel2 / ZeroMQ message handlers',
      author='James Dennis',
      author_email='jdennis@gmail.com',
      url='http://github.com/j2labs/brubeck',
      packages=['brubeck'],
      install_requires=['ujson'])
