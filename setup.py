from setuptools import setup


setup(
  name = 'flask-secure-headers',
  packages = ['flask_secure_headers'],
  include_package_data = True,
  version = '0.2',
  description = 'Secure Header Wrapper for Flask Applications',
  long_description = ('Add security headers to a Flask application. '
                      'This is intended to be a simplified version of the '
                      'Twitter SecureHeaders Ruby Gem'),
  license='MIT',
  author = 'Tristan Waldear',
  author_email = 'trwaldear@gmail.com',
  url = 'https://github.com/twaldear/flask-secure-headers',
  download_url = 'https://github.com/twaldear/flask-secure-headers/tarball/0.1',
  keywords = ['flask', 'security', 'header'],
  install_requires = ['flask'],
  test_suite="nose.collector",
  tests_require = ['nose'],
  classifiers=[
    'Development Status :: 4 - Beta',
    'Framework :: Flask',
    'License :: OSI Approved :: MIT License',
    'Operating System :: OS Independent',
    'Programming Language :: Python',
    'Topic :: Software Development :: Libraries :: Python Modules',
  ]
)
