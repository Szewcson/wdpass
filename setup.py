from setuptools import setup

# linter complains about undefined __version__
# actually it will be defined at exec(open(....)) statement later
__version__ = ''
# Get the version from wdpass/version.py without importing the package
exec(open('wdpass/version.py').read())

with open("README.md", encoding='utf-8') as f:
    long_description = f.read()

setup(name='wdpass',
      version=__version__,
      description='Western Digital My Passport Utility',
      long_description=long_description,
      long_description_content_type='text/markdown',
      url='http://github.com/7aman/wdpass',
      author='Zaman',
      author_email='7amaaan@gmail.com',
      license='MIT',
      packages=['wdpass'],
      entry_points={
          'console_scripts': ['wdpass=wdpass:main'],
      },
      install_requires=["py3_sg >= 0.16", "SecretStorage >= 3.3.3"],
      python_requires='>=3.6',
      zip_safe=False,
      keywords='HDD WD MyPassport Unlocker WesternDigital',
      include_package_data=True,
      classifiers=[
          'Programming Language :: Python :: 3 :: Only',
          'Operating System :: POSIX :: Linux',
          'Development Status :: 3 - Alpha',
          'Environment :: Console',
          'Intended Audience :: End Users/Desktop',
          'License :: OSI Approved :: MIT License',
          'Natural Language :: English',
          'Topic :: Utilities'
      ],
      project_urls={
          'source': 'http://github.com/7aman/wdpass'
      }
)
