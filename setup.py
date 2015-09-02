from setuptools import setup, find_packages

setup(
      name='bro-tools',
      version='0.1',
      description='Some tools for working with the output of Bro',
      url='https://github.com/gmacon/bro_tools',
      author='George Macon',
      author_email='george.macon@gmail.com',
      license='MIT',
      classifiers=[
            'Development Status :: 3 - Alpha',
            'License :: OSI Approved :: MIT License',
            'Programming Language :: Python :: 3',
      ],
      packages=find_packages(),
)
