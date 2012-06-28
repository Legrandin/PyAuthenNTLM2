from distutils.core import setup

setup(  name='PyAuthenNTLM2',
        description='PyAuthenNTLM2 is a pure Python module that enables Apache to carry out authentication via NTLM and an external Domain Controller or Active Directory server.',
        version="2.3alpha",
        author='Legrandin',
        author_email='gooksankoo@hoiptorrow.mailexpire.com',
        url='https://github.com/Legrandin/PyAuthenNTLM2',
        license='Apache 2.0',
        py_modules=['pyntlm'],
        packages=['PyAuthenNTLM2'],
        classifiers=[
            'Development Status :: 4 - Beta',
            'Programming Language :: Python',
            'Intended Audience :: System Administrators',
            'Environment :: Plugins',
            'Framework :: mod-python',
        ],
)

