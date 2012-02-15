from distutils.core import setup

setup(  name='PyAuthenNTLM2',
        version="2.0",
        description='A mod-python module for Apache that carries out NTLM authentication',
        author='Legrandin',
        author_email='gooksankoo@hoiptorrow.mailexpire.com',
        license='Apache 2.0',
        py_modules=['ntlm_client','ntlm_proxy','pyntlm']
)

