from setuptools import setup, find_packages

setup(
    name="security-hardening-client",
    version="1.0.0",
    packages=find_packages(),
    py_modules=["app", "rules_manifest"],
    install_requires=[
        "flet",
    ],
    entry_points={
        'console_scripts': [
            'security-hardening-client=app:run_app',
        ],
    },
)
