# Notes

## Release

```shell
python3 -m pip install twine setuptools
python3 setup.py sdist bdist_wheel

# test upload
python3 -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*

# test install
python3 -m pip install --user --index-url https://test.pypi.org/simple/ wdpass
# or specify the version
python3 -m pip install --user --index-url https://test.pypi.org/simple/ wdpass==0.1.0


# real upload
python3 -m twine upload dist/*

```
