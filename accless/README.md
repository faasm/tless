# Accless Core Library

To build:

```bash
accli docker run --mount --cwd /code/accless/accless python3 build.py [-- --clean]
```

To test:

```bash
accli docker run --mount --cwd /code/accless/accless/build-native  ctest -- --output-on-failure
```
