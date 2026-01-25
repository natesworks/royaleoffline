import frida

session = frida.attach(0)

with open("script.js", "r") as f:
    source = f.read()

compiled = session.compile_script(source)

with open("script.compiled.js", "wb") as f:
    f.write(compiled)
