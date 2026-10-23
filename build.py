import sys
src=open('game.html').read()
three=open('package/build/three.min.js').read()
mode=sys.argv[1]
if mode=='local':
    body=src.replace('<script src="three.min.js"></script>','<script>'+three+'</script>')
    out='<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">'+body+'</html>'
    open('index.html','w').write(out)
else:
    open('artifact.html','w').write(src.replace('<script src="three.min.js"></script>','<script src="https://cdn.jsdelivr.net/npm/three@0.149.0/build/three.min.js"></script>'))
