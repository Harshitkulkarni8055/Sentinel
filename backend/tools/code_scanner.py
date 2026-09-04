import ast, os

class Scanner:
    def invoke(self, payload):
        path=payload.get("path","demo_target.py")
        findings=[]
        if os.path.isfile(path):
            try:
                tree=ast.parse(open(path,encoding="utf-8").read())
                # Intentionally conservative: don't flag ordinary subprocess or demo auth code
                # unless a clear shell=True call is present.
                for node in ast.walk(tree):
                    if isinstance(node,ast.Call) and getattr(node.func,"attr","")=="run":
                        for kw in node.keywords:
                            if kw.arg=="shell" and getattr(kw.value,"value",None) is True:
                                findings.append({"file":path,"line":node.lineno,"type":"command_injection","severity":"HIGH","message":"shell=True detected"})
            except Exception:
                pass
        return {"path":path,"files_scanned":1 if os.path.isfile(path) else 0,"findings":findings}
code_scanner=Scanner()
