import ast
src = "x = 1 + 2"
tree = ast.parse(src)
print(ast.dump(tree))
