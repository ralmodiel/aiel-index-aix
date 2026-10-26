#!/usr/bin/env python3
"""Freeze bench/codegraph/eval.json from the cloned repos (ground truth by grep + manual disambiguation).

  mkeval.py <repos dir> > eval.json

Each question: repo, cmd (aix argv), kind (callers|callees|outline), gt (file:line, repo-relative), tol, must / mustnot
(substrings of the answer text). Ground truth is a regex over source lines (definition lines excluded by `excl`), or a
literal list. Re-run only to re-pin after the clones move; the heads are recorded."""
import json, os, re, subprocess, sys

ROOT = sys.argv[1]
EXT = {"java": (".java",), "py": (".py",), "ts": (".ts", ".tsx"), "go": (".go",)}

def files(repo, lang):
    out = subprocess.run(["git", "-C", os.path.join(ROOT, repo), "ls-files"], capture_output=True, text=True).stdout.split()
    return [f for f in out if f.endswith(EXT[lang]) and "/node_modules/" not in f and "/client/" not in f]

def grep(repo, lang, pat, excl=None, only=None, skip=None, files_=None):
    rx, ex = re.compile(pat), re.compile(excl) if excl else None
    res = []
    for f in (files_ or files(repo, lang)):
        if only and not re.search(only, f): continue
        if skip and re.search(skip, f): continue
        for i, l in enumerate(open(os.path.join(ROOT, repo, f), errors="replace"), 1):
            if rx.search(l) and not (ex and ex.search(l)) and not l.lstrip().startswith(("//", "#", "*", "/*")):
                res.append(f"{f}:{i}")
    return res

Q = []
def q(id, repo, lang, kind, cmd, gt, tol=0, must=(), mustnot=()):
    Q.append(dict(id=id, repo=repo, lang=lang, kind=kind, cmd=cmd, gt=sorted(set(gt)), tol=tol, must=list(must), mustnot=list(mustnot)))

# ---- Java: spring-petclinic
R = "spring-petclinic"; J = lambda *a, **k: grep(R, "java", *a, **k)
q("j01", R, "java", "callers", ["callers", "OwnerRepository.findById"], J(r"\.findById\("))
q("j02", R, "java", "callers", ["callers", "Pet.addVisit"], ["src/main/java/org/springframework/samples/petclinic/owner/Owner.java:185", "src/main/java/org/springframework/samples/petclinic/owner/VisitController.java:79"])
q("j03", R, "java", "callers", ["callers", "Owner.addVisit"], ["src/main/java/org/springframework/samples/petclinic/owner/VisitController.java:108", "src/test/java/org/springframework/samples/petclinic/service/ClinicServiceTests.java:229"])
q("j04", R, "java", "callers", ["callers", "PetTypeRepository.findPetTypes"], J(r"\bfindPetTypes\(", excl=r"List<PetType> findPetTypes\(\)"))
q("j05", R, "java", "callers", ["callers", "OwnerRepository.findByLastNameStartingWith"], J(r"\.findByLastNameStartingWith\("))
q("j06", R, "java", "callers", ["callers", "Owner.getPet"], J(r"\bgetPet\(", excl=r"public Pet getPet\("))
q("j07", R, "java", "callers", ["callers", "VetRepository.findAll"], J(r"vets?(Repository)?\)?\.findAll\(", excl=r"Page<Vet>|Collection<Vet> findAll"))
D = "src/main/java/org/springframework/samples/petclinic/"
q("j08", R, "java", "callees", ["callees", "OwnerController.processFindForm"], [D + "model/Person.java:49", D + "owner/OwnerController.java:141", D + "model/BaseEntity.java:39", D + "owner/OwnerController.java:132"])
q("j09", R, "java", "outline", ["outline", "OwnerController.java"], [D + f"owner/OwnerController.java:{n}" for n in (55, 59, 64, 72, 77, 89, 94, 132, 141, 148, 153, 178)] , tol=1)
q("j10", R, "java", "callers", ["callers", "OwnerController.setAllowedFields"], [], must=["framework", "InitBinder"])

# ---- Python: full-stack-fastapi-template
R = "full-stack-fastapi-template"; P = lambda *a, **k: grep(R, "py", *a, **k)
B = "backend/"
q("p01", R, "py", "callers", ["callers", "crud.create_user"], P(r"\bcreate_user\(", excl=r"def |^\s*#", only=r"backend/(app/(core|crud)|tests/(crud|utils))|test_users|test_login|app/api/routes/users") )
q("p02", R, "py", "callers", ["callers", "get_password_hash"], P(r"\bget_password_hash\(", excl=r"def "))
q("p03", R, "py", "callers", ["callers", "crud.get_user_by_email"], P(r"\bget_user_by_email\(", excl=r"def "))
q("p04", R, "py", "callers", ["callers", "verify_password"], P(r"\bverify_password\(", excl=r"def "))
q("p05", R, "py", "callers", ["callers", "security.create_access_token"], P(r"\bcreate_access_token\(", excl=r"def "))
q("p06", R, "py", "callers", ["callers", "generate_password_reset_token"], P(r"\bgenerate_password_reset_token\(", excl=r"def "))
q("p07", R, "py", "callers", ["callers", "crud.create_item"], P(r"crud\.create_item\("))
q("p08", R, "py", "callees", ["callees", "crud.authenticate"], [B + "app/crud.py:34", B + "app/core/security.py:29"])
q("p09", R, "py", "outline", ["outline", "backend/app/crud.py"], [B + f"app/crud.py:{n}" for n in (10, 20, 34, 42, 45, 63)], mustnot=["fn def "])
q("p10", R, "py", "callers", ["callers", "Settings._check_default_secret"], [B + "app/core/config.py:" + str(n) for n in (81, 83, 84)])
q("p11", R, "py", "callers", ["callers", "Message"], P(r"(?<![.\w])Message\(", excl=r"class |emails\.", only=r"backend/app"))

# ---- TypeScript: full-stack-fastapi-template frontend (barrel + @/ alias)
F = "frontend/"
T = lambda *a, **k: grep(R, "ts", *a, **k)
q("t01", R, "ts", "callers", ["callers", "ItemsService.readItems"], T(r"ItemsService\.readItems\(", only=r"^frontend/(src|tests)"))
q("t02", R, "ts", "callers", ["callers", "UsersService.readUserMe"], T(r"UsersService\.readUserMe\(", only=r"^frontend/(src|tests)"))
q("t03", R, "ts", "callers", ["callers", "UsersService.deleteUser"], T(r"UsersService\.deleteUser\(", only=r"^frontend/(src|tests)"))
q("t04", R, "ts", "callers", ["callers", "LoginService.loginAccessToken"], T(r"LoginService\.loginAccessToken\(", only=r"^frontend/(src|tests)"))
q("t05", R, "ts", "callers", ["callers", "ItemsService.createItem"], T(r"ItemsService\.createItem\(", only=r"^frontend/(src|tests)"))

# ---- TypeScript: node-express-realworld-example-app
R = "node-express-realworld-example-app"; E = lambda *a, **k: grep(R, "ts", *a, **k)
q("e01", R, "ts", "callers", ["callers", "createUser"], E(r"\bcreateUser\(", excl=r"export const"))
q("e02", R, "ts", "callers", ["callers", "getTags"], E(r"\bgetTags\(", excl=r"const getTags|describe\("))
q("e03", R, "ts", "callers", ["callers", "favoriteArticle"], E(r"(?<![nN])\bfavoriteArticle\(", excl=r"export const"))
q("e04", R, "ts", "callers", ["callers", "getProfile"], E(r"\bgetProfile\(", excl=r"export const|describe\("))
q("e05", R, "ts", "callers", ["callers", "getCurrentUser"], E(r"\bgetCurrentUser\(", excl=r"export const|describe\("), must=["router.get /user"])
q("e06", R, "ts", "callers", ["callers", "login"], E(r"[ (]login\(", excl=r"export const|describe\("))
q("e07", R, "ts", "callers", ["callers", "followUser"], E(r"(?<![nN])\bfollowUser\(", excl=r"export const"))
q("e08", R, "ts", "callers", ["callers", "getTokenFromHeaders"], E(r"getToken: getTokenFromHeaders"))
q("e09", R, "ts", "callers", ["callers", "HttpException"], E(r"new HttpException\("))
ac = open(os.path.join(ROOT, R, "src/app/routes/auth/auth.controller.ts")).read().split("\n")
hl = [i for i, l in enumerate(ac, 1) if re.match(r"router\.(get|post|put|delete)\(", l)]
q("e10", R, "ts", "outline", ["outline", "src/app/routes/auth/auth.controller.ts"], ["src/app/routes/auth/auth.controller.ts:5"] + [f"src/app/routes/auth/auth.controller.ts:{n}" for n in hl], tol=0, mustnot=["user = ", "const user"])

# ---- Go: chi
R = "chi"; G = lambda *a, **k: grep(R, "go", *a, **k)
q("g01", R, "go", "callers", ["callers", "Mux.routeHTTP"], G(r"mx\.routeHTTP\)", skip=r"_test"))
q("g02", R, "go", "callers", ["callers", "Mux.updateRouteHandler"], G(r"mx\.updateRouteHandler\(\)"))
q("g03", R, "go", "callers", ["callers", "Mux.nextRoutePath"], G(r"mx\.nextRoutePath\("))
q("g04", R, "go", "callers", ["callers", "Mux.handle"], G(r"mx\.handle\("))
q("g05", R, "go", "callers", ["callers", "NewRouteContext"], G(r"NewRouteContext\(\)", excl=r"^func|//"))
q("g06", R, "go", "callers", ["callers", "Context.Reset"], G(r"\.Reset\(\)", excl=r"^func"))
q("g07", R, "go", "callers", ["callers", "methodNotAllowedHandler"], ["mux.go:425"])
q("g08", R, "go", "callers", ["callers", "Mux.updateSubRoutes"], G(r"\.updateSubRoutes\(", excl=r"^func"))
mg = [f"mux.go:{i}" for i, l in enumerate(open(os.path.join(ROOT, R, "mux.go")), 1) if re.match(r"(func|type) ", l)]
q("g09", R, "go", "outline", ["outline", "mux.go"], mg, tol=0)
q("g10", R, "go", "callees", ["callees", "Mux.Mount"], ["mux.go:203", "mux.go:223", "mux.go:430", "mux.go:501", "context.go:25"], tol=0)

heads = {r: subprocess.run(["git", "-C", os.path.join(ROOT, r), "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip() for r in ("spring-petclinic", "full-stack-fastapi-template", "node-express-realworld-example-app", "chi")}
json.dump({"heads": heads, "questions": Q}, sys.stdout, indent=1)
