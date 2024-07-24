git ls-files -o -i -X .gitsecrets | xargs tar -cvf apiauthorization-identityserver.tar
if not exist "e:\secrets\" mkdir e:\secrets
mv apiauthorization-identityserver.tar e:\secrets
