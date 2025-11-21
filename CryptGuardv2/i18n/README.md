# i18n Resources

Este diretório armazena os arquivos de tradução (.qm/.ts) para o CryptGuard.

## Como atualizar

1. Gere arquivos .ts atualizados:

   `ash
   pyside6-lupdate main_app.py modules keyguard vault.py -ts i18n/cryptguard_pt_BR.ts
   `

2. Edite e traduza os termos no Qt Linguist.
3. Compile as traduções para .qm:

   `ash
   pyside6-lrelease i18n/cryptguard_pt_BR.ts -qm i18n/cryptguard_pt_BR.qm
   `

Os artefatos compilados .qm não devem ser versionados; gere-os durante o build ou pacote.
