EvenSmarterTools

The SmarterMail Swiss Army Knife for integrity checking and post crash corruption recovery

Why does this tool exists ?

Why python and not PowerShell ?

Use cases

How to install

- Install Python 3.7+
- Clone repository
- Run pip install -r requirements.txt
- Add directory in path (optional)
- Edit sm.ini

How to use

TODOs

- Check integrity (start with domains.json and recursively check each domain/user)
- Check user folders possible issue (case mismatch, non-existing folders, subscribed folders, etc)
- Rebuild user folders
- Check root.cfg / mailbox.cfg for corruption (proprietary format, can we use a DLL shipped with SM?)
- Check GRP files for corruption (proprietary format, can we use a DLL shipped with SM?)
- View raw formatted json for domains / users (settings.json, folders.json, domains,json, etc)

Credits