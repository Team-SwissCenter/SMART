## SmarterMail Analysis and Recovery Tool (SMART)

This utility aims to be the swiss army knife for every SmarterMail server administrator.
It helps detect potential integrity, corruption issues and can in many cases provide an automatic recovery.

### Why does this tool needs to exist. Why not use the official tools provided by SmarterTools ?

Actually, when SmarterMail is not stopped correctly, for example in case of a process crash, hard reset of the server, power loss, anything that prevent the service to stop gracefully, some essential files can easily get corrupted. 
This is probably due to the service writing to these files at the exact moment the service gets killed. 

This can be domain accounts settings (json file), user account settings (json file), maiboxes content indexing (mailbox.cfg, root.cfg that are in a proprietary binary formats) and this will prevent the affected domains and users from using your service correctly.

SmarterMail hopefully periodically backup these files in a sub-folder and it is possible to use them for recovery.
However, this process is manual and on an installation with thousands of domains it can become a nightmare to fully recover to a 100% clean system after such an event.

As for why not use the tools provided by SmarterTools, it's kinda simple. There is no tool for this, and the service doesn't try to heal itself when detecting corrupted files when starting (why not?)

### It's a Windows server. Why python and not PowerShell ?

Unfortunately I lack experience with PowerShell. I'm a bit more comfortable with Python. Also, Python runs well on Windows and has a bunch of great libraries for the script requirements.

### Use cases

### How to install

- Ask your mum
- Install Python 3.7+
- Clone repository
- Run pip install -r requirements.txt
- Add directory in $PATH env (optional)
- Edit sm.ini

### How to use

### TODOs

- Check integrity (start with domains.json and recursively check each domain/user)
  get file from Archive/ or check for .tmp
- Check user folders possible issue (case mismatch, non-existing folders, subscribed folders, etc)
- Check folder path len that could render a user unusable
- Rebuild user folders
- Check root.cfg / mailbox.cfg for corruption (proprietary format, can we use a DLL shipped with SM?)
- Check GRP files for corruption (proprietary format, can we use a DLL shipped with SM?)
- View raw formatted json for domains / users (settings.json, folders.json, domains,json, etc)

### Credits

SmarterMail is a product of SmarterTools Inc. - [Link to SmarterMail product page](https://www.smartertools.com/company/index)