## SmarterMail Analysis and Recovery Tool (SMART)

This utility aims to be the swiss army knife for every SmarterMail server administrator.
It helps detect potential integrity, corruption issues and can in many cases could provide an automatic recovery.

### WARNING *WORK IN PROGESS*

Even the tool is not actually doing any changes to files be aware that you ** USE IT AT YOUR OWN RISK **

### Why does this tool needs to exist. Why not use the official tools provided by SmarterTools ?

Actually, when SmarterMail is not stopped correctly, for example in case of a process crash, hard reset of the server, power loss, anything that prevent the service to stop gracefully, some essential files can easily get corrupted. 
This is probably due to the service writing to these files at the exact moment the service gets killed. 

This can be domain accounts settings (json file), user account settings (json file), maiboxes content indexing (mailbox.cfg, root.cfg that are in a proprietary binary formats) and this will prevent the affected domains and users from using your service correctly.

SmarterMail hopefully periodically backup these files in a sub-folder and it is possible to use them for recovery.
However, this process is manual and on an installation with thousands of domains it can become a nightmare to fully recover to a 100% clean system after such an event.

### It's a Windows server. Why python and not PowerShell ?

Unfortunately I lack experience with PowerShell. I'm a bit more comfortable with Python. Also, Python runs well on Windows and has a bunch of great libraries for the script requirements.

### Use cases

- Use smart.py -h for help and smart.py <command> -h for help on a subcommand

Basically you can:

- Check domains and users integrity (smart.py check)
- Additionally, check domains for DKIM issues (DKIM enabled but missing keys)  (smart.py --check-dkim)
- Additionally, check user folders for issues  (smart.py --check-folders)
- Additionally, check user folders for contact issues  (smart.py --check-contacts)
- Additionally, check user GRP files for corrupted mails, missing headers. (smart.py --check-grp). Warning the code is not optimal yet, and actually it needs to parse the whole GRP files. Can take a long time.

By default all checks are done on all domains. You can restrict it to a single domain using --domain argument.
--fix argument is actually not implemented yet and is ineffective. No changes to SmarterMail files will be made by the tool.

### How to install

- Install Python 3.8 (3.9 not supported yet)
- Clone repository
- Run pip install -r requirements.txt
- Add directory in $PATH env (optional)
- Copy sample config file to sm.ini and edit it

### How to use

Basically use smart.py -h for help

### TODOs

- Autofix corrupt json files (get valid file from Archive/ or check for .tmp)
- Check user folders possible issue (case mismatch, non-existing folders, subscribed folders, etc)
- Check folder path len that could render a user unusable
- Rebuild user folders
- Check root.cfg / mailbox.cfg for corruption (proprietary format, can we use a DLL shipped with SM?)
- View raw formatted json for domains / users (settings.json, folders.json, domains,json, etc)

### Credits

SmarterMail is a product of SmarterTools Inc. - [Link to SmarterMail product page](https://www.smartertools.com/company/index)