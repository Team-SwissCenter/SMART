#!/usr/bin/env python3
# coding=utf-8
import argparse
import configparser
import sys
from os import path
from fqdn import FQDN
import smarterlib
from alive_progress import alive_bar
from colored import fg, bg, attr
from prettytable import PrettyTable

#
# Globally available objects initialization
#
logger = smarterlib.init_logger()
args = {}
config = {}
infos = {
    'total_domains_to_check': 0,
    'total_accounts_to_check': 0,
    'total_subscribed_folders_mismatch': 0
}
sm_domains = {}
sm_domains_settings = {}
sm_domains_accounts = {}
sm_accounts_settings = {}
sm_accounts_folders = {}
stuff_to_fix = []


def process_args():
    #
    # Command-line parser logic
    #
    parser = argparse.ArgumentParser(
        description='SMART - SmarterMail Analysis and Recovery Tool.')

    # global options
    parser.set_defaults(which=None)
    parser.add_argument('-c', action='store_true', help='color-less mode')
    parser.add_argument('-d', action='store_true', help='output debug messages')
    subparsers = parser.add_subparsers(help='Action to execute')

    # service options
    service_parser = subparsers.add_parser('service', help='Service status and commands (stop/start)')
    service_parser.set_defaults(which='service')
    service_parser.add_argument('subaction', help='Sub-action (stop/start/status)')
    service_parser.add_argument('service', help='Service name')

    # check options
    check_parser = subparsers.add_parser('check', help='Check SmarterMail domains / users for config corruption')
    check_parser.set_defaults(which='check')
    check_parser.add_argument('--domain', help='Limit check to this domain', required=False)
    check_parser.add_argument('--check-folders', help='Also check user folders for possible issues', action='store_true', required=False)
    check_parser.add_argument('--check-contacts', help='Also check user contacts for possible issues', action='store_true', required=False)
    check_parser.add_argument('--check-grp', help='Also check user GRP files for possible issues', action='store_true', required=False)
    check_parser.add_argument('--check-dkim', help='Also check domains for DKIM keys issues', action='store_true', required=False)
    check_parser.add_argument('--fix', '-f', help='(Try to) fix what is fixable', action='store_true', required=False)

    # reload-domain options
    reload_domain_parser = subparsers.add_parser('reload-domain', help='Live reload a domain configuration')
    reload_domain_parser.set_defaults(which='reload-domain')
    reload_domain_parser.add_argument('domain', help='Domain name')

    # rebuild options
    rebuild_parser = subparsers.add_parser('rebuild', help='Rebuild a user folder (rebuild mailbox.cfg)')
    rebuild_parser.set_defaults(which='rebuild')
    rebuild_parser.add_argument('--user', help='User to rebuild folders (user@domain)', required=True)
    rebuild_parser.add_argument('--folder', help='Folder to rebuild (i.e. "Inbox" or "all")', required=True)
    args = parser.parse_args()

    # Configure logging
    logger = smarterlib.init_logger(args.d, args.c)

    # Check selection action
    if not args.which:
        parser.print_help()
        sys.exit(1)

    # Disable logger for some actions (if not debug mode)
    if 'service' in args.which:
        logger = smarterlib.init_logger(error_only=True, debug_enabled=args.d)

    # Sanity checking on arguments
    if 'domain' in args and args.domain:
        if not FQDN(args.domain).is_valid:
            logger.error('Domain %s is not a valid FQDN.' % args.domain)
            sys.exit(1)

    return args


def load_config(config_file):
    global logger, config
    # Config file exists ?
    if not path.isfile(config_file):
        logger.error('Config file %s not found.' % config_file)
        sys.exit(1)

    # Parse config file
    config = configparser.ConfigParser()
    config.read(config_file)

    # Check config file for required stuff
    error = False
    if 'general' not in config:
        logger.error('Missing configuration section [general]')
        error = True
    if 'api' not in config:
        logger.error('Missing configuration section [api]')
        error = True
    if error:
        logger.error('Exiting due to missing mandatory configuration sections')
        sys.exit(0)

    error = False
    if 'sm_install_dir' not in config['general']:
        logger.error('Missing SmarterMail installation path in configuration [general.sm_install_dir]')
        error = True
    if 'use_api' in config['api'] and 'use_api' == 1:
        if 'url' not in config['api']:
            logger.error('Missing API url in configuration [api.url]')
            error = True
        if 'username' not in config['api']:
            logger.error('Missing API username in configuration [api.username]')
            error = True
        if 'password' not in config['api']:
            logger.error('Missing API password in configuration [api.password]')
            error = True
    if error:
        logger.error('Exiting due to missing mandatory configuration settings')
        sys.exit(0)

    return True


def sanity_check():
    global logger, infos, config

    # Check if given SmarterMail install dir existing
    sm_root = config['general']['sm_install_dir']
    if not path.isdir(sm_root):
        logger.error('SmarterMail installation directory %s not found' % sm_root)
        sys.exit(0)

    # Executable
    sm_executable = path.join(sm_root, 'Service', 'MailService.exe')
    if not path.isfile(sm_executable):
        logger.error('SmarterMail service executable %s not present' % sm_executable)
        sys.exit(0)

    # Check SmarterMail version
    v = smarterlib.get_executable_version(sm_executable)
    if not v:
        logger.error('Could not determine installed SmarterMail version')
        sys.exit(0)

    # Populate version information for later use
    infos['sm_version'] = ".". join([str(i) for i in v])
    infos['sm_major'] = v[0]
    infos['sm_build'] = v[2]

    if infos['sm_major'] < 100:
        logger.error('Sorry, we only support SmarterMail from v100 (aka v17, aka "not-versionned-anymore"')
        sys.exit(0)

    logger.debug('Detected supported SmarterMail version %s' % infos['sm_version'])

    return True


def check_domains_integrity():
    #
    # Check domains for errors
    #
    global args, infos, sm_domains, sm_domains_settings, sm_domains_accounts, stuff_to_fix
    logger.info('Checking domains data path, settings and accounts definitions')

    # Running on all domains or a particular one ?
    if args.domain:
        infos['total_domains_to_check'] = 1
    else:
        infos['total_domains_to_check'] = len(sm_domains)

    with alive_bar(
            infos['total_domains_to_check'],
            bar='smooth',
            spinner='dots_reverse',
            title='Checking domains integrity ...'
    ) as bar:
        for domain in sm_domains:
            # Only process the selected domain if requested
            if args.domain and args.domain not in domain:
                continue

            # Domain data dir exists ?
            if not path.isdir(sm_domains[domain]['data_path']):
                logger.error('%s: Data path directory does not exists %s' % (domain, sm_domains[domain]['data_path']))
                bar()
                continue

            # Domain settings file exists and is parsable ?
            sm_domains_settings[domain] = smarterlib.load_domain_json(
                domain, sm_domains[domain]['data_path'], 'settings.json', args.fix, False)
            if not sm_domains_settings[domain]:
                logger.error('Domain %s settings json file is not parsable.' % domain)
                stuff_to_fix.append({
                   'what': 'domain_settings_json',
                   'severity': 'critical',
                   'domain': domain,
                })
                bar()

            # Check domain DKIM integrity
            if args.check_dkim:
                if sm_domains_settings[domain]['settings']['enable_dkim_signing']  and \
                        (len(sm_domains_settings[domain]['settings']['dkim_private_key']) == 0
                         or len(sm_domains_settings[domain]['settings']['dkim_public_key']) == 0):
                    stuff_to_fix.append({
                        'what': 'dkim_missing_keys',
                        'severity': 'warning',
                        'domain': domain
                    })
                    logger.warning('%s :: DKIM signing enabled but public an/or private key missing in configuration' % domain)

            # Domain accounts file and is parsable ?
            sm_domains_accounts[domain] = smarterlib.load_domain_json(
                domain, sm_domains[domain]['data_path'], 'accounts.json', args.fix, False)
            if not sm_domains_accounts[domain]:
                logger.error('Domain %s accounts json file is not parsable.' % domain)
                stuff_to_fix.append({
                    'what': 'domain_accounts_json',
                    'severity': 'critical',
                    'domain': domain,
                })

            # Keep track of how many accounts we'll have to check later
            infos['total_accounts_to_check'] += len(sm_domains_accounts[domain]['users'])
            bar()

    return True


def check_accounts_integrity():
    global args, infos, sm_domains, sm_domains_accounts
    # Check accounts integrity
    logger.info('Checking users data path, settings and folders definitions')
    with alive_bar(
            infos['total_accounts_to_check'],
            bar='smooth',
            spinner='dots_reverse',
            title='Checking users integrity ...'
    ) as bar:
        for domain in sm_domains:
            # Only process selected domain
            if args.domain and args.domain not in domain:
                continue

            # Skip currently errored domains
            if next((i for i, d in enumerate(stuff_to_fix) if domain in d['domain'] and 'critical' in d['severity']), None) is not None:
                logger.warning(
                    '%s :: Skipped accounts checking due to errors in previous checks' % domain)
                bar()
                continue

            #####
            # Check accounts
            #####
            for domain_account in sm_domains_accounts[domain]['users']:
                account_data_path = path.join(sm_domains[domain]['data_path'], 'Users', domain_account)
                # Check if user data dir exists
                if not path.isdir(account_data_path):
                    logger.error(
                        '%s@%s :: Account data path directory does not exists %s'
                        % (domain_account, domain, account_data_path))
                    bar()
                    continue

                # User settings file exists and is parsable ?
                account_settings_file = path.join(account_data_path, 'settings.json')
                sm_accounts_settings[domain + '@' + domain_account] = smarterlib.load_json(account_settings_file)
                if not sm_accounts_settings[domain + '@' + domain_account]:
                    stuff_to_fix.append({
                        'what': 'account_settings_json',
                        'severity': 'critical',
                        'domain': domain,
                        'account': domain_account
                    })
                    logger.error(
                        '%s@%s :: Account settings json file is not parsable or does not exists.'
                        % (domain_account, domain))
                    bar()
                    continue

                # User folders definition file exists and is parsable ?
                account_folders_file = path.join(account_data_path, 'folders.json')
                sm_accounts_folders[domain + '@' + domain_account] = smarterlib.load_json(account_folders_file)
                if not sm_accounts_folders[domain + '@' + domain_account]:
                    stuff_to_fix.append({
                        'what': 'accounts_folders_json',
                        'severity': 'critical',
                        'domain': domain,
                        'account': domain_account
                    })
                    logger.error(
                        '%s@%s :: Account folder settings json file is not parsable or does not exists.'
                        % (domain_account, domain))
                    bar()
                    continue
                bar()

                #####
                # Folders check
                #####
                if args.check_folders:
                    # Check for subscribed folder case mismatch issue
                    found_inbox = False
                    for folder in sm_accounts_folders[domain + '@' + domain_account]['folders']:
                        if ('type' in folder and 'special_folder_type' in folder)\
                                and folder['type'] == 1 and folder['special_folder_type'] == 0:
                            if found_inbox:
                                stuff_to_fix.append({
                                    'what': 'multiple_inbox',
                                    'severity': 'warning',
                                    'domain': domain,
                                    'account': domain_account
                                })
                                logger.warning('%s@%s :: Account has MORE than one mail Inbox folder.'
                                               % (domain_account, domain))
                            if folder['display_name'] != 'Inbox' or folder['path'] != 'Inbox':
                                stuff_to_fix.append({
                                    'what': 'inbox_name',
                                    'severity': 'warning',
                                    'domain': domain,
                                    'account': domain_account
                                })
                                logger.warning('%s@%s :: Account Inbox folder name and/or path is not correct' %
                                               (domain_account, domain))
                            found_inbox = True

                    if 'imap_subscribed_folders' in sm_accounts_folders[domain + '@' + domain_account]:
                        for subscribed_folder in sm_accounts_folders[domain + '@' + domain_account]['imap_subscribed_folders']:
                            if subscribed_folder.startswith('INBOX\\'):
                                infos['total_subscribed_folders_mismatch'] += 1
                                stuff_to_fix.append({
                                    'what': 'subscribed_folders_mismatch',
                                    'severity': 'warning',
                                    'domain': domain,
                                    'account': domain_account
                                })
                                logger.warning(
                                    '%s@%s :: IMAP subscribed folder %s for account probably has an issue (INBOX -> Inbox).'
                                    % (domain_account, domain, subscribed_folder))

                #####
                # Contacts check
                #####
                if args.check_contacts:
                    # Check for problematic contacts
                    contacts_folders_files = set()
                    for folder in sm_accounts_folders[domain + '@' + domain_account]['folders']:
                        if ('type' in folder) and folder['type'] == 3:
                            found_contacts_filename = 'folder-%s.json' % folder['id']
                            contacts_folders_files.add(found_contacts_filename)
                            logger.debug(
                                '%s@%s :: Contacts folder found: "%s" (%s)'
                                % (domain_account, domain, folder['display_name'], found_contacts_filename))

                    if len(contacts_folders_files) < 1:
                        stuff_to_fix.append({
                            'what': 'user_no_contact_folders',
                            'severity': 'critical',
                            'domain': domain,
                            'account': domain_account,
                        })
                        logger.warning(
                            '%s@%s :: No contact folder found. This should not happen!' % (domain_account, domain))
                    else:
                        for contacts_folder_file in contacts_folders_files:
                            logger.debug(
                                '%s@%s :: Checking contacts file %s'
                                % (domain_account, domain, contacts_folder_file))
                            contacts_json = smarterlib.load_json(
                                path.join(account_data_path, contacts_folder_file), True)

                            # TODO: Inform if file is not present ?
                            # Skip contact folder if the json file was not found or was not parsable
                            if not contacts_json:
                                continue
                            # Check if there are contacts in the file
                            if not 'contacts' in contacts_json:
                                continue

                            # Parse contacts and check for errors
                            found_bogus_contact = False
                            logger.debug(
                                '%s@%s :: Parsing contacts file %s' % (domain_account, domain, contacts_folder_file))
                            for contact in contacts_json['contacts']:
                                # Check if name_display_as is missing
                                if 'name_display_as' not in contact or (contact['name_display_as'] and contact['name_display_as'].isspace()):
                                    found_bogus_contact = True
                                    logger.warning(
                                        '%s@%s :: Contact file %s is missing mandatory fied name_display_as. EAS Bug ?'
                                        % (domain_account, domain, contacts_folder_file))
                                    continue

                                # These other checks matches a lot of entries and doesn't seem to affect EAS sync
                                # Disabled for now but kept in code in case we need it later
                                """
                                # Check if blank e-mail addresses are found
                                if 'email_addresses' in contact:
                                    for e in contact['email_addresses']:
                                        if 'address' not in e or not (e['address'] and
                                                                      not e['address'].isspace()):
                                            print(e)
                                            exit
                                            found_bogus_contact = True
                                            logger.warning(
                                                '%s@%s :: Contact file %s contains at least one bogus entry (empty e-mail address)'
                                                % (domain_account, domain, contacts_folder_file))
                                            continue

                                # Check if blank phone numbers are found
                                if 'phone_numbers' in contact:
                                    for p in contact['phone_numbers']:
                                        if 'number' not in p or not (p['number'] and
                                                                      not p['number'].isspace()):
                                            found_bogus_contact = True
                                            logger.warning(
                                                '%s@%s :: Contact file %s contains at least one bogus entry (empty phone number)'
                                                % (domain_account, domain, contacts_folder_file))
                                            continue
                                """

                                # Contact is bogus, adding entry to things to fix
                                if found_bogus_contact:
                                    stuff_to_fix.append({
                                        'what': 'user_bogus_contact',
                                        'severity': 'warning',
                                        'domain': domain,
                                        'account': domain_account,
                                        'contacts_folder_file': contacts_folder_file,
                                        'contact_guid': contact['guid']
                                    })

                #####
                # GRP files checks
                #####
                if args.check_grp:
                    logger.debug('%s@%s :: Looking up GRP files' % (domain_account, domain))
                    user_grp_files = smarterlib.lookup_grp_files(path.join(account_data_path, 'Mail'))
                    for grp_file in user_grp_files:
                        grp_file_status = smarterlib.check_grp_file(grp_file)

    return True


def service_action():
    global logger, config
    sm_process = smarterlib.get_process_info('MailService.exe')
    if sm_process:
        print('SmarterMail main process running with PID <yellow>%d</> on <yellow>%s</>'
                                     % (sm_process['pid'], sm_process['os']))
        print('Running since <yellow>%s</> and currently using <yellow>%s</> of system memory.' % (
                sm_process['uptime'],
                sm_process['memory_usage']
        ))

        logger.opt(colors=True).info('SmarterMail main process running with PID <yellow>%d</> on <yellow>%s</>'
                                     % (sm_process['pid'], sm_process['os']))
        logger.opt(colors=True).info(
            'Running since <yellow>%s</> and currently using <yellow>%s</> of system memory.' % (
                sm_process['uptime'],
                sm_process['memory_usage']
            ))
    else:
        logger.error('SmarterMail is not running.')
        sys.exit(0)

    # Get sub-services status
    if config['api']['use_api'] and int(config['api']['use_api']) == 1:
        smarterlib.request_headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'SMART/1.0'
        }
        smarterlib.api_login(config['api']['url'], config['api']['username'], config['api']['password'])
        services = smarterlib.get_services_status(config['api']['url'])
        # Can we manage services ?
        if not services:
            logger.warning('Unable to get SmarterMail sub-services status through API. Ignoring subservices actions')
            return False

        # Check if submitted service name exists
        if args.service and args.service not in services:
            logger.error('Unknown service %s' % args.service)
            return False

        # Subaction given - action needed
        svc_recheck = False
        if 'stop' in args.subaction:
            if not services[args.service]:
                logger.debug('Service "%s" is already stopped' % args.service)
            else:
                smarterlib.stop_subservice(config['api']['url'], args.service)
                logger.debug('Service "%s" stopped successfully' % args.service)
                svc_recheck = True
        if 'start' in args.subaction:
            if services[args.service]:
                logger.debug('Service "%s" is already running' % args.service)
            else:
                smarterlib.start_subservice(config['api']['url'], args.service)
                logger.debug('Service "%s" started successfully' % args.service)
                svc_recheck = True

        # Check again the services state
        if svc_recheck:
            services = smarterlib.get_services_status(config['api']['url'])

        # Standard action
        pt = PrettyTable()
        pt.field_names = ['Service', 'Status']
        for service in services:
            if services[service]:
                pt.add_row([service, '%srunning%s' % (fg('green'), attr('reset'))])
            else:
                pt.add_row([service, '%sstopped%s' % (fg('red'), attr('reset'))])
        pt.align = 'r'
        print(pt)
        return True


#
# Main
#
def main():
    global args, logger, infos, config, sm_domains, sm_domains_settings, sm_domains_accounts, sm_accounts_folders

    # Process command-line arguments
    args = process_args()

    # Load config
    load_config(path.join(path.dirname(path.realpath(__file__)), 'smart.ini'))

    # Check if we're good to go
    sanity_check()

    # Load settings
    sm_root = config['general']['sm_install_dir']
    sm_settings_file = path.join(sm_root, 'Service', 'Settings', 'settings.json')
    if not path.isfile(sm_settings_file):
        logger.error('Global settings json file %s not present' % sm_settings_file)
        sys.exit(0)
    sm_settings = smarterlib.load_json(sm_settings_file)
    if not sm_settings:
        logger.error('Global settings json file is not parsable. A recovery could be attempted with --fix')

    # domains.json
    sm_domains_file = path.join(sm_root, 'Service', 'Settings', 'domains.json')
    if not path.isfile(sm_domains_file):
        logger.error('Global domains definition json file %s not present' % sm_domains_file)
        sys.exit(0)
    domains_json = smarterlib.load_json(sm_domains_file)
    sm_domains = domains_json['domains']
    sm_domains_aliases = domains_json['domain_aliases']
    if not sm_domains:
        logger.error('Global domains definition json file is not parsable. A recovery could be attempted with --fix')

    #
    # Actions
    #
    if 'check' in args.which:
        logger.info('Loaded %d domains and %d domain aliases' % (len(sm_domains), len(sm_domains_aliases)))

        # Check domains integrity (required)
        check_domains_integrity()
        logger.info('Found %d accounts to check while parsing domains data.' % infos['total_accounts_to_check'])

        # Check accounts integrity (required)
        check_accounts_integrity()

        # Final report of issues for action 'check'
        if infos['total_subscribed_folders_mismatch'] and infos['total_subscribed_folders_mismatch'] > 0:
            logger.warning('Found %d IMAP subscribed folder(s) with possible issue in Thunderbird. '
                           'A recovery could be attempted with --fix' % infos['total_subscribed_folders_mismatch'])

        if args.fix:
            stuff_to_fix_unique = [dict(s) for s in set(frozenset(o.items()) for o in stuff_to_fix)]
            print(stuff_to_fix_unique)
    elif 'service' in args.which:
        service_action()
    elif 'reload-domain' in args.which:
        if args.domain not in sm_domains:
            logger.error('Domain %s does not exists.' % args.domain)
            return False
        logger.info('Reloading domain %s' % args.domain)
        smarterlib.api_login(config['api']['url'], config['api']['username'], config['api']['password'])
        smarterlib.reload_domain(config['api']['url'], args.domain)
    elif 'rebuild' in args.which:
        logger.info('Rebuilding folder')
    else:
        logger.critical('Unknown action. The dev guy of this utility is dumb')

    logger.info('All done for now. Exiting.')
    sys.exit(0)


# Main definition
if __name__ == "__main__":
    main()