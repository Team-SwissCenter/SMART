#!/usr/bin/env python3
# coding=utf-8
import argparse
import configparser
import sys
from os import path
from fqdn import FQDN
#import shutil
#import json
#import base64
import smarterlib
from alive_progress import alive_bar
from colored import fg, bg, attr
from prettytable import PrettyTable

#
# Globally available objects initialization
#

args = {}

infos = {}
infos['total_domains_to_check'] = 0
infos['total_accounts_to_check'] = 0
infos['total_subscribed_folders_mismatch'] = 0

sm_domains = {}
sm_domains_settings = {}
sm_domains_accounts = {}
sm_accounts_settings = {}
sm_accounts_folders = {}
logger = smarterlib.init_logger()


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
    global args, infos, sm_domains, sm_domains_settings, sm_domains_accounts
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
            if not path.isfile(path.join(sm_domains[domain]['data_path'], 'settings.json')):
                logger.error('%s: Domain settings json file %s does not exists' % (
                domain, path.join(sm_domains[domain]['data_path'], 'settings.json')))
                bar()
                continue
            sm_domains_settings[domain] = smarterlib.load_json(
                path.join(sm_domains[domain]['data_path'], 'settings.json'))
            if not sm_domains_settings[domain]:
                logger.error('Domain %s settings json file is not parsable' % domain)

            # Domain accounts file and is parsable ?
            if not path.isfile(path.join(sm_domains[domain]['data_path'], 'accounts.json')):
                logger.warning('%s: Domain accounts json file %s does not exists' % (
                domain, path.join(sm_domains[domain]['data_path'], 'accounts.json')))
                bar()
                continue
            sm_domains_accounts[domain] = smarterlib.load_json(
                path.join(sm_domains[domain]['data_path'], 'accounts.json'))
            if not sm_domains_accounts[domain]:
                logger.error('Domain %s accounts json file is not parsable.' % domain)

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

            for domain_account in sm_domains_accounts[domain]['users']:
                account_data_path = path.join(sm_domains[domain]['data_path'], 'Users', domain_account)
                # Check if user data dir exists
                if not path.isdir(account_data_path):
                    logger.error(
                        '%s [%s] :: Account data path directory does not exists %s' % (
                        domain, domain_account, account_data_path))
                    bar()
                    continue

                # User settings file exists and is parsable ?
                account_settings_file = path.join(account_data_path, 'settings.json')
                sm_accounts_settings[domain + '@' + domain_account] = smarterlib.load_json(account_settings_file)
                if not sm_accounts_settings[domain + '@' + domain_account]:
                    logger.error(
                        '%s [%s] :: Account settings json file is not parsable or does not exists.' % (
                        domain, domain_account))
                    bar()
                    continue

                # User folders definition file exists and is parsable ?
                account_folders_file = path.join(account_data_path, 'folders.json')
                sm_accounts_folders[domain + '@' + domain_account] = smarterlib.load_json(account_folders_file)
                if not sm_accounts_folders[domain + '@' + domain_account]:
                    logger.error(
                        '%s [%s] :: Account folder settings json file is not parsable or does not exists.' % (
                        domain, domain_account))
                    bar()
                    continue
                bar()

                # Check for subscribed folder case mismatch issue
                if 'imap_subscribed_folders' in sm_accounts_folders[domain + '@' + domain_account]:
                    for subscribed_folder in sm_accounts_folders[domain + '@' + domain_account][
                        'imap_subscribed_folders']:
                        if subscribed_folder.startswith('Inbox\\'):
                            infos['total_subscribed_folders_mismatch'] += 1
                            logger.warning(
                                '%s [%s] :: IMAP subscribed folder %s for account probably has an issue (Inbox->INBOX).' % (
                                domain, domain_account, subscribed_folder))
    return True


def service_action():
    global logger, config
    sm_process = smarterlib.get_process_info('MailService.exe')
    if sm_process:
        logger.opt(colors=True).info('SmarterMail main process running with PID <yellow>%d</> on <yellow>%s</>' % (
        sm_process['pid'], sm_process['os']))
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
        if args.service and args.service not in ['xmpp', 'ldap', 'all']:
            logger.error('Unknown service %s' % args.service)
            return False

        # Subaction given
        if 'stop' in args.subaction:
            result = smarterlib.stop_subservice(config['api']['url'], args.service)
        if 'start' in args.subaction:
            result = smarterlib.start_subservice(config['api']['url'], args.service)

        # Standard action
        pt = PrettyTable()
        pt.field_names = ['Service', 'Status']
        for service in services:
            pt.add_row([service['name'], '%srunning%s' % (fg('green'), attr('reset'))])
        pt.align = 'r'
        print(pt)
        return True


#
# Main
#
def main():
    global args, logger, infos, config, sm_domains, sm_domains_settings, sm_domains_accounts, sm_accounts_folders
    #
    # Command-line parser logic
    #
    parser = argparse.ArgumentParser(
        description='EvenSmarterTools - The SmarterMail Swiss Army Knife.')

    # Global options
    parser.set_defaults(which=None)
    parser.add_argument('-c', action='store_true', help='color-less mode')
    parser.add_argument('-d', action='store_true', help='output debug messages')
    subparsers = parser.add_subparsers(help='sub-command help')

    # Check options
    service_parser = subparsers.add_parser('service', help='Status and operations on SmarterMail services')
    service_parser.set_defaults(which='service')
    service_parser.add_argument('subaction', help='Sub-action (stop/start/status)')
    service_parser.add_argument('service', help='Service name')

    # Check options
    check_parser = subparsers.add_parser('check', help='Check SmarterMail domains / users for config corruption')
    check_parser.set_defaults(which='check')
    check_parser.add_argument('--fix', '-f', help='(Try to) fix what is fixable', action='store_true', required=False)
    check_parser.add_argument('--domain', help='Limit check to this domain', required=False)

    # Rebuild options
    rebuild_parser = subparsers.add_parser('rebuild', help='Rebuild a user folder (rebuild mailbox.cfg)')
    rebuild_parser.set_defaults(which='rebuild')
    rebuild_parser.add_argument('--user', help='User to rebuild folders (user@domain)', required=True)
    rebuild_parser.add_argument('--folder', help='Folder to rebuild (i.e. "Inbox" or "all")', required=True)
    args = parser.parse_args()

    # Configure logging
    logger = smarterlib.init_logger(args.d, args.c)

    # Check selection action
    action = args.which
    if not action:
        logger.error('Not sure what you want to do ? Try -h for the help')
        sys.exit(1)

    # Sanity checking on arguments
    if 'domain' in args and args.domain:
        if not FQDN(args.domain).is_valid:
            logger.error('Domain %s is not a valid FQDN.' % args.domain)
            sys.exit(1)

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
    if 'check' in action:
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
    elif 'service' in action:
        service_action()
    elif 'rebuild' in action:
        logger.info('Rebuilding folder')
    else:
        logger.critical('Unknown action. The dev guy of this utility is dumb')

    logger.info('All done for now. Exiting.')
    sys.exit(0)


# Main definition
if __name__ == "__main__":
    main()