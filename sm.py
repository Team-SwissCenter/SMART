#!/usr/bin/env python3
# coding=utf-8
import argparse
import configparser
import sys
from os import path
import shutil
import json
import base64
import smarterlib
from alive_progress import alive_bar

#
# Global default settings and variables
#
infos = {}
sm_domains_settings = {}
sm_domains_accounts = {}
logger = None


def load_config(config_file):
    global logger
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
    if 'server' not in config['api']:
        logger.error('Missing API server in configuration [api.server]')
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

    # Return configuration
    return config


def sanity_check(config):
    global logger
    global infos

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


#
# Main
#
def main():
    global logger
    global infos
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
    check_parser = subparsers.add_parser('check', help='Check SmarterMail domains / users for config corruption')
    check_parser.set_defaults(which='check')
    check_parser.add_argument('--fix', '-f', help='(Try to) fix what is fixable', action='store_true', required=False)

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
        sys.exit(0)

    # Bind args depending the selected action
    if 'rebuild' in action:
        user = args.user
        folder = args.folder
    if 'check' in action:
        fix = args.fix

    # Load config
    config = load_config(path.join(path.dirname(path.realpath(__file__)), 'sm.ini'))

    # Check if we're good to go
    sanity_check(config)

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
        #
        # Check domains for errors
        #
        logger.info('Loaded %d domains and %d domain aliases' % (len(sm_domains), len(sm_domains_aliases)))
        logger.info('Checking domains data path, settings and accounts definitions')
        with alive_bar(
                len(sm_domains),
                bar='smooth',
                spinner='dots_reverse',
                title='Checking domains integrity ...'
        ) as bar:
            for domain in sm_domains:
                # Domain data dir exists ?
                if not path.isdir(sm_domains[domain]['data_path']):
                    logger.error('%s: Data path directory does not exists %s' % (domain, sm_domains[domain]['data_path']))
                    bar()
                    continue

                # Domain settings file exists and is parsable ?
                if not path.isfile(path.join(sm_domains[domain]['data_path'], 'settings.json')):
                    logger.error('%s: Domain settings json file %s does not exists' % (domain, path.join(sm_domains[domain]['data_path'], 'settings.json')))
                    bar()
                    continue
                sm_domains_settings[domain] = smarterlib.load_json(path.join(sm_domains[domain]['data_path'], 'settings.json'))
                if not sm_domains_settings[domain]:
                    logger.error('Domain %s settings json file is not parsable. A recovery could be attempted with --fix' % domain)

                # Domain accounts file and is parsable ?
                if not path.isfile(path.join(sm_domains[domain]['data_path'], 'accounts.json')):
                    logger.warning('%s: Domain accounts json file %s does not exists' % (domain, path.join(sm_domains[domain]['data_path'], 'accounts.json')))
                    bar()
                    continue
                sm_domains_accounts[domain] = smarterlib.load_json(path.join(sm_domains[domain]['data_path'], 'accounts.json'))
                if not sm_domains_accounts[domain]:
                    logger.error('Domain %s accounts json file is not parsable. A recovery could be attempted with --fix' % domain)

                bar()


# Main definition
if __name__ == "__main__":
    main()