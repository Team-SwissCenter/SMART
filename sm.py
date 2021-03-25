#!/usr/bin/env python3
# coding=utf-8
import argparse
import configparser
import sys
from os import path
import shutil
import json
import base64
from loguru import logger
import smarterlib


#
# Global default settings
#
debug_enabled = False
colorless = False


def init_logger():
    if debug_enabled:
        log_level = "DEBUG"
    else:
        log_level = "INFO"
    logger.stop()
    logger.start(
        sys.stderr,
        colorize=not colorless,
        format='<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <level>{message}</level>',
        level=log_level
    )


def load_config(config_file):
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
    # Check if given SmarterMail install dir existing
    sm_root = config['general']['sm_install_dir']
    if not path.isdir(sm_root):
        logger.error('SmarterMail installation directory %s not found' % sm_root)
        sys.exit(0)

    # Check if SmarterMail executable is present
    sm_executable = path.join(sm_root, 'Service', 'MailService.exe')
    if not path.isfile(sm_executable):
        logger.error('SmarterMail service executable %s not present' % sm_executable)

    # Check if SmarterMail settings is present and valid
    sm_setting_json = path.join(sm_root, 'Service', 'MailService.exe')
    if not path.isfile(sm_executable):
        logger.error('SmarterMail service executable %s not present' % sm_executable)


    # Check if SmarterMail domains config is present and valid
#
# Main
#
def main():
    global debug_enabled, colorless

    # Configure logging
    init_logger()

    # Load config
    config = load_config(path.join(path.dirname(path.realpath(__file__)), 'sm.ini'))

    # Check if we're good to go
    sanity_check(config)

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

    # Initialize arguments variables
    debug_enabled, colorless, action = None, None, None

    # Bind global args
    debug_enabled = args.d
    colorless = args.c

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


# Main definition
if __name__ == "__main__":
    main()