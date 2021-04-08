#!/usr/bin/env python3
# coding=utf-8
import sys
import shutil
import json
import base64
from os import path
from datetime import datetime
from loguru import logger
from win32api import GetFileVersionInfo, LOWORD, HIWORD
from win32com.client import GetObject
import urllib3
import requests

# Global objects
request_headers = {}
api_verify_ssl = False

# Constants
archive_subfolder = 'Archived Data'

# Disable annoying SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def init_logger(debug_enabled=False, error_only=False, colorless=False):
    # Initialize the logger with custom settings
    if debug_enabled:
        log_level = "DEBUG"
    elif error_only:
        log_level = "ERROR"
    else:
        log_level = "INFO"
    logger.stop()
    logger.start(
        sys.stderr,
        colorize=not colorless,
        format='<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <level>{message}</level>',
        level=log_level
    )
    return logger


def dhms_from_seconds(seconds):
    # Return days, hours, minutes, seconds from seconds
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    return days, hours, minutes, seconds


def dhms_to_string(dhms):
    # Return formatted dhms
    # There is a probably a better way to do it but at least it works (somehow)
    dhms_string = ''
    days, hours, minutes, seconds = dhms
    if days > 0:
        dhms_string = '%d days ' % days
    if hours > 0 or dhms_string != '':
        dhms_string = '%s%d hours ' % (dhms_string, hours)
    if minutes > 0 or dhms_string != '':
        dhms_string = '%s%d minutes ' % (dhms_string, minutes)
    if seconds > 0 or dhms_string != '':
        dhms_string = '%s%d seconds ' % (dhms_string, seconds)
    if dhms_string != '':
        dhms_string = '%sago' % dhms_string

    return dhms_string


def get_executable_version(executable):
    # Get version of an executable file
    try:
        info = GetFileVersionInfo(executable, "\\")
        ms = info['FileVersionMS']
        ls = info['FileVersionLS']
        return HIWORD(ms), LOWORD(ms), HIWORD(ls), LOWORD(ls)
    except:
        return None


def get_process_info(process_name):
    # Check if a process is running
    # Returns dict of infos if process is running or return False
    wmi = GetObject('winmgmts:')
    for p in wmi.ExecQuery('select * from Win32_Process where Name="%s"' % process_name):
        # Getting process creation date and uptime
        start_date, *_ = p.CreationDate.split('.')
        start_date = datetime.strptime(start_date, '%Y%m%d%H%M%S')
        uptime = datetime.now() - start_date

        # Dict to return
        process_infos = {
            'name': p.Name,
            'pid': p.ProcessId,
            'start_date': start_date,
            'uptime': uptime,
            'os': p.OSName.split('|')[0] + ' ' + p.WindowsVersion,
            'memory_usage': "{:.2f}MB".format(int(p.WorkingSetSize) / 1024 / 1024)
        }
        return process_infos
    return False


def load_json(json_file):
    # Try to open a json file and parse the content.
    # Returns the parsed data if successful
    # Returns False if the file is not a valid json
    try:
        with open(json_file, encoding='utf-8-sig') as f:
            json_data = json.load(f)
    except (ValueError, FileNotFoundError) as err:
        logger.error('Could not parse json file %s: %s' % (json_file, err))
        return False
    logger.debug('Json file %s parsed successfully' % json_file)
    return json_data


def api_login(api_url, api_user, api_pass):
    global admin_token
    json_data = {
        "username": api_user,
        "password": api_pass
    }
    # Try to authenticate
    response = api_post(api_url, "auth", "authenticate-user", json_data)

    if response.status_code != 200:
        logger.error('API: Unable to authenticate with %s: (%s) %s' % (
            api_url, response.status_code, response.json()['message']))
        sys.exit(1)

    admin_token = response.json()['accessToken']
    request_headers['Authorization'] = 'Bearer ' + admin_token
    return True


def api_get(api_url, section, action):
    global request_headers
    request_url = "%s/api/v1/%s/%s" % (api_url, section, action)
    response = requests.get(request_url, verify=api_verify_ssl, headers=request_headers)
    logger.debug('GET %s' % request_url)
    logger.debug('Response status code: %s' % response.status_code)
    logger.debug('Response raw content: %s' % response.content)
    if response.status_code not in [200, 400]:
        logger.error('GET failed from %s: (%s) %s' % (request_url, response.status_code, response.json()['message']))
        sys.exit(1)
    return response


def api_post(api_url, section, action, json_data=None):
    global request_headers
    request_url = "%s/api/v1/%s/%s" % (api_url, section, action)
    response = requests.post(request_url, verify=api_verify_ssl, headers=request_headers, json=json_data)
    logger.debug('POST %s' % request_url)
    logger.debug('Response status code: %s' % response.status_code)
    logger.debug('Response raw content: %s' % response.content)
    if response.status_code != 200:
        logger.error('POST failed from %s: (%s) %s' % (request_url, response.status_code, response.json()['message']))
        sys.exit(1)
    return response


def get_services_status(api_url):
    #
    # Get SmarterMail services status
    # Return a dict if successful. False if it's not
    #
    results = api_get(api_url, 'settings/sysadmin', 'services')
    if results:
        services = {}
        for service in results.json()['services']:
            services[service] = results.json()['services'][service]
        return services
    return False


def stop_subservice(api_url, service):
    # Stop a sub-service via the API
    json_data = {'input': [service]}
    results = api_post(api_url, 'settings/sysadmin', 'stop-services', json_data)
    if results:
        return results.json()['success']
    return False


def start_subservice(api_url, service):
    # Start a sub-service via the API
    json_data = {'input': [service]}
    results = api_post(api_url, 'settings/sysadmin', 'start-services', json_data)
    if results:
        return results.json()['success']
    return False


def reload_domain(api_url, domain):
    # Reload a domain configuration
    json_data = {}
    results = api_post(api_url,'settings/sysadmin', 'reload-domain/' + domain)
    if results:
        return results.json()['success']
    return False


# TODO:
def load_domain_json(domain, domain_data_path, json_file, fix, no_prompt):
    # Check if file exists
    f = path.join(domain_data_path, json_file)
    if path.isfile(f):
        json_data = load_json(f)
        if json_data:
            return json_data
        else:
            logger.error('%s :: settings json file is not parsable.' % domain)

    if fix:
        # Check if a tmp file exists
        f = path.join(domain_data_path, json_file + '.tmp')
        if path.isfile(f):
            json_data = load_json(f)
            if json_data:
                logger.info('%s :: Found valid domain settings file [tmp]: %s' % (domain, f))
                # Copy file to original file destination and return data
                return json_data

        # Check if a valid file exists in archive
        f = path.join(domain_data_path, archive_subfolder, json_file)
        if path.isfile(f):
            json_data = load_json(f)
            if json_data:
                logger.info('%s :: Found valid domain settings file [archive] %s' % (domain, f))
                # Copy file to original file destination and return data
                return json_data

    # Check if a valid file exists in zipped archives

    # Return false if all failed
    return False


def autofix_domain_accounts(domain, domain_data_path):
    # Check if a tmp file exists
    # Check if a valid file exists in archive
    # Check if a valid file exists in zipped archives
    return False


# Main definition
if __name__ == "__main__":
    print('Sorry pal, this is a library that is not intended to be used from cli.')
    sys.exit(1)
