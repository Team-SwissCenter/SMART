#!/usr/bin/env python3
# coding=utf-8
import sys
import shutil
import json
import base64
from loguru import logger
from win32api import GetFileVersionInfo, LOWORD, HIWORD


def init_logger(debug_enabled=False, colorless=False):
    # Initialize the logger with custom settings
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
    return logger


def get_executable_version(executable):
    # Get version of an executable file
    try:
        info = GetFileVersionInfo(executable, "\\")
        ms = info['FileVersionMS']
        ls = info['FileVersionLS']
        return HIWORD(ms), LOWORD(ms), HIWORD(ls), LOWORD(ls)
    except:
        return None


def load_json(json_file):
    # Try to open a json file and parse the content.
    # Returns the parsed data if successful
    # Returns False if the file is not a valid json
    try:
        with open(json_file, encoding='utf-8-sig') as f:
            json_data = json.load(f)
    except ValueError as err:
        logger.error('Could not parse json file %s: %s' % (json_file, err))
        return False
    logger.debug('Json file %s parsed successfully' % json_file)
    return json_data


# Main definition
if __name__ == "__main__":
    print('Sorry pal, this is a library that is not intended to be used from cli.')
    sys.exit(1)
