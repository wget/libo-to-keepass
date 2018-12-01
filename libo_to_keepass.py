#!/bin/python
# -*-coding:utf-8 -*
import os
import argparse
import unicodedata
import re
import csv

from getpass import getpass
from datetime import datetime

from pykeepass import PyKeePass
from pykeepass.entry import Entry

class CustomPyKeePass(PyKeePass):

    def add_entry(self, group, entry):

        entries = PyKeePass.find_entries(
            self,
            title = entry.title,
            username = entry.username,
            first = True,
            group = group,
            recursive = False
        )

        if entries:
            raise Exception(
                'An entry "{}" already exists in "{}"'.format(
                    entry.title, group
                )
            )

        group.append(entry)

        return entry


class Colors:

    textBlack = '[30m'
    textRed = '[31m'
    textGreen = '[32m'
    textYellow = '[33m'
    textBlue = '[34m'
    textMagenta = '[35m'
    textCyan = '[36m'
    textLightGray = '[37m'
    textDefault = '[39m'
    textDarkGray = '[90m'
    textLightRed = '[91m'
    textLightGreen = '[92m'
    textLightYellow = '[93m'
    textLightBlue = '[94m'
    textLightMagenta = '[95m'
    textLightCyan = '[96m'
    textWhite = '[97m'

    backgroundBlack = '[40m'
    backgroundRed = '[41m'
    backgroundGreen = '[42m'
    backgroundYellow = '[43m'
    backgroundBlue = '[44m'
    backgroundMagenta = '[45m'
    backgroundCyan = '[46m'
    backgroundLightGray = '[47m'
    backgroundDefault = '[49m'
    backgroundDarkGray = '[100m'
    backgroundLightRed = '[101m'
    backgroundLightGreen = '[102m'
    backgroundLightYellow = '[103m'
    backgroundLightBlue = '[104m'
    backgroundLightMagenta = '[105m'
    backgroundLightCyan = '[106m'
    backgroundWhite = '[107m'

    colorReset = '[0m'


class Effects:

    effectBright = '[1m'
    effectDim = '[2m'
    effectItalic = '[3m'
    effectUnderline = '[4m'
    effectBlink = '[5m'
    effectReverse = '[7m'
    effectHidden = '[8m'
    effectStrikeThrough = '[9m'

    effectBrightReset = '[21m'
    effectDimReset = '[22m'
    effectItalicReset = '[23m'
    effectUnderlineReset = '[24m'
    effectBlinkReset = '[25m'
    effectReverseReset = '[27m'
    effectHiddenReset = '[28m'
    effectStrikeThroughReset = '[29m'

    effectReset = '[0m'


def info(string):
    if os.fstat(0) == os.fstat(1):
        print(
            '[' +
            Colors.textGreen + Effects.effectBright +
            '+' +
            Colors.colorReset +
            '] ' +
            string)
    else:
        print('[+] ' + string)


def error(string):
    if os.fstat(0) == os.fstat(1):
        print(
            '[' +
            Colors.textRed + Effects.effectBright +
            '-' +
            Colors.colorReset +
            '] ' +
            string)
    else:
        print('[-] ' + string)


def progress(step, total):
    return str(step).zfill(len(str(total))) + '/' + str(total)


# src.: https://stackoverflow.com/a/518232/3514658
def sanitize_string(s):
    return ''.join(c for c in unicodedata.normalize('NFD', s)
                  if unicodedata.category(c) != 'Mn')


def main():

    args_parser = argparse.ArgumentParser(
        description = 
            "Convert a CSV file with several columns "\
            "(website name, website address, account state, "\
            "login, password, contacted at and notes) to a keepass database"
    )

    # Even if the required boolean is set, the arguments are still set to the
    # optional group. The argsparse lib considers named arguments are optional and
    # positional arguments are mandatory by default. This fix is to create or own
    # arguments group.
    # src.: https://stackoverflow.com/a/24181138
    required_args = args_parser.add_argument_group('required named arguments')
    required_args.add_argument(
        "-s", "--source", "--src",
        type = argparse.FileType('r'),
        help = "Specify the source csv file",
        required = True)
    required_args.add_argument(
        "-d", "--destination", "--dest",
        type = argparse.FileType('a'),
        help = "Specify the destination keepass database.",
        required = True)
    args_parser.add_argument(
        "-g", "--group",
        type = str,
        help = "The group where to add the entries.",
        required = False)
    args_parser.add_argument(
        "-p", "--password",
        type = str,
        help = "The password to the keepass database file. " \
               "If not specified, it will be asked to you during the process.",
        required = False)
    args = args_parser.parse_args()

    if args.password:
        password = args.password
    else:
        password = getpass('Please specify your keepass database password : ')

    destination_filename = args.destination.name.split('/')
    destination_filename = destination_filename[len(destination_filename) - 1]

    try:
        info('Opening KeePass database \'' + str(destination_filename) + '\'...')
        kp = CustomPyKeePass(filename = args.destination.name, password = password)
    except IndexError:
        error('The password you provided is incorrect or the KeePass file is invalid or has been corrupted.')
        quit()

    if args.group:
        # We always need to have a group instance to feed to PyKeePass
        group = kp.find_groups_by_name(args.group, first=True)
        if group:
            info('Reusing "' + group.name + '" group to store entries in the KDBX database...')
        else:
            info('Creating new "' + args.group + '" group to store entries in the KDBX database...')
            group = kp.add_group(kp.root_group, args.group)
    else:
        info('Using first group found from KDBX database...')
        group = kp.root_group

    # Make sure the password isn't residing in memory since we don't need it
    # anymore
    del password

    entries_to_add = []
    fields = {
        'title': '',
        'url': '',
        'state': '',
        'username': '',
        'password': '',
        'contact': '',
        'notes': ''
    }

    # Regex to remove tabs, new lines, etc. i.e. non visible chars.
    string_sanitizer = re.compile(r'\n|\t|\r|\x0b|\x0c')

    with open(args.source.name, newline = '') as csv_file:
        csv_records_total = len(list(x for x in csv.DictReader(csv_file, fields)))

    with open(args.source.name, newline = '') as csv_file:

        csv_records = csv.DictReader(csv_file, fields)
        csv_records_inserted = 1

        # record is an OrderedDict which remembers the order in which the
        # elements have been inserted
        for record in csv_records:


            # Skip the header line (first line)
            if record['title'].lower() == 'Website name'.lower() and \
               record['url'].lower() == 'Website address'.lower() and \
               record['username'].lower() == 'Login ID'.lower() and \
               record['password'].lower() == 'Password'.lower() and \
               record['contact'].lower() == 'Contacted at'.lower() and \
               record['notes'].lower() == 'Other disclosed informations'.lower():
                info('CSV header detected, skipping it...')
                continue

            # When there are several website names, separate them by slashes;
            # same for URL
            record['title'] = " / ".join(record['title'].splitlines())
            record['url'] = " / ".join(record['url'].splitlines())

            # Remove accentuated characters
            record['title'] = sanitize_string(record['title'])
            record['title'] = string_sanitizer.sub(" ", record['title'])
            record['username'] = string_sanitizer.sub(" ", record['username'])

            # Remember the original record title when we are trying new names
            # when name collisions happen.
            record_title_original = record['title']

            # Using regular expressions with the re module is slower.
            # if re.search("Deprecated", record['state'], re.IGNORECASE) is not None or \
            if 'Deprecated'.lower() in record['state'].lower() or \
               'Pending deletion'.lower() in record['state'].lower() or \
               'Removed'.lower() in record['state'].lower():
                record['expiration_date'] = datetime.utcnow()
            else:
                record['expiration_date'] = None

            retry_count = 0
            collision_username_used = False
            while (True):
                try:
                    # We could have used kp.add_entry() instead but we want to
                    # add a custom property to the entry and there is no other
                    # option than creating our own custom add_entry method.
                    entry = Entry(
                        title = record['title'],
                        username = record['username'],
                        password = record['password'],
                        notes = record['notes'],
                        url = record['url'],
                        tags = None,
                        expires = True if record['expiration_date'] else False,
                        expiry_time = record['expiration_date'],
                        # the key icon
                        icon = '0',
                        version = kp.version
                    )
                    entry.set_custom_property('State', record['state'])

                    # Try to add the entry. If an entry with the same title and
                    # username already exists, fails.
                    kp.add_entry(group, entry)

                    csv_records_inserted += 1
                    info(progress(csv_records_inserted, csv_records_total) + ' Inserting "' + record['title'] + '"...')

                    break

                except Exception:
                    error(record['title'] + ' already exists. Will try to avoid collision...')

                    # If this is the first time it fails, just add the username
                    # to the title to remove the collision.
                    retry_count += 1
                    if retry_count == 1 and record['username']:
                        record['title'] = record_title_original + ' (' + sanitize_string(record['username']) + ')'
                        collision_username_used = True
                        continue

                    # If we still have a collision, add a number as suffix.
                    # We need to remove trailing number with parentheses first (if any)
                    record_title_no_number = re.sub(r" \([0-9]+\)$", "", record['title'])
                    if collision_username_used:
                        retry_count_to_use = retry_count
                    else:
                        retry_count_to_use = retry_count + 1
                    record['title'] = record_title_no_number + ' (' + str(retry_count_to_use) + ')'

        kp.save()

        info('Number of keepass entries added: ' + str(csv_records_inserted))


if __name__ == "__main__":
    main()
