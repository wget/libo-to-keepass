#!/bin/python
# -*-coding:utf-8 -*
import argparse
import os.path
from getpass import getpass
import csv
from pykeepass import PyKeePass
from pykeepass.entry import Entry
from datetime import datetime
import unicodedata
import re
import os

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
        print('[' + Colors.textGreen + Effects.effectBright + '+' + Colors.colorReset + '] ' + string)
    else:
        print('[+] ' + string)

def error(string):
    if os.fstat(0) == os.fstat(1):
        print('[' + Colors.textRed + Effects.effectBright + '-' + Colors.colorReset + '] ' + string)
    else:
        print('[-] ' + string)

class KeePass(PyKeePass):

    def add_entry(self, group, entry):
        group.append(entry)

    def save(self, group, entries_to_add):

        global number_kp_entries

        for entry in entries_to_add:
            info('Adding \'' + entry.title + '\'...')
            self.add_entry(group, entry)
            number_kp_entries += 1

        # Once issue 43 is merged, we will be able to call the parent save()
        # method instead with PyKeePass.save()
        # src.: https://github.com/pschmitt/pykeepass/issues/43
        with open(self.kdb_filename, 'wb+') as outfile:
            self.kdb.unprotect()
            self.kdb.write_to(outfile)

        entries_to_add.clear()

# src.: https://stackoverflow.com/a/518232/3514658
def sanitize_string(s):
    return ''.join(c for c in unicodedata.normalize('NFD', s)
                  if unicodedata.category(c) != 'Mn')

def main():

    args_parser = argparse.ArgumentParser(
        description = "Convert a CSV file with several columns "\
                "(website name, website address, account state, "\
                "login, password, contacted at and notes) to a keepass database")
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

    if args.password is not None:
        password = args.password
    else:
        password = getpass('Please specify your keepass database password : ')

    if args.group is not None:
        group_name = args.group
    else:
        group_name = '3rd parties'
    info('Group name set to \'' + group_name + '\'')

    destination_filename = args.destination.name.split('/')
    destination_filename = destination_filename[len(destination_filename) - 1]
    info('Opening KeePass database \'' + str(destination_filename) + '\'...')
    try:
        kp = KeePass(args.destination.name, password)
    except IndexError:
        error('The password you provided is incorrect or the KeePass file is invalid or has been corrupted.')
        quit()
    del password

    group = kp.find_groups_by_name(group_name, first=True)
    if group is None:
        info('Using root as default target group...')
        group = kp.add_group(kp.root_group, group_name)

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
    global number_kp_entries
    global number_csv_entries

    # Regex to remove tabs, new lines, etc. i.e. non visible chars.
    string_sanitizer = re.compile(r'\n|\t|\r|\x0b|\x0c')

    with open(args.source.name, newline = '') as csv_file:

        csv_records = csv.DictReader(csv_file, fields)
        # record is an OrderedDict which remembers the order in which the
        # elements have been inserted
        for record in csv_records:

            # If this is the first line
            if record['title'].lower() == 'Website name'.lower() and \
               record['url'].lower() == 'Website address'.lower() and \
               record['username'].lower() == 'Login ID'.lower() and \
               record['password'].lower() == 'Password'.lower() and \
               record['contact'].lower() == 'Contacted at'.lower() and \
               record['notes'].lower() == 'Other disclosed informations'.lower():
                info('CSV header detected, skipping it...')
                continue

            # Sanitization
            record['title'] = sanitize_string(record['title'])
            record['title'] = string_sanitizer.sub(" ", record['title'])
            record['username'] = string_sanitizer.sub(" ", record['username'])
            username_sanitized = sanitize_string(record['username'])

            # Remember the original record title when we are trying new names
            # when name collisions happen.
            title = record['title']

            # Using regular expressions with the re module is slower.
            # if re.search("Deprecated", record['state'], re.IGNORECASE) is not None or \
            if 'Deprecated'.lower() in record['state'].lower() or \
               'Pending deletion'.lower() in record['state'].lower() or \
               'Removed'.lower() in record['state'].lower():
                record['expiration_date'] = datetime.utcnow()
            else:
                record['expiration_date'] = None

            number_csv_entries += 1
            name_collisions = 1
            while name_collisions > 0:
                # Since the keepass is only saved when the save method is called on the
                # keepass object, we do not have to search for values in the keepass
                # now, but we rather have to search in the list of items we want to
                # add. If we have an existing keepass, we should check in it as well.
                # entry_list = kp.find_entries_by_title(group_name + '/' + row['title'])
                number_matches_from_keepass = len(kp.find_entries_by_title(record['title']))

                # A comprehensive list returns a generator, we have thus to
                # cast it to a list first as we are not able to get the size of
                # a generator.
                #
                # csv_records is making use of an internal iterator. If we use
                # it here, the pointer will be moved and other csv lines will
                # not be reached.
                #
                # Remembering the location in the file is not a possible
                # solution either as we cannot call csv_file.tell() in this
                # case, because it is disabled when we are making use of an
                # iterator.
                # >>> OSError: telling position disabled by next() call
                # It's better to reopen a file descriptor in this use case.
                # src.: https://stackoverflow.com/a/6755778/3514658
                # FIXME: I know this is increasing the big O complexity, but
                # our csv file might not be sorted anyway. A more efficient
                # algorithm would require sorting the csv file first and reuse
                # the same file desriptor when checking.
                with open(args.source.name, newline = '') as csv_file_bis:

                    csv_records_bis = csv.DictReader(csv_file_bis, fields)
                    number_matches_from_csv = len(list(x for x in csv_records_bis if x['title'].lower() == record['title'].lower()))

                # Since this is the same file, there is the current occurrence
                # in it, we need to remove it.
                if number_matches_from_csv > 0:
                    number_matches_from_csv -= 1

                number_matches_from_memory = len(list(x for x in entries_to_add if x.title.lower() == record['title'].lower()))

                number_matches = \
                    number_matches_from_keepass + \
                    number_matches_from_csv + \
                    number_matches_from_memory
                
                if number_matches > 0:
                    if name_collisions == 1 and username_sanitized:
                        record['title'] = title + ' (' + str(username_sanitized) + ')'
                    else:
                        record['title'] = title + ' (' + str(name_collisions) + ')'
                    name_collisions += 1
                else:
                    # Avoid to have too much records in memory by saving the
                    # file.
                    if len(entries_to_add) == 10:
                        kp.save(group, entries_to_add)

                    entry = Entry(
                        title = record['title'],
                        username = record['username'],
                        password = record['password'],
                        notes = record['notes'],
                        url = record['url'],
                        tags = None,
                        expires = True if record['expiration_date'] else False,
                        expiry_time = record['expiration_date'],
                        icon = '0' # the key icon
                    )
                    entry.set_custom_property('State', record['state'])
                    entries_to_add.append(entry)

                    name_collisions = 0

        # If we reach the end of the csv file and we haven't reached our 10
        # records, ensure to save it before leaving.
        kp.save(group, entries_to_add)

        if number_kp_entries != number_csv_entries:
            error('Inconsistency detected.')
        else:
            info('Operation run successfully.')
            
        print('    Number of keepass entries added: ' + \
                str(number_kp_entries) + \
                '.\n    Number of csv records: ' + \
                str(number_csv_entries))


number_kp_entries = 0
number_csv_entries = 0
if __name__ == "__main__":
    main()
