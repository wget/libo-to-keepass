# libo to keepass

[A few years ago](https://extensions.libreoffice.org/templates/account-id-management), I created a kind of password manager using my favourite spreadsheet piece of software.

Now, it's time to convert the bunch of password protected spreadsheets I have built up to a real mobile friendly password manager ([Nextcloud](https://github.com/jhass/nextcloud-keeweb) + [KeeWeb](https://keeweb.info))

This python script aims at converting a CSV export of the aforementionned spreadsheet project and insert the records in a keepass database.

## Installation

This script makes use of [pykeepass](https://github.com/pschmitt/pykeepass), itself using [libkeepass](https://github.com/libkeepass/libkeepass).

* Simply download [the pip requirements.txt file from pykeepass](https://github.com/pschmitt/pykeepass/blob/master/requirements.txt).

* Execute the following command:

    $ pip install --user -r requirements.txt

## Usage

* Using LibreOffice, export each spreadsheet sheet to a CSV file.
* Create a new KeePass database using the KeePass piece of software of your choice (KeePassX, KeeWeb, etc.). Please make sure you use the KDB4 database format, more secure.
* Execute this script against the CSV file.

```
$ ./libo_to_keepass.py -h
usage: libo_to_keepass.py [-h] -s SOURCE -d DESTINATION [-g GROUP]
                          [-p PASSWORD]

Convert a CSV file with several columns (website name, website address,
account state, login, password, contacted at and notes) to a keepass database

optional arguments:
  -h, --help            show this help message and exit
  -g GROUP, --group GROUP
                        The group where to add the entries.
  -p PASSWORD, --password PASSWORD
                        The password to the keepass database file. If not
                        specified, it will be asked to you during the process.

required named arguments:
  -s SOURCE, --source SOURCE, --src SOURCE
                        Specify the source csv file
  -d DESTINATION, --destination DESTINATION, --dest DESTINATION
                        Specify the destination keepass database.
```

## License

This software is licensed under the terms of the GNU General Public License v3.0.
