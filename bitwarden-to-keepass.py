import json
import logging
import os
import re
import subprocess
import getpass

from argparse import ArgumentParser
from typing import Dict, List

from pykeepass import PyKeePass, create_database
from pykeepass.exceptions import CredentialsError
from pykeepass.group import Group as KPGroup

import folder as FolderType
from item import Item, Types as ItemTypes


def bitwarden_to_keepass(
        bw_path: str,
        bw_session: str,
        file: str,
        password: str,
        keyfile: str):

    if os.path.exists(file):
        try:
            kp = PyKeePass(file, password, keyfile)
        except CredentialsError as e:
            logging.error(f'Wrong password for KeePass database: {e}')
            exit(1)
    else:
        logging.info('KeePass database does not exist, creating a new one.')
        kp = create_database(
            file, password, keyfile)

    folders = subprocess.check_output(
        [bw_path, "list", "folders", "--session", bw_session])
    folders = json.loads(folders)
    groups_by_id = load_folders(kp, folders)
    logging.info(f'Folders done ({len(groups_by_id)}).')

    items = subprocess.check_output(
        [bw_path, "list", "items", "--session", bw_session])
    items = json.loads(items)
    logging.info(f'Starting to process {len(items)} items.')

    for item in items:
        if item['type'] in [ItemTypes.CARD, ItemTypes.IDENTITY]:
            logging.warning(
                f'Skipping credit card or identity item "{item["name"]}".')
            continue

        bw_item = Item(item)

        try:
            entry = kp.add_entry(
                groups_by_id[bw_item.get_folder_id()],
                bw_item.get_name(),
                bw_item.get_username(),
                bw_item.get_password(),
                notes=bw_item.get_notes(),
                force_creation=True)

            totp_secret, totp_settings = bw_item.get_totp()
            if totp_secret and totp_settings:
                entry.set_custom_property('TOTP Seed', totp_secret)
                entry.set_custom_property('TOTP Settings', totp_settings)

            uris = bw_item.get_uris()
            if uris:
                entry.url = uris[0]['uri']
                for i, uri in enumerate(uris[1:]):
                    entry.set_custom_property("URL " + str(i + 1), uri["uri"])

            for field in bw_item.get_custom_fields():
                name = field["name"]
                if name == "Password":
                    name = "pw"
                entry.set_custom_property(name, field['value'])

            for attachment in bw_item.get_attachments():
                data = subprocess.check_output(
                    [bw_path, "get", "attachment", attachment["id"], "--itemid", bw_item.get_id(), "--raw", "--session", bw_session])
                attachment_id = kp.add_binary(data)
                entry.add_attachment(attachment_id, attachment['fileName'])

        except Exception as e:
            logging.warning(
                f'Skipping item named "{item["name"]}" because of this error: {repr(e)}')

    logging.info('Saving changes to KeePass database.')
    kp.save()
    logging.info('Export completed.')


def load_folders(kp: PyKeePass, folders) -> Dict[str, KPGroup]:
    # sort folders so that in the case of nested folders, the parents would be guaranteed to show up before the children
    folders.sort(key=lambda x: x['name'])

    # dict to store mapping of Bitwarden folder id to keepass group
    groups_by_id: Dict[str, KPGroup] = {}

    # build up folder tree
    folder_root: FolderType.Folder = FolderType.Folder(None)
    folder_root.keepass_group = kp.root_group
    groups_by_id[None] = kp.root_group

    for folder in folders:
        if folder['id'] is not None:
            new_folder: FolderType.Folder = FolderType.Folder(folder['id'])
            # regex lifted from https://github.com/bitwarden/jslib/blob/ecdd08624f61ccff8128b7cb3241f39e664e1c7f/common/src/services/folder.service.ts#L108
            folder_name_parts: List[str] = re.sub(
                r'^\/+|\/+$', '', folder['name']).split('/')
            FolderType.nested_traverse_insert(
                folder_root, folder_name_parts, new_folder, '/')

    # create keepass groups based off folder tree
    def add_keepass_group(folder: FolderType.Folder):
        parent_group: KPGroup = folder.parent.keepass_group
        new_group: KPGroup = kp.add_group(parent_group, folder.name)
        folder.keepass_group = new_group
        groups_by_id[folder.id] = new_group

    FolderType.bfs_traverse_execute(folder_root, add_keepass_group)

    return groups_by_id


def environ_or_required(key: str) -> Dict[str, str]:
    return (
        {'default': os.environ.get(key)} if os.environ.get(key)
        else {'required': True}
    )


def main():
    parser = ArgumentParser()
    parser.add_argument(
        '--bw-session',
        help='Session generated from bitwarden-cli (bw login)',
        **environ_or_required('BW_SESSION'),
    )
    parser.add_argument(
        '--database-path',
        help='Path to KeePass database. If database does not exists it will be created.',
        **environ_or_required('DATABASE_PATH'),
    )
    parser.add_argument(
        '--database-keyfile',
        help='Path to Key File for KeePass database',
        default=os.environ.get('DATABASE_KEYFILE', None),
    )
    parser.add_argument(
        '--bw-path',
        help='Path for bw binary',
        default=os.environ.get('BW_PATH', 'bw'),
    )
    args = parser.parse_args()

    bw_path = args.bw_path
    bw_session = args.bw_session

    database_keyfile = args.database_keyfile
    if database_keyfile:
        assert os.path.isfile(database_keyfile)
        assert os.access(database_keyfile, os.R_OK)

    database_path = args.database_path

    database_password = os.environ.get("DATABASE_PASSWORD")
    if not database_password:
        database_password = getpass.getpass("New Password: ")

    bitwarden_to_keepass(bw_path, bw_session, database_path,
                         database_password, database_keyfile)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s :: %(levelname)s :: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    main()
