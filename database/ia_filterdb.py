import logging
import re
import base64
import json
from struct import pack
from pyrogram.file_id import FileId
from pymongo import MongoClient, WriteConcern
from pymongo.errors import DuplicateKeyError
from info import (
    FILE_DB_URI, SEC_FILE_DB_URI, DATABASE_NAME, COLLECTION_NAME,
    MULTIPLE_DATABASE, USE_CAPTION_FILTER, MAX_B_TN
)
from utils import get_settings, save_group_settings

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Initialize MongoDB Clients and Collections
client = MongoClient(FILE_DB_URI)
db = client[DATABASE_NAME]
col = db[COLLECTION_NAME]

sec_client = MongoClient(SEC_FILE_DB_URI)
sec_db = sec_client[DATABASE_NAME]
sec_col = sec_db[COLLECTION_NAME]


async def save_file(media):
    """Save file in database"""
    file_id, file_ref = unpack_new_file_id(media.file_id)
    file_name = re.sub(r"(_|\-|\.|\+)", " ", str(media.file_name))
    unwanted_chars = ['[', ']', '(', ')']
    for char in unwanted_chars:
        file_name = file_name.replace(char, '')
    file_name = ' '.join(filter(lambda x: not x.startswith('@'), file_name.split()))
    
    file = {
        'file_id': file_id,
        'file_name': file_name,
        'file_size': media.file_size,
        'caption': media.caption.html if media.caption else None
    }

    filters = [{'file_name': file_name}, {'file_id': file_id}]
    for f in filters:
        if col.find_one(f) or (MULTIPLE_DATABASE and sec_col.find_one(f)):
            print(f"{file_name} is already saved.")
            return False, 0

    result = db.command('dbstats')
    data_size = result['dataSize']
    target_col = sec_col if MULTIPLE_DATABASE and data_size > 503316480 else col

    try:
        target_col.with_options(write_concern=WriteConcern("majority")).insert_one(file)
        print(f"{file_name} is successfully saved.")
        return True, 1
    except DuplicateKeyError:
        print(f"{file_name} is already saved.")
        return False, 0


async def get_search_results(chat_id, query, file_type=None, max_results=10, offset=0, filter=False):
    """For given query return (results, next_offset)"""
    if chat_id is not None:
        settings = await get_settings(int(chat_id))
        try:
            max_results = 10 if settings.get('max_btn') else int(MAX_B_TN)
        except KeyError:
            await save_group_settings(int(chat_id), 'max_btn', False)
            settings = await get_settings(int(chat_id))
            max_results = 10 if settings.get('max_btn') else int(MAX_B_TN)

    query = query.strip()
    if not query:
        raw_pattern = '.'
    elif ' ' not in query:
        raw_pattern = r'(\b|[\.\+\-_])' + query + r'(\b|[\.\+\-_])'
    else:
        raw_pattern = query.replace(' ', r'.*[\s\.\+\-_]')
    
    try:
        regex = re.compile(raw_pattern, flags=re.IGNORECASE)
    except:
        return []

    filter = {'$or': [{'file_name': regex}, {'caption': regex}]} if USE_CAPTION_FILTER else {'file_name': regex}
    cursor1 = cursor2 = []

    if MULTIPLE_DATABASE:
        cursor1 = col.find(filter)
        cursor2 = sec_col.find(filter)
    else:
        cursor1 = col.find(filter)
    
    files1 = list(cursor1)
    files2 = list(cursor2) if MULTIPLE_DATABASE else []
    all_files = files1 + files2
    files = all_files[offset:offset + max_results]
    total_results = len(all_files)
    next_offset = offset + max_results if offset + max_results < total_results else ""

    return files, next_offset, total_results


async def get_bad_files(query, file_type=None, filter=False):
    """For given query return bad files"""
    query = query.strip()
    if not query:
        raw_pattern = '.'
    elif ' ' not in query:
        raw_pattern = r'(\b|[\.\+\-_])' + query + r'(\b|[\.\+\-_])'
    else:
        raw_pattern = query.replace(' ', r'.*[\s\.\+\-_]')
    
    try:
        regex = re.compile(raw_pattern, flags=re.IGNORECASE)
    except:
        return []

    filter = {'$or': [{'file_name': regex}, {'caption': regex}]} if USE_CAPTION_FILTER else {'file_name': regex}

    if MULTIPLE_DATABASE:
        result1 = col.count_documents(filter)
        result2 = sec_col.count_documents(filter)
        total_results = result1 + result2
        cursor1 = col.find(filter)
        cursor2 = sec_col.find(filter)
        files = list(cursor1) + list(cursor2)
    else:
        total_results = col.count_documents(filter)
        files = list(col.find(filter))

    return files, total_results


async def get_file_details(query):
    """Get file details by file_id"""
    filter = {'file_id': query}
    filedetails = col.find_one(filter)
    if not filedetails and MULTIPLE_DATABASE:
        filedetails = sec_col.find_one(filter)
    return filedetails


def encode_file_id(s: bytes) -> str:
    """Encode file ID"""
    r = b""
    n = 0
    for i in s + bytes([22]) + bytes([4]):
        if i == 0:
            n += 1
        else:
            if n:
                r += b"\x00" + bytes([n])
                n = 0
            r += bytes([i])
    return base64.urlsafe_b64encode(r).decode().rstrip("=")


def encode_file_ref(file_ref: bytes) -> str:
    """Encode file reference"""
    return base64.urlsafe_b64encode(file_ref).decode().rstrip("=")


def unpack_new_file_id(new_file_id):
    """Unpack new file ID into file_id and file_ref"""
    decoded = FileId.decode(new_file_id)
    file_id = encode_file_id(
        pack(
            "<iiqq",
            int(decoded.file_type),
            decoded.dc_id,
            decoded.media_id,
            decoded.access_hash
        )
    )
    file_ref = encode_file_ref(decoded.file_reference)
    return file_id, file_ref
