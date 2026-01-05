"""
故事书解析与语言层编解码

功能：
- parse_book_from_bytes: 将字节数组解析为 Book 对象
- pack_language_layers / unpack_language_layers: 语言层的打包与解包
"""

import json
import logging
import struct
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from zlib import crc32

import msgpack

logger = logging.getLogger('app')


@dataclass
class Layer:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    text: Optional[str] = None
    data: Optional[bytes] = None
    offset: Any = None
    rotation: float = 0.0
    scale: float = 1.0
    flipX: bool = False
    flipY: bool = False
    clickAnimation: Any = None
    enterAnimation: Any = None
    type: str = "Unknown"
    page: int = -1

    @staticmethod
    def from_map(m: Dict[str, Any]) -> 'Layer':
        return Layer(
            id=m.get('id') or str(uuid.uuid4()),
            text=m.get('text'),
            data=m.get('data'),
            offset=m.get('offset'),
            rotation=float(m.get('rotation', 0.0) or 0.0),
            scale=float(m.get('scale', 1.0) or 1.0),
            flipX=bool(m.get('flipX', False)),
            flipY=bool(m.get('flipY', False)),
            clickAnimation=m.get('clickAnimation'),
            enterAnimation=m.get('enterAnimation'),
            type=m.get('type') or 'Unknown',
        )


@dataclass
class EditorStateHistory:
    layers: List[Layer]


@dataclass
class BookPage:
    editorStateHistories: List[EditorStateHistory]

    @staticmethod
    def from_map(data: Dict[str, Any]) -> 'BookPage':
        layers: List[Layer] = []
        layers_data = data.get('layers')
        if isinstance(layers_data, list):
            for element in layers_data:
                if isinstance(element, dict):
                    layers.append(Layer.from_map({str(k): v for k, v in element.items()}))
        state = EditorStateHistory(layers)
        return BookPage([state])


@dataclass
class Book:
    bookId: Optional[str] = None
    bookKey: Optional[str] = None
    bookTitle: Optional[str] = None
    author: Optional[str] = None
    language: Optional[str] = None
    description: Optional[str] = None
    minAge: Optional[int] = None
    maxAge: Optional[int] = None
    layout: Any = None
    pageList: List[BookPage] = field(default_factory=list)
    cover: Any = None
    editorSize: Any = None
    createPageAfterInit: bool = True
    coverKey: Optional[str] = None
    tags: Optional[str] = None
    bgMusic: Any = None
    bgMusicName: Optional[str] = None
    publicVersionId: Optional[int] = None
    top: Optional[int] = None
    selected: Optional[int] = None
    categoryId: Optional[str] = None
    categoryName: Optional[str] = None
    voiceName: Optional[str] = None
    voicePrompt: Optional[str] = None

    def get_layers_by_types(self, *type_name: str) -> List[Layer]:
        result: List[Layer] = []
        if not self.pageList:
            return result
        for page_index, page in enumerate(self.pageList):
            for history in page.editorStateHistories:
                for layer in history.layers:
                    if layer.type in type_name:
                        layer.page = page_index
                        result.append(layer)
        return result

    def set_up_binary_data(self, binary_data: Dict[str, bytes]) -> None:
        if not self.pageList:
            return
        for page in self.pageList:
            for state in page.editorStateHistories:
                for layer in state.layers:
                    if layer.id in binary_data:
                        layer.data = binary_data[layer.id]

    @staticmethod
    def from_map(m: Dict[str, Any]) -> 'Book':
        title = m.get('bookTitle') or "--"
        author = m.get('author') or "--"
        min_age = int(m.get('minAge') or 0)
        max_age = int(m.get('maxAge') or 0)
        language = m.get('language') or "en"
        description = m.get('description') or ""
        layout_value = m.get('layout')
        layout = layout_value or "portrait"
        book_id = str(m.get('bookId')) if m.get('bookId') is not None else None
        tags = m.get('tags')
        cover_key = m.get('coverKey')
        book_key = m.get('bookKey')
        bg_music_name = m.get('bgMusicName')
        public_version_id = int(m['publicVersionId']) if isinstance(m.get('publicVersionId'), (int, float)) else None
        top = int(m['top']) if isinstance(m.get('top'), (int, float)) else None
        selected = int(m['selected']) if isinstance(m.get('selected'), (int, float)) else None
        category_id = m.get('categoryId')
        category_name = m.get('categoryName')
        voice_name = None
        gallery = m.get('gallery')
        if isinstance(gallery, dict):
            vn = gallery.get('voiceName')
            if isinstance(vn, str):
                voice_name = vn
        voice_prompt = m.get('voicePrompt')

        pages_map = m.get('pageList') or []
        pages: List[BookPage] = []
        if isinstance(pages_map, list):
            for element in pages_map:
                if isinstance(element, dict):
                    page_map = {str(k): v for k, v in element.items()}
                    pages.append(BookPage.from_map(page_map))

        book = Book(
            bookId=book_id,
            bookKey=book_key,
            bookTitle=title,
            author=author,
            language=language,
            description=description,
            minAge=min_age,
            maxAge=max_age,
            layout=layout,
            pageList=pages,
            cover=None,
            editorSize=None,
            coverKey=cover_key,
            tags=tags,
            bgMusic=None,
            bgMusicName=bg_music_name,
            publicVersionId=public_version_id,
            top=top,
            selected=selected,
            categoryId=category_id,
            categoryName=category_name,
            voiceName=voice_name,
            voicePrompt=voice_prompt,
        )
        return book


OLD_SEPARATOR = bytes([0xFF, 0xFE, 0xFD, 0xFC])
NEW_SEPARATOR = bytes([
    0xFF, 0xFE, 0xFD, 0xFC,
    0xFB, 0xFA, 0xF9, 0xF8,
    0xFF, 0xFE, 0xFD, 0xFC,
    0xFB, 0xFA, 0xF9, 0xF8,
])

OLD_LINE_SEPARATOR = bytes([0x0A])
NEW_LINE_SEPARATOR = bytes([0x0A, 0xF7, 0xF6, 0xF5, 0xF7, 0xF6, 0xF5, 0xF4])


def _get_separators(version_byte: int) -> Tuple[bytes, bytes]:
    if version_byte == 0x02:
        return NEW_SEPARATOR, NEW_LINE_SEPARATOR
    return OLD_SEPARATOR, OLD_LINE_SEPARATOR


def _split_data(data: bytes, separator: bytes) -> List[bytes]:
    parts: List[bytes] = []
    if not data or not separator:
        return [bytes(data)]
    data_len = len(data)
    sep_len = len(separator)
    start = 0
    i = 0
    while i <= data_len - sep_len:
        if data[i:i + sep_len] == separator:
            if start != i:
                parts.append(data[start:i])
            i += sep_len
            start = i
        else:
            i += 1
    if start < data_len:
        parts.append(data[start:data_len])
    return parts


def _parse_msgpack_data(data: bytes) -> Dict[str, Any]:
    unpacked = msgpack.unpackb(data, raw=False)
    if not isinstance(unpacked, dict):
        raise ValueError('MessagePack root is not a map')
    result: Dict[str, Any] = {}
    for k, v in unpacked.items():
        result[str(k)] = v
    return result


def parse_book_from_bytes(data: bytes) -> Book:
    if not data:
        raise ValueError('Book data is empty')

    version = data[0]
    separator, line_separator = _get_separators(version)
    parts = _split_data(data, separator)

    if not parts or len(parts[0]) == 0:
        raise ValueError('Book content is empty')

    if version in (0x02, 0x01):
        decoded: Optional[Dict[str, Any]] = None
        current_data = parts[0][1:]
        max_attempts = min(5, len(parts))
        for i in range(max_attempts):
            try:
                decoded = _parse_msgpack_data(current_data)
                break
            except Exception as e:
                logger.warning(f"MessagePack parse attempt {i} failed: {e}")
            if i == max_attempts - 1:
                break
            next_bytes = parts[i + 1]
            current_data = current_data + separator + next_bytes
        if decoded is None:
            raise ValueError('Failed to parse MessagePack data after multiple attempts')
        book_data = decoded
    else:
        try:
            book_json = parts[0].decode('utf-8')
            book_data = json.loads(book_json)
        except Exception as e:
            logger.warning('Error parsing old format; retry by skipping first byte: %s', e)
            book_json = parts[0][1:].decode('utf-8')
            book_data = json.loads(book_json)

    binary_map: Dict[str, bytes] = {}
    for i in range(1, len(parts)):
        chunk = parts[i]
        idx = chunk.find(line_separator)
        if idx == -1:
            continue
        try:
            _id = chunk[:idx].decode('utf-8')
        except Exception as e:
            logger.warning(f'Error parsing binary data ID: {e}')
            _id = str(uuid.uuid4())
        payload = chunk[idx + len(line_separator):]
        binary_map[_id] = payload

    book = Book.from_map(book_data or {})
    book.set_up_binary_data(binary_map)
    return book


LANG_MAGIC = bytes([0x0B, 0x0E, 0x0E])
LANG_VERSION = 0x01


@dataclass
class LanguageLayer:
    id: str
    languageCode: str
    type: str
    data: bytes


def pack_language_layers(layers: List[LanguageLayer]) -> bytes:
    from io import BytesIO
    out = BytesIO()
    out.write(LANG_MAGIC + bytes([LANG_VERSION]))
    packer = msgpack.Packer(use_bin_type=True)

    payload = []
    for layer in layers:
        payload.append({
            'id': layer.id,
            'languageCode': layer.languageCode,
            'type': layer.type,
            'data': layer.data,
        })
    out.write(packer.pack(payload))

    message = out.getvalue()
    checksum = crc32(message[4:]) & 0xFFFFFFFF
    checksum_bytes = struct.pack('>I', checksum)
    return message + checksum_bytes


def unpack_language_layers(blob: bytes) -> List[LanguageLayer]:
    if len(blob) < 8:
        raise ValueError('Invalid data length')
    if blob[:3] != LANG_MAGIC:
        raise ValueError('Invalid magic number')
    version = blob[3]
    if version != LANG_VERSION:
        raise ValueError(f'Unsupported version: {version}')

    message = blob[:-4]
    expected_crc = struct.unpack('>I', blob[-4:])[0]
    actual_crc = crc32(message[4:]) & 0xFFFFFFFF
    if actual_crc != expected_crc:
        raise ValueError(f'CRC32 mismatch! expected=0x{expected_crc:08x}, actual=0x{actual_crc:08x}')

    payload = message[4:]
    arr = msgpack.unpackb(payload, raw=False)
    if not isinstance(arr, list):
        raise ValueError('Invalid payload format')
    result: List[LanguageLayer] = []
    for item in arr:
        if not isinstance(item, dict):
            continue
        _id = str(item.get('id', ''))
        language_code = str(item.get('languageCode', ''))
        _type = str(item.get('type', 'Unknown'))
        _data = item.get('data') or b''
        if not isinstance(_data, (bytes, bytearray)):
            if isinstance(_data, list) and all(isinstance(x, int) for x in _data):
                _data = bytes(_data)
            else:
                raise ValueError('Invalid binary data in layer')
        result.append(LanguageLayer(id=_id, languageCode=language_code, type=_type, data=bytes(_data)))
    return result
