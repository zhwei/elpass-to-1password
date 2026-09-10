#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""把 Elpass 导出的 JSON 转成 1Password 的 .1pux 文件。

用法：
    uv run elpass_to_1password.py Elpass.elpassexport -o export.1pux
    python3 elpass_to_1password.py Elpass.elpassexport -o export.1pux

只用标准库，没有第三方依赖。

.1pux 就是一个 zip 包，里面有：
    export.attributes   导出元信息
    export.data         全部账号 / 保险库 / 条目
    files/              附件本体，文件名是 <documentId>__<原文件名>

格式说明：https://support.1password.com/1pux-format/
说明跟 1Password 真实导出不符的地方以真实导出为准：时间戳键是 timestamp 不是
createdAt，files/ 的分隔符是两个下划线不是三个。
字段映射见 README 里的表格，或者 python3 elpass_to_1password.py --show-mapping。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# 1Password 分类 UUID
# ---------------------------------------------------------------------------

CATEGORY_LOGIN = "001"
CATEGORY_CREDIT_CARD = "002"
CATEGORY_SECURE_NOTE = "003"
CATEGORY_IDENTITY = "004"
CATEGORY_PASSWORD = "005"
CATEGORY_DOCUMENT = "006"
CATEGORY_SOFTWARE_LICENSE = "100"
CATEGORY_BANK_ACCOUNT = "101"
CATEGORY_DATABASE = "102"
CATEGORY_DRIVER_LICENSE = "103"
CATEGORY_OUTDOOR_LICENSE = "104"
CATEGORY_MEMBERSHIP = "105"
CATEGORY_PASSPORT = "106"
CATEGORY_REWARD_PROGRAM = "107"
CATEGORY_SSN = "108"
CATEGORY_WIRELESS_ROUTER = "109"
CATEGORY_SERVER = "110"
CATEGORY_EMAIL_ACCOUNT = "111"
CATEGORY_API_CREDENTIAL = "112"
CATEGORY_MEDICAL_RECORD = "113"
CATEGORY_SSH_KEY = "114"

# Elpass 的 _type -> 1Password categoryUuid
TYPE_TO_CATEGORY = {
    "login": CATEGORY_LOGIN,
    "password": CATEGORY_PASSWORD,
    "note": CATEGORY_SECURE_NOTE,
    "secure_note": CATEGORY_SECURE_NOTE,
    "securenote": CATEGORY_SECURE_NOTE,
    "card": CATEGORY_CREDIT_CARD,
    "bankcard": CATEGORY_CREDIT_CARD,
    "creditcard": CATEGORY_CREDIT_CARD,
    "credit_card": CATEGORY_CREDIT_CARD,
    "bank_card": CATEGORY_CREDIT_CARD,
    "identity": CATEGORY_IDENTITY,
    "bank_account": CATEGORY_BANK_ACCOUNT,
    "email": CATEGORY_EMAIL_ACCOUNT,
    "email_account": CATEGORY_EMAIL_ACCOUNT,
    "server": CATEGORY_SERVER,
    "database": CATEGORY_DATABASE,
    "api_credential": CATEGORY_API_CREDENTIAL,
    "membership": CATEGORY_MEMBERSHIP,
    "passport": CATEGORY_PASSPORT,
    "driver_license": CATEGORY_DRIVER_LICENSE,
    "outdoor_license": CATEGORY_OUTDOOR_LICENSE,
    "social_security_number": CATEGORY_SSN,
    "reward_program": CATEGORY_REWARD_PROGRAM,
    "software_license": CATEGORY_SOFTWARE_LICENSE,
    "wireless_router": CATEGORY_WIRELESS_ROUTER,
    "document": CATEGORY_DOCUMENT,
    "medical_record": CATEGORY_MEDICAL_RECORD,
    "ssh_key": CATEGORY_SSH_KEY,
}

# 已知能处理的 Elpass 顶层属性，其余的会进「Elpass」区块并给出提示
KNOWN_KEYS = {
    "uuid",
    "_type",
    "title",
    "username",
    "password",
    "notes",
    "domains",
    "otpURL",
    "tags",
    "customFields",
    "favIdx",
    "createdAt",
    "updatedAt",
    "archived",
    "securityLevel",
    "noAutoFill",
    "noAutoSubmit",
    "noAutoFillOTP",
    "passkeyBackupEligible",
    "passkeyBackedUp",
    "passkeySignatureCounter",
    "passkeyAlgorithm",
    "importSourceUUID",
    "passwordHistories",
    # bankcard 分类
    "cardNumber",
    "cardBrand",
    "cardType",
    "cardExpiryDateMonth",
    "cardExpiryDateYear",
    "cardVerificationCode",
    "pin",
    "identificationType",
    "identificationNumber",
    "otherFields",
    "attachments",
}

# Elpass 的 identification 是通用「证件」，1Password 没有这么一个分类，
# 只能按 identificationType 的内容挑一个最接近的，挑不到就当安全备注。
IDENTIFICATION_CATEGORIES = [
    (("护照", "passport"), CATEGORY_PASSPORT),
    (("驾驶", "驾照", "driver", "driving"), CATEGORY_DRIVER_LICENSE),
    (("社保", "社会保障", "social security"), CATEGORY_SSN),
]

# otherFields 是个对象，这里的键能对上 1Password 银行卡模板自带的字段。
# 值是 (显示标题, 1Password 的固定字段 id)
OTHER_FIELD_TO_1PASSWORD = {
    "issuingBank": ("issuing bank", "bank"),
}

# Elpass 的 cardBrand -> 1Password 银行卡类型菜单的取值
CARD_BRAND_TO_1PASSWORD = {
    "visa": "visa",
    "mastercard": "mc",
    "master card": "mc",
    "mc": "mc",
    "americanexpress": "amex",
    "american express": "amex",
    "amex": "amex",
    "discover": "discover",
    "jcb": "jcb",
    "diners": "diners",
    "diners club": "diners",
    "dinersclub": "diners",
    "unionpay": "unionpay",
    "union pay": "unionpay",
    "银联": "unionpay",
    "maestro": "maestro",
    "carteblanche": "carteblanche",
    "carte blanche": "carteblanche",
    "laser": "laser",
    "elo": "elo",
    "hipercard": "hipercard",
    "visaelectron": "visaelectron",
    "visa electron": "visaelectron",
}

# 这些属性 1Password 没有对应位置，只能原样保留到「Elpass」区块
UNMAPPED_KEYS = [
    ("cardType", None),  # 信用卡 / 借记卡，1Password 的银行卡分类没有这个字段
    ("importSourceUUID", None),
    ("securityLevel", 0),
    ("noAutoFill", False),
    ("noAutoSubmit", False),
    ("noAutoFillOTP", False),
    ("passkeyBackupEligible", False),
    ("passkeyBackedUp", False),
    ("passkeySignatureCounter", 0),
    ("passkeyAlgorithm", 0),
]

MAPPING_DOC = """\
Elpass 属性                  1Password (.1pux) 位置
--------------------------- ------------------------------------------------
uuid                        item.uuid（转成 26 位大写字母数字，1Password 的 ID 格式）
_type                       item.categoryUuid（login -> 001，见 TYPE_TO_CATEGORY）
_type=identification        按 identificationType 挑分类：护照 106 / 驾照 103 /
                            社保号 108，其余（身份证等）当安全备注 003
title                       item.overview.title
username                    details.loginFields[designation=username]（非登录类进区块字段）
password                    details.loginFields[designation=password]（密码类进 details.password）
notes                       details.notesPlain
domains                     overview.url（第一个）+ overview.urls[]，缺协议时补 https://
otpURL                      区块字段 value.totp，id 必须是 TOTP_ 前缀
tags                        overview.tags，另外统一加一个 elpass 标签（--import-tag）
customFields[].title        区块字段 title
customFields[].value        区块字段 value.concealed / value.string
customFields[].sensitive    决定用 concealed 还是 string
otherFields                 数组时同 customFields；对象时每个键一个字段
otherFields.issuingBank     银行卡的区块字段 id=bank，落在 Contact Information
pin                         区块字段（银行卡用固定 id=pin，落在 Additional Details）
identificationType          区块字段 identification type
identificationNumber        区块字段 identification number（按敏感信息存 concealed）
attachments[]               每个附件一个「文档」条目（details.documentAttributes）
                            + zip 里的 files/<documentId>__<原文件名>，见 --attachments
attachments[].fileSize      decryptedSize（以磁盘上的实际大小为准）
attachments[].fileModific.. zip 里该文件的修改时间
favIdx                      item.favIndex
createdAt                   item.createdAt（秒），同时以可读文本存进「Elpass」区块
updatedAt                   item.updatedAt（秒），同时以可读文本存进「Elpass」区块
archived                    item.state（"archived" / "active"，1Password 的归档）
passwordHistories[]         details.passwordHistory[]（value + voidDateTimestamp -> time）
--------------------------- ------------------------------------------------
bankcard 分类（categoryUuid 002）的预置字段：
cardHolder / username       区块字段 id=cardholder（持卡人）
cardBrand                   区块字段 id=type，value.creditCardType（visa / mc / amex ...）
cardNumber                  区块字段 id=ccnum，value.creditCardNumber
cardVerificationCode        区块字段 id=cvv，value.concealed
cardExpiryDateYear + Month  区块字段 id=expiry，value.monthYear（整数 YYYYMM）
--------------------------- ------------------------------------------------
以下 1Password 没有对应字段，默认原样写入名为「Elpass」的区块（--unmapped 控制）：
cardType（信用卡/借记卡）, importSourceUUID,
securityLevel, noAutoFill, noAutoSubmit, noAutoFillOTP,
passkeyBackupEligible, passkeyBackedUp, passkeySignatureCounter, passkeyAlgorithm
"""


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------

_ID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def one_password_id(seed: str) -> str:
    """把任意字符串映射成 26 位大写字母数字，贴近 1Password 自己的 ID 形态。"""
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    encoded = base64.b32encode(digest).decode("ascii").rstrip("=")
    return encoded[:26]


def field_id(seed: str) -> str:
    """区块字段的 ID，跟 1Password 自己导出的形态一致：26 位小写字母数字。"""
    return one_password_id(seed).lower()


def normalize_timestamp(value: Any) -> int | None:
    """Elpass 用秒；顺手兼容毫秒。"""
    if value is None:
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    if number > 100_000_000_000:  # 毫秒
        number //= 1000
    return number


def format_timestamp(timestamp: int) -> str:
    """按本机时区格式化成可读时间，带时区偏移，避免歧义。"""
    return (
        datetime.fromtimestamp(timestamp, timezone.utc)
        .astimezone()
        .strftime("%Y-%m-%d %H:%M:%S %z")
    )


def to_url(domain: str) -> str:
    domain = str(domain).strip()
    if not domain:
        return ""
    if "://" in domain:
        return domain
    return "https://" + domain.lstrip("/")


def scalar_to_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    if isinstance(value, (int, float, str)):
        return str(value)
    return json.dumps(value, ensure_ascii=False)


# 不同值类型的输入习惯，取自 1Password 真实导出
DEFAULT_INPUT_TRAITS = {
    "keyboard": "default",
    "correction": "default",
    "capitalization": "default",
}
VALUE_INPUT_TRAITS = {
    "totp": {"keyboard": "default", "correction": "no", "capitalization": "none"},
    "file": {"keyboard": "default", "correction": "no", "capitalization": "none"},
    "email": {"keyboard": "emailAddress", "correction": "no", "capitalization": "none"},
    "url": {"keyboard": "uRL", "correction": "default", "capitalization": "default"},
}


def make_field(
    title: str, value: dict, ident: str, guarded: bool = False
) -> dict:
    """区块里的一个字段。

    字段顺序就是数组顺序，1Password 自己的导出里没有 indexAtSource，所以不写。
    guarded 表示这个字段属于分类模板自带的预置字段。
    """
    value_type = next(iter(value), "")
    raw = next(iter(value.values()), "")
    return {
        "title": title,
        "id": ident,
        "value": value,
        "guarded": guarded,
        "multiline": isinstance(raw, str) and "\n" in raw,
        "dontGenerate": False,
        "inputTraits": VALUE_INPUT_TRAITS.get(value_type, DEFAULT_INPUT_TRAITS),
    }


# ---------------------------------------------------------------------------
# 转换
# ---------------------------------------------------------------------------


class Converter:
    def __init__(
        self,
        unmapped: str = "auto",
        skip_archived: bool = False,
        attachments_dir: Path | None = None,
        import_tag: str = "elpass",
        attachments: str = "inline",
    ) -> None:
        self.attachments = attachments  # items / inline / skip
        self.pending_items: list[dict] = []
        self.unmapped = unmapped  # auto / all / none
        self.skip_archived = skip_archived
        self.attachments_dir = attachments_dir
        self.import_tag = import_tag
        self.warnings: list[str] = []
        self.unknown_keys: dict[str, int] = {}
        self.unmapped_other_fields: dict[str, int] = {}
        self.skipped = 0
        # 要打进 zip 的附件：(zip 内路径, 本地路径, 修改时间)
        self.files: list[tuple[str, Path, int]] = []

    # -- 区块 ---------------------------------------------------------------

    def _tags(self, entry: dict) -> list[str]:
        """原有标签，再统一加一个导入标签，方便导入后一眼筛出来。"""
        tags = [str(tag) for tag in (entry.get("tags") or [])]
        if self.import_tag and self.import_tag not in tags:
            tags.append(self.import_tag)
        return tags

    def _identification_category(self, entry: dict) -> str:
        """Elpass 的 identification 按 identificationType 挑一个最接近的 1Password 分类。

        护照 / 驾照 / 社保号 有对应分类，身份证这种没有，就当安全备注，
        证件类型和号码照样作为字段带过去。
        """
        id_type = str(entry.get("identificationType") or "").lower()
        for keywords, category in IDENTIFICATION_CATEGORIES:
            if any(keyword in id_type for keyword in keywords):
                return category
        return CATEGORY_SECURE_NOTE

    def _extra_content_fields(
        self, entry: dict, uuid: str, category: str
    ) -> list[tuple[str, str, dict, bool]]:
        """pin / 证件类型 / 证件号码，返回 (标题, 字段 id, 值, 是否预置字段)。

        分类自带这些字段时（银行卡的 PIN、护照/驾照/社保号的号码）用 1Password
        认得的固定 id，让它渲染成模板里的预置字段；否则用生成的 id，
        证件号码当敏感信息存成 concealed。
        """
        specs: list[tuple[str, str, dict, bool]] = []

        pin = entry.get("pin")
        if pin:
            built_in = category == CATEGORY_CREDIT_CARD
            specs.append(
                (
                    "PIN",
                    "pin" if built_in else field_id(f"{uuid}:pin"),
                    {"concealed": str(pin)},
                    built_in,
                )
            )

        id_type = entry.get("identificationType")
        if id_type not in (None, ""):
            built_in = category == CATEGORY_PASSPORT
            specs.append(
                (
                    "type" if built_in else "identification type",
                    "type" if built_in else field_id(f"{uuid}:idtype"),
                    {"string": scalar_to_text(id_type)},
                    built_in,
                )
            )

        id_number = entry.get("identificationNumber")
        if id_number:
            built_in = category in (
                CATEGORY_PASSPORT,
                CATEGORY_DRIVER_LICENSE,
                CATEGORY_SSN,
            )
            specs.append(
                (
                    "number" if built_in else "identification number",
                    "number" if built_in else field_id(f"{uuid}:idnumber"),
                    # 预置字段按模板存成普通文本，自建字段才藏起来
                    {"string": str(id_number)}
                    if built_in
                    else {"concealed": str(id_number)},
                    built_in,
                )
            )
        return specs

    def _find_attachment_file(self, attachment: dict, source_uuid: str) -> Path | None:
        """附件本体在 <输入文件名>.attachments/<uuid>/ 下面。

        子目录名优先按附件自己的 uuid 找，找不到再按条目 uuid 找；
        目录里优先取跟 fileName 同名的文件，只有一个文件时就取那个。
        """
        if self.attachments_dir is None:
            return None
        file_name = str(attachment.get("fileName") or "")
        for directory in (attachment.get("uuid"), source_uuid):
            if not directory:
                continue
            base = self.attachments_dir / str(directory)
            if not base.is_dir():
                continue
            candidate = base / file_name
            if file_name and candidate.is_file():
                return candidate
            files = [path for path in sorted(base.iterdir()) if path.is_file()]
            if len(files) == 1:
                return files[0]
        return None

    def _document_item(
        self,
        entry: dict,
        attachment: dict,
        file_name: str,
        document_id: str,
        size: int,
        position: int,
        source_uuid: str,
    ) -> dict:
        """把一个附件做成 1Password 的「文档」条目。

        .1pux 里只有文档条目的 documentAttributes 是明确写进格式说明的，
        所以默认走这条路，导入成功率最高。
        """
        created = normalize_timestamp(entry.get("createdAt")) or 0
        modified = normalize_timestamp(attachment.get("fileModificationDate"))
        return {
            "uuid": one_password_id(f"{source_uuid}:document:{position}"),
            "favIndex": 0,
            "createdAt": created,
            "updatedAt": modified or normalize_timestamp(entry.get("updatedAt")) or created,
            "state": "archived" if entry.get("archived") else "active",
            "categoryUuid": CATEGORY_DOCUMENT,
            "details": {
                "loginFields": [],
                "notesPlain": f"Elpass 附件，来自条目「{entry.get('title') or ''}」",
                "sections": [],
                "passwordHistory": [],
                "documentAttributes": {
                    "fileName": file_name,
                    "documentId": document_id,
                    "decryptedSize": size,
                },
            },
            "overview": {
                "title": file_name,
                "subtitle": str(entry.get("title") or ""),
                "url": "",
                "urls": [],
                "tags": self._tags(entry),
                "icons": None,
                "watchtowerExclusions": None,
                "ps": 0,
                "pbe": 0,
                "pgrng": False,
            },
        }

    def _build_attachment_fields(
        self, entry: dict, uuid: str, source_uuid: str
    ) -> tuple[list[tuple[str, str, dict]], list]:
        """附件本体打进 zip 的 files/ 目录。

        attachments=items 时每个附件另建一个文档条目（格式说明里写明的做法）；
        attachments=inline 时在原条目上加一个 file 字段（1Password 自己的导出这么干，
        但格式说明没写，导入可能不认）。
        返回 (inline 字段, 没处理的附件)，后者原样保留到「Elpass」区块。
        """
        if self.attachments == "skip":
            return [], list(entry.get("attachments") or [])
        attachments = entry.get("attachments") or []
        if not isinstance(attachments, list):
            self.warnings.append(f"{source_uuid}: attachments 不是数组，已原样保留")
            return [], [attachments]

        specs: list[tuple[str, str, dict]] = []
        unresolved: list = []
        for position, attachment in enumerate(attachments):
            if not isinstance(attachment, dict):
                unresolved.append(attachment)
                continue
            for extra in set(attachment) - {
                "fileName",
                "fileSize",
                "fileModificationDate",
                "uuid",
            }:
                self._note_unknown(f"attachments[].{extra}")

            path = self._find_attachment_file(attachment, source_uuid)
            if path is None:
                self.warnings.append(
                    f"{source_uuid}: 找不到附件 {attachment.get('fileName')!r} 的本体，"
                    f"只保留了元信息"
                )
                unresolved.append(attachment)
                continue

            file_name = str(attachment.get("fileName") or path.name)
            document_id = one_password_id(
                f"{source_uuid}:{attachment.get('uuid') or position}"
            ).lower()
            size = path.stat().st_size
            declared = attachment.get("fileSize")
            if declared is not None and int(declared) != size:
                self.warnings.append(
                    f"{source_uuid}: 附件 {file_name} 的实际大小 {size} "
                    f"跟 fileSize {declared} 对不上，按实际大小写入"
                )
            # zip 里的文件名是 documentId + 两个下划线 + 原文件名
            # fileModificationDate 1Password 没地方放，写成 zip 里的文件修改时间
            self.files.append(
                (
                    f"files/{document_id}__{file_name}",
                    path,
                    normalize_timestamp(attachment.get("fileModificationDate"))
                    or int(path.stat().st_mtime),
                )
            )

            if self.attachments == "inline":
                specs.append(
                    (
                        file_name,
                        field_id(f"{uuid}:attachment:{position}"),
                        {
                            "file": {
                                "fileName": file_name,
                                "documentId": document_id,
                                "decryptedSize": size,
                            }
                        },
                    )
                )
            else:
                self.pending_items.append(
                    self._document_item(
                        entry,
                        attachment,
                        file_name,
                        document_id,
                        size,
                        position,
                        source_uuid,
                    )
                )
        return specs, unresolved

    def _dict_like_fields(
        self, raw: dict, key: str, uuid: str, category: str
    ) -> list[tuple[str, str, dict]]:
        """otherFields 这种 {键: 值} 形状的对象，目前只在银行卡上见过。

        能对上 1Password 银行卡模板的键，在银行卡条目里交给卡片自己的区块；
        其它键按普通文本字段导入，并在结束时列出来提醒。
        """
        specs: list[tuple[str, str, dict]] = []
        for name, value in raw.items():
            if value in (None, ""):
                continue
            mapped = OTHER_FIELD_TO_1PASSWORD.get(name)
            if mapped and category == CATEGORY_CREDIT_CARD:
                continue  # 由「Contact Information」区块处理
            if not mapped:
                label = f"{key}.{name}"
                self.unmapped_other_fields[label] = (
                    self.unmapped_other_fields.get(label, 0) + 1
                )
            specs.append(
                (
                    mapped[0] if mapped else name,
                    field_id(f"{uuid}:{key}:{name}"),
                    {"string": scalar_to_text(value)},
                )
            )
        return specs

    def _custom_like_fields(
        self, entry: dict, key: str, uuid: str, category: str
    ) -> list[tuple[str, str, dict]] | None:
        """customFields / otherFields 里的字段。

        customFields 是 [{title, value, sensitive}] 的数组，
        otherFields 是 {键: 值} 的对象，两种都认。
        形状对不上就返回 None，让调用方把原始内容塞进「Elpass」区块，别丢数据。
        """
        raw = entry.get(key)
        if not raw:
            return []
        if isinstance(raw, dict):
            return self._dict_like_fields(raw, key, uuid, category)
        if not isinstance(raw, list):
            self.warnings.append(f"{entry.get('uuid')}: {key} 不是数组，已原样保留")
            return None

        specs: list[tuple[str, str, dict]] = []
        for position, item in enumerate(raw):
            # 只要认得出是「字段」就照常转，value 缺失当空值处理
            if not isinstance(item, dict) or not (
                {"title", "name", "value", "sensitive"} & set(item)
            ):
                self.warnings.append(
                    f"{entry.get('uuid')}: {key}[{position}] 的形状不认识，"
                    f"整个 {key} 已原样保留"
                )
                return None
            for extra in set(item) - {"title", "name", "value", "sensitive"}:
                self._note_unknown(f"{key}[].{extra}")
            title = item.get("title") or item.get("name") or ""
            text = scalar_to_text(item.get("value"))
            value = {"concealed": text} if item.get("sensitive") else {"string": text}
            specs.append((title, field_id(f"{uuid}:{key}:{position}"), value))
        return specs

    def _build_main_section(
        self, entry: dict, uuid: str, source_uuid: str, category: str
    ) -> tuple[dict | None, dict]:
        """otpURL / pin / 证件 / customFields / otherFields / 附件放在一个无标题区块里。

        返回 (区块, 处理不了只能原样保留的属性)。
        """
        fields: list[dict] = []
        unhandled: dict[str, Any] = {}

        def add(title: str, ident: str, value: dict, guarded: bool = False) -> None:
            fields.append(make_field(title, value, ident, guarded))

        otp_url = entry.get("otpURL")
        if otp_url:
            # TOTP 字段的 id 必须是 TOTP_ 前缀，1Password 靠这个认出一次性密码
            add(
                "one-time password",
                "TOTP_" + field_id(f"{uuid}:otp"),
                {"totp": str(otp_url)},
            )

        # 银行卡的 pin / 证件另有自己的区块，这里只管其它分类
        if category != CATEGORY_CREDIT_CARD:
            for title, ident, value, guarded in self._extra_content_fields(
                entry, uuid, category
            ):
                add(title, ident, value, guarded)

        for key in ("customFields", "otherFields"):
            specs = self._custom_like_fields(entry, key, uuid, category)
            if specs is None:
                unhandled[key] = entry.get(key)
                continue
            for title, ident, value in specs:
                add(title, ident, value)

        attachment_specs, unresolved = self._build_attachment_fields(
            entry, uuid, source_uuid
        )
        for title, ident, value in attachment_specs:
            add(title, ident, value)
        if unresolved:
            unhandled["attachments"] = unresolved

        if not fields:
            return None, unhandled
        return {
            "title": "",
            "name": "add more",
            "fields": fields,
        }, unhandled

    def _build_password_history(self, entry: dict) -> list[dict]:
        """Elpass 的 passwordHistories -> 1Password 的 details.passwordHistory。

        Elpass 的 voidDateTimestamp 是「这个密码作废的时间」，
        1Password 的 time 语义一致，直接对应。
        """
        histories = entry.get("passwordHistories") or []
        if not isinstance(histories, list):
            self.warnings.append(f"{entry.get('uuid')}: passwordHistories 不是数组，已跳过")
            return []

        result = []
        for position, history in enumerate(histories):
            if not isinstance(history, dict):
                self.warnings.append(
                    f"{entry.get('uuid')}: passwordHistories[{position}] 不是对象，已跳过"
                )
                continue
            for key in set(history) - {"value", "voidDateTimestamp"}:
                self._note_unknown(f"passwordHistories[].{key}")
            value = history.get("value")
            if value is None:
                continue
            result.append(
                {
                    "value": str(value),
                    "time": normalize_timestamp(history.get("voidDateTimestamp")) or 0,
                }
            )
        result.sort(key=lambda item: item["time"])
        return result

    def _build_card_section(self, entry: dict, uuid: str) -> dict | None:
        """银行卡分类的预置字段，字段 id 必须用 1Password 的固定名字才会被认出来。"""
        fields: list[dict] = []

        def add(title: str, ident: str, value: dict, guarded: bool = False) -> None:
            fields.append(make_field(title, value, ident, guarded))

        holder = (
            entry.get("cardHolder")
            or entry.get("cardholderName")
            or entry.get("username")
        )
        if holder:
            add("cardholder name", "cardholder", {"string": str(holder)}, True)

        brand = entry.get("cardBrand")
        if brand:
            key = str(brand).strip().lower()
            mapped = CARD_BRAND_TO_1PASSWORD.get(key)
            if mapped is None:
                mapped = key.replace(" ", "")
                self.warnings.append(
                    f"{entry.get('uuid')}: 不认识的 cardBrand={brand!r}，"
                    f"原样写成 {mapped!r}，1Password 里可能显示为空"
                )
            add("type", "type", {"creditCardType": mapped}, True)

        number = entry.get("cardNumber")
        if number:
            add("number", "ccnum", {"creditCardNumber": str(number)}, True)

        cvv = entry.get("cardVerificationCode")
        if cvv:
            add("verification number", "cvv", {"concealed": str(cvv)}, True)

        year = entry.get("cardExpiryDateYear")
        month = entry.get("cardExpiryDateMonth")
        if year and month:
            try:
                add("expiry date", "expiry", {"monthYear": int(year) * 100 + int(month)}, True)
            except (TypeError, ValueError):
                self.warnings.append(
                    f"{entry.get('uuid')}: 有效期解析失败（{year!r}/{month!r}），已跳过"
                )
        elif year or month:
            self.warnings.append(
                f"{entry.get('uuid')}: 有效期只有年或只有月，1Password 需要两者，已跳过"
            )

        if not fields:
            return None
        return {
            "title": "",
            "name": "Section_" + field_id(f"{uuid}:card"),
            "fields": fields,
        }

    def _build_elpass_section(
        self, entry: dict, uuid: str, unhandled: dict | None = None
    ) -> dict | None:
        """1Password 没有对应位置的属性，原样保留。"""
        if self.unmapped == "none":
            return None

        fields: list[dict] = []
        index = 0

        def add(title: str, raw: Any) -> None:
            nonlocal index
            fields.append(
                make_field(
                    title,
                    {"string": scalar_to_text(raw)},
                    field_id(f"{uuid}:elpass:{title}"),
                )
            )
            index += 1

        # 1Password 导入时有可能把创建/修改时间重置成导入时刻，
        # 所以这里再存一份可读的原始时间，信息不至于丢掉。
        for key in ("createdAt", "updatedAt"):
            timestamp = normalize_timestamp(entry.get(key))
            if timestamp is not None:
                add(key, format_timestamp(timestamp))

        for key, default in UNMAPPED_KEYS:
            if key not in entry:
                continue
            value = entry[key]
            if self.unmapped == "auto" and value == default:
                continue  # 默认值没有保留价值
            add(key, value)

        # 形状不认识、以及附件这种转不过去的，原始内容原样保留
        for key, raw in (unhandled or {}).items():
            add(key, raw)

        # 脚本没见过的属性一律保留，避免丢数据
        for key in sorted(set(entry) - KNOWN_KEYS):
            self._note_unknown(key)
            add(key, entry[key])

        if not fields:
            return None
        return {
            "title": "Elpass",
            "name": "Section_" + field_id(f"{uuid}:elpass"),
            "fields": fields,
        }

    def _note_unknown(self, key: str) -> None:
        self.unknown_keys[key] = self.unknown_keys.get(key, 0) + 1

    # -- 条目 ---------------------------------------------------------------

    def convert_item(self, entry: dict, position: int) -> dict | None:
        if not isinstance(entry, dict):
            self.warnings.append(f"第 {position} 条不是对象，已跳过")
            return None

        if self.skip_archived and entry.get("archived"):
            self.skipped += 1
            return None

        source_uuid = str(entry.get("uuid") or f"elpass-item-{position}")
        uuid = one_password_id(source_uuid)

        raw_type = str(entry.get("_type") or "login").lower()
        if raw_type == "identification":
            category = self._identification_category(entry)
        else:
            category = TYPE_TO_CATEGORY.get(raw_type)
        if category is None:
            category = CATEGORY_LOGIN if entry.get("password") else CATEGORY_SECURE_NOTE
            self.warnings.append(
                f"{source_uuid}: 未知的 _type={entry.get('_type')!r}，按 {category} 处理"
            )

        username = entry.get("username")
        password = entry.get("password")

        details: dict[str, Any] = {
            "loginFields": [],
            "notesPlain": entry.get("notes") or "",
            "sections": [],
            "passwordHistory": self._build_password_history(entry),
        }

        if category == CATEGORY_LOGIN:
            if username:
                details["loginFields"].append(
                    {
                        "value": str(username),
                        "id": "",
                        "name": "username",
                        "fieldType": "T",
                        "designation": "username",
                    }
                )
            if password:
                details["loginFields"].append(
                    {
                        "value": str(password),
                        "id": "",
                        "name": "password",
                        "fieldType": "P",
                        "designation": "password",
                    }
                )
        elif category == CATEGORY_PASSWORD:
            if password:
                details["password"] = str(password)
            if username:
                details["sections"].append(
                    {
                        "title": "",
                        "name": "Section_" + field_id(f"{uuid}:credential"),
                        "fields": [
                            make_field(
                                "username",
                                {"string": str(username)},
                                field_id(f"{uuid}:username"),
                            )
                        ],
                    }
                )
        else:
            if category == CATEGORY_CREDIT_CARD:
                card_section = self._build_card_section(entry, uuid)
                if card_section:
                    details["sections"].append(card_section)

                # otherFields 里能对上银行卡模板的键，放进「Contact Information」
                other_fields = entry.get("otherFields")
                contact_fields = []
                if isinstance(other_fields, dict):
                    for name, (title, built_in_id) in OTHER_FIELD_TO_1PASSWORD.items():
                        value = other_fields.get(name)
                        if value in (None, ""):
                            continue
                        contact_fields.append(
                            make_field(
                                title,
                                {"string": scalar_to_text(value)},
                                built_in_id,
                                True,
                            )
                        )
                if contact_fields:
                    details["sections"].append(
                        {
                            "title": "Contact Information",
                            "name": "contactInfo",
                            "fields": contact_fields,
                        }
                    )

                # PIN / 证件放进 1Password 银行卡模板自带的「Additional Details」
                extras = self._extra_content_fields(entry, uuid, category)
                if extras:
                    details["sections"].append(
                        {
                            "title": "Additional Details",
                            "name": "details",
                            "fields": [
                                make_field(title, value, extra_id, guarded)
                                for title, extra_id, value, guarded in extras
                            ],
                        }
                    )
                if username:
                    username = None  # 已经当持卡人写进去了，别再重复一遍

            # 其它分类没有 loginFields，用户名密码落到区块字段
            credential_fields = []
            if username:
                credential_fields.append(
                    make_field(
                        "username",
                        {"string": str(username)},
                        field_id(f"{uuid}:username"),
                    )
                )
            if password:
                credential_fields.append(
                    make_field(
                        "password",
                        {"concealed": str(password)},
                        field_id(f"{uuid}:password"),
                    )
                )
            if credential_fields:
                details["sections"].append(
                    {
                        "title": "",
                        "name": "Section_" + field_id(f"{uuid}:credential"),
                        "fields": credential_fields,
                    }
                )

        main_section, unhandled = self._build_main_section(
            entry, uuid, source_uuid, category
        )
        if main_section:
            details["sections"].append(main_section)

        elpass_section = self._build_elpass_section(entry, uuid, unhandled)
        if elpass_section:
            details["sections"].append(elpass_section)

        domains = entry.get("domains") or []
        if isinstance(domains, str):
            domains = [domains]
        urls = [to_url(domain) for domain in domains if str(domain).strip()]

        overview: dict[str, Any] = {
            "title": entry.get("title") or "",
            "subtitle": str(username) if username else "",
            "url": urls[0] if urls else "",
            "urls": [
                {"label": "website", "url": url, "mode": "default"} for url in urls
            ],
            "tags": self._tags(entry),
            "icons": None,
            "watchtowerExclusions": None,
            "ps": 0,
            "pbe": 0,
            "pgrng": False,
        }

        item: dict[str, Any] = {
            "uuid": uuid,
            "favIndex": int(entry.get("favIdx") or 0),
            "createdAt": normalize_timestamp(entry.get("createdAt")) or 0,
            "updatedAt": normalize_timestamp(entry.get("updatedAt"))
            or normalize_timestamp(entry.get("createdAt"))
            or 0,
            "state": "archived" if entry.get("archived") else "active",
            "categoryUuid": category,
            "details": details,
            "overview": overview,
        }
        return item

    # -- 顶层 ---------------------------------------------------------------

    def convert(
        self,
        entries: list,
        account_name: str,
        email: str,
        vault_name: str,
    ) -> dict:
        items = []
        for position, entry in enumerate(entries):
            item = self.convert_item(entry, position)
            if item is not None:
                items.append(item)
        # 附件建出来的文档条目排在后面
        items.extend(self.pending_items)

        return {
            "accounts": [
                {
                    "attrs": {
                        "accountName": account_name,
                        "name": account_name,
                        "avatar": "",
                        "email": email,
                        "uuid": one_password_id("elpass-account"),
                        "domain": "https://my.1password.com/",
                    },
                    "vaults": [
                        {
                            "attrs": {
                                "uuid": one_password_id("elpass-vault"),
                                "desc": "Imported from Elpass",
                                "name": vault_name,
                                "type": "P",
                            },
                            "items": items,
                        }
                    ],
                }
            ]
        }


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------


def load_entries(path: Path) -> list:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("items", "data", "records", "entries"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    raise SystemExit(f"无法识别的输入格式：{type(data).__name__}")


def find_attachments_dir(source: Path) -> Path | None:
    """附件目录：优先「输入文件全名 + .attachments」，其次换掉后缀的写法。"""
    for candidate in (
        Path(str(source) + ".attachments"),
        source.with_suffix(".attachments"),
    ):
        if candidate.is_dir():
            return candidate
    return None


def write_1pux(
    export_data: dict, output: Path, files: list[tuple[str, Path, int]] | None = None
) -> None:
    # 键名跟 1Password 自己的导出对齐：timestamp，Unix 秒
    attributes = {
        "version": 3,
        "description": "1Password Unencrypted Export",
        "timestamp": int(datetime.now(timezone.utc).timestamp()),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("export.attributes", json.dumps(attributes, ensure_ascii=False))
        archive.writestr(
            "export.data", json.dumps(export_data, ensure_ascii=False, indent=2)
        )
        for arcname, path, modified_at in files or []:
            info = zipfile.ZipInfo(
                arcname, datetime.fromtimestamp(modified_at).timetuple()[:6]
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="把 Elpass 导出的 JSON 转成 1Password 的 .1pux 文件",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("input", nargs="?", type=Path, help="Elpass 导出的文件（.elpassexport，内容是 JSON）")
    parser.add_argument(
        "-o", "--output", type=Path, help="输出的 .1pux 路径，默认与输入同名"
    )
    parser.add_argument("--vault-name", default="Elpass", help="保险库名字，默认 Elpass")
    parser.add_argument(
        "--account-name", default="Elpass Import", help="账号名字，默认 Elpass Import"
    )
    parser.add_argument("--email", default="", help="账号邮箱，可留空")
    parser.add_argument(
        "--unmapped",
        choices=("auto", "all", "none"),
        default="auto",
        help="1Password 没有对应字段的属性怎么处理："
        "auto 只保留非默认值（默认），all 全部保留，none 丢弃",
    )
    parser.add_argument(
        "--skip-archived",
        action="store_true",
        help="不导出 archived=true 的条目（默认是导出成 state=archived，进 1Password 的归档）",
    )
    parser.add_argument(
        "--import-tag",
        default="elpass",
        help="给每个导入的条目加的标签，默认 elpass，传空字符串则不加",
    )
    parser.add_argument(
        "--attachments",
        choices=("inline", "items", "skip"),
        default="inline",
        help="附件怎么导：inline 挂在原条目上（默认，跟 1Password 自己的导出一致）；"
        "items 每个附件单独建一个文档条目；skip 只留元信息",
    )
    parser.add_argument(
        "--attachments-dir",
        type=Path,
        help="附件目录，默认找「输入文件名 + .attachments」",
    )
    parser.add_argument(
        "--dump-json", type=Path, help="额外把 export.data 写一份到这个路径，方便检查"
    )
    parser.add_argument(
        "--show-mapping", action="store_true", help="打印字段映射表后退出"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.show_mapping:
        print(MAPPING_DOC)
        return 0

    if args.input is None:
        parser.error("需要指定输入文件（或用 --show-mapping 查看映射表）")

    entries = load_entries(args.input)
    attachments_dir = args.attachments_dir or find_attachments_dir(args.input)
    converter = Converter(
        unmapped=args.unmapped,
        skip_archived=args.skip_archived,
        attachments_dir=attachments_dir,
        import_tag=args.import_tag,
        attachments=args.attachments,
    )
    export_data = converter.convert(
        entries,
        account_name=args.account_name,
        email=args.email,
        vault_name=args.vault_name,
    )

    output = args.output or args.input.with_suffix(".1pux")
    write_1pux(export_data, output, converter.files)

    if args.dump_json:
        args.dump_json.parent.mkdir(parents=True, exist_ok=True)
        args.dump_json.write_text(
            json.dumps(export_data, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    item_count = len(export_data["accounts"][0]["vaults"][0]["items"])
    print(f"读取 {len(entries)} 条，写出 {item_count} 条 -> {output}")
    if converter.files:
        print(f"打包附件 {len(converter.files)} 个")
    elif attachments_dir is None and any(entry.get("attachments") for entry in entries if isinstance(entry, dict)):
        print("有条目带附件，但没找到附件目录，只保留了元信息", file=sys.stderr)
    if converter.skipped:
        print(f"跳过 archived 条目 {converter.skipped} 条")
    for warning in converter.warnings:
        print(f"警告：{warning}", file=sys.stderr)
    if converter.unmapped_other_fields:
        print("otherFields 里下面这些键没有专门映射，按普通文本字段导入：", file=sys.stderr)
        for key, count in sorted(converter.unmapped_other_fields.items()):
            print(f"  {key}（{count} 次）", file=sys.stderr)
    if converter.unknown_keys:
        print("下面这些属性脚本没有专门处理，已原样放进「Elpass」区块：", file=sys.stderr)
        for key, count in sorted(converter.unknown_keys.items()):
            print(f"  {key}（{count} 次）", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
