"""Frozen original SPOP fixtures and independent finite-sample predictions.

Preparation is source-based. Constructed NOTIFY packets are component fixtures,
never observations of HAProxy; only the private host observer supplies those.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import stat
from pathlib import Path
import struct

from connector_suite.adapters.haproxy.harness.i12_spop_wire import Reader, InvalidFrame, decode_frame, MAX_FRAME
from connector_suite.adapters.haproxy.harness.i12_oracle_fixture import source_hash_map

LEG = "haproxy-spop-request"
PREFIX = "I12::" + LEG + "::"
SCHEMA = "i12-spop-original-source-fixture-v1"
ORIGINAL_IDS_SHA256 = "bb34ce6c26063b1c13df6087b0a3cc5034f227216720aeaca2f195fba38b33d1"
ORIGINAL_CONTRACTS_SHA256 = "f4ca4e4b97cf3cf5dd267684afdfa39a8fd5b9e8b88b71bf6470cb184ce7ea3b"
REQUEST_MARKER = b"no-crs-request-body-marker"
BACKEND_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nBACKEND"
REQUEST_BODY_FETCH = "req.body"
REQUEST_BODY_SIZE_FETCH = "req.body_size"
PARTIAL_BODY_FETCH = "req.body,bytes(0,4)"
MISMATCHED_BODY_SIZE_FETCH = "int(99)"
CONFIG_NAMES = ("valid_rules_file", "missing_rules_file", "unsafe_event_path")
ORIGINAL_HASHES = {'HIST-SPOP-FIRST-CAUSE-SINK-FAILURE': '3da69f02d20fb781a5aa9fddc27cd246e5d259f650ca92e6b18497f73c1fec06',
 'NEED-503-error': 'f6fc9806759850fbf76e098a605ee024d3fc5664abf1c6495d3472fa3ebd7102',
 'NEED-abort-reset-observation': '0d12460bac9d5315b8634a98c5ecaa00c1837ad32cf7c32a709e8e7d2b05b33c',
 'NEED-ack-success': '8dc727e6a969383b518a64046546d2f439739a7ad6f19e7f1e3d8002d8d5332d',
 'NEED-budget-postcommit': '77bc8e9c94c97f93b4e5c6fcd61e330ef58a4611335136e50d1da98aef6f3de2',
 'NEED-budget-precommit': 'caa5115daf23f6f009bfd16ed69c86e89b7af4893105a57e4b2944700ee360d6',
 'NEED-cancel': 'dfc59a29e7b953fe9c66c7bf4210a02983497dde2a855793cc53f363310a06a9',
 'NEED-client-exit-signal': '79086646d87c6bef3ecffb4fe76af359e2980ac7a0d9af53d0b145d6ab93ad64',
 'NEED-client-response-bytes': '6ece5618dcfdc3d1bc35f92725c3ffa86a9041e562fde0e27ccfc1ce1a705549',
 'NEED-complete-sample': '8a305fb4959399b35f476fc0423334323a160f0872840a2a81696f276194cffb',
 'NEED-connection-reuse': 'a3669b1b076d54e696474158ad702824924bfeebda79abd4d72f97777dad1c4b',
 'NEED-first-byte-before-late-error': 'd6a24ad3fd622bbe8eaa62c82440bd4d2b8543d7902bbdc48fb8b8d4c58fb910',
 'NEED-first-error': '372a9a0545c68edd1e79be4a5293452ab3c91feef0d2d8623d330142488adea2',
 'NEED-frame-boundary-not-engine-limit': '811ebe4863ad9e9a5e0c0a4db962e6b6046b6a7615bfa6ec175a9388d0339bb8',
 'NEED-incomplete-framing': '6998d703f9124c61fa30ccb38d23b93f88fc28377bb85802488360f2882482ea',
 'NEED-incomplete-sample': 'd350510cef722c7a96aff8e5d2247b42b17e8ea99c22c6779de19de546115061',
 'NEED-invalid-metadata': '9eaa549a03ee7eff6bbfea350daf677967a7adcb795c4ea941c1f9741d91cc4c',
 'NEED-invalid-native-return': 'd2b3a5b8bc67673d2e24a5eb5240df8c758259a0f85cf7b148f7b3cffab945bf',
 'NEED-missing-eos': 'ad0aad4bd6ad04c986799f68bdbed106ae8261e2598f671d9b28bb862181b6b3',
 'NEED-neighbor-connection-stream': '0c763b71c46c00c1e009b2f63b80723466591a97059a25d07da4c263dd01e7f1',
 'NEED-physical-event-sink-close': 'eed774a20e8447defeabcc7b5644fa2bd9e4f9b4beb3d094d59ee275ec481144',
 'NEED-physical-event-sink-flush': '1e2caeb17d68097622ea7533b1e7622d48f3d725df6df2e16503c298ad770a00',
 'NEED-physical-event-sink-open': 'bfbf0a27c0423148d4e2e83492b6f02b0e4a871b876b0891d56f66953585c9ed',
 'NEED-physical-event-sink-short-write': 'b08aa7f41418cfae25eb927edce80c1c6e07b85f6a5553047910583f52942a57',
 'NEED-physical-event-sink-write': 'f7eb0e14d23bcb1d087b35a3d737af24f099273df417aad41a80dce627e8399c',
 'NEED-postcommit-error': '4bf87a713c61a3675640db08340760401831b7ae51dda3cdbd3827af0ac2559f',
 'NEED-precommit-error': '2dd96136c407055365acaf0513d0551f35307afc89684879341c16d81a962671',
 'NEED-request-above-former-connector-limit': '4dabe5024383154fd78304d4cebc85e42950361d932e0a958f8b72590a2f1332',
 'NEED-request-charset-missing': '50b6d586c50befa20b22a41098f5b8689eda85c86ec0db4582a5b6a144972f1b',
 'NEED-request-charset-present': 'fd584e52e3820f205ef28e48eed3fce5d688320b164cab69ef8e9a8bfbd0619b',
 'NEED-request-content-type-missing': '810369504549ab2fca73471450b7cc46eff15be2f7afaee011a724af5c2c5c9a',
 'NEED-request-content-type-present': '80400fcd3f0e78a665d497b1459c3a7a2e82d667bf20b9c0048b1c2082904afc',
 'NEED-request-csv': '873ee47a525a7f32d1069f34603314c826ec869ae0efaac023f2c1432f37797e',
 'NEED-request-empty': '28e6f659d626268d57fb0b824710acd500be416b345d55ba37f329645b93fc5e',
 'NEED-request-eos-once': 'ab9440ddc260fcb34a7332a29bb4abcdd388ca8447def67fcd35398850039406',
 'NEED-request-file': '258aa3d252891153055c0d52442cde44eed0390981528c534c905cf222caec2e',
 'NEED-request-marker-at-payload-end': 'ec687b475bcba60dea04b45a01a78cb88889e71146a1c540a6d3e223c9b9ee1a',
 'NEED-request-mime-scope-in': '429480ec9f4caa204ce8c07e957e31d97a57ea0ad4cd4d118ae3a9bc23b034bf',
 'NEED-request-mime-scope-out': '7b645c50c0826c9ac511ebe399813aee8ad1fc74ad14b140f6358f363e77d6a3',
 'NEED-request-multiple-chunks': 'c2f8b92066db616c705eeecaa6eb9912c0f3a741a223f7f1c19de7402128cac5',
 'NEED-request-single-chunk': 'c502af4043df8892cc8d8adc7c0ceff424c2a0891b521b371e8c71b6a62a16cb',
 'NEED-response-companion-binding': '61de93272775cb9e18ae026c80471be7beb6273fabdd425bbf9dbfe9827081a2',
 'NEED-timeout': '071a7762d8ac482bfbbba0af4f737ea24f29541a0e9cea5c813268d8199c780c',
 'NEED-ttl': 'aa3a7169f74362be416bdc5c43087f70ac55444a92354dc5857458cc571a4c48',
 'allow': '76ca79568571e5c9c256f34e5f54a6b23a642003ef7d01a25e5fdd8ae6023759',
 'allow_without_marker': 'ad845d8fe432f8a69efa041c26840589af809bfe1eab70f69ec92611c00532b5',
 'body_size_nonzero_with_null_data': '163400592ea2e64510834ad14f33187058842433ca0c767a41052132b86a4569',
 'case_insensitive_header_name': 'ff52c19b3e527ec48e2862f23c77ad3a293b750b24f179daaa23c775e5181fea',
 'clean_shutdown': '85799fe92315aad091d81c57182c9b11fb2f58693a29a50d170c8c78700348cc',
 'conflicting_content_length': '3937bb06e20f62832f718354e51def9b739db3865c14d58ab57b976f98714cfb',
 'content_length_overflow': 'faf3539b7648fea8e4dfa9509ba8492515037103b77d89696fc7e708136a2a82',
 'deny': 'e0a73eb4442c7500edad8b9abcf10c85ec29997c8ca51ab4f6ef0e822f0527e9',
 'deny_header_marker_403': '7bb0985b3e431678b9d6cd146763dc42d4241bd13a62ee128114f87e6715b509',
 'deny_request_body_marker_403': '7916e45963023792c8827d1e3b1525186dc0e8a65b20382c05387bf9e4b80d76',
 'deny_with_alternative_status': 'a8475ebb3f35fa7a573ca0aa33184f49022e67dc383b6f0f1e054c138afae692',
 'duplicate_header_names': '1a6e79c033500cc140c9e8e4a5bc0a6b375521af4bcb7d27416350e616b92173',
 'duplicate_transfer_encoding': '106089597d09dbb1c49a8660b2f5e5e037459d38e24e94c65fc18dc4faded400',
 'early_mapping_failure_cleanup': 'd940860e2f5c59f71e6d05f3b4cc3c997dc9737de740d3a42cb10fb6a203de1a',
 'empty_header_value': 'bbc2c62060f7261a16d1fea31c57b3ce18a37c9746d6ac8ba358cba373215daa',
 'event_contains_connector': '5d2487cb7e1887d2841679fbb4cf284a117d2b5347ad8a35141a7951b7e608b9',
 'event_contains_phase': '9774ad07f3d21a574df6e2099466b5bbed9e1b2fba8e776bb6234db4311b0b35',
 'event_contains_rule_id': 'fdc35243044206e0de26280cb85e43847f3a206eda49194afbc83e16a8b5ba5a',
 'event_contains_status': '811828645c2cd34165004d8d3aa981686d90386cb017e91727a19a29fb4850b8',
 'event_contains_transaction_id': 'd45a13718299191e4201043e25830cd5215dc976d7ce80f054cd8d683acf9e1b',
 'event_has_no_request_body_payload': 'd217f8859d320bbaeb65a81dc8568c67d7801b80e0784d88b54899bdd1217ba5',
 'event_json_limit': 'cf7a2c9ca7feb51ad9b9ce080550125d488d222af265b58b2a23059318cf907f',
 'event_metadata_truncation': '4960a9468bd870b1933032f90e441c8a1a9dce05adbbe5c279bd746a464501a6',
 'finish_failure_propagation': 'f14a1fd4c2ccdb5f08e12c5f85c371981ac973edfa4ce5fdd13324db63a0a3b9',
 'header_count_nonzero_with_null_headers': '716be33028022c88685ce0a0c4decedb33d7075def43c60c7f32129382da4bd1',
 'invalid_content_length': '0cd9251d18a573da386d24b69b189afe24a05eabc8bb302ce42d7326c33a4502',
 'keep_alive_requests_if_supported': 'b3056313af43a9888561979eff32d76a69acac855959e1e08dfc5183cc47fb52',
 'keepalive_allow_allow': 'ea2ef8390cfdc867ad88c5e88583c73ac93bc4cc35b931a719778a181916daa0',
 'keepalive_allow_deny_allow': '721895a651c95665194e352600fa3421a5a4a6e18c9a3e9ca0df869fa5bf206c',
 'log_only': '5006c7604b924c4c4280b5d76dbc92433ebf94a0da979756f326c5b90e6cdf05',
 'missing_rules_file': 'feba9932169dedffd6b9e42073cd7b343a4d1486e66755f0537e278a7cced6e6',
 'multiple_headers': 'c0ed2b5b3e2e7f3489f8372bacde89cdaa09f02c3887f04023cd5742b949d031',
 'multiple_sequential_requests': 'ec0ce441200ed8ce0a77e776fe383369b504af52d6bfd45b018c8d6c8b26fef0',
 'phase1_allow': '8670875d8618adcf77d7d26e4aab4fbf5721ccabc8c6530f2c8dcd8f6fe500f7',
 'phase1_alternative_status': '33525c9ac10f044a774cbefd1f00034be7dc9b5f239f822cda7b224f02239964',
 'phase1_deny_403': '063336d4a3db5b87de67b5798a97a2262f83d5aa4d07fa232bb989c926dc7b2a',
 'phase1_redirect': '617f893ea469bdd7d567e2672d630059ab8983315d31a68eab2535683f1c3a82',
 'phase1_transaction_id': '9d41723500e2b5bc54b68e90f0e4ea0d85556ec0ff85ebd66004deac437b0f3a',
 'phase2_at_limit': 'c917de3223889c6a5d9754383adf5894e2c15fe304518f3d9b0b5475c7ddd960',
 'phase2_no_payload_event': '309b291fb5ebcaa663db9f2bbe1102864b3c9d882636d782edb1f2a73c49a9b8',
 'phase2_over_limit': '98f5423f9cf2a019997a8c751429c43956d3211488452b1e323b6099d10f847d',
 'phase2_request_body_rule': '5db50777caeaa6ae7aa9221e45c9abc1f3e858ac5254eb5ed99eb6a6206d7a55',
 'phase2_truncated': 'dc6d179909281fc8dac22047cfe1211045bf665d965a3c07261395703d97c57c',
 'redirect_if_supported': '748bf401660647c501fbe0808b34ec98105b88b23c606b8d2baf1012abcddb4e',
 'single_request_cleanup': 'b375e7fc4bbd7cba33f0098818ef71b5943b1b5b0c68114fd4fb4f4889878012',
 'transaction_begin_failure_cleanup': 'b2f4ed37c7fd16f6bd97970dd1fc74e6dfdda5ab286bfcf24f69cff084f43c12',
 'transaction_id_generated_or_fallback': 'e32479853a8e0cbf32c61f816a9f168984c933e7073f6b27e901edfd4238ba6d',
 'transaction_id_present': '0538e332d6a3c1d7d0bd89889802f56673c833f254b56834a45af1d7c0a24caf',
 'unsafe_event_path': 'acf2964fc47fc3abaa533059ca75338d1b912d1b6748ed61cb2a8e88b7461334',
 'valid_rules_file': 'e22b5021f4cab0ed1300daaee33ec990e6b95c4b0dcbf3c704dab7f1e44fe700'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def original_rows(inventory):
    identities = "\n".join(row["run_scoped_case_id"] for row in inventory["rows"]) + "\n"
    contracts = [row["original_selected_requirement"] for row in inventory["rows"]]
    if hashlib.sha256(identities.encode()).hexdigest() != ORIGINAL_IDS_SHA256 or digest(contracts) != ORIGINAL_CONTRACTS_SHA256:
        raise ValueError("frozen original inventory differs")
    rows = [row for row in inventory["rows"] if row["leg_id"] == LEG]
    if len(rows) != 94 or len({row["run_scoped_case_id"] for row in rows}) != 94:
        raise ValueError("exact94 original SPOP IDs required")
    return rows


def validate_original(selected):
    if selected.get("schema") != SCHEMA:
        raise ValueError("original SPOP fixture schema required")
    contract = selected.get("original_selected_requirement", {})
    name = contract.get("case_id")
    expected = ORIGINAL_HASHES.get(name)
    if expected is None or digest(contract) != expected or selected.get("original_selected_requirement_sha256") != expected:
        raise ValueError("original SPOP contract is not frozen membership")
    case_id = PREFIX + name
    if selected.get("case_id") != case_id or contract.get("run_scoped_case_id") != case_id:
        raise ValueError("exact original SPOP case ID required")
    if selected.get("effective_oracle_sha256") != digest(selected.get("effective_oracle")):
        raise ValueError("effective oracle hash mismatch")
    return case_id


def physical_source(path):
    if not path.is_absolute() or ".." in path.parts or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("absolute physical source file required")
    data = path.read_bytes()
    return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def encode_uint(value):
    if type(value) is not int or not 0 <= value <= (1 << 64) - 1:
        raise ValueError("SPOP unsigned representation requires uint64")
    if value < 240:
        return bytes((value,))
    encoded = bytearray(((value & 255) | 240,))
    value = (value - 240) >> 4
    while value >= 128:
        encoded.append((value & 255) | 128)
        value = (value - 128) >> 7
    encoded.append(value)
    return bytes(encoded)


def encode_blob(value):
    return encode_uint(len(value)) + value


def encode_typed(tag, value):
    if tag in (2, 3, 4, 5):
        payload = encode_uint(value)
    elif tag in (8, 9):
        payload = encode_blob(value.encode() if tag == 8 else value)
    elif tag in (6, 7):
        address = ipaddress.ip_address(value)
        if address.version != (4 if tag == 6 else 6):
            raise ValueError("SPOP IP tag and address family disagree")
        payload = address.packed
    elif tag in (0, 1, 17):
        payload = b""
    else:
        raise ValueError("unsupported fixture type")
    return bytes((tag,)) + payload


def encode_notify(arguments, stream=1, frame=1):
    if len(arguments) > 255 or stream < 1 or frame < 1:
        raise ValueError("bounded nonzero SPOP request identifiers required")
    message = encode_blob(b"check-request") + bytes((len(arguments),))
    for name, tag, value in arguments:
        message += encode_blob(name.encode()) + encode_typed(tag, value)
    payload = bytes((3,)) + struct.pack("!I", 1) + encode_uint(stream) + encode_uint(frame) + message
    return struct.pack("!I", len(payload)) + payload


def encode_headers(headers):
    return b"".join(encode_blob(name.encode()) + encode_blob(value.encode()) for name, value in headers) + b"\x00\x00"


def decode_headers(data):
    reader = Reader(data)
    headers = []
    while reader.pos < len(reader.data):
        name, value = reader.blob(), reader.blob()
        if not name and not value:
            if reader.pos != len(reader.data):
                raise InvalidFrame("trailing binary header bytes")
            return headers
        if not name:
            raise InvalidFrame("empty header name")
        headers.append((name.decode("ascii"), value.decode("latin-1")))
    raise InvalidFrame("missing binary header terminator")


def argument_bytes(argument):
    if argument.get("tag") == 9:
        return bytes.fromhex(argument["value"])
    if argument.get("tag") == 8:
        return argument["value"].encode()
    raise InvalidFrame("concrete string or binary value required")


def sample_arguments(arguments):
    grouped = {}
    for argument in arguments:
        grouped.setdefault(argument["name"], []).append(argument)
    required = ("request_id", "client_ip", "client_port", "server_ip", "server_port", "method", "path", "uri", "host", "body", "body_len", "http_version")
    missing = [name for name in required if name not in grouped]
    duplicates = [name for name, values in grouped.items() if len(values) != 1]
    if missing or duplicates:
        raise InvalidFrame("missing or duplicate metadata: " + repr((missing, duplicates)))
    return {name: values[0] for name, values in grouped.items()}


def sample_headers(arguments):
    if "headers_bin" in arguments:
        binary = decode_headers(argument_bytes(arguments["headers_bin"]))
        if "headers" in arguments:
            text = sample_headers({"headers": arguments["headers"]})
            normalized = lambda rows: [(name.lower(), value.strip()) for name, value in rows]
            if normalized(binary) != normalized(text):
                raise InvalidFrame("binary and text headers disagree")
        return binary
    if "headers" not in arguments:
        raise InvalidFrame("header block missing")
    text = argument_bytes(arguments["headers"])
    if not text.endswith(b"\r\n\r\n"):
        raise InvalidFrame("text header terminator missing")
    rows = []
    for line in text[:-4].split(b"\r\n"):
        name, value = line.split(b":", 1)
        rows.append((name.decode("ascii"), value.strip().decode("latin-1")))
    return rows


def framing_predicate(headers, body, advertised, version):
    lengths = [value for name, value in headers if name.lower() == "content-length"]
    transfer = [value for name, value in headers if name.lower() == "transfer-encoding"]
    if transfer:
        return False, "transfer-encoding has no trusted SPOP EOM"
    if len(lengths) > 1:
        return False, "ambiguous content-length"
    if lengths and (not lengths[0].isascii() or not lengths[0].isdigit() or len(lengths[0]) > 10):
        return False, "invalid content-length"
    declared = int(lengths[0]) if lengths else 0
    known_end = bool(lengths) or (not body and version in ("1.0", "1.1"))
    complete = known_end and declared == len(body) == advertised
    return complete, None if complete else "unknown or incomplete finite body sample"


def inspect_sample(arguments):
    result = {"metadata_complete": False, "finite_sample_complete": False, "fully_inspected_http2": False,
              "native_lifecycle_proven": False, "reason": None}
    try:
        return inspect_concrete_sample(sample_arguments(arguments), result)
    except (ValueError, KeyError, TypeError) as error:
        result["reason"] = str(error)
        return result


def inspect_concrete_sample(arguments, result):
    body = argument_bytes(arguments["body"])
    length = arguments["body_len"]
    version = arguments["http_version"]
    if length.get("tag") not in (2, 3, 4, 5) or type(length.get("value")) is not int or not 0 <= length["value"] <= (1 << 32) - 1:
        raise InvalidFrame("req.body_size must be a representable integer sample")
    if length["tag"] == 2 and length["value"] > (1 << 31) - 1:
        raise InvalidFrame("signed INT32 length exceeds its representation")
    if version.get("tag") != 8 or version.get("value") not in ("1.0", "1.1", "2.0"):
        raise InvalidFrame("unrecognized HTTP version metadata")
    validate_endpoint_metadata(arguments)
    headers = sample_headers(arguments)
    complete, reason = framing_predicate(headers, body, length["value"], version["value"])
    result.update(metadata_complete=True, finite_sample_complete=complete, reason=reason,
                  advertised_body_size=length["value"], advertised_body_size_tag=length["tag"],
                  body_sample_bytes=len(body), body_sample_sha256=hashlib.sha256(body).hexdigest(),
                  http_version=version["value"], http_version_tag=version["tag"], headers=headers)
    return result


def validate_endpoint_metadata(arguments):
    for name in ("request_id", "method", "path", "uri", "host"):
        value = arguments[name]
        if value.get("tag") != 8 or not value.get("value") or "\x00" in value["value"]:
            raise InvalidFrame("missing concrete metadata: " + name)
    for name in ("client_ip", "server_ip"):
        validate_endpoint_ip(name, arguments[name])
    for name in ("client_port", "server_port"):
        validate_endpoint_port(name, arguments[name])


def validate_endpoint_ip(name, value):
    if value.get("tag") not in (6, 7) or not isinstance(value.get("value"), str):
        raise InvalidFrame("endpoint requires actual typed IPv4 or IPv6: " + name)
    address = ipaddress.ip_address(value["value"])
    if address.version != (4 if value["tag"] == 6 else 6):
        raise InvalidFrame("endpoint address family and tag disagree: " + name)


def validate_endpoint_port(name, value):
    if value.get("tag") not in (2, 3, 4, 5) or type(value.get("value")) is not int or not 0 <= value["value"] <= 65535:
        raise InvalidFrame("invalid endpoint port: " + name)


def request_headers(document):
    headers = document.get("headers", [])
    return list(headers.items()) if isinstance(headers, dict) else [(row["name"], str(row["value"])) for row in headers]


def resolve_request(name, catalog, seen=()):
    if name in seen or len(seen) > 64:
        raise ValueError("bounded canonical request reuse required")
    request = copy.deepcopy(catalog[name]["request"])
    reused = request.pop("reuses", None)
    if reused is not None:
        base = resolve_request(reused, catalog, (*seen, name))
        base.update(request)
        return base
    return request


def source_document(name, request, catalog, directory):
    import yaml  # Preparation only; the private host needs standard library only.
    relative = request.get("fixture") or catalog[name].get("runner_case")
    if relative is None:
        return {}, None
    path = directory / relative
    reference = physical_source(path)
    return yaml.safe_load(path.read_text()), reference


def supplemental_rules(document):
    lines = document.get("rules", "").splitlines(keepends=True)
    first = next((index for index, line in enumerate(lines) if line.startswith(("SecRule ", "SecAction "))), len(lines))
    return "".join(lines[first:])


def canonical_request(name, catalog, directory):
    request = resolve_request(name, catalog)
    document, reference = source_document(name, request, catalog, directory)
    merged = copy.deepcopy(document.get("request", {}))
    merged.update(request)
    return merged, document, reference


NATIVE_FAULTS = {
    "body_size_nonzero_with_null_data": "actual native caller body pointer NULL with positive length; a SPOP NULL typed value is a different protocol failure",
    "header_count_nonzero_with_null_headers": "actual native caller header pointer NULL with positive count; not an HTTP header omission",
    "early_mapping_failure_cleanup": "native mapping boundary fault before transaction allocation",
    "transaction_begin_failure_cleanup": "native transaction allocation failure with actual fail-closed ACK and client effect",
    "finish_failure_propagation": "checked authorization finish primitive failure before ACK publication",
    "NEED-invalid-native-return": "controlled nonzero native API return at a named actual request phase",
    "event_metadata_truncation": "actual checked Common sink serialization at an explicit source-bound metadata limit",
    "event_json_limit": "actual checked Common sink JSON serialization at explicit configured boundary",
    "NEED-physical-event-sink-open": "actual secure sink open failure before agent admission",
    "NEED-physical-event-sink-write": "actual fputs/ferror failure on configured physical sink",
    "NEED-physical-event-sink-short-write": "actual short sink write or partial buffered serialization observed physically",
    "NEED-physical-event-sink-flush": "actual fflush failure on configured physical sink",
    "NEED-physical-event-sink-close": "actual fclose failure and nonzero terminal process result",
    "HIST-SPOP-FIRST-CAUSE-SINK-FAILURE": "historical physical sink fault with first error retained through fail-closed publication and cleanup",
    "NEED-request-file": "source decision whether HTTP file-sourced bytes or the native file API is the original contract",
    "NEED-request-above-former-connector-limit": "source-bound former connector threshold; distinguish finite frame rejection from native body-limit inspection",
    "NEED-postcommit-error": "concrete error after HTTP response commitment; authorization-only scope has already released normal native transaction",
    "NEED-budget-postcommit": "concrete budget cause after commitment without inventing response streaming inspection",
    "NEED-first-byte-before-late-error": "client receipt barrier and actual late cause; request authorization alone supplies no response callback",
    "NEED-first-error": "ordered pair of real faults with physical retained first error rather than final errno projection",
    "NEED-timeout": "source-bound timeout kind plus bounded real trigger; native deadline is not SPOP transport timeout",
    "NEED-cancel": "actual client cancel before sample admission with measured native lifetime and terminal transport",
    "NEED-abort-reset-observation": "actual transport reset measurement and unaffected neighbor, not merely socket.close()",
}


RAW_REQUESTS = {
    "invalid_content_length": b"Content-Length: invalid\r\n",
    "conflicting_content_length": b"Content-Length: 1\r\nContent-Length: 2\r\n",
    "duplicate_transfer_encoding": b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
    "content_length_overflow": b"Content-Length: 18446744073709551616\r\n",
}


def wire_http(method, path, headers, body, version="1.1"):
    if version not in ("1.0", "1.1") or "\r" in path or "\n" in path:
        raise ValueError("bounded HTTP1 request target/version required")
    supplied = {name.lower() for name, _value in headers}
    fields = [("Host", "localhost"), ("Connection", "close")]
    if "content-length" not in supplied and "transfer-encoding" not in supplied:
        fields.append(("Content-Length", str(len(body))))
    fields.extend(headers)
    start = f"{method} {path} HTTP/{version}\r\n"
    return (start + "".join(name + ": " + value + "\r\n" for name, value in fields) + "\r\n").encode() + body


def ordinary_profile(name):
    return {"case": name, "http2": False, "request_method": "POST", "request_path": "/i12/" + name,
            "request_body_hex": b"abcdefgh".hex(), "request_headers": [("Content-Type", "text/plain")],
            "request_version": "1.1", "body_fetch": REQUEST_BODY_FETCH, "body_size_fetch": REQUEST_BODY_SIZE_FETCH,
            "version_fetch": "req.ver", "sample_mutation": None, "request_chunk_sizes": [],
            "native_request_limit": 1048576, "native_request_limit_action": "Reject",
            "with_companion": False, "companion_export_only": False, "settle_seconds": .2,
            "required_mechanisms": [NATIVE_FAULTS[name]] if name in NATIVE_FAULTS else []}


def apply_limit_variant(profile, request, document):
    variant = request.get("limit_variant")
    if variant is None:
        return
    lifecycle = document.get("full_lifecycle", {})
    limit = lifecycle["limit_bytes"]
    count = lifecycle["variants"][variant]
    source = bytes.fromhex(profile["request_body_hex"])
    body = source[:count] if len(source) >= count else source + b"x" * (count - len(source))
    profile.update(request_body_hex=body.hex(), native_request_limit=limit,
                   native_request_limit_action="ProcessPartial" if variant == "process_partial" else "Reject")


def canonical_sequence(value):
    if isinstance(value, list):
        return [name for name in value if name != "shutdown"], False
    if value == "keep_alive_allow_deny_allow":
        return ["allow_without_marker", "deny_header_marker_403", "allow_without_marker"], True
    if value == "allow_deny_allow":
        return ["allow_without_marker", "deny_header_marker_403", "allow_without_marker"], False
    raise ValueError("unresolved canonical sequence representation: " + repr(value))


def apply_request_contract(profile, request, document, extra_rules):
    body = request.get("body", request.get("body_fixture", ""))
    profile.update(request_method=request.get("method", "GET"), request_path=request.get("path", "/i12-main"),
                   request_headers=request_headers(request), request_body_hex=body.encode().hex(), rules_extra=extra_rules)
    apply_limit_variant(profile, request, document)
    if request.get("generator"):
        profile["required_mechanisms"].append("canonical source generator: " + request["generator"])
    if request.get("fault_injection"):
        profile["required_mechanisms"].append("canonical native injection: " + request["fault_injection"])
    if request.get("transport_variant"):
        profile["sequence"] = ["allow_without_marker", "allow_without_marker"] if request["transport_variant"] == "keepalive_allow_allow" else ["allow_without_marker", "deny_header_marker_403", "allow_without_marker"]
        profile["connection_reuse"] = True
    if request.get("sequence"):
        profile["sequence"], profile["connection_reuse"] = canonical_sequence(request["sequence"])
    if request.get("keep_alive"):
        profile["connection_reuse"] = True
    if request.get("raw_template"):
        profile["raw_template"] = request["raw_template"]


NAMED_OVERRIDES = (
    (("NEED-request-empty", "NEED-ack-success", "NEED-complete-sample"), {"request_method": "GET", "request_body_hex": ""}),
    (("NEED-request-content-type-missing",), {"request_headers": []}),
    (("NEED-request-charset-present",), {"request_headers": [("Content-Type", "text/plain; charset=utf-8")]}),
    (("NEED-request-mime-scope-out",), {"request_headers": [("Content-Type", "application/octet-stream")]}),
    (("NEED-request-csv",), {"request_headers": [("Content-Type", "text/csv")], "request_body_hex": b"id,value\n1,clean\n".hex()}),
    (("NEED-request-multiple-chunks",), {"request_chunk_sizes": [4, 4]}),
    (("NEED-incomplete-sample",), {"body_fetch": PARTIAL_BODY_FETCH}),
    (("NEED-invalid-metadata", "NEED-precommit-error", "NEED-503-error"), {"body_size_fetch": MISMATCHED_BODY_SIZE_FETCH}),
    (("NEED-request-marker-at-payload-end",), {"request_body_hex": (b"x" * 240 + REQUEST_MARKER).hex()}),
    (("NEED-frame-boundary-not-engine-limit",), {"request_body_hex": (b"x" * 66000).hex()}),
    (("NEED-ttl", "NEED-response-companion-binding"), {"with_companion": True, "companion_export_only": True, "companion_ttl_ms": 100, "settle_seconds": .8}),
    (("NEED-connection-reuse",), {"sequence": ["allow_without_marker", "deny_header_marker_403", "allow_without_marker"], "connection_reuse": True}),
    (("NEED-incomplete-framing", "NEED-missing-eos"), {"raw_template": "incomplete-body"}),
    (("NEED-budget-precommit",), {"request_body_hex": b"0123456789abcdef ".hex(), "native_request_limit": 16}),
)


def named_profile(name):
    profile = ordinary_profile(name)
    profile["rules_extra"] = ""
    for names, overrides in NAMED_OVERRIDES:
        if name in names:
            profile.update(copy.deepcopy(overrides))
    return profile


def profile_wire(profile):
    raw_template = profile.get("raw_template")
    if raw_template in RAW_REQUESTS:
        tail = b"0\r\n\r\n" if raw_template == "duplicate_transfer_encoding" else b""
        return b"POST /i12-malformed HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n" + RAW_REQUESTS[raw_template] + b"\r\n" + tail
    if raw_template == "incomplete-body":
        return b"POST /i12-incomplete HTTP/1.1\r\nHost: localhost\r\nContent-Length: 8\r\nConnection: close\r\n\r\nabcd"
    return wire_http(profile["request_method"], profile["request_path"], profile["request_headers"], bytes.fromhex(profile["request_body_hex"]), profile["request_version"])


def constructed_notify(profile):
    if profile.get("raw_template") in RAW_REQUESTS:
        raise ValueError("HTTP parser rejection has no honest NOTIFY observation fixture")
    body = b"abcd" if profile.get("raw_template") == "incomplete-body" else bytes.fromhex(profile["request_body_hex"])
    declared = 8 if profile.get("raw_template") == "incomplete-body" else len(body)
    headers = [("host", "localhost"), *profile["request_headers"]]
    if profile.get("include_content_length", True):
        headers.append(("content-length", str(declared)))
    binary_headers = encode_headers(headers)
    text_headers = ("".join(name + ": " + value + "\r\n" for name, value in headers) + "\r\n").encode()
    sample_body = body[:4] if profile["body_fetch"] == PARTIAL_BODY_FETCH else body
    advertised = 99 if profile["body_size_fetch"] == MISMATCHED_BODY_SIZE_FETCH else declared
    arguments = [("request_id", 8, "source-fixture-0001"), ("client_ip", 6, "127.0.0.1"), ("client_port", 4, 45000),
                 ("server_ip", 6, "127.0.0.1"), ("server_port", 4, 18540), ("method", 8, profile["request_method"]),
                 ("path", 8, profile["request_path"]), ("uri", 8, profile["request_path"]), ("host", 8, "localhost"),
                 ("headers_bin", 9, binary_headers), ("headers", 8, text_headers.decode()), ("body", 9, sample_body),
                 ("body_len", 4, advertised), ("http_version", 8, profile["request_version"])]
    return encode_notify(arguments)


def expected_observations(profile, original):
    raw_template = profile.get("raw_template")
    if raw_template in RAW_REQUESTS or raw_template == "incomplete-body":
        return {"ack_status": None, "ack_blocked": None, "client_status": 400, "backend_requests": 0,
                "native_transaction_allocations": 0, "sample_inspection_claim": False,
                "source": "HAProxy HTTP1 framing rejection before request-only SPOP authorization", "unresolved_expected_fields": []}
    if len(bytes.fromhex(profile["request_body_hex"])) >= 65532:
        return {"ack_status": None, "ack_blocked": None, "client_status": 503, "backend_requests": 0,
                "native_transaction_allocations": 0, "sample_inspection_claim": False,
                "source": "finite SPOP frame bound or incomplete sample guard before native allocation",
                "unresolved_expected_fields": ["ack_status", "ack_blocked", "first_cause"]}
    if profile["body_fetch"] != REQUEST_BODY_FETCH or profile["body_size_fetch"] != REQUEST_BODY_SIZE_FETCH:
        return {"ack_status": 503, "ack_blocked": True, "client_status": 503, "backend_requests": 0,
                "native_transaction_allocations": 0, "sample_inspection_claim": False,
                "source": "notify_request_has_complete_body_sample and pre-native admission", "unresolved_expected_fields": []}
    if len(bytes.fromhex(profile["request_body_hex"])) > profile["native_request_limit"] and profile["native_request_limit_action"] == "Reject":
        return {"ack_status": None, "ack_blocked": None, "client_status": None, "backend_requests": None,
                "native_transaction_allocations": 1, "sample_inspection_claim": None,
                "source": "native body-limit Reject boundary requires independent SDK oracle",
                "unresolved_expected_fields": ["ack_status", "ack_blocked", "client_status", "backend_requests", "native_first_cause"]}
    status = original.get("visible_status")
    if status in (None, 0):
        status = 403 if REQUEST_MARKER in bytes.fromhex(profile["request_body_hex"]) else 200
    disruptive = status in (302, 403, 429)
    return {"ack_status": status if disruptive else 200, "ack_blocked": disruptive,
            "client_status": status, "backend_requests": int(not disruptive),
            "native_transaction_allocations": 1,
            "native_request_eos": not (disruptive and original.get("phase") == 1),
            "native_response_phases": [], "sample_inspection_claim": True,
            "source": "frozen original contract plus exact canonical rules and complete finite sample",
            "unresolved_expected_fields": []}


def profile_requests(profile, catalog, directory):
    sequence = profile.get("sequence")
    if not sequence:
        return [profile]
    profiles = []
    for name in sequence:
        request, document, _reference = canonical_request(name, catalog, directory)
        item = ordinary_profile(name)
        apply_request_contract(item, request, document, supplemental_rules(document))
        item["expected"] = expected_observations(item, {"visible_status": catalog[name].get("expected_status"),
                                                      "phase": catalog[name].get("phase")})
        profiles.append(item)
    return profiles


def bind_row(row, catalog, directory, rules_source, source_references):
    name = row["original_selected_requirement"]["case_id"]
    profile = named_profile(name)
    references = list(source_references)
    if name in catalog and name not in CONFIG_NAMES:
        request, document, reference = canonical_request(name, catalog, directory)
        apply_request_contract(profile, request, document, supplemental_rules(document))
        if reference is not None:
            references.append(reference)
    original = copy.deepcopy(row["original_selected_requirement"])
    if digest(original) != ORIGINAL_HASHES[name]:
        raise ValueError("selected original contract hash changed")
    profile["requests"] = profile_requests(profile, catalog, directory)
    # Avoid a recursive profile when the transaction has one request.
    if profile["requests"][0] is profile:
        profile.pop("requests")
    effective = sequence_expectation(profile) if profile.get("requests") else expected_observations(profile, row["original_oracle"])
    if profile["required_mechanisms"]:
        effective = None
    selected = {"schema": SCHEMA, "case": name, "case_id": PREFIX + name,
                "run": "i12-415-spop-" + hashlib.sha256(name.encode()).hexdigest()[:12],
                "execution_kind": row["execution_kind"], "original_selected_requirement": original,
                "original_selected_requirement_sha256": ORIGINAL_HASHES[name], "original_oracle": row["original_oracle"],
                "required_measurement_contract": row["required_measurement_contract"], "source_references": references,
                "runtime": profile, "rules_source": rules_source,
                "neighbor_expected": neighbor_expectation(profile),
                "effective_oracle": effective, "effective_oracle_sha256": digest(effective),
                "component_packets_are_host_observations": False, "actual_host_execution": None,
                "full_lifecycle_pass": None, "companion_profile_qualified": False}
    if name in CONFIG_NAMES:
        selected.update(runtime=None, effective_oracle=row["original_oracle"], effective_oracle_sha256=digest(row["original_oracle"]),
                        configuration_parser_contract="actual SPOP agent configuration/native rules admission; Root-owned config qualification")
    return selected


def prepare_definitions(inventory, catalog_path, rules_path):
    rows = original_rows(inventory)
    catalog = {case["case_id"]: case for case in json.loads(catalog_path.read_text())["cases"]}
    references = [physical_source(catalog_path), physical_source(rules_path)]
    source_hashes = {source_hash_map(row["original_source_hashes"]).get("framework:tests/cases/no-crs-baseline/catalog.json")
                     for row in rows if row.get("original_source_hashes")}
    if source_hashes and source_hashes != {references[0]["sha256"]}:
        raise ValueError("catalog differs from pinned original source")
    return [bind_row(row, catalog, catalog_path.parent, rules_path.read_text(), references) for row in rows]


def validate_runtime(selected):
    validate_original(selected)
    if selected.get("execution_kind") == "actual_configtest":
        raise ValueError("configuration original requires configuration parser driver")
    profile = selected["runtime"]
    if profile["required_mechanisms"]:
        raise ValueError("required measured mechanism not ready: " + repr(profile["required_mechanisms"]))
    if profile["request_version"] not in ("1.0", "1.1") or profile["http2"]:
        raise ValueError("original HTTP1 driver cannot qualify an unimplemented HTTP2 transport mapping")
    if len(bytes.fromhex(profile["request_body_hex"])) > 2 * 1024 * 1024:
        raise ValueError("request fixture exceeds bounded storage")
    if profile["body_fetch"] not in (REQUEST_BODY_FETCH, PARTIAL_BODY_FETCH) or profile["body_size_fetch"] not in (REQUEST_BODY_SIZE_FETCH, MISMATCHED_BODY_SIZE_FETCH):
        raise ValueError("unsupported source sample fetch")
    return profile


def corrupt_notify_frame(raw):
    decoded = decode_frame(raw)
    if decoded["kind"] != 3:
        return raw
    if not decoded.get("messages") or not decoded["messages"][-1]["arguments"]:
        raise InvalidFrame("concrete NOTIFY arguments required for damage fixture")
    last = decoded["messages"][-1]["arguments"][-1]
    if last["name"] != "http_version" or last["tag"] != 8:
        raise InvalidFrame("source damage targets final typed HTTP version")
    return struct.pack("!I", len(raw) - 5) + raw[4:-1]


def inspect_notify_frame(raw):
    decoded = decode_frame(raw)
    if decoded["kind"] != 3 or decoded["flags"] != 1 or not decoded["stream"] or not decoded["frame"]:
        return {"finite_sample_complete": False, "reason": "unsupported NOTIFY envelope", "native_lifecycle_proven": False}
    messages = decoded.get("messages", [])
    if len(messages) != 1 or messages[0]["name"] != "check-request":
        return {"finite_sample_complete": False, "reason": "unknown or mismatched request message", "native_lifecycle_proven": False}
    return inspect_sample(messages[0]["arguments"])


def sequence_expectation(profile):
    expected = [item["expected"] for item in profile["requests"]]
    return {"requests": expected, "client_statuses": [item["client_status"] for item in expected],
            "ack_statuses": [item["ack_status"] for item in expected],
            "backend_requests": sum(item["backend_requests"] for item in expected),
            "native_transaction_allocations": len(expected), "once_per_transaction": True,
            "connection_reuse_required": profile.get("connection_reuse", False),
            "unresolved_expected_fields": [], "source": "exact canonical request sequence; no co-counted original IDs"}


def neighbor_expectation(profile):
    return {"client_status": 200, "backend_requests": 1, "body_bytes": 7,
            "body_sha256": hashlib.sha256(b"BACKEND").hexdigest(), "native_transaction_allocations": 1,
            "native_response_phases": [3, 4] if profile["with_companion"] else [],
            "source": "clean independent neighbor HTTP request in same HAProxy/agent; response companion only when explicitly configured",
            "companion_profile_qualified": False}


def neighbor_profile():
    profile = ordinary_profile("neighbor")
    profile.update(request_method="GET", request_path="/i12-neighbor", request_headers=[], request_body_hex="", rules_extra="")
    return profile


def source_requests(profile):
    return profile.get("requests", [profile])


def fixture_tree_paths(directory):
    if not directory.is_absolute() or ".." in directory.parts:
        raise ValueError("absolute physical fixture tree required")
    if any(path.is_symlink() for path in (directory, *directory.parents)):
        raise ValueError("symlink fixture root forbidden")
    paths = [directory, *directory.rglob("*")]
    if any(path.is_symlink() or not (path.is_dir() or path.is_file()) for path in paths):
        raise ValueError("fixture tree requires only physical directories and regular files")
    return paths


def seal_fixture_tree(directory):
    paths = fixture_tree_paths(directory)
    for path in paths:
        if path.is_file():
            path.chmod(0o444)
    for path in reversed(paths):
        if path.is_dir():
            path.chmod(0o555)
    validate_sealed_fixture_tree(directory)


def validate_sealed_fixture_tree(directory):
    for path in fixture_tree_paths(directory):
        expected = 0o555 if path.is_dir() else 0o444
        if stat.S_IMODE(path.stat().st_mode) != expected:
            raise ValueError("fixture admission requires sealed mode " + oct(expected) + ": " + str(path))
