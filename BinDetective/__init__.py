# -*- coding: utf-8 -*-
import json
import os
import socket
from urllib.parse import urlparse
from typing import List, Dict, Union, Optional, Callable, Any, Sequence
from functools import wraps

__all__ = [
    "check_server_available",
    "validate_hex_address",
    "parse_response",
    "DEFAULT_API_KEY",
    "ENV_API_KEY",
    "DEFAULT_PORT",
    "SUPPORTED_INTERFACES",
    "INTERFACE_MODES",
    "INTERFACE_CALL_INFO",
    "Config",
    "BaseHttpClient",
    "SessionApi",
    "ServiceApi",
    "DirectApi",
    "FileApi",
    "DecompileApi",
    "StructApi",
    "XrefApi",
    "TypeApi",
    "DetectApi",
    "EditApi",
    "BinDetectiveClient",
]

def check_server_available(func: Callable) -> Callable:
    """调用前先探测 TCP 端口（TTL 缓存）；不可用返回统一错误；支持 str/json 双响应模式。"""

    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self.config.is_server_available():
            return self._maybe_json(json.dumps({
                "status": "error",
                "code": "E_SERVER_UNAVAILABLE",
                "result": {"error": "Server unavailable"},
            }, ensure_ascii=False))
        result = func(self, *args, **kwargs)
        if isinstance(result, str):
            return self._maybe_json(result)
        return result

    return wrapper


def _normalize_numeric_text(value: Any) -> str:
    """移除地址/数值中的空白及转义空白标记，避免解析在中途被截断。"""
    text = str(value)
    normalized: List[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char.isspace():
            index += 1
            continue
        if char == "\\" and index + 1 < len(text) and text[index + 1] in "trnvf":
            index += 2
            continue
        normalized.append(char)
        index += 1
    return "".join(normalized)


def validate_hex_address(address: Union[int, str]) -> Optional[str]:
    """把 int / "0x..." / 十进制串规范化为服务端可接受的地址串，非法返回 None。"""
    if isinstance(address, int):
        return hex(address)
    addr_str = _normalize_numeric_text(address)
    if not addr_str:
        return None
    if addr_str.startswith(("0x", "0X")):
        try:
            int(addr_str, 16)
            return addr_str
        except ValueError:
            return None
    try:
        int(addr_str, 10)
        return addr_str
    except ValueError:
        return None


def parse_response(text: str) -> Optional[Dict]:
    """把服务端返回的 JSON 字符串解析为 dict；解析失败返回 None。"""
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _coerce_params(values: Sequence) -> List[str]:
    """把参数序列转成服务端字符串数组：None -> 空串；尾部空串裁剪。

    统一 call() 与 _pack() 的裁剪语义：直接 call("X", ["a", None]) 与
    方法内 _pack("a", None) 行为一致，避免尾部空参残留。
    """
    out: List[str] = []
    for v in values:
        out.append("" if v is None else str(v))
    while out and out[-1] == "":
        out.pop()
    return out


def _pack(*values: Any) -> List[str]:
    """把位置参数打包成服务端要求的字符串数组（复用 _coerce_params 裁剪规则）。"""
    return _coerce_params(values)


def _addr(value: Union[int, str], what: str = "address") -> str:
    """校验并规范化地址参数（VA / RVA / FOA 通用）。"""
    s = validate_hex_address(value)
    if s is None:
        raise ValueError("invalid %s: %r" % (what, value))
    return s


DEFAULT_API_KEY = "7f3c9a1e5b8d2046c9e7f1a3b5d2c4e8f"
DEFAULT_PORT = 8000
ENV_API_KEY = "BINDETECTIVE_TOKEN"


# 重接口最小超时（秒）。服务端对这些接口的真实耗时远超默认 socket 超时
# （实测 CallSites≈144s、DataXrefAll≈162s、AnalyzeAll≈82–97s、CallGraphLocal≈7.5–88s，
# 见《BinDetective_接口测试与交叉验证报告》§4），若不放大会把正常完成误报为 E_TIMEOUT。
# call()/call_json() 会对命中的接口取 max(显式超时, HEAVY_IFACES 下限)；未命中则按原逻辑。
HEAVY_IFACES = {
    # 实测最重：≥140s
    "CallSites": 300, "DataXrefAll": 300, "AnalyzeAll": 300,
    "DataXrefs": 300, "BatchXrefs": 300, "CallGraph": 300,
    "FunctionGraph": 300, "BatchDecompile": 300, "BatchFunctionSummary": 300,
    "BatchFunctionStrings": 300, "TypeInferAll": 300, "AnalyzerRun": 300,
    # 实测/轮测超时：中等偏重
    "CallGraphLocal": 180, "Strings": 180, "Decompile": 180, "DecompileRaw": 180,
    "Signatures": 180, "Xrefs": 180, "PatchBytes": 180, "UndoPatch": 180,
    "PatchHistory": 180, "SessionDashboard": 180, "TextLocate": 180,
    "AddrCode": 180, "AddrToFunction": 180, "TypeInferAt": 180,
    "FunctionSummary": 180, "FunctionStrings": 180, "FileDiffDetail": 180,
    "FileDiffSummary": 180, "SimilarFunctionSearch": 180, "VtableList": 180,
    "FunctionLevelCrypt": 180, "BytePatternSearch": 180, "StructInfer": 180,
    "StructInferNative": 180, "TypeInferNative": 180, "DecompileMarshal": 180,
    "DecompileXml": 180, "PcodeEmit": 180, "PcodeDump": 180,
    "PrintTree": 180, "PrintBlockTree": 180, "PrintRaw": 180,
    # 轮测超时样本之一（首次分析 + 会话统计）
    "ListFunctions": 60, "FileBasicInfo": 60, "FunctionSeeds": 60,
}


def _default_api_key() -> str:
    """未显式传入 api_key 时的取值：环境变量 BINDETECTIVE_TOKEN，否则 DEFAULT_API_KEY。"""
    return os.environ.get(ENV_API_KEY, "") or DEFAULT_API_KEY


SUPPORTED_INTERFACES = (
    "Open", "FileBasicInfo", "FunctionSeeds", "ListFunctions", "DisassembleAt", "Decompile", "DecompileRaw", "FunctionGraph", "Xrefs", "Signatures", "CallGraph", "CallSites", "Strings", "MemoryDump", "Types", "AnalyzeAll", "AddrCode", "TextLocate", "DecompileHex", "ListLanguages", "DecodeInstruction", "PcodeEmit", "SearchImmediate", "DisasmBytes", "ListRegisters", "FindFunctionStarts", "HexEntropy", "DisasmRange", "RegisterUsage", "Crc32", "BytesToNumber", "IdentifyArchitecture", "SessionCreate", "SessionList", "SessionClose", "Switches", "ParamID", "Prototype", "PcodeDump", "Emulate", "EmulateBytes", "FunctionHash", "CfgStructure", "Variables", "OverrideAdd", "OverrideList", "DecompileOptions", "CLineMap", "Rename", "RenameVariable", "RenameType", "RenameList", "Comment", "CommentList", "BatchDecompile", "StringXrefs", "StackFrame", "DotExport", "DataXrefs", "EmulateEx", "FunctionSimilarity", "CryptDetect", "TypePropagate", "CallConvList", "ObfuscationDetect", "ApiSequence", "DecompileOptionsEx", "AssembleInstruction", "AssembleBlock", "AssembleRoundTrip", "CppDemangle", "UnicodeString", "ImportTable", "ExportTable", "DangerousCalls", "GenerateOpenAPI", "OpcodeHistogram", "EntropyProfile", "StackDepth", "UnreachableCode", "InlineDetect", "TailCallDetect", "Globals", "LoopInfo", "InstructionCoverage", "EmulateWatch", "HealthStats", "BatchSession", "ContextGet", "ContextSet", "LabelAdd", "LabelList", "TypeDefine", "ArchOptionList", "ArchOptionSet", "ExternalMark", "DecompileXml", "InjectPayload", "RecursionDetect", "RecursionDetectFast", "TypeInferAll", "JumpTableDetail", "RegisterSnapshot", "DataXrefAll", "SessionDashboard", "PatchBytes", "PatchHistory", "UndoPatch", "BytePatternSearch", "EquateAdd", "EquateList", "DefineData", "DataMarkList", "SymbolSearch", "OverrideProto", "OverrideJumpTable", "OverrideFlow", "ForceFormat", "ForceDatatypeFormat", "Isolate", "Retype", "Volatile", "Readonly", "PointerSetting", "PreferSplit", "DeadcodeDelay", "PrototypeLock", "PrototypeUnlock", "CallFixupAdd", "CallOtherFixupAdd", "FixupApply", "ActionStats", "ActionStatsReset", "CountPcode", "PrintTree", "PrintBlockTree", "PrintRaw", "PrintLocalRange", "DecompileMarshal", "TypeInferNative", "StructInferNative", "LoaderInfo", "AssociateType", "AssociationList", "AnalyzerList", "AnalyzerRun", "StructInfer", "FidbMatch", "DbStatus", "PdbLoad", "DwarfLoad", "SessionSave", "SessionLoad", "FunctionStrings", "TypeInferAt", "AddrToFunction", "CallGraphLocal", "FunctionSummary", "BatchFunctionSummary", "BatchFunctionStrings", "BatchXrefs", "FunctionDiff", "CallSiteArguments", "DataFlowTo", "FileDiffSummary", "VtableList", "FunctionLevelCrypt", "StringXrefContext", "SectionTable", "ConstantsInFunction", "CreateFunction", "CryptoKeyCandidates", "FileDiffDetail", "SimilarFunctionSearch",
)

INTERFACE_MODES = {
    "Open": "direct",
    "FileBasicInfo": "session",
    "FunctionSeeds": "session",
    "ListFunctions": "session",
    "DisassembleAt": "session",
    "Decompile": "session",
    "DecompileRaw": "session",
    "FunctionGraph": "session",
    "Xrefs": "session",
    "Signatures": "session",
    "CallGraph": "session",
    "CallSites": "session",
    "Strings": "session",
    "MemoryDump": "session",
    "Types": "session",
    "AnalyzeAll": "session",
    "AddrCode": "session",
    "TextLocate": "session",
    "DecompileHex": "direct",
    "ListLanguages": "direct",
    "DecodeInstruction": "session",
    "PcodeEmit": "session",
    "SearchImmediate": "session",
    "DisasmBytes": "direct",
    "ListRegisters": "direct",
    "FindFunctionStarts": "direct",
    "HexEntropy": "session",
    "DisasmRange": "session",
    "RegisterUsage": "session",
    "Crc32": "direct",
    "BytesToNumber": "session",
    "IdentifyArchitecture": "direct",
    "SessionCreate": "direct",
    "SessionList": "direct",
    "SessionClose": "direct",
    "Switches": "session",
    "ParamID": "session",
    "Prototype": "session",
    "PcodeDump": "session",
    "Emulate": "session",
    "EmulateBytes": "direct",
    "FunctionHash": "session",
    "CfgStructure": "session",
    "Variables": "session",
    "OverrideAdd": "session",
    "OverrideList": "session",
    "DecompileOptions": "session",
    "CLineMap": "session",
    "Rename": "session",
    "RenameVariable": "session",
    "RenameType": "session",
    "RenameList": "session",
    "Comment": "session",
    "CommentList": "session",
    "BatchDecompile": "session",
    "StringXrefs": "session",
    "StackFrame": "session",
    "DotExport": "session",
    "DataXrefs": "session",
    "EmulateEx": "session",
    "FunctionSimilarity": "session",
    "CryptDetect": "session",
    "TypePropagate": "session",
    "CallConvList": "session",
    "ObfuscationDetect": "session",
    "ApiSequence": "session",
    "DecompileOptionsEx": "session",
    "AssembleInstruction": "direct",
    "AssembleBlock": "direct",
    "AssembleRoundTrip": "direct",
    "CppDemangle": "direct",
    "UnicodeString": "session",
    "ImportTable": "session",
    "ExportTable": "session",
    "DangerousCalls": "session",
    "GenerateOpenAPI": "direct",
    "OpcodeHistogram": "session",
    "EntropyProfile": "session",
    "StackDepth": "session",
    "UnreachableCode": "session",
    "InlineDetect": "session",
    "TailCallDetect": "session",
    "Globals": "session",
    "LoopInfo": "session",
    "InstructionCoverage": "session",
    "EmulateWatch": "session",
    "HealthStats": "direct",
    "BatchSession": "session",
    "ContextGet": "session",
    "ContextSet": "session",
    "LabelAdd": "session",
    "LabelList": "session",
    "TypeDefine": "session",
    "ArchOptionList": "session",
    "ArchOptionSet": "session",
    "ExternalMark": "session",
    "DecompileXml": "session",
    "InjectPayload": "session",
    "RecursionDetect": "session",
    "RecursionDetectFast": "session",
    "TypeInferAll": "session",
    "JumpTableDetail": "session",
    "RegisterSnapshot": "session",
    "DataXrefAll": "session",
    "SessionDashboard": "session",
    "PatchBytes": "session",
    "PatchHistory": "session",
    "UndoPatch": "session",
    "BytePatternSearch": "session",
    "EquateAdd": "session",
    "EquateList": "session",
    "DefineData": "session",
    "DataMarkList": "session",
    "SymbolSearch": "session",
    "OverrideProto": "session",
    "OverrideJumpTable": "session",
    "OverrideFlow": "session",
    "ForceFormat": "session",
    "ForceDatatypeFormat": "session",
    "Isolate": "session",
    "Retype": "session",
    "Volatile": "session",
    "Readonly": "session",
    "PointerSetting": "session",
    "PreferSplit": "session",
    "DeadcodeDelay": "session",
    "PrototypeLock": "session",
    "PrototypeUnlock": "session",
    "CallFixupAdd": "session",
    "CallOtherFixupAdd": "session",
    "FixupApply": "session",
    "ActionStats": "session",
    "ActionStatsReset": "session",
    "CountPcode": "session",
    "PrintTree": "session",
    "PrintBlockTree": "session",
    "PrintRaw": "session",
    "PrintLocalRange": "session",
    "DecompileMarshal": "session",
    "TypeInferNative": "session",
    "StructInferNative": "session",
    "LoaderInfo": "session",
    "AssociateType": "session",
    "AssociationList": "session",
    "AnalyzerList": "session",
    "AnalyzerRun": "session",
    "StructInfer": "session",
    "FidbMatch": "session",
    "DbStatus": "session",
    "PdbLoad": "session",
    "DwarfLoad": "session",
    "SessionSave": "session",
    "SessionLoad": "session",
    "FunctionStrings": "session",
    "TypeInferAt": "session",
    "AddrToFunction": "session",
    "CallGraphLocal": "session",
    "FunctionSummary": "session",
    "BatchFunctionSummary": "session",
    "BatchFunctionStrings": "session",
    "BatchXrefs": "session",
    "FunctionDiff": "session",
    "CallSiteArguments": "session",
    "DataFlowTo": "session",
    "FileDiffSummary": "session",
    "VtableList": "session",
    "FunctionLevelCrypt": "session",
    "StringXrefContext": "session",
    "SectionTable": "session",
    "ConstantsInFunction": "session",
    "CreateFunction": "session",
    "CryptoKeyCandidates": "session",
    "FileDiffDetail": "session",
    "SimilarFunctionSearch": "session",
}

INTERFACE_CALL_INFO = {
    "Open": {"mode": "direct", "params": ["path", "language=None", "base=None"]},
    "FileBasicInfo": {"mode": "session", "params": []},
    "FunctionSeeds": {"mode": "session", "params": ["address", "name", "kind='0'", "source='user'"]},
    "ListFunctions": {"mode": "session", "params": []},
    "DisassembleAt": {"mode": "session", "params": ["address", "count", "detail=None"]},
    "Decompile": {"mode": "session", "params": ["address"]},
    "DecompileRaw": {"mode": "session", "params": ["func_addr"]},
    "FunctionGraph": {"mode": "session", "params": ["address"]},
    "Xrefs": {"mode": "session", "params": ["address"]},
    "Signatures": {"mode": "session", "params": []},
    "CallGraph": {"mode": "session", "params": []},
    "CallSites": {"mode": "session", "params": ["address"]},
    "Strings": {"mode": "session", "params": []},
    "MemoryDump": {"mode": "session", "params": ["address", "size"]},
    "Types": {"mode": "session", "params": ["kind='list'"]},
    "AnalyzeAll": {"mode": "session", "params": []},
    "AddrCode": {"mode": "session", "params": ["address"]},
    "TextLocate": {"mode": "session", "params": ["text", "format='annotated'"]},
    "DecompileHex": {"mode": "direct", "params": ["hex_str", "language", "base", "func_addr=None"]},
    "ListLanguages": {"mode": "direct", "params": []},
    "DecodeInstruction": {"mode": "session", "params": ["address"]},
    "PcodeEmit": {"mode": "session", "params": ["address", "count"]},
    "SearchImmediate": {"mode": "session", "params": ["imm", "width=None", "endian=None"]},
    "DisasmBytes": {"mode": "direct", "params": ["hex_str", "language", "base", "count=None"]},
    "ListRegisters": {"mode": "direct", "params": ["language"]},
    "FindFunctionStarts": {"mode": "direct", "params": ["hex_str", "language", "base"]},
    "HexEntropy": {"mode": "session", "params": ["address", "size"]},
    "DisasmRange": {"mode": "session", "params": ["address", "count"]},
    "RegisterUsage": {"mode": "session", "params": ["address", "count"]},
    "Crc32": {"mode": "direct", "params": ["hex_str"]},
    "BytesToNumber": {"mode": "session", "params": ["address", "width='4'", "endian='le'"]},
    "IdentifyArchitecture": {"mode": "direct", "params": ["path"]},
    "SessionCreate": {"mode": "direct", "params": []},
    "SessionList": {"mode": "direct", "params": []},
    "SessionClose": {"mode": "direct", "params": ["session_id"]},
    "Switches": {"mode": "session", "params": ["address"]},
    "ParamID": {"mode": "session", "params": ["address"]},
    "Prototype": {"mode": "session", "params": ["address"]},
    "PcodeDump": {"mode": "session", "params": ["address"]},
    "Emulate": {"mode": "session", "params": ["address", "steps=None", "watch=None"]},
    "EmulateBytes": {"mode": "direct", "params": ["hex_str", "language", "base", "entry=None", "max_steps=None", "watch_regs=None"]},
    "FunctionHash": {"mode": "session", "params": ["address"]},
    "CfgStructure": {"mode": "session", "params": ["address"]},
    "Variables": {"mode": "session", "params": ["address"]},
    "OverrideAdd": {"mode": "session", "params": ["func_addr", "kind", "at", "target=0", "flow_type=0"]},
    "OverrideList": {"mode": "session", "params": ["address"]},
    "DecompileOptions": {"mode": "session", "params": []},
    "CLineMap": {"mode": "session", "params": ["address"]},
    "Rename": {"mode": "session", "params": ["address", "new_name"]},
    "RenameVariable": {"mode": "session", "params": ["func_addr", "var_name", "new_name"]},
    "RenameType": {"mode": "session", "params": ["old_type_name", "new_type_name"]},
    "RenameList": {"mode": "session", "params": []},
    "Comment": {"mode": "session", "params": ["address", "text", "kind=None"]},
    "CommentList": {"mode": "session", "params": ["address"]},
    "BatchDecompile": {"mode": "session", "params": ["addresses_json"]},
    "StringXrefs": {"mode": "session", "params": ["min_length=None"]},
    "StackFrame": {"mode": "session", "params": ["address"]},
    "DotExport": {"mode": "session", "params": ["address", "kind=None"]},
    "DataXrefs": {"mode": "session", "params": ["address"]},
    "EmulateEx": {"mode": "session", "params": ["address", "steps=None", "watch=None", "init_regs=None", "init_mem=None", "branch_trace=None", "externs=None"]},
    "FunctionSimilarity": {"mode": "session", "params": ["address", "top_n=None", "candidates_json=None"]},
    "CryptDetect": {"mode": "session", "params": ["address", "size", "bins"]},
    "TypePropagate": {"mode": "session", "params": ["address", "target='return'", "type_name='int'"]},
    "CallConvList": {"mode": "session", "params": []},
    "ObfuscationDetect": {"mode": "session", "params": ["address"]},
    "ApiSequence": {"mode": "session", "params": ["address"]},
    "DecompileOptionsEx": {"mode": "session", "params": []},
    "AssembleInstruction": {"mode": "direct", "params": ["asm_text", "flag='true'", "cip=None"]},
    "AssembleBlock": {"mode": "direct", "params": ["asm_text", "flag='true'", "base=None"]},
    "AssembleRoundTrip": {"mode": "direct", "params": ["asm_text", "flag='true'"]},
    "CppDemangle": {"mode": "direct", "params": ["mangled"]},
    "UnicodeString": {"mode": "session", "params": ["count"]},
    "ImportTable": {"mode": "session", "params": []},
    "ExportTable": {"mode": "session", "params": []},
    "DangerousCalls": {"mode": "session", "params": ["address"]},
    "GenerateOpenAPI": {"mode": "direct", "params": []},
    "OpcodeHistogram": {"mode": "session", "params": ["address"]},
    "EntropyProfile": {"mode": "session", "params": ["address", "size", "bins"]},
    "StackDepth": {"mode": "session", "params": ["address"]},
    "UnreachableCode": {"mode": "session", "params": ["address"]},
    "InlineDetect": {"mode": "session", "params": ["address"]},
    "TailCallDetect": {"mode": "session", "params": ["address"]},
    "Globals": {"mode": "session", "params": []},
    "LoopInfo": {"mode": "session", "params": ["address"]},
    "InstructionCoverage": {"mode": "session", "params": ["address"]},
    "EmulateWatch": {"mode": "session", "params": ["address", "steps=None", "exprs=None"]},
    "HealthStats": {"mode": "direct", "params": []},
    "BatchSession": {"mode": "session", "params": ["addresses_json"]},
    "ContextGet": {"mode": "session", "params": ["address", "context='flow'"]},
    "ContextSet": {"mode": "session", "params": ["address", "key", "value"]},
    "LabelAdd": {"mode": "session", "params": ["address", "label"]},
    "LabelList": {"mode": "session", "params": ["address=None"]},
    "TypeDefine": {"mode": "session", "params": ["kind", "name", "spec_json"]},
    "ArchOptionList": {"mode": "session", "params": ["option_name=None"]},
    "ArchOptionSet": {"mode": "session", "params": ["key", "value"]},
    "ExternalMark": {"mode": "session", "params": ["address", "ref_addr=0", "name=''"]},
    "DecompileXml": {"mode": "session", "params": ["address", "format=None"]},
    "InjectPayload": {"mode": "session", "params": ["payload_name=None"]},
    "RecursionDetect": {"mode": "session", "params": ["address=None"]},
    "RecursionDetectFast": {"mode": "session", "params": ["address=None"]},
    "TypeInferAll": {"mode": "session", "params": []},
    "JumpTableDetail": {"mode": "session", "params": ["address"]},
    "RegisterSnapshot": {"mode": "session", "params": ["address", "max_steps=None", "regs_csv=None"]},
    "DataXrefAll": {"mode": "session", "params": []},
    "SessionDashboard": {"mode": "session", "params": []},
    "PatchBytes": {"mode": "session", "params": ["address", "hex_data"]},
    "PatchHistory": {"mode": "session", "params": []},
    "UndoPatch": {"mode": "session", "params": []},
    "BytePatternSearch": {"mode": "session", "params": ["pattern", "limit=None"]},
    "EquateAdd": {"mode": "session", "params": ["value", "name"]},
    "EquateList": {"mode": "session", "params": []},
    "DefineData": {"mode": "session", "params": ["address", "data_type", "size"]},
    "DataMarkList": {"mode": "session", "params": []},
    "SymbolSearch": {"mode": "session", "params": ["keyword", "limit=None"]},
    "OverrideProto": {"mode": "session", "params": ["func_addr", "callpoint", "proto_decl"]},
    "OverrideJumpTable": {"mode": "session", "params": ["func_addr", "jmpaddr", "startval", "target..."]},
    "OverrideFlow": {"mode": "session", "params": ["func_addr", "at", "type_str"]},
    "ForceFormat": {"mode": "session", "params": ["func_addr", "varnode_desc", "format"]},
    "ForceDatatypeFormat": {"mode": "session", "params": ["type_name", "format"]},
    "Isolate": {"mode": "session", "params": ["func_addr", "symbol_name"]},
    "Retype": {"mode": "session", "params": ["func_addr", "symbol_name", "type_name"]},
    "Volatile": {"mode": "session", "params": ["addr", "size"]},
    "Readonly": {"mode": "session", "params": ["addr", "size"]},
    "PointerSetting": {"mode": "session", "params": ["name", "base_type", "setting", "value"]},
    "PreferSplit": {"mode": "session", "params": ["addr", "size", "split"]},
    "DeadcodeDelay": {"mode": "session", "params": ["func_addr", "space_name", "delay"]},
    "PrototypeLock": {"mode": "session", "params": ["func_addr"]},
    "PrototypeUnlock": {"mode": "session", "params": ["func_addr"]},
    "CallFixupAdd": {"mode": "session", "params": ["name", "pcode_snippet"]},
    "CallOtherFixupAdd": {"mode": "session", "params": ["name", "outname", "inname_csv", "pcode_snippet"]},
    "FixupApply": {"mode": "session", "params": ["fixup_name", "func_addr"]},
    "ActionStats": {"mode": "session", "params": []},
    "ActionStatsReset": {"mode": "session", "params": []},
    "CountPcode": {"mode": "session", "params": ["func_addr"]},
    "PrintTree": {"mode": "session", "params": ["func_addr"]},
    "PrintBlockTree": {"mode": "session", "params": ["func_addr"]},
    "PrintRaw": {"mode": "session", "params": ["func_addr"]},
    "PrintLocalRange": {"mode": "session", "params": ["func_addr"]},
    "DecompileMarshal": {"mode": "session", "params": ["func_addr"]},
    "TypeInferNative": {"mode": "session", "params": ["func_addr"]},
    "StructInferNative": {"mode": "session", "params": ["func_addr"]},
    "LoaderInfo": {"mode": "session", "params": []},
    "AssociateType": {"mode": "session", "params": ["address", "type_name"]},
    "AssociationList": {"mode": "session", "params": []},
    "AnalyzerList": {"mode": "session", "params": []},
    "AnalyzerRun": {"mode": "session", "params": ["name"]},
    "StructInfer": {"mode": "session", "params": []},
    "FidbMatch": {"mode": "session", "params": ["sig_path", "max_results=None", "dump=None", "ranges_json=None", "refs_json=None"]},
    "DbStatus": {"mode": "session", "params": []},
    "PdbLoad": {"mode": "session", "params": ["pdb_path"]},
    "DwarfLoad": {"mode": "session", "params": []},
    "SessionSave": {"mode": "session", "params": ["path=None"]},
    "SessionLoad": {"mode": "session", "params": ["path_or_json"]},
    "FunctionStrings": {"mode": "session", "params": ["address", "min_length=None"]},
    "TypeInferAt": {"mode": "session", "params": ["address"]},
    "AddrToFunction": {"mode": "session", "params": ["address"]},
    "CallGraphLocal": {"mode": "session", "params": ["address", "depth=None", "direction=None"]},
    "FunctionSummary": {"mode": "session", "params": ["address"]},
    "BatchFunctionSummary": {"mode": "session", "params": ["addresses"]},
    "BatchFunctionStrings": {"mode": "session", "params": ["addresses", "min_length=None"]},
    "BatchXrefs": {"mode": "session", "params": ["addresses"]},
    "FunctionDiff": {"mode": "session", "params": ["addr1", "addr2"]},
    "CallSiteArguments": {"mode": "session", "params": ["address"]},
    "DataFlowTo": {"mode": "session", "params": ["address", "depth=None"]},
    "FileDiffSummary": {"mode": "session", "params": ["file2_path"]},
    "VtableList": {"mode": "session", "params": ["min_entries=None"]},
    "FunctionLevelCrypt": {"mode": "session", "params": ["address"]},
    "StringXrefContext": {"mode": "session", "params": ["address", "context=None"]},
    "SectionTable": {"mode": "session", "params": ["detail=None"]},
    "ConstantsInFunction": {"mode": "session", "params": ["address", "min_value=None", "max=None"]},
    "CreateFunction": {"mode": "session", "params": ["address", "name=None", "overwrite=None"]},
    "CryptoKeyCandidates": {"mode": "session", "params": ["detail=None", "max=None"]},
    "FileDiffDetail": {"mode": "session", "params": ["file2_path", "max_items=None"]},
    "SimilarFunctionSearch": {"mode": "session", "params": ["address", "top_n=None", "min_score=None"]},
}

class Config:
    def __init__(self, address: str = "127.0.0.1", port: int = DEFAULT_PORT,
                 api_key: Optional[str] = None, session: Optional[str] = None,
                 timeout: int = 5, response: str = "str",
                 probe_timeout: float = 1.5, probe_ttl: float = 10.0):
        self.address = address
        self.port = port
        self.server_addr = "http://{}:{}".format(address, port)
        self.api_key = api_key if api_key is not None else _default_api_key()
        self.timeout = timeout
        self.session = session
        self.response = response if response in ("str", "json") else "str"
        self.probe_timeout = probe_timeout
        self.probe_ttl = probe_ttl
        self._probe_ts = 0.0
        self._probe_ok: Optional[bool] = None

    def set_server(self, address: str, port: int = DEFAULT_PORT) -> None:
        self.address = address
        self.port = port
        self.server_addr = "http://{}:{}".format(address, port)
        self._probe_ok = None

    def set_api_key(self, api_key: Optional[str]) -> None:
        """设置鉴权 token；传 None 或空串表示恢复内置默认 KEY。"""
        self.api_key = api_key or DEFAULT_API_KEY

    def set_session(self, session: Optional[str]) -> None:
        self.session = session or None

    def is_server_available(self, timeout: Optional[float] = None) -> bool:
        """TCP 探测（带 TTL 缓存）：窗口内不重复 connect，宕机时快速失败不阻塞。"""
        import time
        now = time.monotonic()
        if self._probe_ok is not None and (now - self._probe_ts) < self.probe_ttl:
            return self._probe_ok
        timeout = timeout or self.probe_timeout
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                ok = sock.connect_ex((self.address, self.port)) == 0
        except socket.error as e:
            print("WARNING: Server check failed: {}".format(str(e)))
            ok = False
        self._probe_ts = now
        self._probe_ok = ok
        return ok


class BaseHttpClient:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        parsed_url = urlparse(self.config.server_addr)
        self.address = parsed_url.hostname
        self.port = parsed_url.port
        self.scheme = parsed_url.scheme
        self.path = parsed_url.path or "/"
        self.verify_ssl = True

    def set_server(self, address: str, port: int = DEFAULT_PORT) -> None:
        self.config.set_server(address, port)
        self.address = address
        self.port = port

    def set_api_key(self, api_key: str) -> None:
        self.config.set_api_key(api_key)

    def set_session(self, session: Optional[str]) -> None:
        self.config.set_session(session)

    def _maybe_json(self, text: str) -> Any:
        """按 Config.response 模式返回：str 原样 / json 解析为 dict（解析失败返回 None）。"""
        if getattr(self.config, "response", "str") == "json":
            return parse_response(text)
        return text

    def _session_required(self) -> Any:
        """会话域缺 session 的客户端预检结果（码与服务端 E_SESSION_REQUIRED 一致）。"""
        text = json.dumps({
            "status": "error",
            "code": "E_SESSION_REQUIRED",
            "result": {"error": "A session is required: call Open or SessionCreate first (direct-call mode removed in v2.1)"},
        }, ensure_ascii=False)
        return self._maybe_json(text)

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json", "Connection": "close"}
        token = getattr(self.config, "api_key", "") or DEFAULT_API_KEY
        if token:
            headers["X-Auth-Token"] = token
        return headers

    def custom_post(self, payload: Optional[Dict] = None,
                    timeout: Optional[int] = None) -> str:
        import socket
        body = json.dumps(payload).encode("utf-8") if payload else None
        timeout = timeout or self.config.timeout
        token = getattr(self.config, "api_key", "") or DEFAULT_API_KEY
        try:
            s = socket.create_connection((self.address, self.port), timeout=timeout)
            s.settimeout(timeout)
            head = ("POST %s HTTP/1.1\r\n" % (self.path or "/"))
            head += "Host: %s:%s\r\n" % (self.address, self.port)
            head += "Content-Type: application/json\r\n"
            head += "Connection: close\r\n"
            if token:
                head += "X-Auth-Token: %s\r\n" % token
            head += "Content-Length: %d\r\n\r\n" % (len(body) if body else 0)
            s.sendall(head.encode("utf-8"))
            if body:
                s.sendall(body)
            buf = b""
            recv_timed_out = False
            conn_closed = False
            while b"\r\n\r\n" not in buf:
                try:
                    d = s.recv(4096)
                except socket.timeout:
                    recv_timed_out = True
                    break
                if not d:
                    conn_closed = True
                    break
                buf += d
                if len(buf) > 64 * 1024:
                    break
            body_b = b""
            header_ok = b"\r\n\r\n" in buf
            if header_ok:
                header_part, body_part = buf.split(b"\r\n\r\n", 1)
                clen = 0
                for line in header_part.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        try:
                            clen = int(line.split(b":", 1)[1].strip())
                        except ValueError:
                            clen = 0
                body_b = body_part
                while len(body_b) < clen:
                    try:
                        d = s.recv(4096)
                    except socket.timeout:
                        recv_timed_out = True
                        break
                    if not d:
                        conn_closed = True
                        break
                    body_b += d
            s.close()
            if recv_timed_out:
                # 已发出请求但未在超时窗口内收到完整响应：报告为超时，
                # 避免把空串/残缺响应误当成服务端成功返回。
                return json.dumps({"status": "error", "code": "E_TIMEOUT",
                                   "result": {"error": "Request timed out while waiting for response"}},
                                  ensure_ascii=False)
            if conn_closed or not header_ok:
                # 连接被服务端关闭或响应不完整（并发/负载下服务端可能提前断开），
                # 同样报告为明确错误，而不是返回空串让调用方误判。
                return json.dumps({"status": "error", "code": "E_CONN_CLOSED",
                                   "result": {"error": "Connection closed before a complete response was received"}},
                                  ensure_ascii=False)
            return body_b.decode("utf-8", errors="ignore")
        except socket.timeout:
            return json.dumps({"status": "error", "code": "E_TIMEOUT",
                               "result": {"error": "Request timed out"}}, ensure_ascii=False)
        except ConnectionRefusedError:
            return json.dumps({"status": "error", "code": "E_CONN_REFUSED",
                               "result": {"error": "Connection refused by server"}},
                              ensure_ascii=False)
        except Exception as e:
            return json.dumps({"status": "error", "code": "E_REQUEST_FAILED",
                               "result": {"error": "Request failed: {}".format(str(e))}},
                              ensure_ascii=False)

    def custom_get(self, timeout: Optional[int] = None) -> str:
        """GET / —— 取服务端 plugin_info（版本、接口数、会话 TTL、interface_modes 等）。"""
        import http.client
        headers = self._headers()
        timeout = timeout or self.config.timeout
        try:
            if self.scheme == "https":
                import ssl
                context = ssl._create_unverified_context() if not self.verify_ssl else None
                conn = http.client.HTTPSConnection(self.address, self.port,
                                                   timeout=timeout, context=context)
            else:
                conn = http.client.HTTPConnection(self.address, self.port, timeout=timeout)
            conn.request("GET", self.path, headers=headers)
            response = conn.getresponse()
            response_text = response.read().decode("utf-8", errors="ignore")
            conn.close()
            return response_text
        except socket.timeout:
            return json.dumps({"status": "error", "code": "E_TIMEOUT",
                               "result": {"error": "Request timed out"}}, ensure_ascii=False)
        except ConnectionRefusedError:
            return json.dumps({"status": "error", "code": "E_CONN_REFUSED",
                               "result": {"error": "Connection refused by server"}},
                              ensure_ascii=False)
        except Exception as e:
            return json.dumps({"status": "error", "code": "E_REQUEST_FAILED",
                               "result": {"error": "Request failed: {}".format(str(e))}},
                              ensure_ascii=False)

    def call(self, interface: str, params: Optional[Sequence] = None,
             session: Optional[str] = None, mode: Optional[str] = None,
             timeout: Optional[int] = None) -> str:
        """通用调用入口：任何接口都可以直接走这里。

        mode 可选（v2 Phase2）：direct|session，与服务端注册表校验；
        不传则服务端按注册表行为处理（会话域缺 session 返回 E_SESSION_REQUIRED）。
        """
        if interface not in SUPPORTED_INTERFACES:
            raise ValueError("unsupported interface: {}".format(interface))
        payload: Dict[str, Any] = {
            "interface": interface,
            "params": _coerce_params(params or []),
        }
        sid = session if session is not None else getattr(self.config, "session", None)
        if sid:
            payload["session"] = str(sid)
        if mode:
            payload["mode"] = mode
        # 重接口最小超时对齐（见模块级 HEAVY_IFACES 说明）
        eff = timeout
        heavy = HEAVY_IFACES.get(interface, 0)
        if heavy > 0:
            base = self.config.timeout if eff is None else eff
            if base < heavy:
                eff = heavy
        return self.custom_post(payload, eff)

    def call_json(self, interface: str, params: Optional[Sequence] = None,
                  session: Optional[str] = None, mode: Optional[str] = None,
                  timeout: Optional[int] = None) -> Optional[Dict]:
        """同 call()，但直接返回解析后的 dict。"""
        return parse_response(self.call(interface, params, session, mode, timeout))


class SessionApi(BaseHttpClient):
    """会话 / 文件装载管理"""

    @check_server_available
    def open(self, path, language=None, base=None, session=None, mode=None):
        """Open —— 装载二进制文件（绝对路径），自动识别 PE/ELF/Mach-O 格式与 CPU 架构；
        language 可省略（自动识别），也可显式传入语言 ID（如 x86:LE:64:default:gcc）强制覆盖；
        base 可省略（按镜像头自动解析），也可显式覆盖加载基址（hex 字符串或十进制）。
        成功后自动把返回的 session_id 绑定到当前客户端，后续会话域调用无需再传 session。"""
        params = [path]
        if language is not None:
            params.append(language)
        if base is not None:
            params.append(str(base))
        r = self.call("Open", _pack(*params), session, mode)
        # check_server_available 装饰器在方法外才做 str->dict 转换，内部需自行解析
        rj = None
        if isinstance(r, dict):
            rj = r
        elif isinstance(r, str):
            try:
                rj = json.loads(r)
            except Exception:
                rj = None
        if rj and rj.get("status") == "success" and not session:
            sid = (rj.get("result") or {}).get("session_id")
            if sid:
                self.config.set_session(sid)
        return r

    @check_server_available
    def session_create(self, session=None, mode=None):
        """SessionCreate —— 新建空会话，返回 session_id"""
        return self.call("SessionCreate", _pack(), session, mode)

    @check_server_available
    def session_list(self, session=None, mode=None):
        """SessionList —— 列出全部会话"""
        return self.call("SessionList", _pack(), session, mode)

    @check_server_available
    def session_close(self, session_id=None, session=None, mode=None):
        """SessionClose —— 关闭指定会话。

        服务端解析目标会话的优先级为：请求 `session` 字段 > params[0] > 当前会话。
        本方法把 session_id 显式放入 `session` 字段（而不是仅作 params[0]），
        避免 config.session（当前配置会话）被注入 `session` 字段后覆盖目标，误关其它会话。
        等价语义：
          session_close("S5")          -> 关闭 S5
          session_close()              -> 关闭当前配置会话（config.session）
        """
        sid = session if session is not None else (session_id or None)
        return self.call("SessionClose", _pack(session_id) if session_id else _pack(), sid, mode)


class ServiceApi(BaseHttpClient):
    """服务信息与控制面（无状态）"""

    @check_server_available
    def list_languages(self, session=None, mode=None):
        """ListLanguages —— 列出全部语言 ID"""
        return self.call("ListLanguages", _pack(), session, mode)

    @check_server_available
    def generate_openapi(self, session=None, mode=None):
        """GenerateOpenAPI —— 生成 OpenAPI 契约"""
        return self.call("GenerateOpenAPI", _pack(), session, mode)

    @check_server_available
    def health_stats(self, session=None, mode=None):
        """HealthStats —— 运行期统计（请求数/耗时/错误）"""
        return self.call("HealthStats", _pack(), session, mode)


class DirectApi(BaseHttpClient):
    """无状态分析（无需会话）"""

    @check_server_available
    def disasm_bytes(self, hex_str, language, base, count=None, session=None, mode=None):
        """DisasmBytes —— 反汇编字节流 [hex, lang, base, count=64]，无需会话"""
        params = [hex_str, language, str(base)]
        if count is not None:
            params.append(str(count))
        return self.call("DisasmBytes", _pack(*params), session, mode)

    @check_server_available
    def decompile_hex(self, hex_str, language, base, func_addr=None, session=None, mode=None):
        """DecompileHex —— 反编译字节流 [hex, lang, base, func_addr=base]，无需会话"""
        params = [hex_str, language, str(base)]
        if func_addr is not None:
            params.append(str(func_addr))
        return self.call("DecompileHex", _pack(*params), session, mode)

    @check_server_available
    def list_registers(self, language, session=None, mode=None):
        """ListRegisters —— 语言寄存器列表，无需会话"""
        return self.call("ListRegisters", _pack(language), session, mode)

    @check_server_available
    def find_function_starts(self, hex_str, language, base, session=None, mode=None):
        """FindFunctionStarts —— 字节流函数起点扫描，无需会话"""
        return self.call("FindFunctionStarts", _pack(hex_str, language, base), session, mode)

    @check_server_available
    def crc32(self, hex_str, session=None, mode=None):
        """Crc32 —— 字节流 CRC32，无需会话"""
        return self.call("Crc32", _pack(hex_str), session, mode)

    @check_server_available
    def identify_architecture(self, path, session=None, mode=None):
        """IdentifyArchitecture —— 识别文件架构，无需会话"""
        return self.call("IdentifyArchitecture", _pack(path), session, mode)

    @check_server_available
    def emulate_bytes(self, hex_str, language, base, entry=None, max_steps=None,
                      watch_regs=None, session=None, mode=None):
        """EmulateBytes —— 字节流仿真执行
        [hex, lang, base, entry=base, max_steps=1000, watch_regs=""]，无需会话"""
        params = [hex_str, language, str(base)]
        if entry is not None:
            params.append(str(entry))
        if max_steps is not None:
            params.append(str(max_steps))
        if watch_regs is not None:
            params.append(str(watch_regs))
        return self.call("EmulateBytes", _pack(*params), session, mode)

    @check_server_available
    def assemble_instruction(self, asm_text, flag="true", cip=None, session=None, mode=None):
        """AssembleInstruction —— 汇编单条指令 [asm, flag, cip]，无需会话"""
        params = [asm_text, str(flag)]
        if cip is not None:
            params.append(str(cip))
        return self.call("AssembleInstruction", _pack(*params), session, mode)

    @check_server_available
    def assemble_block(self, asm_text, flag="true", base=None, session=None, mode=None):
        """AssembleBlock —— 汇编指令块 [asm, flag, base]，无需会话"""
        params = [asm_text, str(flag)]
        if base is not None:
            params.append(str(base))
        return self.call("AssembleBlock", _pack(*params), session, mode)

    @check_server_available
    def assemble_round_trip(self, asm_text, flag="true", session=None, mode=None):
        """AssembleRoundTrip —— 汇编-反汇编往返校验，无需会话"""
        return self.call("AssembleRoundTrip", _pack(asm_text, flag), session, mode)

    @check_server_available
    def cpp_demangle(self, mangled, session=None, mode=None):
        """CppDemangle —— MSVC 修饰名还原，无需会话"""
        return self.call("CppDemangle", _pack(mangled), session, mode)


class FileApi(BaseHttpClient):
    """文件 / 函数基础"""

    @check_server_available
    def file_basic_info(self, session=None, mode=None):
        """FileBasicInfo —— 文件基本信息（语言/入口/大小）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("FileBasicInfo", _pack(), session, mode)

    @check_server_available
    def function_seeds(self, address, name, kind="0", source="user", session=None, mode=None):
        """FunctionSeeds —— 注入函数种子 [addr, name, kind, source]"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("FunctionSeeds", _pack(address, name, kind, source), session, mode)

    @check_server_available
    def loader_info(self, session=None, mode=None):
        """LoaderInfo —— 文件结构全量解析视图（头字段/数据目录/节区/导入/导出/符号/依赖）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("LoaderInfo", _pack(), session, mode)

    @check_server_available
    def associate_type(self, address, type_name, session=None, mode=None):
        """AssociateType —— 关联模式：把类型（结构体/联合体/typedef）关联到内存地址"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("AssociateType", _pack(address, type_name), session, mode)

    @check_server_available
    def association_list(self, session=None, mode=None):
        """AssociationList —— 关联模式：当前地址->类型 关联表"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("AssociationList", _pack(), session, mode)

    @check_server_available
    def analyzer_list(self, session=None, mode=None):
        """AnalyzerList —— 列出已注册分析器与运行状态"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("AnalyzerList", _pack(), session, mode)

    @check_server_available
    def analyzer_run(self, name, session=None, mode=None):
        """AnalyzerRun —— 按名运行单个分析器（functions/xrefs/strings/signatures/constants/noreturn/typeinfer）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("AnalyzerRun", _pack(name), session, mode)

    @check_server_available
    def struct_infer(self, session=None, mode=None):
        """StructInfer —— 结构体自动推断：扫描基址+偏移访问模式，自动定义结构体并建立地址关联"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("StructInfer", _pack(), session, mode)

    @check_server_available
    def fidb_match(self, sig_path, max_results=None, dump=None, ranges_json=None,
                   refs_json=None, session=None, mode=None):
        """FidbMatch —— 加载 .fidbf 签名库（或 auto），对当前会话函数做真实特征匹配
        （full-hash/prologue/前缀打分；自研 FID）。
        可选：dump="dump" 输出指令哈希转储；ranges_json 注入函数体多段范围；
        refs_json 注入 primary reference（均为外部分析元数据，缺省为空）。"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        params = [sig_path]
        if max_results is not None:
            params.append(str(int(max_results)))
        if dump is not None:
            params.append(str(dump))
        if ranges_json is not None:
            params.append(str(ranges_json))
        if refs_json is not None:
            params.append(str(refs_json))
        return self.call("FidbMatch", _pack(*params), session, mode)

    @check_server_available
    def db_status(self, session=None, mode=None):
        """DbStatus —— 三库（fidb/symbols/gdt/pdb_auto）自动加载状态汇总"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("DbStatus", _pack(), session, mode)

    @check_server_available
    def pdb_load(self, pdb_path, session=None, mode=None):
        """PdbLoad —— 加载 PDB（MSF v7 + DBI + S_PUB32/S_GPROC32），注入函数种子（）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("PdbLoad", _pack(pdb_path), session, mode)

    @check_server_available
    def dwarf_load(self, session=None, mode=None):
        """DwarfLoad —— 从当前镜像 .debug_info 解析 DWARF4/5，注入函数种子（）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("DwarfLoad", _pack(), session, mode)

    @check_server_available
    def session_save(self, path=None, session=None, mode=None):
        """SessionSave —— 导出会话状态（种子/标号/equates/补丁等）到 JSON 文件；path 为空则内联返回"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("SessionSave", _pack(path) if path else _pack(), session, mode)

    @check_server_available
    def session_load(self, path_or_json, session=None, mode=None):
        """SessionLoad —— 从 JSON 文件（或内联 JSON）恢复会话状态（需已装载同一镜像）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("SessionLoad", _pack(path_or_json), session, mode)

    @check_server_available
    def function_strings(self, address, min_length=None, session=None, mode=None):
        """FunctionStrings —— 单函数引用的字符串列表（AI 按需行为指纹）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("FunctionStrings", _pack(address, min_length), session, mode)

    @check_server_available
    def type_infer_at(self, address, session=None, mode=None):
        """TypeInferAt —— 单函数类型推断（参数名/类型 + 返回类型）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("TypeInferAt", _pack(address), session, mode)

    @check_server_available
    def addr_to_function(self, address, session=None, mode=None):
        """AddrToFunction —— 任意地址 → 所属函数/偏移/符号归属解析"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("AddrToFunction", _pack(address), session, mode)

    @check_server_available
    def call_graph_local(self, address, depth=None, direction=None, session=None, mode=None):
        """CallGraphLocal —— 从目标函数出发的 N 层局部调用子图（direction: callees|callers|both）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("CallGraphLocal", _pack(address, depth, direction), session, mode)

    @check_server_available
    def function_summary(self, address, session=None, mode=None):
        """FunctionSummary —— 单函数聚合摘要（大小/块/指令/调用/字符串/跳转表/递归等）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("FunctionSummary", _pack(address), session, mode)

    @check_server_available
    def batch_function_summary(self, addresses, session=None, mode=None):
        """BatchFunctionSummary —— 批量单函数聚合摘要（JSON 地址数组）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("BatchFunctionSummary", _pack(addresses), session, mode)

    @check_server_available
    def batch_function_strings(self, addresses, min_length=None, session=None, mode=None):
        """BatchFunctionStrings —— 批量单函数字符串引用（JSON 地址数组；min_length 缺省 4）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("BatchFunctionStrings", _pack(addresses, min_length), session, mode)

    @check_server_available
    def batch_xrefs(self, addresses, session=None, mode=None):
        """BatchXrefs —— 批量单函数交叉引用（JSON 地址数组；一次全量分析按函数过滤）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("BatchXrefs", _pack(addresses), session, mode)

    @check_server_available
    def function_diff(self, addr1, addr2, session=None, mode=None):
        """FunctionDiff —— 双函数语义对比（块/调用/字符串/类型差异 + 相似度）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("FunctionDiff", _pack(addr1, addr2), session, mode)

    @check_server_available
    def call_site_arguments(self, address, session=None, mode=None):
        """CallSiteArguments —— 单函数全部调用点实参明细（常量/寄存器/unique/mem）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("CallSiteArguments", _pack(address), session, mode)

    @check_server_available
    def data_flow_to(self, address, depth=None, session=None, mode=None):
        """DataFlowTo —— 引用链数据流追踪（谁引用目标地址，1..depth 跳，缺省 2）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("DataFlowTo", _pack(address, depth), session, mode)

    @check_server_available
    def file_diff_summary(self, file2_path, session=None, mode=None):
        """FileDiffSummary —— 跨文件整体统计对比（当前会话=file1，参数=file2 路径）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("FileDiffSummary", _pack(file2_path), session, mode)

    @check_server_available
    def vtable_list(self, min_entries=None, session=None, mode=None):
        """VtableList —— 全镜像虚表识别（数据段连续指向代码的指针序列，缺省 min_entries=3）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("VtableList", _pack(min_entries), session, mode)

    @check_server_available
    def function_level_crypt(self, address, session=None, mode=None):
        """FunctionLevelCrypt —— 单函数加密特征检测（熵 + 常量表 + crypto 调用）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("FunctionLevelCrypt", _pack(address), session, mode)

    @check_server_available
    def string_xref_context(self, address, context=None, session=None, mode=None):
        """StringXrefContext —— 字符串引用的函数级上下文（引用指令前后反汇编窗口，缺省 context=4）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("StringXrefContext", _pack(address, context), session, mode)

    @check_server_available
    def section_table(self, detail=None, session=None, mode=None):
        """SectionTable —— 镜像节表明细（名称/VA/大小/熵/指纹/标志），detail=1..3 缺省 2"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("SectionTable", _pack(detail), session, mode)

    @check_server_available
    def constants_in_function(self, address, min_value=None, max=None, session=None, mode=None):
        """ConstantsInFunction —— 函数内立即数常量收集（魔数/标志/句柄），min_value 过滤、max 上限缺省 256"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("ConstantsInFunction", _pack(address, min_value, max), session, mode)

    @check_server_available
    def create_function(self, address, name=None, overwrite=None, session=None, mode=None):
        """CreateFunction —— 未识别区域创建函数；overwrite=1 时对已有函数改名，成功后刷新函数列表缓存"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("CreateFunction", _pack(address, name, overwrite), session, mode)

    @check_server_available
    def crypto_key_candidates(self, detail=None, max=None, session=None, mode=None):
        """CryptoKeyCandidates —— 全镜像密钥候选：高熵块/可打印密钥/结构密钥（RSA DER/XOR 表/Base64 字母表）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("CryptoKeyCandidates", _pack(detail, max), session, mode)

    @check_server_available
    def file_diff_detail(self, file2_path, max_items=None, session=None, mode=None):
        """FileDiffDetail —— 跨文件函数/字符串级差异明细：added/removed/modified + 独有字符串列表"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("FileDiffDetail", _pack(file2_path, max_items), session, mode)

    @check_server_available
    def similar_function_search(self, address, top_n=None, min_score=None, session=None, mode=None):
        """SimilarFunctionSearch —— 结构签名相似函数搜索（callee Jaccard + 块/指令/调用归一化），秒级全镜像"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("SimilarFunctionSearch", _pack(address, top_n, min_score), session, mode)

    @check_server_available
    def list_functions(self, session=None, mode=None):
        """ListFunctions —— 已识别函数列表"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("ListFunctions", _pack(), session, mode)

    @check_server_available
    def disassemble_at(self, address, count, detail=None, session=None, mode=None):
        """DisassembleAt —— 指定地址反汇编 [addr, count, annotate|cfg(可选)]"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("DisassembleAt", _pack(address, count, detail), session, mode)

    @check_server_available
    def disasm_range(self, address, count, session=None, mode=None):
        """DisasmRange —— 区间反汇编"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("DisasmRange", _pack(address, count), session, mode)

    @check_server_available
    def addr_code(self, address, session=None, mode=None):
        """AddrCode —— 地址取指令/代码信息"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("AddrCode", _pack(address), session, mode)

    @check_server_available
    def text_locate(self, text, format="annotated", session=None, mode=None):
        """TextLocate —— 文本定位（函数名 / 反汇编文本 / 0x 地址），会话模式 [text, format]
        format: annotated|asm|decompile"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("TextLocate", _pack(text, format), session, mode)


class DecompileApi(BaseHttpClient):
    """反编译核心"""

    @check_server_available
    def decompile(self, address, session=None, mode=None):
        """Decompile —— 反编译函数，返回 C 代码"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("Decompile", _pack(address), session, mode)

    @check_server_available
    def decompile_raw(self, func_addr, session=None, mode=None):
        """DecompileRaw —— 引擎原生反编译输出（不经自动美化/后处理；应用用户显式重命名）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("DecompileRaw", _pack(func_addr), session, mode)

    @check_server_available
    def batch_decompile(self, addresses_json, session=None, mode=None):
        """BatchDecompile —— 批量反编译（JSON 地址数组）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("BatchDecompile", _pack(addresses_json), session, mode)

    @check_server_available
    def decompile_xml(self, address, format=None, session=None, mode=None):
        """DecompileXml —— 反编译 XML 中间表示（format: xml/ir，缺省 xml）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        params = [address]
        if format is not None:
            params.append(str(format))
        return self.call("DecompileXml", _pack(*params), session, mode)

    @check_server_available
    def decompile_options(self, session=None, mode=None):
        """DecompileOptions —— 反编译选项（读）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("DecompileOptions", _pack(), session, mode)

    @check_server_available
    def decompile_options_ex(self, session=None, mode=None):
        """DecompileOptionsEx —— 反编译选项（读写）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("DecompileOptionsEx", _pack(), session, mode)

    @check_server_available
    def c_line_map(self, address, session=None, mode=None):
        """CLineMap —— C 行号映射"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("CLineMap", _pack(address), session, mode)

    @check_server_available
    def decode_instruction(self, address, session=None, mode=None):
        """DecodeInstruction —— 单条指令解码"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("DecodeInstruction", _pack(address), session, mode)

    @check_server_available
    def pcode_emit(self, address, count, session=None, mode=None):
        """PcodeEmit —— 输出 p-code"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("PcodeEmit", _pack(address, count), session, mode)

    @check_server_available
    def pcode_dump(self, address, session=None, mode=None):
        """PcodeDump —— p-code 全量转储"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("PcodeDump", _pack(address), session, mode)


class StructApi(BaseHttpClient):
    """函数结构 / 图"""

    @check_server_available
    def function_graph(self, address, session=None, mode=None):
        """FunctionGraph —— 函数调用图"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("FunctionGraph", _pack(address), session, mode)

    @check_server_available
    def cfg_structure(self, address, session=None, mode=None):
        """CfgStructure —— 控制流图结构"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("CfgStructure", _pack(address), session, mode)

    @check_server_available
    def variables(self, address, session=None, mode=None):
        """Variables —— 函数变量分析"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("Variables", _pack(address), session, mode)

    @check_server_available
    def stack_frame(self, address, session=None, mode=None):
        """StackFrame —— 栈帧布局"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("StackFrame", _pack(address), session, mode)

    @check_server_available
    def prototype(self, address, session=None, mode=None):
        """Prototype —— 函数原型"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("Prototype", _pack(address), session, mode)

    @check_server_available
    def param_id(self, address, session=None, mode=None):
        """ParamID —— 参数识别"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("ParamID", _pack(address), session, mode)

    @check_server_available
    def switches(self, address, session=None, mode=None):
        """Switches —— switch 跳转表分析"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("Switches", _pack(address), session, mode)

    @check_server_available
    def function_hash(self, address, session=None, mode=None):
        """FunctionHash —— 函数哈希/指纹"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("FunctionHash", _pack(address), session, mode)

    @check_server_available
    def dot_export(self, address, kind=None, session=None, mode=None):
        """DotExport —— 导出 dot 图（kind: cfg 等，缺省 cfg）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        params = [address]
        if kind is not None:
            params.append(str(kind))
        return self.call("DotExport", _pack(*params), session, mode)

    @check_server_available
    def opcode_histogram(self, address, session=None, mode=None):
        """OpcodeHistogram —— 操作码直方图"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("OpcodeHistogram", _pack(address), session, mode)


class XrefApi(BaseHttpClient):
    """交叉引用 / 数据"""

    @check_server_available
    def xrefs(self, address, session=None, mode=None):
        """Xrefs —— 交叉引用"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("Xrefs", _pack(address), session, mode)

    @check_server_available
    def call_sites(self, address, session=None, mode=None):
        """CallSites —— 调用点"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("CallSites", _pack(address), session, mode)

    @check_server_available
    def call_graph(self, session=None, mode=None):
        """CallGraph —— 全图调用图"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("CallGraph", _pack(), session, mode)

    @check_server_available
    def string_xrefs(self, min_length=None, session=None, mode=None):
        """StringXrefs —— 字符串引用（min_length 过滤，缺省 4）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        params = []
        if min_length is not None:
            params.append(str(min_length))
        return self.call("StringXrefs", _pack(*params), session, mode)

    @check_server_available
    def data_xrefs(self, address, session=None, mode=None):
        """DataXrefs —— 数据交叉引用"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("DataXrefs", _pack(address), session, mode)

    @check_server_available
    def data_xref_all(self, session=None, mode=None):
        """DataXrefAll —— 全量数据引用"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("DataXrefAll", _pack(), session, mode)

    @check_server_available
    def jump_table_detail(self, address, session=None, mode=None):
        """JumpTableDetail —— 跳转表明细"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("JumpTableDetail", _pack(address), session, mode)

    @check_server_available
    def strings(self, session=None, mode=None):
        """Strings —— 字符串扫描"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("Strings", _pack(), session, mode)

    @check_server_available
    def memory_dump(self, address, size, session=None, mode=None):
        """MemoryDump —— 内存转储"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("MemoryDump", _pack(address, size), session, mode)

    @check_server_available
    def hex_entropy(self, address, size, session=None, mode=None):
        """HexEntropy —— 区间熵"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("HexEntropy", _pack(address, size), session, mode)

    @check_server_available
    def entropy_profile(self, address, size, bins, session=None, mode=None):
        """EntropyProfile —— 分箱熵轮廓"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("EntropyProfile", _pack(address, size, bins), session, mode)

    @check_server_available
    def byte_pattern_search(self, pattern, limit=None, session=None, mode=None):
        """BytePatternSearch —— 字节模式搜索（如 55 8b ec；'?' 通配；limit 缺省 64）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        params = [pattern]
        if limit is not None:
            params.append(str(limit))
        return self.call("BytePatternSearch", _pack(*params), session, mode)

    @check_server_available
    def unicode_string(self, count, session=None, mode=None):
        """UnicodeString —— Unicode 字符串提取"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("UnicodeString", _pack(count), session, mode)

    @check_server_available
    def import_table(self, session=None, mode=None):
        """ImportTable —— 导入表"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("ImportTable", _pack(), session, mode)

    @check_server_available
    def export_table(self, session=None, mode=None):
        """ExportTable —— 导出表"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("ExportTable", _pack(), session, mode)

    @check_server_available
    def globals(self, session=None, mode=None):
        """Globals —— 全局变量分析"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("Globals", _pack(), session, mode)


class TypeApi(BaseHttpClient):
    """类型 / 深度分析"""

    @check_server_available
    def types(self, kind="list", session=None, mode=None):
        """Types —— 类型表（kind: list）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("Types", _pack(kind), session, mode)

    @check_server_available
    def type_define(self, kind, name, spec_json, session=None, mode=None):
        """TypeDefine —— 定义结构体类型 [kind, name, JSON字段数组]（kind 常用 struct）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("TypeDefine", _pack(kind, name, spec_json), session, mode)

    @check_server_available
    def call_conv_list(self, session=None, mode=None):
        """CallConvList —— 调用约定列表"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("CallConvList", _pack(), session, mode)

    @check_server_available
    def type_propagate(self, address, target="return", type_name="int", session=None, mode=None):
        """TypePropagate —— 类型传播 [addr, target, type_name]；target = "return" | "param:<n>" | "local:<name>" """
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("TypePropagate", _pack(address, target, type_name), session, mode)

    @check_server_available
    def type_infer_all(self, session=None, mode=None):
        """TypeInferAll —— 全量类型推断"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("TypeInferAll", _pack(), session, mode)

    @check_server_available
    def analyze_all(self, session=None, mode=None):
        """AnalyzeAll —— 全量分析（重算全部结果）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("AnalyzeAll", _pack(), session, mode)

    @check_server_available
    def signatures(self, session=None, mode=None):
        """Signatures —— 函数签名识别"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("Signatures", _pack(), session, mode)


class DetectApi(BaseHttpClient):
    """检测 / 仿真"""

    @check_server_available
    def crypt_detect(self, address, size, bins, session=None, mode=None):
        """CryptDetect —— 加密算法检测"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("CryptDetect", _pack(address, size, bins), session, mode)

    @check_server_available
    def obfuscation_detect(self, address, session=None, mode=None):
        """ObfuscationDetect —— 混淆检测"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("ObfuscationDetect", _pack(address), session, mode)

    @check_server_available
    def recursion_detect(self, address=None, session=None, mode=None):
        """RecursionDetect —— 递归检测（address 缺省为全量）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        params = []
        if address is not None:
            params.append(str(address))
        return self.call("RecursionDetect", _pack(*params), session, mode)

    @check_server_available
    def recursion_detect_fast(self, address=None, session=None, mode=None):
        """RecursionDetectFast —— 轻量递归检测（仅直连调用边，大二进制秒级返回）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        params = []
        if address is not None:
            params.append(str(address))
        return self.call("RecursionDetectFast", _pack(*params), session, mode)

    @check_server_available
    def inline_detect(self, address, session=None, mode=None):
        """InlineDetect —— 内联检测"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("InlineDetect", _pack(address), session, mode)

    @check_server_available
    def tail_call_detect(self, address, session=None, mode=None):
        """TailCallDetect —— 尾调用检测"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("TailCallDetect", _pack(address), session, mode)

    @check_server_available
    def unreachable_code(self, address, session=None, mode=None):
        """UnreachableCode —— 不可达代码"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("UnreachableCode", _pack(address), session, mode)

    @check_server_available
    def loop_info(self, address, session=None, mode=None):
        """LoopInfo —— 循环分析"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("LoopInfo", _pack(address), session, mode)

    @check_server_available
    def stack_depth(self, address, session=None, mode=None):
        """StackDepth —— 栈深度"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("StackDepth", _pack(address), session, mode)

    @check_server_available
    def instruction_coverage(self, address, session=None, mode=None):
        """InstructionCoverage —— 指令覆盖率"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("InstructionCoverage", _pack(address), session, mode)

    @check_server_available
    def api_sequence(self, address, session=None, mode=None):
        """ApiSequence —— API 调用序列"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("ApiSequence", _pack(address), session, mode)

    @check_server_available
    def function_similarity(self, address, top_n=None, candidates_json=None, session=None, mode=None):
        """FunctionSimilarity —— 函数相似度（top_n 缺省 20；candidates_json 可选候选地址数组）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        params = [address]
        if top_n is not None:
            params.append(str(top_n))
        if candidates_json is not None:
            params.append(str(candidates_json))
        return self.call("FunctionSimilarity", _pack(*params), session, mode)

    @check_server_available
    def emulate(self, address, steps=None, watch=None, session=None, mode=None):
        """Emulate —— 仿真执行函数 [addr, steps=1000, watch=""]"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        params = [address]
        if steps is not None:
            params.append(str(steps))
        if watch is not None:
            params.append(str(watch))
        return self.call("Emulate", _pack(*params), session, mode)

    @check_server_available
    def emulate_ex(self, address, steps=None, watch=None, init_regs=None, init_mem=None,
                   branch_trace=None, externs=None, session=None, mode=None):
        """EmulateEx —— 仿真执行（扩展）
        [addr, steps=1000, watch="", init_regs, init_mem, branch_trace, externs]"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        params = [address]
        for v in (steps, watch, init_regs, init_mem, branch_trace, externs):
            if v is not None:
                params.append(str(v))
        return self.call("EmulateEx", _pack(*params), session, mode)

    @check_server_available
    def emulate_watch(self, address, steps=None, exprs=None, session=None, mode=None):
        """EmulateWatch —— 仿真单步观察 [addr, steps=1000, exprs=""]"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        params = [address]
        if steps is not None:
            params.append(str(steps))
        if exprs is not None:
            params.append(str(exprs))
        return self.call("EmulateWatch", _pack(*params), session, mode)

    @check_server_available
    def dangerous_calls(self, address, session=None, mode=None):
        """DangerousCalls —— 危险 API 调用"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("DangerousCalls", _pack(address), session, mode)


class EditApi(BaseHttpClient):
    """标注 / 修改 / 审计"""

    @check_server_available
    def rename(self, address, new_name, session=None, mode=None):
        """Rename —— 函数重命名"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("Rename", _pack(address, new_name), session, mode)

    @check_server_available
    def rename_variable(self, func_addr, var_name, new_name, session=None, mode=None):
        """RenameVariable —— 变量/参数名重命名（内存态，下次反编译自动绑定）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("RenameVariable", _pack(func_addr, var_name, new_name), session, mode)

    @check_server_available
    def rename_type(self, old_name, new_name, session=None, mode=None):
        """RenameType —— 结构体/联合体等类型名重命名（内存态，下次反编译自动绑定）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("RenameType", _pack(old_name, new_name), session, mode)

    @check_server_available
    def rename_list(self, session=None, mode=None):
        """RenameList —— 列出当前会话全部变量/类型重命名映射"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("RenameList", _pack(), session, mode)

    @check_server_available
    def comment(self, address, text, kind=None, session=None, mode=None):
        """Comment —— 添加注释 [addr, text, kind=0]（kind: 0 常规 / 1 行前 / 2 行后 / 8 函数头）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        params = [address, text]
        if kind is not None:
            params.append(str(kind))
        return self.call("Comment", _pack(*params), session, mode)

    @check_server_available
    def comment_list(self, address, session=None, mode=None):
        """CommentList —— 注释列表"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("CommentList", _pack(address), session, mode)

    @check_server_available
    def label_add(self, address, label, session=None, mode=None):
        """LabelAdd —— 添加标签"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("LabelAdd", _pack(address, label), session, mode)

    @check_server_available
    def label_list(self, address=None, session=None, mode=None):
        """LabelList —— 标签列表（address 缺省为全量）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        params = []
        if address is not None:
            params.append(str(address))
        return self.call("LabelList", _pack(*params), session, mode)

    @check_server_available
    def override_add(self, func_addr, kind, at, target=None, flow_type=None, session=None, mode=None):
        """OverrideAdd —— 覆写调用目标 [function_addr, kind, at, target=0, flow_type=0]（kind 常用 indirect）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        params = _pack(func_addr, kind, at)
        if target is not None:
            params.append(str(target))
        if flow_type is not None:
            params.append(str(flow_type))
        return self.call("OverrideAdd", params, session, mode)

    @check_server_available
    def override_list(self, address, session=None, mode=None):
        """OverrideList —— 覆写列表"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("OverrideList", _pack(address), session, mode)

    @check_server_available
    def equate_add(self, value, name, session=None, mode=None):
        """EquateAdd —— 定义常量（equate）[value, name]"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("EquateAdd", _pack(value, name), session, mode)

    @check_server_available
    def equate_list(self, session=None, mode=None):
        """EquateList —— 常量列表"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("EquateList", _pack(), session, mode)

    @check_server_available
    def context_get(self, address, context="flow", session=None, mode=None):
        """ContextGet —— 读取寄存器上下文"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("ContextGet", _pack(address, context), session, mode)

    @check_server_available
    def context_set(self, address, key, value, session=None, mode=None):
        """ContextSet —— 设置寄存器上下文"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("ContextSet", _pack(address, key, value), session, mode)

    @check_server_available
    def arch_option_list(self, option_name=None, session=None, mode=None):
        """ArchOptionList —— 架构选项列表（option_name 缺省为全部）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        params = []
        if option_name is not None:
            params.append(str(option_name))
        return self.call("ArchOptionList", _pack(*params), session, mode)

    @check_server_available
    def arch_option_set(self, key, value, session=None, mode=None):
        """ArchOptionSet —— 设置架构选项"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("ArchOptionSet", _pack(key, value), session, mode)

    @check_server_available
    def external_mark(self, address, ref_addr=0, name="", session=None, mode=None):
        """ExternalMark —— 标记外部调用 [addr, ref_addr=0, 名称]"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("ExternalMark", _pack(address, ref_addr, name), session, mode)

    @check_server_available
    def patch_bytes(self, address, hex_data, session=None, mode=None):
        """PatchBytes —— 补丁字节（只读模式返回 E_READONLY）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("PatchBytes", _pack(address, hex_data), session, mode)

    @check_server_available
    def patch_history(self, session=None, mode=None):
        """PatchHistory —— 补丁历史"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("PatchHistory", _pack(), session, mode)

    @check_server_available
    def undo_patch(self, session=None, mode=None):
        """UndoPatch —— 撤销补丁"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("UndoPatch", _pack(), session, mode)

    @check_server_available
    def inject_payload(self, payload_name=None, session=None, mode=None):
        """InjectPayload —— 注入载荷（payload_name 缺省列出全部）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        params = []
        if payload_name is not None:
            params.append(str(payload_name))
        return self.call("InjectPayload", _pack(*params), session, mode)

    @check_server_available
    def register_snapshot(self, address, max_steps=None, regs_csv=None, session=None, mode=None):
        """RegisterSnapshot —— 寄存器快照 [addr, max_steps=64, regs_csv=""]"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        params = [address]
        if max_steps is not None:
            params.append(str(max_steps))
        if regs_csv is not None:
            params.append(str(regs_csv))
        return self.call("RegisterSnapshot", _pack(*params), session, mode)

    @check_server_available
    def define_data(self, address, data_type, size, session=None, mode=None):
        """DefineData —— 定义数据 [addr, type, size]"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("DefineData", _pack(address, data_type, size), session, mode)

    @check_server_available
    def data_mark_list(self, session=None, mode=None):
        """DataMarkList —— 数据标记列表"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("DataMarkList", _pack(), session, mode)

    @check_server_available
    def symbol_search(self, keyword, limit=None, session=None, mode=None):
        """SymbolSearch —— 符号搜索（limit 缺省 64）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        params = [keyword]
        if limit is not None:
            params.append(str(limit))
        return self.call("SymbolSearch", _pack(*params), session, mode)

    @check_server_available
    def session_dashboard(self, session=None, mode=None):
        """SessionDashboard —— 会话面板"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("SessionDashboard", _pack(), session, mode)

    @check_server_available
    def batch_session(self, addresses_json, session=None, mode=None):
        """BatchSession —— 批量会话分析（JSON 地址数组）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("BatchSession", _pack(addresses_json), session, mode)

    @check_server_available
    def bytes_to_number(self, address, width="4", endian="le", session=None, mode=None):
        """BytesToNumber —— 读内存字节转数值 [addr, width=4, endian=le]"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("BytesToNumber", _pack(address, width, endian), session, mode)

    @check_server_available
    def search_immediate(self, imm, width=None, endian=None, session=None, mode=None):
        """SearchImmediate —— 立即数搜索 [imm, width=4, endian=le]（width: 1/2/4/8）"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        params = [imm]
        if width is not None:
            params.append(str(width))
        if endian is not None:
            params.append(str(endian))
        return self.call("SearchImmediate", _pack(*params), session, mode)

    @check_server_available
    def register_usage(self, address, count, session=None, mode=None):
        """RegisterUsage —— 寄存器使用"""
        if session is None and not getattr(self.config, "session", None):
            return self._session_required()
        return self.call("RegisterUsage", _pack(address, count), session, mode)


class AlignApi(BaseHttpClient):
    """高级接口族（P0/P1 移植，全部 session 域）。"""

    @check_server_available
    def override_proto(self, func_addr, callpoint, proto_decl, session=None, mode=None):
        """OverrideProto —— 原型覆盖：给指定调用点安装原型覆盖
        proto_decl = [model:]ret_type[:p1[,p2...]]"""
        return self.call("OverrideProto", _pack(func_addr, callpoint, proto_decl), session, mode)

    @check_server_available
    def override_jump_table(self, func_addr, jmpaddr, startval, targets, session=None, mode=None):
        """OverrideJumpTable —— 跳转表覆盖：覆盖跳转表地址表"""
        params = [func_addr, jmpaddr, startval] + list(targets)
        return self.call("OverrideJumpTable", _pack(*params), session, mode)

    @check_server_available
    def override_flow(self, func_addr, at, type_str, session=None, mode=None):
        """OverrideFlow —— 流程覆盖：branch|call|callreturn|return"""
        return self.call("OverrideFlow", _pack(func_addr, at, type_str), session, mode)

    @check_server_available
    def force_format(self, func_addr, varnode_desc, format, session=None, mode=None):
        """ForceFormat —— 强制变量显示格式 hex|dec|oct|bin|char"""
        return self.call("ForceFormat", _pack(func_addr, varnode_desc, format), session, mode)

    @check_server_available
    def force_datatype_format(self, type_name, format, session=None, mode=None):
        """ForceDatatypeFormat —— Ghidra forceformat 类型版：强制数据类型显示格式"""
        return self.call("ForceDatatypeFormat", _pack(type_name, format), session, mode)

    @check_server_available
    def isolate(self, func_addr, symbol_name, session=None, mode=None):
        """Isolate —— 隔离符号：隔离符号（禁止参与类型传播）"""
        return self.call("Isolate", _pack(func_addr, symbol_name), session, mode)

    @check_server_available
    def retype(self, func_addr, symbol_name, type_name, session=None, mode=None):
        """Retype —— 重定类型：重定符号类型并锁定"""
        return self.call("Retype", _pack(func_addr, symbol_name, type_name), session, mode)

    @check_server_available
    def volatile_mark(self, addr, size, session=None, mode=None):
        """Volatile —— volatile 标记：标记内存区间为 volatile"""
        return self.call("Volatile", _pack(addr, size), session, mode)

    @check_server_available
    def readonly_mark(self, addr, size, session=None, mode=None):
        """Readonly —— 只读标记：标记内存区间为只读"""
        return self.call("Readonly", _pack(addr, size), session, mode)

    @check_server_available
    def pointer_setting(self, name, base_type, setting, value, session=None, mode=None):
        """PointerSetting —— 指针设置：offset|space 指针类型参数设置"""
        return self.call("PointerSetting", _pack(name, base_type, setting, value), session, mode)

    @check_server_available
    def prefer_split(self, addr, size, split, session=None, mode=None):
        """PreferSplit —— 拆分点设置：指定结构化变量拆分点 (0 < split < size)"""
        return self.call("PreferSplit", _pack(addr, size, split), session, mode)

    @check_server_available
    def deadcode_delay(self, func_addr, space_name, delay, session=None, mode=None):
        """DeadcodeDelay —— 死代码延迟：设置指定空间的死代码延迟轮数"""
        return self.call("DeadcodeDelay", _pack(func_addr, space_name, delay), session, mode)

    @check_server_available
    def prototype_lock(self, func_addr, session=None, mode=None):
        """PrototypeLock —— 锁定原型：锁定函数原型（输入/输出槽位）"""
        return self.call("PrototypeLock", _pack(func_addr), session, mode)

    @check_server_available
    def prototype_unlock(self, func_addr, session=None, mode=None):
        """PrototypeUnlock —— 解锁原型：解锁函数原型"""
        return self.call("PrototypeUnlock", _pack(func_addr), session, mode)

    @check_server_available
    def call_fixup_add(self, name, pcode_snippet, session=None, mode=None):
        """CallFixupAdd —— 调用固定：注册调用固定（p-code 模板）"""
        return self.call("CallFixupAdd", _pack(name, pcode_snippet), session, mode)

    @check_server_available
    def call_other_fixup_add(self, name, outname, inname_csv, pcode_snippet, session=None, mode=None):
        """CallOtherFixupAdd —— CALLOTHER 固定：注册 CALLOTHER 固定"""
        return self.call("CallOtherFixupAdd", _pack(name, outname, inname_csv, pcode_snippet), session, mode)

    @check_server_available
    def fixup_apply(self, fixup_name, func_addr, session=None, mode=None):
        """FixupApply —— 应用固定：给函数应用已注册的 call fixup"""
        return self.call("FixupApply", _pack(fixup_name, func_addr), session, mode)

    @check_server_available
    def action_stats(self, session=None, mode=None):
        """ActionStats —— Action 统计：打印流水线 Action 统计"""
        return self.call("ActionStats", _pack(), session, mode)

    @check_server_available
    def action_stats_reset(self, session=None, mode=None):
        """ActionStatsReset —— 清零 Action 统计：清零 Action 统计"""
        return self.call("ActionStatsReset", _pack(), session, mode)

    @check_server_available
    def count_pcode(self, func_addr, session=None, mode=None):
        """CountPcode —— pcode 计数：统计 p-code 指令数"""
        return self.call("CountPcode", _pack(func_addr), session, mode)

    @check_server_available
    def print_tree(self, func_addr, session=None, mode=None):
        """PrintTree —— 表达式树：打印高亮表达式树"""
        return self.call("PrintTree", _pack(func_addr), session, mode)

    @check_server_available
    def print_block_tree(self, func_addr, session=None, mode=None):
        """PrintBlockTree —— 基本块树：打印基本块树"""
        return self.call("PrintBlockTree", _pack(func_addr), session, mode)

    @check_server_available
    def print_raw(self, func_addr, session=None, mode=None):
        """PrintRaw —— 原始 pcode：打印原始 p-code"""
        return self.call("PrintRaw", _pack(func_addr), session, mode)

    @check_server_available
    def print_local_range(self, func_addr, session=None, mode=None):
        """PrintLocalRange —— 局部变量区间：打印局部变量内存区间"""
        return self.call("PrintLocalRange", _pack(func_addr), session, mode)

    @check_server_available
    def decompile_marshal(self, func_addr, session=None, mode=None):
        """DecompileMarshal —— 引擎原生 marshal XML"""
        return self.call("DecompileMarshal", _pack(func_addr), session, mode)

    @check_server_available
    def type_infer_native(self, func_addr, session=None, mode=None):
        """TypeInferNative —— 引擎原生类型传播（重跑完整反编译流水线 + 原型输出）"""
        return self.call("TypeInferNative", _pack(func_addr), session, mode)

    @check_server_available
    def struct_infer_native(self, func_addr, session=None, mode=None):
        """StructInferNative —— SDK 原生结构恢复（流水线重跑 + 结构体访问统计）"""
        return self.call("StructInferNative", _pack(func_addr), session, mode)

class BinDetectiveClient(
    SessionApi,
    ServiceApi,
    DirectApi,
    FileApi,
    DecompileApi,
    StructApi,
    XrefApi,
    TypeApi,
    DetectApi,
    EditApi,
    AlignApi):
    """BinDetective 全功能客户端：聚合 161 个接口（direct 18 + session 143），与 main.cpp interfaceList 保持一致。"""

    def __init__(self, config: Optional[Config] = None, address: str = "",
                 port: int = DEFAULT_PORT, api_key: Optional[str] = None,
                 session: Optional[str] = None, timeout: int = 5,
                 response: str = "str", probe_timeout: float = 1.5,
                 probe_ttl: float = 10.0):
        if config is None:
            config = Config(address=address or "127.0.0.1", port=port,
                            api_key=api_key, session=session, timeout=timeout,
                            response=response, probe_timeout=probe_timeout,
                            probe_ttl=probe_ttl)
        else:
            if api_key:
                config.set_api_key(api_key)
            if session:
                config.set_session(session)
        super().__init__(config)

    def bind(self, address: str, port: int = DEFAULT_PORT,
             api_key: Optional[str] = None) -> "BinDetectiveClient":
        """切换目标服务；api_key 为 None 时保留原有 token。"""
        self.set_server(address, port)
        if api_key is not None:
            self.set_api_key(api_key)
        return self

    def server_info(self) -> str:
        """GET / —— 服务信息（plugin_info / interfaces / interface_modes / languages）。"""
        return self.custom_get()

    def server_info_json(self) -> Optional[Dict]:
        """GET / 的 dict 版本。"""
        return parse_response(self.custom_get())


IFACE_METHODS = (
    ("Open", "open"),
    ("FileBasicInfo", "file_basic_info"),
    ("FunctionSeeds", "function_seeds"),
    ("ListFunctions", "list_functions"),
    ("DisassembleAt", "disassemble_at"),
    ("Decompile", "decompile"),
    ("DecompileRaw", "decompile_raw"),
    ("FunctionGraph", "function_graph"),
    ("Xrefs", "xrefs"),
    ("Signatures", "signatures"),
    ("CallGraph", "call_graph"),
    ("CallSites", "call_sites"),
    ("Strings", "strings"),
    ("MemoryDump", "memory_dump"),
    ("Types", "types"),
    ("AnalyzeAll", "analyze_all"),
    ("AddrCode", "addr_code"),
    ("TextLocate", "text_locate"),
    ("DecompileHex", "decompile_hex"),
    ("ListLanguages", "list_languages"),
    ("DecodeInstruction", "decode_instruction"),
    ("PcodeEmit", "pcode_emit"),
    ("SearchImmediate", "search_immediate"),
    ("DisasmBytes", "disasm_bytes"),
    ("ListRegisters", "list_registers"),
    ("FindFunctionStarts", "find_function_starts"),
    ("HexEntropy", "hex_entropy"),
    ("DisasmRange", "disasm_range"),
    ("RegisterUsage", "register_usage"),
    ("Crc32", "crc32"),
    ("BytesToNumber", "bytes_to_number"),
    ("IdentifyArchitecture", "identify_architecture"),
    ("SessionCreate", "session_create"),
    ("SessionList", "session_list"),
    ("SessionClose", "session_close"),
    ("Switches", "switches"),
    ("ParamID", "param_id"),
    ("Prototype", "prototype"),
    ("PcodeDump", "pcode_dump"),
    ("Emulate", "emulate"),
    ("EmulateBytes", "emulate_bytes"),
    ("FunctionHash", "function_hash"),
    ("CfgStructure", "cfg_structure"),
    ("Variables", "variables"),
    ("OverrideAdd", "override_add"),
    ("OverrideList", "override_list"),
    ("DecompileOptions", "decompile_options"),
    ("CLineMap", "c_line_map"),
    ("Rename", "rename"),
    ("RenameVariable", "rename_variable"),
    ("RenameType", "rename_type"),
    ("RenameList", "rename_list"),
    ("Comment", "comment"),
    ("CommentList", "comment_list"),
    ("BatchDecompile", "batch_decompile"),
    ("StringXrefs", "string_xrefs"),
    ("StackFrame", "stack_frame"),
    ("DotExport", "dot_export"),
    ("DataXrefs", "data_xrefs"),
    ("EmulateEx", "emulate_ex"),
    ("FunctionSimilarity", "function_similarity"),
    ("CryptDetect", "crypt_detect"),
    ("TypePropagate", "type_propagate"),
    ("CallConvList", "call_conv_list"),
    ("ObfuscationDetect", "obfuscation_detect"),
    ("ApiSequence", "api_sequence"),
    ("DecompileOptionsEx", "decompile_options_ex"),
    ("AssembleInstruction", "assemble_instruction"),
    ("AssembleBlock", "assemble_block"),
    ("AssembleRoundTrip", "assemble_round_trip"),
    ("CppDemangle", "cpp_demangle"),
    ("UnicodeString", "unicode_string"),
    ("ImportTable", "import_table"),
    ("ExportTable", "export_table"),
    ("DangerousCalls", "dangerous_calls"),
    ("GenerateOpenAPI", "generate_openapi"),
    ("OpcodeHistogram", "opcode_histogram"),
    ("EntropyProfile", "entropy_profile"),
    ("StackDepth", "stack_depth"),
    ("UnreachableCode", "unreachable_code"),
    ("InlineDetect", "inline_detect"),
    ("TailCallDetect", "tail_call_detect"),
    ("Globals", "globals"),
    ("LoopInfo", "loop_info"),
    ("InstructionCoverage", "instruction_coverage"),
    ("EmulateWatch", "emulate_watch"),
    ("HealthStats", "health_stats"),
    ("BatchSession", "batch_session"),
    ("ContextGet", "context_get"),
    ("ContextSet", "context_set"),
    ("LabelAdd", "label_add"),
    ("LabelList", "label_list"),
    ("TypeDefine", "type_define"),
    ("ArchOptionList", "arch_option_list"),
    ("ArchOptionSet", "arch_option_set"),
    ("ExternalMark", "external_mark"),
    ("DecompileXml", "decompile_xml"),
    ("InjectPayload", "inject_payload"),
    ("RecursionDetect", "recursion_detect"),
    ("RecursionDetectFast", "recursion_detect_fast"),
    ("TypeInferAll", "type_infer_all"),
    ("JumpTableDetail", "jump_table_detail"),
    ("RegisterSnapshot", "register_snapshot"),
    ("DataXrefAll", "data_xref_all"),
    ("SessionDashboard", "session_dashboard"),
    ("PatchBytes", "patch_bytes"),
    ("PatchHistory", "patch_history"),
    ("UndoPatch", "undo_patch"),
    ("BytePatternSearch", "byte_pattern_search"),
    ("EquateAdd", "equate_add"),
    ("EquateList", "equate_list"),
    ("DefineData", "define_data"),
    ("DataMarkList", "data_mark_list"),
    ("SymbolSearch", "symbol_search"),
    ("OverrideProto", "override_proto"),
    ("OverrideJumpTable", "override_jump_table"),
    ("OverrideFlow", "override_flow"),
    ("ForceFormat", "force_format"),
    ("ForceDatatypeFormat", "force_datatype_format"),
    ("Isolate", "isolate"),
    ("Retype", "retype"),
    ("Volatile", "volatile_mark"),
    ("Readonly", "readonly_mark"),
    ("PointerSetting", "pointer_setting"),
    ("PreferSplit", "prefer_split"),
    ("DeadcodeDelay", "deadcode_delay"),
    ("PrototypeLock", "prototype_lock"),
    ("PrototypeUnlock", "prototype_unlock"),
    ("CallFixupAdd", "call_fixup_add"),
    ("CallOtherFixupAdd", "call_other_fixup_add"),
    ("FixupApply", "fixup_apply"),
    ("ActionStats", "action_stats"),
    ("ActionStatsReset", "action_stats_reset"),
    ("CountPcode", "count_pcode"),
    ("PrintTree", "print_tree"),
    ("PrintBlockTree", "print_block_tree"),
    ("PrintRaw", "print_raw"),
    ("PrintLocalRange", "print_local_range"),
    ("DecompileMarshal", "decompile_marshal"),
    ("TypeInferNative", "type_infer_native"),
    ("StructInferNative", "struct_infer_native"),
    ("LoaderInfo", "loader_info"),
    ("AssociateType", "associate_type"),
    ("AssociationList", "association_list"),
    ("AnalyzerList", "analyzer_list"),
    ("AnalyzerRun", "analyzer_run"),
    ("StructInfer", "struct_infer"),
    ("FidbMatch", "fidb_match"),
    ("DbStatus", "db_status"),
    ("PdbLoad", "pdb_load"),
    ("DwarfLoad", "dwarf_load"),
    ("SessionSave", "session_save"),
    ("SessionLoad", "session_load"),
    ("FunctionStrings", "function_strings"),
    ("TypeInferAt", "type_infer_at"),
    ("AddrToFunction", "addr_to_function"),
    ("CallGraphLocal", "call_graph_local"),
    ("FunctionSummary", "function_summary"),
    ("BatchFunctionSummary", "batch_function_summary"),
    ("BatchFunctionStrings", "batch_function_strings"),
    ("BatchXrefs", "batch_xrefs"),
    ("FunctionDiff", "function_diff"),
    ("CallSiteArguments", "call_site_arguments"),
    ("DataFlowTo", "data_flow_to"),
    ("FileDiffSummary", "file_diff_summary"),
    ("VtableList", "vtable_list"),
    ("FunctionLevelCrypt", "function_level_crypt"),
    ("StringXrefContext", "string_xref_context"),
    ("SectionTable", "section_table"),
    ("ConstantsInFunction", "constants_in_function"),
    ("CreateFunction", "create_function"),
    ("CryptoKeyCandidates", "crypto_key_candidates"),
    ("FileDiffDetail", "file_diff_detail"),
    ("SimilarFunctionSearch", "similar_function_search"),
)

def _self_check() -> None:
    """import 时自检：注册表/接口集/方法集/调用信息四方一致，防止手工编辑漂移。
    """
    import inspect as _inspect
    problems = []
    if set(INTERFACE_MODES) != set(SUPPORTED_INTERFACES):
        problems.append("INTERFACE_MODES 与 SUPPORTED_INTERFACES 键集不一致")
    if set(INTERFACE_CALL_INFO) != set(SUPPORTED_INTERFACES):
        problems.append("INTERFACE_CALL_INFO 与 SUPPORTED_INTERFACES 键集不一致")
    if len(SUPPORTED_INTERFACES) < 100:
        problems.append("接口总数异常偏少: %d" % len(SUPPORTED_INTERFACES))
    iface_to_method = dict(IFACE_METHODS)
    if set(iface_to_method) != set(SUPPORTED_INTERFACES) or len(iface_to_method) != len(SUPPORTED_INTERFACES):
        problems.append("IFACE_METHODS 与 SUPPORTED_INTERFACES 未 1:1 覆盖")
    missing = [m for _i, m in IFACE_METHODS if not hasattr(BinDetectiveClient, m)]
    if missing:
        problems.append("缺失方法: " + ", ".join(missing))
    for iface, info in INTERFACE_CALL_INFO.items():
        if info.get("mode") != INTERFACE_MODES.get(iface):
            problems.append("INTERFACE_CALL_INFO[%s] mode 与 INTERFACE_MODES 不一致" % iface)
    for iface, info in INTERFACE_CALL_INFO.items():
        method = iface_to_method.get(iface)
        if not method or not hasattr(BinDetectiveClient, method):
            continue
        fn = getattr(BinDetectiveClient, method)
        sig = _inspect.signature(fn)
        count = 0
        for pname, p in sig.parameters.items():
            if pname in ("self", "session", "mode"):
                continue
            if p.kind in (_inspect.Parameter.POSITIONAL_OR_KEYWORD,
                          _inspect.Parameter.KEYWORD_ONLY):
                count += 1
        if count != len(info.get("params", [])):
            problems.append("%s 参数数不一致: 方法签名 %d vs 调用信息 %d"
                            % (iface, count, len(info.get("params", []))))
    if problems:
        raise ImportError("bin_detective_client self-check failed:\n  - " + "\n  - ".join(problems))

_self_check()
