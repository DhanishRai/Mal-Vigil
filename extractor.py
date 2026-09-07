import math
import pefile

SUSPICIOUS_APIS = {
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", 
    "CreateRemoteThread", "WinExec", "ShellExecuteA", 
    "URLDownloadToFileA", "InternetOpenA", "HttpSendRequestA"
}

def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy to detect packed or encrypted payloads."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / length
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

def extract_features(file_path: str) -> list:
    """
    Extracts 7 structural indicators from a PE file:
    [num_sections, max_entropy, mean_entropy, has_rwe, susp_api_count, total_imports, size_ratio]
    """
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    except Exception:
        # If unparseable or corrupted, mark high suspicion fallback
        return [0, 8.0, 8.0, 1, 5, 0, 2.0]

    # 1. Section metrics & Shannon entropy
    num_sections = len(pe.sections)
    entropies = []
    rwe_count = 0
    total_raw_size = 0
    total_virt_size = 0

    for s in pe.sections:
        data = s.get_data()
        entropies.append(calculate_entropy(data))
        total_raw_size += s.SizeOfRawData
        total_virt_size += s.Misc_VirtualSize

        # Check for Read-Write-Execute flags (IMAGE_SCN_MEM_EXECUTE & IMAGE_SCN_MEM_WRITE)
        if (s.Characteristics & 0x20000000) and (s.Characteristics & 0x80000000):
            rwe_count += 1

    max_entropy = max(entropies) if entropies else 0.0
    mean_entropy = sum(entropies) / len(entropies) if entropies else 0.0
    has_rwe = 1 if rwe_count > 0 else 0

    # 2. Virtual to raw size discrepancy ratio
    size_ratio = (total_virt_size / (total_raw_size + 1)) if total_raw_size else 1.0

    # 3. Import table inspection
    susp_api_count = 0
    total_imports = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                total_imports += 1
                if imp.name:
                    name = imp.name.decode('utf-8', 'ignore')
                    if name in SUSPICIOUS_APIS:
                        susp_api_count += 1

    pe.close()
    return [num_sections, max_entropy, mean_entropy, has_rwe, susp_api_count, total_imports, size_ratio]