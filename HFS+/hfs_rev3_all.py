import struct
import os
import sys
import re
from datetime import datetime, timezone, timedelta


def sanitize_filename(name):
    safe_name = re.sub(r'[\r\n<>:"/\\|?*\x00-\x1F]', '_', name)
    return safe_name.strip(' .')

FILENAME = "KS2203_16.dmg"
tz_msk = timezone(timedelta(hours=3))
MAC_EPOCH_OFFSET = 2082844800

def format_hex_dump(data, start_address, length=128):
    res = ""
    for i in range(0, min(len(data), length), 16):
        chunk = data[i:i+16]
        hex_str = " ".join(f"{b:02X}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        res += f"0x{start_address+i:08X}  {hex_str:<47}  {ascii_str}\n"
    return res.strip()

def format_time_msk(ts):
    if ts == 0:
        return "0 (Нет)"
    try:
        unix_ts = ts - MAC_EPOCH_OFFSET
        return datetime.fromtimestamp(unix_ts, tz_msk).strftime('%d.%m.%Y %H:%M:%S')
    except:
        return str(ts)

def get_ordinal(idx):
    ordinals = {1: "Первая", 2: "Вторая", 3: "Третья", 4: "Четвертая", 5: "Пятая", 
                6: "Шестая", 7: "Седьмая", 8: "Восьмая", 9: "Девятая", 10: "Десятая"}
    return ordinals.get(idx, f"{idx}-я")

def find_hfs_partition(filepath, max_scan_mb=100):
    with open(filepath, 'rb') as f:
        offset = 0
        max_bytes = max_scan_mb * 1024 * 1024
        while offset < max_bytes:
            f.seek(offset + 1024)
            magic = f.read(2)
            if magic == b'\x48\x2B':
                return offset
            offset += 512 
    return None

class HFSPlusDetailedAnalyzer:
    def __init__(self, filepath, partition_offset):
        self.filepath = filepath
        self.f = open(filepath, 'rb')
        self.partition_offset = partition_offset
        self.files_info = []
        self.tree_nodes = {}
        self.total_objects = 0
        self.total_dirs = 0
        self.total_files = 0
        self.total_sys = 0
        self.max_depth = 0
        self.volume_name = "Неизвестно"
        
        self.extract_base_dir = "HFS_Recovered"
        os.makedirs(self.extract_base_dir, exist_ok=True)
        
        self.analyze_volume_header()
        self.analyze_catalog_btree()
        self.extract_all_files()

    def analyze_volume_header(self):
        print("====================================================================================================")
        print("                                1. АНАЛИЗ VOLUME HEADER (ЗАГОЛОВОК ТОМА)")
        print("====================================================================================================")
        
        vh_offset = self.partition_offset + 1024
        print(f"\n📌 Volume Header расположен по смещению: 0x{vh_offset:08X} (смещение 1024 байт от начала раздела)")
        print(f"📌 Размер структуры: 512 байт\n")
        
        self.f.seek(vh_offset)
        vh = self.f.read(512)
        
        print("📋 Сырые данные Volume Header (первые 128 байт):")
        print(format_hex_dump(vh, vh_offset, 128))
        
        self.signature = struct.unpack('>H', vh[0x00:0x02])[0]
        self.version = struct.unpack('>H', vh[0x02:0x04])[0]
        self.attributes = struct.unpack('>I', vh[0x04:0x08])[0]
        self.lastMountedVersion = struct.unpack('>I', vh[0x08:0x0C])[0]
        self.journalInfoBlock = struct.unpack('>I', vh[0x0C:0x10])[0]
        self.createDate = struct.unpack('>I', vh[0x10:0x14])[0]
        self.modifyDate = struct.unpack('>I', vh[0x14:0x18])[0]
        self.backupDate = struct.unpack('>I', vh[0x18:0x1C])[0]
        self.checkedDate = struct.unpack('>I', vh[0x1C:0x20])[0]
        self.fileCount = struct.unpack('>I', vh[0x20:0x24])[0]
        self.folderCount = struct.unpack('>I', vh[0x24:0x28])[0]
        self.blockSize = struct.unpack('>I', vh[0x28:0x2C])[0]
        self.totalBlocks = struct.unpack('>I', vh[0x2C:0x30])[0]
        self.freeBlocks = struct.unpack('>I', vh[0x30:0x34])[0]
        
        self.catalog_fork_data = vh[0x110:0x160]
        self.catalog_logical_size = struct.unpack('>Q', self.catalog_fork_data[0x00:0x08])[0]
        self.catalog_extents = []
        for i in range(8):
            ext_offset = 0x10 + (i * 8)
            start_block = struct.unpack('>I', self.catalog_fork_data[ext_offset:ext_offset+4])[0]
            block_count = struct.unpack('>I', self.catalog_fork_data[ext_offset+4:ext_offset+8])[0]
            if block_count > 0:
                self.catalog_extents.append((start_block, block_count))
        
        print("\n════════════════════════════════════════════════════════════════════════════════════════════════════")
        print("ТАБЛИЦА 1.1 - ПОЛЯ VOLUME HEADER")
        print("════════════════════════════════════════════════════════════════════════════════════════════════════")
        print(f"{'Смещение':<10} {'Размер':<8} {'Название поля':<28} {'Значение (HEX)':<22} {'Значение (DEC/STR)':<25} {'Описание'}")
        print("────────────────────────────────────────────────────────────────────────────────────────────────────")
        print(f"0x00       2        signature                    {vh[0x00:0x02].hex(' ').upper():<22} 0x{self.signature:04X} ✓                Сигнатура HFS+")
        print(f"0x02       2        version                      {vh[0x02:0x04].hex(' ').upper():<22} {self.version:<25} Версия ФС")
        print(f"0x10       4        createDate                   {vh[0x10:0x14].hex(' ').upper():<22} {format_time_msk(self.createDate):<25} Дата создания")
        print(f"0x20       4        fileCount                    {vh[0x20:0x24].hex(' ').upper():<22} {self.fileCount:<25} Количество файлов")
        print(f"0x24       4        folderCount                  {vh[0x24:0x28].hex(' ').upper():<22} {self.folderCount:<25} Количество папок")
        print(f"0x28       4        blockSize                    {vh[0x28:0x2C].hex(' ').upper():<22} {self.blockSize:<25} Размер блока (байт)")
        print(f"0x2C       4        totalBlocks                  {vh[0x2C:0x30].hex(' ').upper():<22} {self.totalBlocks:<25} Всего блоков")
        print(f"0x110      80       catalogFile                  (структура HFSPlusForkData)                        Расположение Catalog File")
        
        print("\n────────────────────────────────────────────────────────────")
        print("1.2 РАСЧЕТНЫЕ ПАРАМЕТРЫ СУПЕРБЛОКА")
        print("────────────────────────────────────────────────────────────")
        print(f"📐 Формула 1: Общий размер тома = totalBlocks * blockSize = {self.totalBlocks} * {self.blockSize} = {self.totalBlocks * self.blockSize} байт")
        if self.catalog_extents:
            cat_start = self.catalog_extents[0][0]
            cat_phys = self.partition_offset + (cat_start * self.blockSize)
            print(f"📐 Формула 2: Смещение Catalog File = startBlock * blockSize = {cat_start} * {self.blockSize} = 0x{cat_phys:08X}")

    def read_logical_data(self, logical_offset, size, extents):
        data = b''
        bytes_left = size
        curr_log_offset = logical_offset
        
        logical_block_idx = 0
        for start_blk, blk_cnt in extents:
            if blk_cnt == 0: continue
            
            ext_log_start = logical_block_idx * self.blockSize
            ext_log_end = (logical_block_idx + blk_cnt) * self.blockSize
            
            if curr_log_offset >= ext_log_start and curr_log_offset < ext_log_end:
                offset_in_extent = curr_log_offset - ext_log_start
                phys_start = self.partition_offset + (start_blk * self.blockSize) + offset_in_extent
                
                chunk_size = min(bytes_left, ext_log_end - curr_log_offset)
                self.f.seek(phys_start)
                data += self.f.read(chunk_size)
                
                bytes_left -= chunk_size
                curr_log_offset += chunk_size
                
                if bytes_left <= 0:
                    break
            logical_block_idx += blk_cnt
            
        return data

    def get_physical_offset(self, logical_offset, extents):
        logical_block_idx = 0
        for start_blk, blk_cnt in extents:
            ext_log_start = logical_block_idx * self.blockSize
            ext_log_end = (logical_block_idx + blk_cnt) * self.blockSize
            if logical_offset >= ext_log_start and logical_offset < ext_log_end:
                return self.partition_offset + (start_blk * self.blockSize) + (logical_offset - ext_log_start)
            logical_block_idx += blk_cnt
        return 0

    def analyze_catalog_btree(self):
        print("\n====================================================================================================")
        print("                                2. АНАЛИЗ B-TREE CATALOG FILE (ФАЙЛ КАТАЛОГА)")
        print("====================================================================================================")
        
        header_node_data = self.read_logical_data(0, 4096, self.catalog_extents)
        if not header_node_data:
            return
            
        phys_header = self.get_physical_offset(0, self.catalog_extents)
        print(f"\n📌 Заголовок B-Tree (Header Node) расположен по физическому смещению: 0x{phys_header:08X}")
        print("📋 Сырые данные B-Tree Header Node (первые 128 байт):")
        print(format_hex_dump(header_node_data, phys_header, 128))
        
        header_rec_offset = 14
        self.nodeSize = struct.unpack('>H', header_node_data[header_rec_offset+18:header_rec_offset+20])[0]
        self.rootNode = struct.unpack('>I', header_node_data[header_rec_offset+2:header_rec_offset+6])[0]
        self.firstLeafNode = struct.unpack('>I', header_node_data[header_rec_offset+10:header_rec_offset+14])[0]
        
        print("\n════════════════════════════════════════════════════════════════════════════════════════════════════")
        print("ТАБЛИЦА 2.1 - ПОЛЯ B-TREE HEADER NODE")
        print("════════════════════════════════════════════════════════════════════════════════════════════════════")
        print(f"{'Смещение':<10} {'Размер':<8} {'Название поля':<28} {'Значение (HEX)':<22} {'Значение (DEC/STR)'}")
        print("────────────────────────────────────────────────────────────────────────────────────────────────────")
        print(f"0x00+0x0E  2        treeDepth                    {header_node_data[14:16].hex(' ').upper():<22} {struct.unpack('>H', header_node_data[14:16])[0]}")
        print(f"0x02+0x0E  4        rootNode                     {header_node_data[16:20].hex(' ').upper():<22} {self.rootNode}")
        print(f"0x06+0x0E  4        leafRecords                  {header_node_data[20:24].hex(' ').upper():<22} {struct.unpack('>I', header_node_data[20:24])[0]}")
        print(f"0x0A+0x0E  4        firstLeafNode                {header_node_data[24:28].hex(' ').upper():<22} {self.firstLeafNode}")
        print(f"0x12+0x0E  2        nodeSize                     {header_node_data[32:34].hex(' ').upper():<22} {self.nodeSize}")
        
        root_ofs = self.rootNode * self.nodeSize
        phys_root = self.get_physical_offset(root_ofs, self.catalog_extents)
        print(f"\n📍 Расчет смещения корневого узла: rootNodeOfs = rootNode * nodeSize = {self.rootNode} * {self.nodeSize} = 0x{root_ofs:08X} (Физический: 0x{phys_root:08X})")
        
        print(f"\n  🔍 ============================================================")
        print(f"  🔍 АНАЛИЗ КОРНЕВОГО УЗЛА B-ДЕРЕВА (Root Node ID: {self.rootNode}, Физическое смещение: 0x{phys_root:08X})")
        print(f"  🔍 ============================================================")
        root_data = self.read_logical_data(root_ofs, self.nodeSize, self.catalog_extents)
        if root_data:
            r_fLink = struct.unpack('>I', root_data[0:4])[0]
            r_bLink = struct.unpack('>I', root_data[4:8])[0]
            r_kind = root_data[8]
            r_height = root_data[9]
            r_numRecords = struct.unpack('>H', root_data[10:12])[0]
            
            kind_str = "Неизвестный"
            if r_kind == 0x00: kind_str = "Index Node (0x00) - Индексный узел"
            elif r_kind == 0x01: kind_str = "Header Node (0x01) - Заголовочный узел"
            elif r_kind == 0x02: kind_str = "Map Node (0x02) - Узел карты"
            elif r_kind == 0xFF: kind_str = "Leaf Node (0xFF) - Листовой узел"
            
            print(f"  Тип узла: {kind_str}")
            print(f"  Количество записей: {r_numRecords}")
            print(f"  Высота в дереве: {r_height}")
            print("  📋 Сырые данные Root Node (первые 128 байт):")
            print(format_hex_dump(root_data, phys_root, 128))
            
            if r_kind == 0x00:
                print("\n  📂 РАЗБОР ИНДЕКСНЫХ ЗАПИСЕЙ КОРНЕВОГО УЗЛА:")
                for i in range(r_numRecords):
                    offset_ptr = self.nodeSize - 2 * (i + 1)
                    rec_offset = struct.unpack('>H', root_data[offset_ptr:offset_ptr+2])[0]
                    
                    if i < r_numRecords - 1:
                        next_offset_ptr = self.nodeSize - 2 * (i + 2)
                        next_rec_offset = struct.unpack('>H', root_data[next_offset_ptr:next_offset_ptr+2])[0]
                        rec_len = next_rec_offset - rec_offset
                    else:
                        rec_len = offset_ptr - rec_offset
                        
                    record_data = root_data[rec_offset : rec_offset + rec_len]
                    
                    if len(record_data) >= 8:
                        keyLength = struct.unpack('>H', record_data[0:2])[0]
                        r_parentID = struct.unpack('>I', record_data[2:6])[0]
                        r_nameLen = struct.unpack('>H', record_data[6:8])[0]
                        
                        name_bytes = record_data[8:8+(r_nameLen*2)]
                        r_nodeName = name_bytes.decode('utf-16be', errors='ignore')
                        r_nodeName = sanitize_filename(r_nodeName)
                        
                        data_offset = 2 + keyLength
                        if data_offset + 4 <= len(record_data):
                            childNode = struct.unpack('>I', record_data[data_offset:data_offset+4])[0]
                            print(f"        Запись {i+1}: Ключ (parentID: {r_parentID}, name: '{r_nodeName}') -> Указывает на дочерний узел (Node ID): {childNode}")
                        else:
                            print(f"        Запись {i+1}: Ключ (parentID: {r_parentID}, name: '{r_nodeName}') -> [Ошибка: нет данных указателя]")

        current_node = self.firstLeafNode
        leaf_idx = 1
        
        while current_node != 0:
            node_logical_offset = current_node * self.nodeSize
            node_data = self.read_logical_data(node_logical_offset, self.nodeSize, self.catalog_extents)
            phys_node = self.get_physical_offset(node_logical_offset, self.catalog_extents)
            
            fLink = struct.unpack('>I', node_data[0:4])[0]
            kind = node_data[8]
            numRecords = struct.unpack('>H', node_data[10:12])[0]
            
            if kind != 0xFF:
                break
                
            print(f"\n  📂 ============================================================")
            print(f"  📂 РАЗБОР ЛИСТОВОГО УЗЛА (Node {current_node}, Физическое смещение: 0x{phys_node:08X})")
            print(f"  📂 ============================================================")
            print("  📋 Сырые данные Leaf Node (первые 128 байт):")
            print(format_hex_dump(node_data, phys_node, 128))
            
            for i in range(numRecords):
                offset_ptr = self.nodeSize - 2 * (i + 1)
                rec_offset = struct.unpack('>H', node_data[offset_ptr:offset_ptr+2])[0]
                
                if i < numRecords - 1:
                    next_offset_ptr = self.nodeSize - 2 * (i + 2)
                    next_rec_offset = struct.unpack('>H', node_data[next_offset_ptr:next_offset_ptr+2])[0]
                    rec_len = next_rec_offset - rec_offset
                else:
                    rec_len = offset_ptr - rec_offset
                    
                record_data = node_data[rec_offset : rec_offset + rec_len]
                phys_rec = phys_node + rec_offset
                
                keyLength = struct.unpack('>H', record_data[0:2])[0]
                parentID = struct.unpack('>I', record_data[2:6])[0]
                nameLen = struct.unpack('>H', record_data[6:8])[0]
                
                name_bytes = record_data[8:8+(nameLen*2)]
                nodeName = name_bytes.decode('utf-16be', errors='ignore')
                nodeName = sanitize_filename(nodeName)
                
                data_offset = 2 + keyLength
                if data_offset % 2 != 0:
                    pass 
                
                if data_offset >= len(record_data):
                    continue
                    
                recordType = struct.unpack('>H', record_data[data_offset:data_offset+2])[0]
                
                if recordType in (1, 2, 3, 4):
                    ord_str = get_ordinal(i + 1)
                    
                    if recordType == 1: ftype_desc = "папка (folder)"
                    elif recordType == 2: ftype_desc = "файл (file)"
                    elif recordType == 3: ftype_desc = "поток папки (folder thread)"
                    elif recordType == 4: ftype_desc = "поток файла (file thread)"
                    else: ftype_desc = f"неизвестно (0x{recordType:04X})"
                    
                    print("\n  ──────────────────────────────────────────────────────────────────────")
                    print(f"        {ord_str} запись (смещение внутри узла 0x{rec_offset:04X}):")
                    print(f"        {record_data[:16].hex(' ').upper()} ...")
                    print(f"        keyLength =0x{keyLength:04X} → {keyLength} байт")
                    print(f"        parentID = 0x{parentID:08X} → {parentID}")
                    print(f"        nodeName = «{nodeName}»")
                    print(f"        recordType = 0x{recordType:04X} → {ftype_desc}")
                    
                    item_info = {
                        'name': nodeName,
                        'parentID': parentID,
                        'is_dir': recordType == 1,
                        'size': 0,
                        'cnid': 0,
                        'createDate': 0,
                        'extents': []
                    }
                    
                    if recordType == 1:
                        folderID = struct.unpack('>I', record_data[data_offset+8:data_offset+12])[0]
                        createDate = struct.unpack('>I', record_data[data_offset+12:data_offset+16])[0]
                        item_info['cnid'] = folderID
                        item_info['createDate'] = createDate
                        
                        self.total_dirs += 1
                        print(f"        folderID = 0x{folderID:08X} ({folderID})")
                        print(f"        createDate = {format_time_msk(createDate)}")

                        if parentID == 1 and folderID == 2:
                            self.volume_name = nodeName
                            print(f"\n МЕТКА ТОМА: «{self.volume_name}»\n")
                            
                    elif recordType == 2:
                        fileID = struct.unpack('>I', record_data[data_offset+8:data_offset+12])[0]
                        createDate = struct.unpack('>I', record_data[data_offset+12:data_offset+16])[0]
                        
                        df_offset = data_offset + 0x58
                        logicalSize = struct.unpack('>Q', record_data[df_offset:df_offset+8])[0]
                        
                        extents = []
                        for ext_idx in range(8):
                            e_off = df_offset + 0x10 + (ext_idx * 8)
                            e_start = struct.unpack('>I', record_data[e_off:e_off+4])[0]
                            e_cnt = struct.unpack('>I', record_data[e_off+4:e_off+8])[0]
                            if e_cnt > 0:
                                extents.append((e_start, e_cnt))
                                
                        item_info['cnid'] = fileID
                        item_info['createDate'] = createDate
                        item_info['size'] = logicalSize
                        item_info['extents'] = extents
                        
                        self.total_files += 1
                        
                        print(f"        fileID = 0x{fileID:08X} ({fileID})")
                        print(f"        logicalSize = 0x{logicalSize:016X} ({logicalSize} байт)")
                        if extents:
                            print(f"        dataFork Start Block = 0x{extents[0][0]:02X}")
                            print(f"        dataFork Block Count = 0x{extents[0][1]:02X}")
                            phys_file = self.partition_offset + (extents[0][0] * self.blockSize)
                            print(f"        Физический адрес данных: 0x{phys_file:08X} (startBlock * blockSize)")
                            
                            self.files_info.append({
                                'name': nodeName,
                                'cnid': fileID,
                                'size': logicalSize,
                                'start_block': extents[0][0],
                                'phys_addr': phys_file,
                                'extents': extents
                            })
                            
                    elif recordType in (3, 4):
                        if len(record_data) >= data_offset + 10:
                            thread_parentID = struct.unpack('>I', record_data[data_offset+4:data_offset+8])[0]
                            thread_nameLen = struct.unpack('>H', record_data[data_offset+8:data_offset+10])[0]
                            thread_name_bytes = record_data[data_offset+10 : data_offset+10+(thread_nameLen*2)]
                            thread_nodeName = thread_name_bytes.decode('utf-16be', errors='ignore')
                            print(f"        [Thread Data] Обратная ссылка: parentID = {thread_parentID}, name = «{thread_nodeName}»")
                            
                    if parentID not in self.tree_nodes:
                        self.tree_nodes[parentID] = []
                    if recordType in (1, 2):
                        self.tree_nodes[parentID].append(item_info)
                    
            current_node = fLink
            leaf_idx += 1

    def extract_all_files(self):
        print("\n====================================================================================================")
        print("                                3. ИЗВЛЕЧЕНИЕ И ВОССТАНОВЛЕНИЕ ФАЙЛОВ")
        print("====================================================================================================")
        
        path_map = {1: self.extract_base_dir}
        
        def build_paths(parent_id, current_path):
            if parent_id in self.tree_nodes:
                for item in self.tree_nodes[parent_id]:
                    item_path = os.path.join(current_path, item['name'])
                    path_map[item['cnid']] = item_path
                    if item['is_dir']:
                        os.makedirs(item_path, exist_ok=True)
                        build_paths(item['cnid'], item_path)
                        
        root_parent_id = 2 
        build_paths(root_parent_id, self.extract_base_dir)
        
        for file_info in self.files_info:
            target_path = path_map.get(file_info['cnid'], os.path.join(self.extract_base_dir, file_info['name']))
            
            print(f"Извлечен {file_info['name']} ({file_info['size']} байт) -> {target_path}")
            
            try:
                with open(target_path, 'wb') as out_f:
                    bytes_left = file_info['size']
                    for ext_start, ext_count in file_info['extents']:
                        if bytes_left <= 0: break
                        
                        phys_start = self.partition_offset + (ext_start * self.blockSize)
                        self.f.seek(phys_start)
                        
                        chunk_to_read = min(bytes_left, ext_count * self.blockSize)
                        out_f.write(self.f.read(chunk_to_read))
                        bytes_left -= chunk_to_read
            except Exception as e:
                print(f"  [!] Ошибка при извлечении {file_info['name']}: {e}")

    def build_tree_str(self, parent_id, prefix=""):
        lines = []
        if parent_id in self.tree_nodes:
            items = self.tree_nodes[parent_id]
            for idx, item in enumerate(items):
                is_last = (idx == len(items) - 1)
                connector = "└── " if is_last else "├── "
                child_prefix = "    " if is_last else "│   "
                
                icon = '📁' if item['is_dir'] else '📄'
                sz_str = f"({item['size']} B)" if not item['is_dir'] else ""
                dt_str = format_time_msk(item['createDate'])
                
                line = f"{prefix}{connector}{icon} {item['name']} {sz_str} | {dt_str}"
                lines.append(line)
                
                if item['is_dir']:
                    lines.extend(self.build_tree_str(item['cnid'], prefix + child_prefix))
        return lines

    def print_final_report(self):
        print("\n====================================================================================================")
        print("                                     4. ПОЛНОЕ ДЕРЕВО КАТАЛОГОВ")
        print("====================================================================================================")
        print(f"📁 / (корневой каталог тома)")
        
        tree_lines = self.build_tree_str(2, "")
        for line in tree_lines:
            print(line)
            
        self.total_objects = self.total_dirs + self.total_files

        print("\n====================================================================================================")
        print("                               5. ТАБЛИЦА ФАЙЛОВ И ИХ ФИЗИЧЕСКИХ АДРЕСОВ")
        print("====================================================================================================")
        print(f"{'Файл':<35} {'CNID':<10} {'Start Block':<15} {'Адрес данных':<15} {'Размер'}")
        print("────────────────────────────────────────────────────────────────────────────────────────────────────")
        for f in self.files_info:
            print(f"{f['name']:<35} {f['cnid']:<10} {f['start_block']:<15} 0x{f['phys_addr']:08X}    {f['size']} B")

        print("\n====================================================================================================")
        print("                                               ВЫВОДЫ")
        print("====================================================================================================")
        
        print(f"\n💿 ИНФОРМАЦИЯ О ТОМЕ:")
        print(f"   - Метка тома (Имя): {self.volume_name}")

        print(f"\n📊 СТАТИСТИКА:")
        print(f"   - Всего объектов: {self.total_objects}")
        print(f"   - Каталогов: {self.total_dirs}")
        print(f"   - Файлов: {self.total_files}")
        
        print(f"\n🔍 ОСОБЕННОСТИ HFS+:")
        print("   - Вся адресация данных производится блоками распределения (Allocation Blocks)")
        print(f"   - Размер блока: {self.blockSize} байт")
        print("   - Структура каталогов организована в B-Tree (сбалансированное дерево поиска)")
        print("   - Имена файлов хранятся в UTF-16 Big Endian")
        
        print(f"\n📁 СТРУКТУРА:")
        print(f"   - Корневой каталог имеет ParentID = 2")
        print(f"   - ✨ Файлы и структура каталогов успешно восстановлены в директорию: ./{self.extract_base_dir}/")

if __name__ == '__main__':
    if not os.path.exists(FILENAME):
        print(f"[-] ОШИБКА: Файл '{FILENAME}' не найден.")
        sys.exit(1)
        
    offset = find_hfs_partition(FILENAME)
    if offset is not None:
        base_name = os.path.splitext(os.path.basename(FILENAME))[0]
        report_name = f"2_{base_name}_hfsplus.txt"
        
        print(f"[+] Раздел HFS+ найден по смещению: 0x{offset:08X}")
        
        original_stdout = sys.stdout
        try:
            with open(report_name, 'w', encoding='utf-8') as report_file:
                sys.stdout = report_file
                print(f"                                Исследование файловой системы HFS+ от кролика")
                print(f"\n📍 Смещение раздела: 0x{offset:08X} ({offset} байт)")
                analyzer = HFSPlusDetailedAnalyzer(FILENAME, offset)
                analyzer.print_final_report()
                
        finally:
            sys.stdout = original_stdout
            
        print(f"[+] Анализ завершен")
    else:
        print("[-] ОШИБКА: Сигнатура HFS+ (0x482B) не найдена в образе.")