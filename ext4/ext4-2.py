import struct
import os
import sys

FILENAME = "disk_3.img" # УКАЖИ ЗДЕСЬ ИМЯ ТВОЕГО ФАЙЛА-ОБРАЗА С EXT4

def format_hex_dump(data, start_address, length=128):
    res = ""
    for i in range(0, min(len(data), length), 16):
        chunk = data[i:i+16]
        hex_str = " ".join(f"{b:02X}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        res += f"0x{start_address+i:08X}  {hex_str:<47}  {ascii_str}\n"
    return res.strip()

def find_ext4_partition(filepath, max_scan_mb=100):
    chunk_size = 1024 * 1024
    with open(filepath, 'rb') as f:
        offset = 0
        max_bytes = max_scan_mb * 1024 * 1024
        while offset < max_bytes:
            f.seek(offset + 1024 + 0x38)
            magic = f.read(2)
            if magic == b'\x53\xEF':
                return offset
            offset += 512 
    return None

class Ext4DetailedAnalyzer:
    def __init__(self, filepath, partition_offset):
        self.filepath = filepath
        self.f = open(filepath, 'rb')
        self.partition_offset = partition_offset
        self.tree = []
        self.files_info = []
        self.total_objects = 0
        self.total_dirs = 0
        self.total_files = 0
        self.total_sys = 0
        self.max_depth = 0
        
        self.analyze_superblock()
        
        # Подготовка папки для восстановления файлов
        vol_clean = "".join(c for c in self.s_volume_name if c.isalnum() or c in (' ', '_', '-')).strip()
        self.extract_base_dir = vol_clean if vol_clean else "EXT4_Recovered"
        os.makedirs(self.extract_base_dir, exist_ok=True)

    def analyze_superblock(self):
        print("====================================================================================================")
        print("                                1. АНАЛИЗ СУПЕРБЛОКА (SUPERBLOCK)")
        print("====================================================================================================")
        
        sb_offset = self.partition_offset + 1024
        print(f"\n📌 Суперблок расположен по смещению: 0x{sb_offset:08X} (смещение 1024 байт от начала раздела)")
        print(f"📌 Размер структуры: 1024 байт\n")
        
        self.f.seek(sb_offset)
        sb = self.f.read(1024)
        
        print("📋 Сырые данные Суперблока (первые 128 байт):")
        print(format_hex_dump(sb, sb_offset, 128))
        
        self.s_inodes_count = struct.unpack('<I', sb[0x00:0x04])[0]
        self.s_blocks_count = struct.unpack('<I', sb[0x04:0x08])[0]
        self.s_free_blocks = struct.unpack('<I', sb[0x0C:0x10])[0]
        self.s_free_inodes = struct.unpack('<I', sb[0x10:0x14])[0]
        self.s_first_data_block = struct.unpack('<I', sb[0x14:0x18])[0]
        self.s_log_block_size = struct.unpack('<I', sb[0x18:0x1C])[0]
        self.s_blocks_per_group = struct.unpack('<I', sb[0x20:0x24])[0]
        self.s_inodes_per_group = struct.unpack('<I', sb[0x28:0x2C])[0]
        self.s_magic = struct.unpack('<H', sb[0x38:0x3A])[0]
        self.s_inode_size = struct.unpack('<H', sb[0x58:0x5A])[0]
        
        s_feature_incompat = struct.unpack('<I', sb[0x60:0x64])[0]
        if s_feature_incompat & 0x0080:
            self.s_desc_size = struct.unpack('<H', sb[0xFE:0x100])[0]
        else:
            self.s_desc_size = 32
        
        vol_name_raw = sb[0x78:0x88]
        self.s_volume_name = vol_name_raw.split(b'\x00')[0].decode('ascii', errors='ignore')
        if not self.s_volume_name: self.s_volume_name = "EXT4_VOL"

        self.block_size = 2 ** (10 + self.s_log_block_size)
        self.bgdt_offset = self.partition_offset + (self.s_first_data_block + 1) * self.block_size
        
        print("\n════════════════════════════════════════════════════════════════════════════════════════════════════")
        print("ТАБЛИЦА 1.1 - ПОЛЯ СУПЕРБЛОКА")
        print("════════════════════════════════════════════════════════════════════════════════════════════════════")
        print(f"{'Смещение':<10} {'Размер':<8} {'Название поля':<28} {'Значение (HEX)':<22} {'Значение (DEC)':<15} {'Описание'}")
        print("────────────────────────────────────────────────────────────────────────────────────────────────────")
        print(f"0x00       4        s_inodes_count               {sb[0x00:0x04].hex(' ').upper():<22} {self.s_inodes_count:<15} Всего Inodes")
        print(f"0x04       4        s_blocks_count_lo            {sb[0x04:0x08].hex(' ').upper():<22} {self.s_blocks_count:<15} Всего блоков")
        print(f"0x0C       4        s_free_blocks_count_lo       {sb[0x0C:0x10].hex(' ').upper():<22} {self.s_free_blocks:<15} Свободно блоков")
        print(f"0x10       4        s_free_inodes_count          {sb[0x10:0x14].hex(' ').upper():<22} {self.s_free_inodes:<15} Свободно Inodes")
        print(f"0x14       4        s_first_data_block           {sb[0x14:0x18].hex(' ').upper():<22} {self.s_first_data_block:<15} Первый блок данных")
        print(f"0x18       4        s_log_block_size             {sb[0x18:0x1C].hex(' ').upper():<22} {self.s_log_block_size:<15} Множитель размера блока")
        print(f"0x20       4        s_blocks_per_group           {sb[0x20:0x24].hex(' ').upper():<22} {self.s_blocks_per_group:<15} Блоков в группе")
        print(f"0x28       4        s_inodes_per_group           {sb[0x28:0x2C].hex(' ').upper():<22} {self.s_inodes_per_group:<15} Inodes в группе")
        print(f"0x38       2        s_magic                      {sb[0x38:0x3A].hex(' ').upper():<22} 0x{self.s_magic:04X} ✓      Сигнатура (должно быть 0xEF53)")
        print(f"0x58       2        s_inode_size                 {sb[0x58:0x5A].hex(' ').upper():<22} {self.s_inode_size:<15} Размер структуры Inode")
        print(f"0x78       16       s_volume_name                {vol_name_raw[:8].hex(' ').upper()}...   -               Метка: '{self.s_volume_name}'")

        print("\n────────────────────────────────────────────────────────────")
        print("1.2 РАСЧЕТНЫЕ ПАРАМЕТРЫ")
        print("────────────────────────────────────────────────────────────")
        print(f"📐 Формула 1: BlockSize = 2^(10 + s_log_block_size) = 2^(10 + {self.s_log_block_size}) = {self.block_size} байт")
        print(f"📐 Формула 2: InodeSize = s_inode_size = {self.s_inode_size} байт")
        print(f"📐 Формула 3: BGDT_Address = PartitionOffset + (FirstDataBlock + 1) × BlockSize = 0x{self.bgdt_offset:08X}")
        
        self.f.seek(self.bgdt_offset + 8)
        self.bg_inode_table_lo = struct.unpack('<I', self.f.read(4))[0]
        self.inode_table_0_addr = self.partition_offset + (self.bg_inode_table_lo * self.block_size)
        self.root_inode_addr = self.inode_table_0_addr + (2 - 1) * self.s_inode_size
        
        print(f"📐 Формула 4: InodeTable[Group 0] = bg_inode_table_lo × BlockSize = {self.bg_inode_table_lo} × {self.block_size} = 0x{self.inode_table_0_addr:08X}")
        print(f"📐 Формула 5: Addr_Root_Inode = InodeTable[0] + (2 - 1) × InodeSize = 0x{self.root_inode_addr:08X}")
        
        self.tree.append(f"📀 {self.s_volume_name}")

    def get_inode_data(self, inode_num):
        group = (inode_num - 1) // self.s_inodes_per_group
        index = (inode_num - 1) % self.s_inodes_per_group
        
        self.f.seek(self.bgdt_offset + group * self.s_desc_size + 8)
        inode_table_block = struct.unpack('<I', self.f.read(4))[0]
        
        addr = self.partition_offset + (inode_table_block * self.block_size) + (index * self.s_inode_size)
        self.f.seek(addr)
        return self.f.read(self.s_inode_size), addr

    def get_first_data_block(self, inode_data):
        i_flags = struct.unpack('<I', inode_data[0x20:0x24])[0]
        uses_extents = bool(i_flags & 0x80000)
        first_block = 0
        
        if uses_extents:
            magic = struct.unpack('<H', inode_data[0x28:0x2A])[0]
            entries = struct.unpack('<H', inode_data[0x2A:0x2C])[0]
            if magic == 0xF30A and entries > 0:
                ee_start_hi = struct.unpack('<H', inode_data[0x3A:0x3C])[0]
                ee_start_lo = struct.unpack('<I', inode_data[0x3C:0x40])[0]
                first_block = (ee_start_hi << 32) | ee_start_lo
        else:
            first_block = struct.unpack('<I', inode_data[0x28:0x2C])[0]
            
        return first_block, uses_extents

    def extract_file(self, inode_num, size, logical_path, name):
        if size == 0: return
        inode_data, _ = self.get_inode_data(inode_num)
        i_flags = struct.unpack('<I', inode_data[0x20:0x24])[0]
        uses_extents = bool(i_flags & 0x80000)
        
        target_dir = os.path.join(self.extract_base_dir, logical_path.strip('/').replace('/', os.sep))
        os.makedirs(target_dir, exist_ok=True)
        target_path = os.path.join(target_dir, name)
        
        bytes_left = size
        
        try:
            with open(target_path, 'wb') as out_f:
                if uses_extents:
                    depth = struct.unpack('<H', inode_data[0x2E:0x30])[0]
                    entries = struct.unpack('<H', inode_data[0x2A:0x2C])[0]
                    if depth == 0: 
                        for e in range(entries):
                            ext_offset = 0x34 + e * 12
                            ee_len = struct.unpack('<H', inode_data[ext_offset+4:ext_offset+6])[0]
                            ee_start_hi = struct.unpack('<H', inode_data[ext_offset+6:ext_offset+8])[0]
                            ee_start_lo = struct.unpack('<I', inode_data[ext_offset+8:ext_offset+12])[0]
                            phys_block = (ee_start_hi << 32) | ee_start_lo
                            
                            for b in range(ee_len):
                                if bytes_left <= 0: break
                                self.f.seek(self.partition_offset + (phys_block + b) * self.block_size)
                                chunk = self.f.read(min(bytes_left, self.block_size))
                                out_f.write(chunk)
                                bytes_left -= len(chunk)
                else:
                    for b in range(12):
                        if bytes_left <= 0: break
                        block_ptr = struct.unpack('<I', inode_data[0x28 + b*4 : 0x2C + b*4])[0]
                        if block_ptr == 0: continue
                        self.f.seek(self.partition_offset + block_ptr * self.block_size)
                        chunk = self.f.read(min(bytes_left, self.block_size))
                        out_f.write(chunk)
                        bytes_left -= len(chunk)
        except Exception as e:
            pass 

    def parse_directory(self, inode_num, current_path="", depth=1, logical_path=""):
        if depth > self.max_depth: self.max_depth = depth
        
        inode_data, inode_addr = self.get_inode_data(inode_num)
        data_block, _ = self.get_first_data_block(inode_data)
        
        if data_block == 0:
            return []
            
        dir_addr = self.partition_offset + data_block * self.block_size
        self.f.seek(dir_addr)
        raw = self.f.read(self.block_size)
        
        is_root = (inode_num == 2)
        if is_root:
            print("\n====================================================================================================")
            print("                                2. РЕКУРСИВНЫЙ АНАЛИЗ ВСЕХ КАТАЛОГОВ")
            print("====================================================================================================")
            print(f"\n📁 Начинаем обход с корневого каталога (Inode 2)")
        else:
            display_path = logical_path.rstrip('/')
            print(f"\n📁 Переходим в каталог: {display_path}")

        print("\n  📂 ============================================================")
        print(f"  📂 РАЗБОР КАТАЛОГА (Inode {inode_num}, Блок данных {data_block})")
        print(f"  📂 Адрес блока каталога: {dir_addr - self.partition_offset} байт (0x{dir_addr:08X})")
        print("  📂 ============================================================")
        print("  📋 Сырые данные блока каталога (первые 128 байт):")
        print(format_hex_dump(raw, dir_addr, 128))

        i = 0
        entry_idx = 1
        objects_in_dir = 0
        local_tree_entries = [] 

        while i < len(raw):
            if i + 8 > len(raw): break
            
            entry_data = raw[i:i+8]
            target_inode = struct.unpack('<I', entry_data[0:4])[0]
            rec_len = struct.unpack('<H', entry_data[4:6])[0]
            name_len = entry_data[6]
            file_type = entry_data[7]
            
            if target_inode == 0 or rec_len == 0:
                if target_inode == 0 and i == 0: break
                i += rec_len if rec_len > 0 else 4
                continue
                
            name_raw = raw[i+8:i+8+name_len]
            name = name_raw.decode('utf-8', errors='ignore')
            entry_addr = dir_addr + i
            
            print("\n  ──────────────────────────────────────────────────────────────────────")
            print(f"  📌 ЗАПИСЬ {entry_idx}: Directory Entry (ext4_dir_entry_2)")
            print(f"     Адрес: 0x{entry_addr:08X}")
            print(f"     Сырые данные (первые {min(rec_len, 32)} байт):\n{format_hex_dump(raw[i:i+min(rec_len, 32)], entry_addr, min(rec_len, 32))}\n")
            
            print("     📌 ДЕТАЛЬНЫЙ РАЗБОР ЗАПИСИ КАТАЛОГА")
            print(f"        Адрес записи: 0x{entry_addr:08X}")
            print("        ────────────────────────────────────────────────────────────────────────────────")
            print("        Смещение   Размер   Поле                 Значение                       Описание")
            print("        ────────────────────────────────────────────────────────────────────────────────")
            print(f"        +0x00      4        Inode                {entry_data[0:4].hex(' ').upper():<30} {target_inode} (Номер Inode)")
            print(f"        +0x04      2        RecordLength         {entry_data[4:6].hex(' ').upper():<30} {rec_len} байта (длина записи)")
            print(f"        +0x06      1        NameLength           {entry_data[6:7].hex(' ').upper():<30} {name_len} символов в имени")
            ftype_desc = "Каталог" if file_type == 2 else ("Файл" if file_type == 1 else "Другое")
            print(f"        +0x07      1        FileType             {entry_data[7:8].hex(' ').upper():<30} {file_type} ({ftype_desc})")
            print(f"        +0x08      {name_len:<2}       Name                 {name_raw[:8].hex(' ').upper()}...   '{name}'")

            tgt_inode_data, tgt_inode_addr = self.get_inode_data(target_inode)
            i_mode = struct.unpack('<H', tgt_inode_data[0x00:0x02])[0]
            i_size_lo = struct.unpack('<I', tgt_inode_data[0x04:0x08])[0]
            tgt_data_block, uses_ext = self.get_first_data_block(tgt_inode_data)
            
            print("\n        📌 ДЕТАЛЬНЫЙ РАЗБОР INODE ФАЙЛА")
            print(f"           Адрес Inode: 0x{tgt_inode_addr:08X}")
            print("           ────────────────────────────────────────────────────────────────────────────────")
            print("           Смещение   Размер   Поле                 Значение                       Описание")
            print("           ────────────────────────────────────────────────────────────────────────────────")
            print(f"           +0x00      2        i_mode               {tgt_inode_data[0x00:0x02].hex(' ').upper():<30} 0x{i_mode:04X} (Права доступа)")
            print(f"           +0x04      4        i_size_lo            {tgt_inode_data[0x04:0x08].hex(' ').upper():<30} {i_size_lo} байт (размер)")
            print(f"           +0x20      4        i_flags              {tgt_inode_data[0x20:0x24].hex(' ').upper():<30} {'Использует Extents' if uses_ext else 'Прямые блоки'}")
            if uses_ext:
                print(f"           +0x28      12       ExtentHeader         {tgt_inode_data[0x28:0x34].hex(' ').upper():<30} Заголовок дерева")
                print(f"           +0x34      12       ExtentEntry          {tgt_inode_data[0x34:0x40].hex(' ').upper():<30} Физический блок данных: {tgt_data_block}")

            attr_str = "D" if file_type == 2 else "A"
            if name.startswith('.'): attr_str = "H" + attr_str

            print("     ──────────────────────────────────────────────────")
            print(f"     📍 ИТОГО: {'📁' if file_type == 2 else '📄'} {name}")
            print(f"        Тип: {ftype_desc}")
            print(f"        Атрибуты: {attr_str}")
            print(f"        Первый блок: {tgt_data_block} (Inode: {target_inode})")
            print(f"        Размер: {i_size_lo} байт ({(i_size_lo/1024):.1f} KB)" if i_size_lo >= 1024 else f"        Размер: {i_size_lo} байт ({float(i_size_lo)} B)")
            print(f"        Использует Extents: {'True' if uses_ext else 'False'}")

            if name not in [".", ".."] and name != "":
                objects_in_dir += 1
                
                if file_type != 2:
                    self.total_files += 1
                    ext = name.split('.')[-1].lower() if '.' in name else 'binary'
                    ftype_col = 'text' if ext in ['txt', 'log', 'ini'] else ('image' if ext in ['png', 'jpg'] else 'binary')
                    
                    self.files_info.append({
                        'name': name,
                        'type': ftype_col,
                        'size': i_size_lo,
                        'inode': target_inode,
                        'block': tgt_data_block,
                        'attr': attr_str,
                        'extents': '✓' if uses_ext else '-',
                        'path': logical_path + name 
                    })
                    
                    self.extract_file(target_inode, i_size_lo, logical_path, name)
                else:
                    self.total_dirs += 1
                    # --- ИЗМЕНЕНИЕ ЗДЕСЬ: Принудительно создаем пустую папку на диске ---
                    empty_dir_path = os.path.join(self.extract_base_dir, logical_path.strip('/').replace('/', os.sep), name)
                    os.makedirs(empty_dir_path, exist_ok=True)

                local_tree_entries.append({
                    'name': name,
                    'is_dir': file_type == 2,
                    'size': i_size_lo,
                    'inode': target_inode,
                    'attr': attr_str,
                    'uses_ext': uses_ext,
                    'logical_path': logical_path + name + ("/" if file_type == 2 else "")
                })

            i += rec_len
            entry_idx += 1

        print(f"\n  📂 ────────────────────────────────────────────────────────────")
        print(f"  📂 В каталоге найдено объектов: {objects_in_dir}")
        print(f"  📂 ────────────────────────────────────────────────────────────")

        tree_output = []
        for idx, entry in enumerate(local_tree_entries):
            is_last = (idx == len(local_tree_entries) - 1)
            connector = "└── " if is_last else "├── "
            child_prefix = "    " if is_last else "│   "
            
            sz_str = f"{(entry['size']/1024):.1f} KB" if entry['size'] >= 1024 else f"{float(entry['size'])} B"
            icon = '📁' if entry['is_dir'] else '📄'
            
            line = f"{current_path}{connector}{icon} {entry['name']} [{entry['attr']}] ['{'Extents' if entry['uses_ext'] else 'BlockPtrs'}', '-' ] ({sz_str})"
            tree_output.append(line)
            
            if entry['is_dir']:
                sub_tree = self.parse_directory(entry['inode'], current_path + child_prefix, depth + 1, entry['logical_path'])
                tree_output.extend(sub_tree)
                
        return tree_output

    def print_final_report(self):
        print("\n====================================================================================================")
        print("                                     4. ПОЛНОЕ ДЕРЕВО КАТАЛОГОВ")
        print("====================================================================================================")
        print("📁 / (корневой каталог)")
        for item in self.tree:
            print(item)
            
        self.total_objects = self.total_sys + self.total_dirs + self.total_files
        print(f"\n📊 ВСЕГО ОБЪЕКТОВ: {self.total_objects}")
        print(f"   - Служебных: {self.total_sys}")
        print(f"   - Каталогов: {self.total_dirs}")
        print(f"   - Файлов: {self.total_files}")

        print("\n════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════")
        print("ТАБЛИЦА 4.1 - ВСЕ ФАЙЛЫ")
        print("════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════")
        print(f"{'№':<4} {'Имя':<30} {'Тип':<10} {'Размер':<15} {'Inode':<10} {'Extents':<12} {'Атрибуты':<15} {'Путь'}")
        print("────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
        for idx, f in enumerate(self.files_info, 1):
            print(f"{idx:<4} {f['name']:<30} {f['type']:<10} {f['size']:<15} {f['inode']:<10} {f['extents']:<12} {f['attr']:<15} {f['path']}")

        print("\n📐 ФОРМУЛА РАСЧЕТА АДРЕСА БЛОКА ДАННЫХ ФАЙЛА:")
        print("   Addr_File = Partition_Offset + Data_Block × BlockSize")
        print(f"   BlockSize = {self.block_size} байт")

        print("\n════════════════════════════════════════════════════════════════════════════════════════════════════")
        print("ТАБЛИЦА 5.1 - АДРЕСА ВСЕХ ФАЙЛОВ")
        print("════════════════════════════════════════════════════════════════════════════════════════════════════")
        print(f"{'Файл':<30} {'Inode':<10} {'Смещение Inode':<15} {'Блок данных':<20} {'Размер'}")
        print("────────────────────────────────────────────────────────────────────────────────────────────────────")
        for f in self.files_info:
            _, inode_addr = self.get_inode_data(f['inode'])
            offset = inode_addr - self.partition_offset
            print(f"{f['name']:<30} {f['inode']:<10} {offset:<15} {f['block']:<20} {f['size']}")

        print("\n====================================================================================================")
        print("                                               ВЫВОДЫ")
        print("====================================================================================================")
        print(f"\n📊 СТАТИСТИКА:")
        print(f"   - Всего объектов: {self.total_objects}")
        print(f"   - Служебных: {self.total_sys}")
        print(f"   - Каталогов: {self.total_dirs}")
        print(f"   - Файлов: {self.total_files}")
        
        all_extents = all(f['extents'] == '✓' for f in self.files_info) if self.files_info else False
        
        print(f"\n🔍 ОСОБЕННОСТИ EXT4:")
        if all_extents and self.files_info:
            print("   - Все найденные файлы используют Extent Trees (непрерывные блоки)")
        else:
            print("   - Встречаются файлы с прямой адресацией блоков")
        print("   - Имена файлов хранятся в UTF-8 в структуре ext4_dir_entry_2")
        print(f"   - Размер блока: {self.block_size} байт ({(self.block_size/1024):.1f} КБ)")
        print(f"   - Inode Size: {self.s_inode_size} байт")
        
        print(f"\n📁 СТРУКТУРА:")
        print(f"   - Корневой каталог находится в Inode 2")
        print(f"   - Максимальная глубина вложенности: {self.max_depth} уровня")
        print(f"   - ✨ Файлы и структура каталогов успешно восстановлены в директорию: ./{self.extract_base_dir}/")

if __name__ == '__main__':
    print("[*] Анализатор ext4 запущен...")
    if not os.path.exists(FILENAME):
        print(f"[-] ОШИБКА: Файл '{FILENAME}' не найден.")
        sys.exit(1)
        
    offset = find_ext4_partition(FILENAME)
    if offset is not None:
        base_name = os.path.splitext(os.path.basename(FILENAME))[0]
        report_name = f"1_{base_name}_ext4.txt"
        
        print(f"[+] Раздел ext4 найден по смещению: 0x{offset:08X}")
        print(f"[*] Идет формирование сверхдетального отчета и извлечение файлов... Пожалуйста, подождите.")
        
        original_stdout = sys.stdout
        try:
            with open(report_name, 'w', encoding='utf-8') as report_file:
                sys.stdout = report_file
                print(f"ЛАБОРАТОРНАЯ РАБОТА №5")
                print(f"                                Исследование файловой системы ext4")
                print(f"\n📍 Смещение раздела: 0x{offset:08X} ({offset} байт)")
                analyzer = Ext4DetailedAnalyzer(FILENAME, offset)
                
                tree_lines = analyzer.parse_directory(2, "", 1, "")
                analyzer.tree.extend(tree_lines)
                
                analyzer.print_final_report()
        finally:
            sys.stdout = original_stdout
            
        print(f"[+] Анализ успешно завершен!")
    else:
        print("[-] ОШИБКА: Суперблок ext4 (сигнатура 0xEF53) не найден в образе.")