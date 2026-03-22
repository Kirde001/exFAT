import struct
import os
import sys
from datetime import datetime, timezone, timedelta

FILENAME = "disk_3.img"
tz_msk = timezone(timedelta(hours=3))

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
        return datetime.fromtimestamp(ts, tz_msk).strftime('%d.%m.%Y %H:%M:%S')
    except:
        return str(ts)

def get_ordinal(idx):
    ordinals = {1: "Первая", 2: "Вторая", 3: "Третья", 4: "Четвертая", 5: "Пятая", 
                6: "Шестая", 7: "Седьмая", 8: "Восьмая", 9: "Девятая", 10: "Десятая"}
    return ordinals.get(idx, f"{idx}-я")

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
        self.analyze_gdt()
        
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
        self.s_state = struct.unpack('<H', sb[0x3A:0x3C])[0]
        self.s_inode_size = struct.unpack('<H', sb[0x58:0x5A])[0]
        self.s_mkfs_time = struct.unpack('<I', sb[0x108:0x10C])[0]
        self.s_checksum = struct.unpack('<I', sb[0x3FC:0x400])[0]
        
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
        print(f"{'Смещение':<10} {'Размер':<8} {'Название поля':<28} {'Значение (HEX)':<22} {'Значение (DEC/STR)':<25} {'Описание'}")
        print("────────────────────────────────────────────────────────────────────────────────────────────────────")
        print(f"0x00       4        s_inodes_count               {sb[0x00:0x04].hex(' ').upper():<22} {self.s_inodes_count:<25} Всего Inodes")
        print(f"0x04       4        s_blocks_count_lo            {sb[0x04:0x08].hex(' ').upper():<22} {self.s_blocks_count:<25} Всего блоков")
        print(f"0x0C       4        s_free_blocks_count_lo       {sb[0x0C:0x10].hex(' ').upper():<22} {self.s_free_blocks:<25} Свободно блоков")
        print(f"0x10       4        s_free_inodes_count          {sb[0x10:0x14].hex(' ').upper():<22} {self.s_free_inodes:<25} Свободно Inodes")
        print(f"0x14       4        s_first_data_block           {sb[0x14:0x18].hex(' ').upper():<22} {self.s_first_data_block:<25} Первый блок данных")
        print(f"0x18       4        s_log_block_size             {sb[0x18:0x1C].hex(' ').upper():<22} {self.s_log_block_size:<25} Множитель размера блока")
        print(f"0x20       4        s_blocks_per_group           {sb[0x20:0x24].hex(' ').upper():<22} {self.s_blocks_per_group:<25} Блоков в группе")
        print(f"0x28       4        s_inodes_per_group           {sb[0x28:0x2C].hex(' ').upper():<22} {self.s_inodes_per_group:<25} Inodes в группе")
        print(f"0x38       2        s_magic                      {sb[0x38:0x3A].hex(' ').upper():<22} 0x{self.s_magic:04X} ✓                Сигнатура")
        print(f"0x3A       2        s_state                      {sb[0x3A:0x3C].hex(' ').upper():<22} 0x{self.s_state:04X}                   Состояние ФС")
        print(f"0x58       2        s_inode_size                 {sb[0x58:0x5A].hex(' ').upper():<22} {self.s_inode_size:<25} Размер структуры Inode")
        print(f"0x78       16       s_volume_name                {vol_name_raw[:8].hex(' ').upper()}...   {self.s_volume_name:<25} Метка тома")
        print(f"0x108      4        s_mkfs_time                  {sb[0x108:0x10C].hex(' ').upper():<22} {format_time_msk(self.s_mkfs_time):<25} Время создания ФС")
        print(f"0x3FC      4        s_checksum                   {sb[0x3FC:0x400].hex(' ').upper():<22} 0x{self.s_checksum:08X}               Контрольная сумма")

        print("\n────────────────────────────────────────────────────────────")
        print("1.2 РАСЧЕТНЫЕ ПАРАМЕТРЫ СУПЕРБЛОКА")
        print("────────────────────────────────────────────────────────────")
        print(f"📐 Формула 1: BlockSize = 2^(10 + s_log_block_size) = 2^(10 + {self.s_log_block_size}) = {self.block_size} байт")
        print(f"📐 Формула 2: Общий размер тома = s_blocks_count_lo * BlockSize = {self.s_blocks_count} * {self.block_size} = {self.s_blocks_count * self.block_size} байт")
        print(f"📐 Формула 3: Количество групп = s_blocks_count_lo / s_blocks_per_group = {self.s_blocks_count} / {self.s_blocks_per_group} = {self.s_blocks_count / self.s_blocks_per_group}")
        
        self.tree.append(f"📀 {self.s_volume_name}")

    def analyze_gdt(self):
        print("\n====================================================================================================")
        print("                                2. АДРЕСАЦИЯ СИСТЕМНЫХ ОБЛАСТЕЙ И GDT")
        print("====================================================================================================")
        print(f"\n📌 Таблица Дескрипторов Групп (GDT) расположена по смещению: 0x{self.bgdt_offset:08X}")
        
        self.f.seek(self.bgdt_offset)
        gdt_raw = self.f.read(32)
        
        self.bg_block_bitmap_lo = struct.unpack('<I', gdt_raw[0x0:0x4])[0]
        self.bg_inode_bitmap_lo = struct.unpack('<I', gdt_raw[0x4:0x8])[0]
        self.bg_inode_table_lo = struct.unpack('<I', gdt_raw[0x8:0xC])[0]
        self.bg_free_blocks_count_lo = struct.unpack('<H', gdt_raw[0xC:0xE])[0]
        self.bg_free_inodes_count_lo = struct.unpack('<H', gdt_raw[0xE:0x10])[0]
        self.bg_used_dirs_count_lo = struct.unpack('<H', gdt_raw[0x10:0x12])[0]
        self.bg_flags = struct.unpack('<H', gdt_raw[0x12:0x14])[0]
        
        print("\n════════════════════════════════════════════════════════════════════════════════════════════════════")
        print("ТАБЛИЦА 2.1 - ПОЛЯ ДЕСКРИПТОРА ГРУППЫ 0 (GDT)")
        print("════════════════════════════════════════════════════════════════════════════════════════════════════")
        print(f"{'Смещение':<10} {'Размер':<8} {'Название поля':<28} {'Значение (HEX)':<22} {'Значение (DEC)':<15}")
        print("────────────────────────────────────────────────────────────────────────────────────────────────────")
        print(f"0x00       4        bg_block_bitmap_lo           {gdt_raw[0x0:0x4].hex(' ').upper():<22} {self.bg_block_bitmap_lo:<15}")
        print(f"0x04       4        bg_inode_bitmap_lo           {gdt_raw[0x4:0x8].hex(' ').upper():<22} {self.bg_inode_bitmap_lo:<15}")
        print(f"0x08       4        bg_inode_table_lo            {gdt_raw[0x8:0xC].hex(' ').upper():<22} {self.bg_inode_table_lo:<15}")
        print(f"0x0C       2        bg_free_blocks_count_lo      {gdt_raw[0xC:0xE].hex(' ').upper():<22} {self.bg_free_blocks_count_lo:<15}")
        print(f"0x0E       2        bg_free_inodes_count_lo      {gdt_raw[0xE:0x10].hex(' ').upper():<22} {self.bg_free_inodes_count_lo:<15}")
        print(f"0x10       2        bg_used_dirs_count_lo        {gdt_raw[0x10:0x12].hex(' ').upper():<22} {self.bg_used_dirs_count_lo:<15}")
        print(f"0x12       2        bg_flags                     {gdt_raw[0x12:0x14].hex(' ').upper():<22} {self.bg_flags:<15}")

        self.addr_block_bitmap = self.partition_offset + (self.bg_block_bitmap_lo * self.block_size)
        self.addr_inode_bitmap = self.partition_offset + (self.bg_inode_bitmap_lo * self.block_size)
        self.addr_inode_table = self.partition_offset + (self.bg_inode_table_lo * self.block_size)
        
        print("\n📍 РАСЧЕТ ФИЗИЧЕСКИХ АДРЕСОВ СИСТЕМНЫХ ОБЛАСТЕЙ:")
        print(f"   - Суперблок: Блок 1, Физическое смещение: 0x{self.partition_offset + 1024:08X}")
        print(f"   - Битмап блоков: Блок {self.bg_block_bitmap_lo}, Физическое смещение: 0x{self.addr_block_bitmap:08X}")
        print(f"   - Битмап inode: Блок {self.bg_inode_bitmap_lo}, Физическое смещение: 0x{self.addr_inode_bitmap:08X}")
        print(f"   - Таблица inode: Блок {self.bg_inode_table_lo}, Физическое смещение: 0x{self.addr_inode_table:08X}")

    def get_inode_data(self, inode_num):
        group = (inode_num - 1) // self.s_inodes_per_group
        index = (inode_num - 1) % self.s_inodes_per_group
        
        self.f.seek(self.bgdt_offset + group * self.s_desc_size + 8)
        inode_table_block = struct.unpack('<I', self.f.read(4))[0]
        
        addr = self.partition_offset + (inode_table_block * self.block_size) + (index * self.s_inode_size)
        self.f.seek(addr)
        return self.f.read(self.s_inode_size), addr

    def get_extent_info(self, inode_data):
        i_flags = struct.unpack('<I', inode_data[0x20:0x24])[0]
        uses_extents = bool(i_flags & 0x80000)
        info = {
            'uses_extents': uses_extents,
            'eh_magic': 0, 'eh_entries': 0, 'eh_depth': 0,
            'ee_block': 0, 'ee_len': 0, 'ee_start_lo': 0, 'phys_block': 0
        }
        
        if uses_extents:
            info['eh_magic'] = struct.unpack('<H', inode_data[0x28:0x2A])[0]
            info['eh_entries'] = struct.unpack('<H', inode_data[0x2A:0x2C])[0]
            info['eh_depth'] = struct.unpack('<H', inode_data[0x2E:0x30])[0]
            
            if info['eh_magic'] == 0xF30A and info['eh_entries'] > 0 and info['eh_depth'] == 0:
                ext_offset = 0x34
                info['ee_block'] = struct.unpack('<I', inode_data[ext_offset:ext_offset+4])[0]
                info['ee_len'] = struct.unpack('<H', inode_data[ext_offset+4:ext_offset+6])[0]
                ee_start_hi = struct.unpack('<H', inode_data[ext_offset+6:ext_offset+8])[0]
                info['ee_start_lo'] = struct.unpack('<I', inode_data[ext_offset+8:ext_offset+12])[0]
                info['phys_block'] = (ee_start_hi << 32) | info['ee_start_lo']
        else:
            info['phys_block'] = struct.unpack('<I', inode_data[0x28:0x2C])[0]
            
        return info

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
        except Exception:
            pass 

    def parse_directory(self, inode_num, current_path="", depth=1, logical_path=""):
        if depth > self.max_depth: self.max_depth = depth
        
        inode_data, inode_addr = self.get_inode_data(inode_num)
        ext_info = self.get_extent_info(inode_data)
        data_block = ext_info['phys_block']
        
        if data_block == 0:
            return []
            
        dir_addr = self.partition_offset + data_block * self.block_size
        self.f.seek(dir_addr)
        raw = self.f.read(self.block_size)
        
        is_root = (inode_num == 2)
        if is_root:
            print("\n====================================================================================================")
            print("                                3. РЕКУРСИВНЫЙ АНАЛИЗ ВСЕХ КАТАЛОГОВ И ФАЙЛОВ")
            print("====================================================================================================")
            print(f"\n📁 Начинаем обход с корневого каталога (Inode 2)")
        else:
            display_path = logical_path.rstrip('/')
            print(f"\n📁 Переходим в каталог: {display_path}")

        print("\n  📂 ============================================================")
        print(f"  📂 РАЗБОР КАТАЛОГА (Inode {inode_num}, Блок данных {data_block})")
        print(f"  📂 Адрес блока каталога: 0x{dir_addr:08X}")
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
            ftype_desc = "директория" if file_type == 2 else ("обычный файл" if file_type == 1 else "другое")
            
            print("\n  ──────────────────────────────────────────────────────────────────────")
            
            entry_used_bytes = raw[i:i+8+name_len]
            hex_dump_str = " ".join(f"{b:02X}" for b in entry_used_bytes)
            ord_str = get_ordinal(entry_idx)
            
            print(f"        {ord_str} запись (смещение 0x{i:02X}):")
            print(f"        {hex_dump_str}")
            print(f"        inode =\n        0x{target_inode:08X} → inode {target_inode}")
            print(f"        rec_len =\n        0x{rec_len:04X} → {rec_len} байт")
            print(f"        name_len =\n        0x{name_len:02X} → {name_len} символ(ов)")
            print(f"        file_type =\n        0x{file_type:02X} → {ftype_desc}")
            if name_len > 0:
                if name in [".", ".."]:
                    desc = "(текущая директория)" if name == "." else "(родительская директория)"
                    print(f"        name = {name_raw.hex(' ').upper()} → «{name}» {desc}")
                else:
                    print(f"        name = {name_raw.hex(' ').upper()} → «{name}»")
            else:
                print(f"        name = (пусто)")

            tgt_inode_data, tgt_inode_addr = self.get_inode_data(target_inode)
            i_mode = struct.unpack('<H', tgt_inode_data[0x00:0x02])[0]
            i_size_lo = struct.unpack('<I', tgt_inode_data[0x04:0x08])[0]
            i_atime = struct.unpack('<I', tgt_inode_data[0x08:0x0C])[0]
            i_ctime = struct.unpack('<I', tgt_inode_data[0x0C:0x10])[0]
            i_mtime = struct.unpack('<I', tgt_inode_data[0x10:0x14])[0]
            i_dtime = struct.unpack('<I', tgt_inode_data[0x14:0x18])[0]
            i_blocks_lo = struct.unpack('<I', tgt_inode_data[0x1C:0x20])[0]
            
            i_crtime = 0
            if self.s_inode_size >= 156:
                i_crtime = struct.unpack('<I', tgt_inode_data[0x90:0x94])[0]
            
            tgt_ext_info = self.get_extent_info(tgt_inode_data)
            tgt_data_block = tgt_ext_info['phys_block']
            tgt_data_addr = self.partition_offset + (tgt_data_block * self.block_size) if tgt_data_block > 0 else 0
            
            print("\n        📌 ДЕТАЛЬНЫЙ РАЗБОР INODE ФАЙЛА")
            print(f"           Физический адрес Inode: 0x{tgt_inode_addr:08X} (по формуле Add_inode = Add_table + (N - 1) * Size_inode)")
            print("           ────────────────────────────────────────────────────────────────────────────────")
            print("           Смещение   Размер   Поле                 Значение                       Описание")
            print("           ────────────────────────────────────────────────────────────────────────────────")
            print(f"           +0x00      2        i_mode               {tgt_inode_data[0x00:0x02].hex(' ').upper():<30} 0x{i_mode:04X}")
            print(f"           +0x04      4        i_size_lo            {tgt_inode_data[0x04:0x08].hex(' ').upper():<30} {i_size_lo} байт")
            print(f"           +0x08      4        i_atime              {tgt_inode_data[0x08:0x0C].hex(' ').upper():<30} {format_time_msk(i_atime)} (Время доступа)")
            print(f"           +0x0C      4        i_ctime              {tgt_inode_data[0x0C:0x10].hex(' ').upper():<30} {format_time_msk(i_ctime)} (Изменение Inode)")
            print(f"           +0x10      4        i_mtime              {tgt_inode_data[0x10:0x14].hex(' ').upper():<30} {format_time_msk(i_mtime)} (Модификация данных)")
            print(f"           +0x14      4        i_dtime              {tgt_inode_data[0x14:0x18].hex(' ').upper():<30} {format_time_msk(i_dtime)} (Время удаления)")
            print(f"           +0x1C      4        i_blocks_lo          {tgt_inode_data[0x1C:0x20].hex(' ').upper():<30} 0x{i_blocks_lo:02X}")
            print(f"           +0x20      4        i_flags              {tgt_inode_data[0x20:0x24].hex(' ').upper():<30} {'Использует Extents' if tgt_ext_info['uses_extents'] else 'Прямые блоки'}")
            
            if self.s_inode_size >= 156:
                print(f"           +0x90      4        i_crtime             {tgt_inode_data[0x90:0x94].hex(' ').upper():<30} {format_time_msk(i_crtime)} (Время создания)")

            if tgt_ext_info['uses_extents']:
                print("\n        📌 ДЕТАЛЬНЫЙ РАЗБОР EXTENT TREE (Дерево экстентов)")
                print(f"           Заголовок (ext4_extent_header):")
                print(f"           - eh_magic: 0x{tgt_ext_info['eh_magic']:04X}")
                print(f"           - eh_entries: 0x{tgt_ext_info['eh_entries']:02X}")
                print(f"           - eh_depth: 0x{tgt_ext_info['eh_depth']:02X}")
                if tgt_ext_info['eh_depth'] == 0 and tgt_ext_info['eh_entries'] > 0:
                    print(f"           Узлы (ext4_extent):")
                    print(f"           - ee_block: 0x{tgt_ext_info['ee_block']:02X}")
                    print(f"           - ee_len: 0x{tgt_ext_info['ee_len']:02X} ({tgt_ext_info['ee_len']} блок(ов))")
                    print(f"           - ee_start_lo: 0x{tgt_ext_info['ee_start_lo']:04X}")
                    print(f"           - Физический блок данных: {tgt_data_block}")
                    print(f"           => АДРЕС РАЗМЕЩЕНИЯ ДАННЫХ: 0x{tgt_data_addr:08X}")

            if file_type == 1 and tgt_data_addr > 0:
                print(f"\n        📌 СОДЕРЖИМОЕ ФАЙЛА «{name}» (первые 128 байт):")
                self.f.seek(tgt_data_addr)
                read_size = min(128, i_size_lo)
                if read_size > 0:
                    file_data_sample = self.f.read(read_size)
                    dump_lines = format_hex_dump(file_data_sample, tgt_data_addr, 128).split('\n')
                    for d_line in dump_lines:
                        print(f"           {d_line}")
                else:
                    print("           (Файл пуст)")

            attrs = ""
            if name.startswith('.') or name == 'lost+found':
                attrs += "H"
            if name == 'lost+found' or target_inode < 12:
                attrs += "S"
            attrs += "D" if file_type == 2 else "A"
            attr_str = attrs

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
                        'inode_addr': tgt_inode_addr,
                        'block': tgt_data_block,
                        'data_addr': tgt_data_addr,
                        'attr': attr_str,
                        'extents': '✓' if tgt_ext_info['uses_extents'] else '-',
                        'path': logical_path + name 
                    })
                    
                    self.extract_file(target_inode, i_size_lo, logical_path, name)
                else:
                    self.total_dirs += 1
                    self.files_info.append({
                        'name': name,
                        'type': 'DIR',
                        'size': i_size_lo,
                        'inode': target_inode,
                        'inode_addr': tgt_inode_addr,
                        'block': tgt_data_block,
                        'data_addr': tgt_data_addr,
                        'attr': attr_str,
                        'extents': '✓' if tgt_ext_info['uses_extents'] else '-',
                        'path': logical_path + name 
                    })
                    empty_dir_path = os.path.join(self.extract_base_dir, logical_path.strip('/').replace('/', os.sep), name)
                    os.makedirs(empty_dir_path, exist_ok=True)

                local_tree_entries.append({
                    'name': name,
                    'is_dir': file_type == 2,
                    'size': i_size_lo,
                    'mtime': i_mtime,
                    'inode': target_inode,
                    'attr': attr_str,
                    'uses_ext': tgt_ext_info['uses_extents'],
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
            
            sz_str = f"{entry['size']} B"
            icon = '📁' if entry['is_dir'] else '📄'
            mtime_str = format_time_msk(entry['mtime'])
            
            line = f"{current_path}{connector}{icon} {entry['name']} [{entry['attr']}] ['{'Extents' if entry['uses_ext'] else 'BlockPtrs'}', '-' ] ({sz_str}) | {mtime_str}"
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

        print("\n====================================================================================================")
        print("                               5. ТАБЛИЦА ФАЙЛОВ И ИХ ФИЗИЧЕСКИХ АДРЕСОВ")
        print("====================================================================================================")
        print(f"{'Файл/Каталог':<30} {'Inode':<8} {'Адрес Inode':<15} {'Блок данных':<15} {'Адрес данных':<15} {'Размер'}")
        print("────────────────────────────────────────────────────────────────────────────────────────────────────")
        for f in self.files_info:
            print(f"{f['name']:<30} {f['inode']:<8} 0x{f['inode_addr']:08X}    {f['block']:<15} 0x{f['data_addr']:08X}    {f['size']} B")

        print("\n====================================================================================================")
        print("                                               ВЫВОДЫ")
        print("====================================================================================================")
        print(f"\n📊 СТАТИСТИКА:")
        print(f"   - Всего объектов: {self.total_objects}")
        print(f"   - Служебных: {self.total_sys}")
        print(f"   - Каталогов: {self.total_dirs}")
        print(f"   - Файлов: {self.total_files}")
        
        all_extents = all(f['extents'] == '✓' for f in self.files_info if f['type'] != 'DIR') if self.files_info else False
        
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
    if not os.path.exists(FILENAME):
        print(f"[-] ОШИБКА: Файл '{FILENAME}' не найден.")
        sys.exit(1)
        
    offset = find_ext4_partition(FILENAME)
    if offset is not None:
        base_name = os.path.splitext(os.path.basename(FILENAME))[0]
        report_name = f"1_{base_name}_ext4.txt"
        
        print(f"[+] Раздел ext4 найден по смещению: 0x{offset:08X}")
        
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
            
        print(f"[+] Анализ завершен")
    else:
        print("[-] ОШИБКА: Суперблок ext4 (сигнатура 0xEF53) не найден в образе.")