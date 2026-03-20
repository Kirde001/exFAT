import struct
import os
import sys
import datetime
import uuid

FILENAME = "disk_17.vhd"  

def format_hex_dump(data, start_address, length=128):
    res = ""
    for i in range(0, min(len(data), length), 16):
        chunk = data[i:i+16]
        hex_str = " ".join(f"{b:02X}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        res += f"0x{start_address+i:08X}  {hex_str:<47}  {ascii_str}\n"
    return res.strip()

def ntfs_time_to_str(ntfs_time):
    if ntfs_time == 0:
        return "Нет данных"
    try:
        dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ntfs_time / 10)
        dt_local = dt + datetime.timedelta(hours=3)
        return dt_local.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "Недопустимая дата"

def parse_dos_attrs(attr_val):
    attrs = []
    if attr_val & 0x0001: attrs.append("ReadOnly")
    if attr_val & 0x0002: attrs.append("Hidden")
    if attr_val & 0x0004: attrs.append("System")
    if attr_val & 0x0020: attrs.append("Archive")
    if attr_val & 0x0040: attrs.append("Device")
    if attr_val & 0x0080: attrs.append("Normal")
    if attr_val & 0x0100: attrs.append("Temporary")
    if attr_val & 0x0200: attrs.append("Sparse File")
    if attr_val & 0x0400: attrs.append("Reparse Point")
    if attr_val & 0x0800: attrs.append("Compressed")
    if attr_val & 0x1000: attrs.append("Offline")
    if attr_val & 0x2000: attrs.append("Not Content Indexed")
    if attr_val & 0x4000: attrs.append("Encrypted")
    
    return " | ".join(attrs) if attrs else "Normal"

def get_namespace_str(ns_val):
    if ns_val == 0: return "POSIX"
    elif ns_val == 1: return "Win32"
    elif ns_val == 2: return "DOS"
    elif ns_val == 3: return "Win32 & DOS"
    return f"Unknown ({ns_val})"

def find_ntfs_partition(filepath, max_scan_mb=100):
    chunk_size = 1024 * 1024
    overlap = 16
    with open(filepath, 'rb') as f:
        offset = 0
        max_bytes = max_scan_mb * 1024 * 1024
        while offset < max_bytes:
            f.seek(offset)
            chunk = f.read(chunk_size + overlap)
            if not chunk: break
            
            idx = chunk.find(b'NTFS    ')
            if idx != -1 and idx >= 3:
                start_pos = offset + idx - 3
                f.seek(start_pos)
                if f.read(1) == b'\xeb': 
                    return start_pos
            offset += chunk_size
    return None

class NTFSDetailedAnalyzer:
    NTFS_SYS_FILES = {
        0: ("$MFT", "Главная файловая таблица."),
        1: ("$MFTMirr", "Зеркало MFT."),
        2: ("$LogFile", "Журнал транзакций."),
        3: ("$Volume", "Служебная информация о томе."),
        4: ("$AttrDef", "Таблица определений атрибутов."),
        5: (".", "Корневой каталог диска (Root)."),
        6: ("$Bitmap", "Битовая карта кластеров тома."),
        7: ("$Boot", "Загрузочный сектор (BPB)."),
        8: ("$BadClus", "Файл плохих кластеров."),
        9: ("$Secure", "База дескрипторов безопасности."),
        10: ("$UpCase", "Таблица перевода символов Unicode."),
        11: ("$Extend", "Каталог дополнительных метафайлов.")
    }

    def __init__(self, filepath, partition_offset):
        self.filepath = filepath
        self.f = open(filepath, 'rb')
        self.partition_offset = partition_offset
        
        # ДОБАВЛЕНО: Инициализация резервных записей MFT (12-23)
        for i in range(12, 24):
            self.NTFS_SYS_FILES[i] = ("<Reserved>", f"Зарезервировано (MFT #{i})")
        
        self.parsed_records = {}
        self.volume_label = ""
        self.fs_type_str = ""
        self.fs_type_hex = ""
        
        self.ntfs_version = "Неизвестно"
        self.is_dirty = False
        self.detected_vol_flags = [] # ДОБАВЛЕНО: Список всех флагов тома
        self.fixup_errors_detected = 0 
        
        self.total_dirs = 0
        self.total_files = 0
        self.total_sys = 0
        self.total_deleted = 0 
        
        self.detailed_vol_record = None
        self.detailed_file_record = None
        
        self.analyze_bpb()
        self.read_mft()

    def analyze_bpb(self):
        print("====================================================================================================")
        print("                                1. АНАЛИЗ ЗАГРУЗОЧНОГО СЕКТОРА (BPB) И ТИП ФС")
        print("====================================================================================================")
        print(f"\n📌 Загрузочный сектор NTFS расположен по смещению: 0x{self.partition_offset:08X}")
        
        self.f.seek(self.partition_offset)
        bpb = self.f.read(512)
        
        print("\n📋 Сырые данные загрузочного сектора (первые 128 байт):")
        print(format_hex_dump(bpb, self.partition_offset, 128))
        
        self.fs_type_str = bpb[3:11].decode('ascii', errors='ignore')
        self.fs_type_hex = bpb[3:11].hex(' ').upper()
        self.bps = struct.unpack('<H', bpb[0x0B:0x0D])[0]
        self.spc = bpb[0x0D]
        self.bpc = self.bps * self.spc
        self.media_desc = bpb[0x15]
        self.sec_per_track = struct.unpack('<H', bpb[0x18:0x1A])[0]
        self.num_heads = struct.unpack('<H', bpb[0x1A:0x1C])[0]
        self.hidden_sec = struct.unpack('<I', bpb[0x1C:0x20])[0]
        self.total_sectors = struct.unpack('<Q', bpb[0x28:0x30])[0]
        
        self.mft_cluster = struct.unpack('<Q', bpb[0x30:0x38])[0]
        self.mft_mirr_cluster = struct.unpack('<Q', bpb[0x38:0x40])[0]
        
        raw_mft_size = bpb[0x40]
        if raw_mft_size >= 128:
            self.mft_record_size = 1 << (256 - raw_mft_size)
            self.mft_rec_size_str = f"{- (256 - raw_mft_size)} ({self.mft_record_size} байт)"
        else:
            self.mft_record_size = raw_mft_size * self.bpc
            self.mft_rec_size_str = f"{raw_mft_size} ({self.mft_record_size} байт)"
            
        raw_idx_size = bpb[0x44]
        if raw_idx_size >= 128:
            self.idx_record_size = 1 << (256 - raw_idx_size)
            self.idx_rec_size_str = f"{- (256 - raw_idx_size)} ({self.idx_record_size} байт)"
        else:
            self.idx_record_size = raw_idx_size * self.bpc
            self.idx_rec_size_str = f"{raw_idx_size} ({self.idx_record_size} байт)"
            
        self.vol_serial = struct.unpack('<Q', bpb[0x48:0x50])[0]
        self.checksum = struct.unpack('<I', bpb[0x50:0x54])[0]
        
        self.mft_absolute_offset = self.partition_offset + (self.mft_cluster * self.bpc)

        print(f"\n✅ ПУНКТ 2 (ТИП ФС): Проверка OEMID: Значение по смещению 0x03 равно '{self.fs_type_str}' [HEX: {self.fs_type_hex}].")
        if self.fs_type_str == "NTFS    ":
            print("   -> Подтверждено: Файл-образ использует файловую систему NTFS.")

        print("\n════════════════════════════════════════════════════════════════════════════════════════════════════")
        print("ТАБЛИЦА 1.1 - ВСЕ КЛЮЧЕВЫЕ ПОЛЯ ЗАГРУЗОЧНОГО СЕКТОРА NTFS")
        print("════════════════════════════════════════════════════════════════════════════════════════════════════")
        print(f"{'Смещение':<10} {'Размер':<8} {'Название поля':<25} {'Значение (HEX)':<22} {'Значение (DEC/String)':<25}")
        print("────────────────────────────────────────────────────────────────────────────────────────────────────")
        print(f"0x00       3        JumpBoot                  {bpb[0:3].hex(' ').upper():<22} Инструкция перехода")
        print(f"0x03       8        OEMID                     {bpb[3:11].hex(' ').upper():<22} '{self.fs_type_str}'")
        print(f"0x0B       2        BytesPerSector            {bpb[0x0B:0x0D].hex(' ').upper():<22} {self.bps:<25}")
        print(f"0x0D       1        SectorsPerCluster         {self.spc:02X}{' '*20} {self.spc:<25}")
        print(f"0x15       1        MediaDescriptor           {self.media_desc:02X}{' '*20} {self.media_desc:<25} (Тип носителя)")
        print(f"0x18       2        SectorsPerTrack           {bpb[0x18:0x1A].hex(' ').upper():<22} {self.sec_per_track:<25}")
        print(f"0x1A       2        NumberOfHeads             {bpb[0x1A:0x1C].hex(' ').upper():<22} {self.num_heads:<25}")
        print(f"0x1C       4        HiddenSectors             {bpb[0x1C:0x20].hex(' ').upper():<22} {self.hidden_sec:<25}")
        print(f"0x28       8        TotalSectors              {bpb[0x28:0x30].hex(' ').upper():<22} {self.total_sectors:<25}")
        print(f"0x30       8        LCN of $MFT               {bpb[0x30:0x38].hex(' ').upper():<22} Кластер {self.mft_cluster:<17}")
        print(f"0x38       8        LCN of $MFTMirr           {bpb[0x38:0x40].hex(' ').upper():<22} Кластер {self.mft_mirr_cluster:<17}")
        print(f"0x40       1        ClustersPerMFTRecord      {raw_mft_size:02X}{' '*20} {self.mft_rec_size_str}")
        print(f"0x44       1        ClustersPerIndexRecord    {raw_idx_size:02X}{' '*20} {self.idx_rec_size_str}")
        print(f"0x48       8        VolumeSerialNumber        {bpb[0x48:0x50].hex(' ').upper():<22} 0x{self.vol_serial:X}")
        print(f"0x50       4        Checksum                  {bpb[0x50:0x54].hex(' ').upper():<22} {self.checksum:<25}")

        print("\n────────────────────────────────────────────────────────────")
        print("1.2 РАСЧЕТНЫЕ ПАРАМЕТРЫ (Полная расшифровка)")
        print("────────────────────────────────────────────────────────────")
        print(f"📐 Формула 1: Размер кластера = {self.bps} байт/сект × {self.spc} сект/класт = {self.bpc} байт")
        total_gb = (self.total_sectors * self.bps) / (1024**3)
        print(f"📐 Формула 2: Общий объем диска = {self.total_sectors} сект × {self.bps} байт = {self.total_sectors * self.bps} байт ({total_gb:.2f} ГБ)")
        print(f"📐 Формула 3: Смещение $MFT = Кластер {self.mft_cluster} × {self.bpc} байт = 0x{self.mft_cluster * self.bpc:X} байт")
        print(f"              Абсолютный адрес $MFT = 0x{self.partition_offset:X} (Начало) + 0x{self.mft_cluster * self.bpc:X} = 0x{self.mft_absolute_offset:08X}")

    def apply_fixups(self, record_data, record_num):
        upd_off = struct.unpack('<H', record_data[0x04:0x06])[0]
        upd_size = struct.unpack('<H', record_data[0x06:0x08])[0]
        
        if upd_off == 0 or upd_size == 0 or upd_off + 2 * upd_size > len(record_data):
            return record_data 
            
        usn = record_data[upd_off:upd_off+2]
        usa = record_data[upd_off+2 : upd_off + 2*upd_size]
        
        fixed_data = bytearray(record_data)
        for i in range(1, upd_size):
            sector_offset = i * self.bps
            if sector_offset > len(fixed_data): break
            
            if fixed_data[sector_offset-2:sector_offset] != usn:
                self.fixup_errors_detected += 1
                
            fixed_data[sector_offset-2:sector_offset] = usa[(i-1)*2 : i*2]
        return bytes(fixed_data)

    def read_mft(self):
        self.f.seek(self.mft_absolute_offset)
        mft0_raw = self.f.read(self.mft_record_size)
        mft0 = self.apply_fixups(mft0_raw, 0)
        
        mft_runs = []
        attr_offset = struct.unpack('<H', mft0[0x14:0x16])[0]
        curr = attr_offset
        
        while curr < self.mft_record_size - 8:
            attr_type = struct.unpack('<I', mft0[curr:curr+4])[0]
            if attr_type == 0xFFFFFFFF: break
            attr_len = struct.unpack('<I', mft0[curr+4:curr+8])[0]
            if attr_len == 0: break
            non_resident = mft0[curr+8]

            if attr_type == 0x80 and non_resident:
                run_offset = struct.unpack('<H', mft0[curr+0x20:curr+0x22])[0]
                run_data = mft0[curr+run_offset : curr+attr_len]
                mft_runs, _ = self.parse_data_runs(run_data, 0)
                break
            curr += attr_len

        if not mft_runs:
            mft_runs = [{'lcn': self.mft_cluster, 'len': 100 * (self.mft_record_size // self.bpc)}]

        record_count = 0
        MAX_RECORDS = 250

        for run in mft_runs:
            if run['lcn'] == -1: continue 
            
            abs_lcn_offset = self.partition_offset + (run['lcn'] * self.bpc)
            self.f.seek(abs_lcn_offset)
            
            bytes_to_read = run['len'] * self.bpc
            records_in_run = bytes_to_read // self.mft_record_size
            
            for _ in range(records_in_run):
                if record_count >= MAX_RECORDS: break
                raw_record = self.f.read(self.mft_record_size)
                if not raw_record or len(raw_record) < self.mft_record_size: break
                
                magic = raw_record[0:4]
                # ДОБАВЛЕНО: Парсинг BAAD записей
                if magic in (b'FILE', b'BAAD'):
                    record = self.apply_fixups(raw_record, record_count)
                    flags = struct.unpack('<H', record[0x16:0x18])[0]
                    
                    is_deleted = not bool(flags & 0x01)
                    abs_rec_address = abs_lcn_offset + (_ * self.mft_record_size)
                    self.parse_mft_record(record, record_count, abs_rec_address, is_deleted)
                
                record_count += 1
                
            if record_count >= MAX_RECORDS: break

    def parse_data_runs(self, run_data, base_addr):
        runs = []
        i = 0
        current_lcn = 0
        details = ""
        run_idx = 1
        
        while i < len(run_data):
            header = run_data[i]
            if header == 0x00:
                details += f"        [Run {run_idx}] Заголовок = 0x00 -> Конец списка Data Runs.\n"
                break
                
            len_size = header & 0x0F  
            off_size = header >> 4    
            i += 1
            
            run_len = int.from_bytes(run_data[i:i+len_size], 'little')
            run_len_hex = run_data[i:i+len_size].hex().upper()
            i += len_size
            
            if off_size > 0:
                run_off_bytes = run_data[i:i+off_size]
                run_off = int.from_bytes(run_off_bytes, 'little', signed=True)
                run_off_hex = run_off_bytes.hex().upper()
                i += off_size
                current_lcn += run_off
                runs.append({'lcn': current_lcn, 'len': run_len})
                details += f"        [Run {run_idx}] Заголовок: 0x{header:02X} | Длина: {run_len} класт. [HEX: {run_len_hex if run_len_hex else '00'}] | Смещение: {run_off} [HEX: {run_off_hex}]. Абс. LCN: {current_lcn} [HEX: 0x{current_lcn:X}]\n"
            else:
                runs.append({'lcn': -1, 'len': run_len}) 
                details += f"        [Run {run_idx}] Заголовок: 0x{header:02X} | Длина: {run_len} класт. [HEX: {run_len_hex if run_len_hex else '00'}] | Sparse/Compressed (пустые данные)\n"
            run_idx += 1
            
        return runs, details

    def parse_mft_record(self, record, mft_num, abs_addr, is_deleted):
        magic_bytes = record[0:4]
        magic_str = magic_bytes.decode('ascii', errors='ignore')
        magic_hex = magic_bytes.hex(' ').upper()
        
        attr_offset = struct.unpack('<H', record[0x14:0x16])[0]
        flags = struct.unpack('<H', record[0x16:0x18])[0]
        flags_hex = f"0x{flags:04X}"
        
        seq_num = struct.unpack('<H', record[0x10:0x12])[0]
        hard_links = struct.unpack('<H', record[0x12:0x14])[0]
        base_ref = struct.unpack('<Q', record[0x20:0x28])[0]
        
        lsn = struct.unpack('<Q', record[0x08:0x10])[0]
        real_mft_size = struct.unpack('<I', record[0x18:0x1C])[0]
        alloc_mft_size = struct.unpack('<I', record[0x1C:0x20])[0]
        
        record_number = struct.unpack('<I', record[0x2C:0x30])[0]
        is_dir = bool(flags & 0x02)
        
        file_info = {
            'id': mft_num,
            'magic_str': magic_str,
            'magic_hex': magic_hex,
            'is_corrupted_by_chkdsk': (magic_str == 'BAAD'), # ДОБАВЛЕНО: Индикатор повреждения MFT
            'flags_hex': flags_hex,
            'is_deleted': is_deleted,
            'seq_num': seq_num,
            'seq_num_zero': (seq_num == 0), # ДОБАВЛЕНО: Отключенная проверка целостности
            'hard_links': hard_links,
            'base_ref': base_ref,
            'lsn': lsn,                        
            'real_mft_size': real_mft_size,    
            'alloc_mft_size': alloc_mft_size,  
            'real_record_num': record_number,
            'parent': 5,
            'name': f'Unknown_{mft_num}',
            'names_list': [],                  
            'fn_times': [],                    
            'namespace': 'Unknown',
            'is_dir': is_dir,
            'size': 0,
            'real_size': 0,
            'alloc_data_size': 0, # ДОБАВЛЕНО: Allocated Size для $DATA
            'init_data_size': 0,  # ДОБАВЛЕНО: Initialized Size для $DATA
            'runs': [],
            'alt_streams': [],
            'abs_addr': abs_addr,
            'raw': record,
            'is_sys': False,
            'sys_desc': '',
            'runs_detail': '',
            'c_time': 'Нет', 'c_time_hex': 'N/A', 'c_time_raw': 0,
            'm_time_mft': 'Нет', 'm_time_mft_hex': 'N/A', 'm_time_mft_raw': 0,
            'a_time_altered': 'Нет', 'a_time_altered_hex': 'N/A', 'a_time_altered_raw': 0, 
            'r_time_read': 'Нет', 
            'max_versions': None, 'version_num': None, 'class_id': None, # ДОБАВЛЕНО: Поля из 0x10
            'owner_id': 'N/A', 'security_id': 'N/A',
            'quota_charged': 'N/A',            
            'usn': 'N/A',                      
            'has_attr_list': False,            
            'attr_list_refs': [],              
            'timestomp_detected': False,       
            'dos_attrs': 'Normal',
            'dos_attrs_hex': '0x00000000',
            'data_resident': False,
            'data_res_offset': 0,
            'is_compressed': False,
            'obj_id': None, 'birth_vol_id': None, 'birth_obj_id': None, 'domain_id': None,
            'has_index_root': False # ДОБАВЛЕНО: Флаг наличия B+ дерева
        }
        
        if mft_num in self.NTFS_SYS_FILES:
            file_info['is_sys'] = True
            file_info['name'] = self.NTFS_SYS_FILES[mft_num][0]
            file_info['sys_desc'] = self.NTFS_SYS_FILES[mft_num][1]

        curr_offset = attr_offset
        while curr_offset < self.mft_record_size:
            if curr_offset + 8 > self.mft_record_size: break
            attr_type = struct.unpack('<I', record[curr_offset:curr_offset+4])[0]
            if attr_type == 0xFFFFFFFF: break
                
            attr_len = struct.unpack('<I', record[curr_offset+4:curr_offset+8])[0]
            if attr_len == 0 or curr_offset + attr_len > self.mft_record_size: break
            
            non_resident = record[curr_offset+8]
            attr_flags = struct.unpack('<H', record[curr_offset+0x0C:curr_offset+0x0E])[0]
            
            # 0x10 $STANDARD_INFORMATION
            if attr_type == 0x10 and non_resident == 0:
                res_offset = struct.unpack('<H', record[curr_offset+0x14:curr_offset+0x16])[0]
                si_data = record[curr_offset+res_offset : curr_offset+attr_len]
                if len(si_data) >= 32:
                    c_time = struct.unpack('<Q', si_data[0:8])[0]
                    a_time_altered = struct.unpack('<Q', si_data[8:16])[0]
                    m_time_mft = struct.unpack('<Q', si_data[16:24])[0] 
                    r_time_read = struct.unpack('<Q', si_data[24:32])[0] 
                    dos_attr_val = struct.unpack('<I', si_data[32:36])[0]
                    
                    file_info['c_time_raw'] = c_time
                    file_info['a_time_altered_raw'] = a_time_altered
                    file_info['c_time'] = ntfs_time_to_str(c_time)
                    file_info['c_time_hex'] = si_data[0:8].hex().upper()
                    file_info['a_time_altered'] = ntfs_time_to_str(a_time_altered)
                    file_info['a_time_altered_hex'] = si_data[8:16].hex().upper()
                    file_info['m_time_mft'] = ntfs_time_to_str(m_time_mft)
                    file_info['m_time_mft_hex'] = si_data[16:24].hex().upper()
                    file_info['r_time_read'] = ntfs_time_to_str(r_time_read)
                    file_info['dos_attrs'] = parse_dos_attrs(dos_attr_val)
                    file_info['dos_attrs_hex'] = f"0x{dos_attr_val:08X}"

                # ДОБАВЛЕНО: Дополнительные поля $STANDARD_INFORMATION (0x24 - 0x30)
                if len(si_data) >= 48:
                    file_info['max_versions'] = struct.unpack('<I', si_data[36:40])[0]
                    file_info['version_num'] = struct.unpack('<I', si_data[40:44])[0]
                    file_info['class_id'] = struct.unpack('<I', si_data[44:48])[0]

                if len(si_data) >= 72:
                    file_info['owner_id'] = struct.unpack('<I', si_data[48:52])[0]
                    file_info['security_id'] = struct.unpack('<I', si_data[52:56])[0]
                    file_info['quota_charged'] = struct.unpack('<Q', si_data[56:64])[0]
                    file_info['usn'] = struct.unpack('<Q', si_data[64:72])[0]

            elif attr_type == 0x20 and non_resident == 0:
                file_info['has_attr_list'] = True
                res_offset = struct.unpack('<H', record[curr_offset+0x14:curr_offset+0x16])[0]
                attr_list_data = record[curr_offset+res_offset : curr_offset+attr_len]
                list_curr = 0
                while list_curr + 0x1A <= len(attr_list_data):
                    l_type = struct.unpack('<I', attr_list_data[list_curr:list_curr+4])[0]
                    l_len = struct.unpack('<H', attr_list_data[list_curr+4:list_curr+6])[0]
                    if l_len == 0: break
                    l_mft_ref = struct.unpack('<Q', attr_list_data[list_curr+0x10:list_curr+0x18])[0] & 0xFFFFFFFFFFFF
                    file_info['attr_list_refs'].append((hex(l_type), l_mft_ref))
                    list_curr += l_len

            # 0x30 $FILE_NAME
            elif attr_type == 0x30 and non_resident == 0:
                res_offset = struct.unpack('<H', record[curr_offset+0x14:curr_offset+0x16])[0]
                fn_data = record[curr_offset+res_offset : curr_offset+attr_len]
                parent_ref = struct.unpack('<Q', fn_data[0:8])[0]
                parent_mft = parent_ref & 0xFFFFFFFFFFFF
                
                # ДОБАВЛЕНО: Извлечение Parent Sequence Number и Размеров из $FILE_NAME
                parent_seq = (parent_ref >> 48) & 0xFFFF 
                
                fn_c_time = struct.unpack('<Q', fn_data[8:16])[0]
                fn_m_time = struct.unpack('<Q', fn_data[16:24])[0]
                file_info['fn_times'].append({'c_time': fn_c_time, 'm_time': fn_m_time})
                
                # ДОБАВЛЕНО: Размеры внутри $FILE_NAME
                fn_alloc_size = struct.unpack('<Q', fn_data[40:48])[0]
                fn_real_size = struct.unpack('<Q', fn_data[48:56])[0]
                
                fname_len = fn_data[0x40]
                name_type = fn_data[0x41]
                name = fn_data[0x42:0x42+fname_len*2].decode('utf-16le', errors='ignore')
                
                ns_str = get_namespace_str(name_type)
                
                # ДОБАВЛЕНО: Сохраняем расширенные данные о $FILE_NAME
                file_info['names_list'].append({
                    'name': f"{name} [{ns_str}]",
                    'parent_seq': parent_seq,
                    'alloc_size': fn_alloc_size,
                    'real_size': fn_real_size
                })
                
                if mft_num not in self.NTFS_SYS_FILES:
                    if name_type in (0, 1, 3) or file_info['name'].startswith('Unknown'):
                        file_info['name'] = name
                        file_info['parent'] = parent_mft
                        file_info['namespace'] = ns_str
                        if name.startswith('$'): file_info['is_sys'] = True

            elif attr_type == 0x40 and non_resident == 0:
                res_offset = struct.unpack('<H', record[curr_offset+0x14:curr_offset+0x16])[0]
                obj_data = record[curr_offset+res_offset : curr_offset+attr_len]
                if len(obj_data) >= 16:
                    file_info['obj_id'] = str(uuid.UUID(bytes_le=obj_data[0:16]))
                if len(obj_data) >= 32:
                    file_info['birth_vol_id'] = str(uuid.UUID(bytes_le=obj_data[16:32]))
                if len(obj_data) >= 48:
                    file_info['birth_obj_id'] = str(uuid.UUID(bytes_le=obj_data[32:48]))
                if len(obj_data) >= 64:
                    file_info['domain_id'] = str(uuid.UUID(bytes_le=obj_data[48:64]))

            elif attr_type == 0x60 and non_resident == 0:
                res_offset = struct.unpack('<H', record[curr_offset+0x14:curr_offset+0x16])[0]
                res_len = struct.unpack('<I', record[curr_offset+0x10:curr_offset+0x14])[0]
                vol_name = record[curr_offset+res_offset : curr_offset+res_offset+res_len].decode('utf-16le', errors='ignore')
                self.volume_label = vol_name
                self.detailed_vol_record = (mft_num, abs_addr, record, curr_offset, res_offset, res_len)
                
            # 0x70 $VOLUME_INFORMATION
            elif attr_type == 0x70 and non_resident == 0:
                res_offset = struct.unpack('<H', record[curr_offset+0x14:curr_offset+0x16])[0]
                vol_info_data = record[curr_offset+res_offset : curr_offset+attr_len]
                if len(vol_info_data) >= 12:
                    major_ver = vol_info_data[8]
                    minor_ver = vol_info_data[9]
                    vol_flags = struct.unpack('<H', vol_info_data[10:12])[0]
                    self.ntfs_version = f"{major_ver}.{minor_ver}"
                    self.is_dirty = bool(vol_flags & 0x0001)
                    
                    # ДОБАВЛЕНО: Парсинг расширенных флагов $VOLUME_INFORMATION
                    vol_flags_dict = {
                        0x0001: "Dirty", 0x0002: "Resize LogFile", 0x0004: "Upgrade on Mount",
                        0x0008: "Mounted on NT4", 0x0010: "Delete USN underway", 
                        0x0020: "Repair Object Ids", 0x8000: "Modified by chkdsk"
                    }
                    self.detected_vol_flags = [name for mask, name in vol_flags_dict.items() if vol_flags & mask]

            # 0x80 $DATA
            elif attr_type == 0x80:
                name_len = record[curr_offset+0x09]
                stream_name = ""
                if name_len > 0:
                    name_off = struct.unpack('<H', record[curr_offset+0x0A:curr_offset+0x0C])[0]
                    stream_name = record[curr_offset+name_off : curr_offset+name_off+name_len*2].decode('utf-16le', errors='ignore')
                
                is_compressed = bool(attr_flags & 0x0001)

                if non_resident:
                    alloc_size = struct.unpack('<Q', record[curr_offset+0x28:curr_offset+0x30])[0]
                    real_size = struct.unpack('<Q', record[curr_offset+0x30:curr_offset+0x38])[0]
                    init_size = struct.unpack('<Q', record[curr_offset+0x38:curr_offset+0x40])[0] # ДОБАВЛЕНО: Initialized Data Size
                    
                    run_offset = struct.unpack('<H', record[curr_offset+0x20:curr_offset+0x22])[0]
                    run_data = record[curr_offset+run_offset : curr_offset+attr_len]
                    runs, run_details = self.parse_data_runs(run_data, abs_addr)
                    
                    if stream_name == "":
                        file_info['size'] = real_size
                        file_info['real_size'] = real_size
                        file_info['alloc_data_size'] = alloc_size   # ДОБАВЛЕНО
                        file_info['init_data_size'] = init_size     # ДОБАВЛЕНО
                        file_info['runs'] = runs
                        file_info['runs_detail'] = run_details
                        file_info['data_resident'] = False
                        file_info['is_compressed'] = is_compressed
                    else:
                        file_info['alt_streams'].append({
                            'name': stream_name, 'size': real_size, 
                            'alloc_size': alloc_size, 'init_size': init_size,
                            'resident': False, 'runs': runs, 'runs_detail': run_details
                        })
                else:
                    res_len = struct.unpack('<I', record[curr_offset+0x10:curr_offset+0x14])[0]
                    res_offset = struct.unpack('<H', record[curr_offset+0x14:curr_offset+0x16])[0]
                    
                    if stream_name == "":
                        file_info['size'] = res_len
                        file_info['real_size'] = res_len
                        file_info['alloc_data_size'] = res_len # Для резидентных совпадает
                        file_info['init_data_size'] = res_len  # Для резидентных совпадает
                        file_info['data_resident'] = True
                        file_info['data_res_offset'] = curr_offset + res_offset
                        file_info['is_compressed'] = is_compressed
                    else:
                        file_info['alt_streams'].append({
                            'name': stream_name, 'size': res_len, 
                            'resident': True, 'res_offset': curr_offset + res_offset
                        })
                        
            # ДОБАВЛЕНО: Индикация наличия B+ дерева каталогов
            elif attr_type == 0x90:
                file_info['has_index_root'] = True
            
            curr_offset += attr_len
            
        if file_info['c_time_raw'] > 0 and len(file_info['fn_times']) > 0:
            for fn_time in file_info['fn_times']:
                if file_info['c_time_raw'] < fn_time['c_time']:
                    file_info['timestomp_detected'] = True
            
        self.parsed_records[mft_num] = file_info
        
        if file_info['is_deleted']: self.total_deleted += 1
        elif file_info['is_sys']: self.total_sys += 1
        elif is_dir: self.total_dirs += 1
        else: self.total_files += 1

    def _extract_stream_data(self, out_f, f_info, stream_info=None):
        is_resident = stream_info['resident'] if stream_info else f_info['data_resident']
        size = stream_info['size'] if stream_info else f_info['real_size']
        is_compressed = f_info['is_compressed']

        if is_resident:
            offset = stream_info['res_offset'] if stream_info else f_info['data_res_offset']
            res_data = f_info['raw'][offset : offset + size]
            out_f.write(res_data)
            return True, size, False
        else:
            if is_compressed:
                return False, size, True 

            runs = stream_info['runs'] if stream_info else f_info['runs']
            bytes_written = 0
            for run in runs:
                if run['lcn'] == -1:
                    data = b'\x00' * (run['len'] * self.bpc)
                else:
                    abs_offset = self.partition_offset + (run['lcn'] * self.bpc)
                    self.f.seek(abs_offset)
                    data = self.f.read(run['len'] * self.bpc)

                out_f.write(data)
                bytes_written += len(data)
            out_f.truncate(size)
            return True, size, False

    def recover_files(self, output_dir="Recovered_Files"):
        print("\n====================================================================================================")
        print("                  ПУНКТ 6: ВОССТАНОВЛЕНИЕ СОДЕРЖИМОГО ФАЙЛОВ (ИЗВЛЕЧЕНИЕ)")
        print("====================================================================================================")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        print(f"📂 Директория для извлеченных файлов создана: {os.path.abspath(output_dir)}\n")

        for mft_id, f in self.parsed_records.items():
            if f['is_sys'] or f['is_dir'] or f['name'] == '.':
                continue

            prefix = "[DEL]_" if f['is_deleted'] else ""
            filepath = os.path.join(output_dir, f"{prefix}{f['name']}")
            
            try:
                with open(filepath, 'wb') as out_f:
                    success, extracted_size, skipped_compressed = self._extract_stream_data(out_f, f)
                    
                    status_prefix = "[DELETED]" if f['is_deleted'] else ""
                    
                    if skipped_compressed:
                        print(f" [!] ПРОПУЩЕНО (СЖАТО LZ77): {status_prefix} {f['name']:<20} (Алгоритм декомпрессии не реализован)")
                    elif f['data_resident']:
                        print(f" [+] Восстановлен РЕЗИДЕНТНЫЙ:   {status_prefix} {f['name']:<20} (Размер: {extracted_size} байт)")
                    else:
                        print(f" [+] Восстановлен НЕрезидентный: {status_prefix} {f['name']:<20} (Размер: {extracted_size} байт)")

                if f['alt_streams']:
                    for ads in f['alt_streams']:
                        ads_filepath = f"{filepath}_{ads['name']}.bin"
                        with open(ads_filepath, 'wb') as ads_out_f:
                            ads_success, ads_size, ads_skipped = self._extract_stream_data(ads_out_f, f, ads)
                            if not ads_skipped:
                                print(f"  └─ [+] Извлечен скрытый поток (ADS): '{ads['name']}' -> сохранен как .bin ({ads_size} байт)")

            except Exception as e:
                print(f" [-] Ошибка восстановления файла {f['name']}: {e}")

    def print_final_report(self):
        print("\n====================================================================================================")
        print("                               ПУНКТ 1: МЕТКА ТОМА (ПОДРОБНЫЙ РАСЧЕТ)")
        print("====================================================================================================")
        print("Найти метку тома можно в системном файле $Volume (обычно это запись MFT #3).")
        if self.detailed_vol_record:
            mft_num, addr, raw, attr_off, res_offset, res_len = self.detailed_vol_record
            print(f"📍 Читаем запись $Volume (MFT #{mft_num}):")
            print(f"   - Абсолютный адрес MFT записи: 0x{addr:08X}")
            print(f"   - Внутри записи ищем атрибут 0x60 ($VOLUME_NAME).")
            print(f"   - Заголовок атрибута 0x60 найден по смещению: +0x{attr_off:X} от начала MFT-записи.")
            print(f"   - Смещение до самих данных имени (Offset to Data): +0x{res_offset:X} байт от заголовка атрибута.")
            print(f"   - Длина данных имени (Length of Name): {res_len} байт [HEX: 0x{res_len:X}].")
            
            name_raw_hex = raw[attr_off+res_offset : attr_off+res_offset+res_len].hex(' ').upper()
            print(f"\nСырые байты имени (UTF-16LE): {name_raw_hex}")
            print(f"📀 Итоговая декодированная метка тома: >> {self.volume_label if self.volume_label else '<Не задана>'} <<")
        else:
            print("Метка тома не найдена в MFT #3.")

        print("\n====================================================================================================")
        print("                        ПУНКТ 2.1: АНАЛИЗ $VOLUME_INFORMATION (MFT #3)")
        print("====================================================================================================")
        print(f"💿 Версия NTFS: {self.ntfs_version}")
        if self.ntfs_version == "1.2": print("   -> Характерно для Windows NT.")
        elif self.ntfs_version == "3.0": print("   -> Характерно для Windows 2000.")
        elif self.ntfs_version == "3.1": print("   -> Характерно для Windows XP и новее.")
        
        print(f"⚠️ Статус тома (Флаг Dirty): {'ДА (Требуется chkdsk!)' if self.is_dirty else 'Чистый (OK)'}")
        # ДОБАВЛЕНО: Вывод подробных флагов тома
        if self.detected_vol_flags:
            print(f"ℹ️ Дополнительные флаги тома: {', '.join(self.detected_vol_flags)}")

        print("\n====================================================================================================")
        print("                 ПУНКТ 3: СТРУКТУРА И АДРЕСАЦИЯ ОБЛАСТЕЙ ТОМА (РАСЧЕТЫ)")
        print("====================================================================================================")
        print("В файловой системе NTFS всё является файлами, поэтому фиксированных областей мало.")
        print("Ключевые области базируются на размере кластера и LCN (Logical Cluster Number).")
        
        boot_size_bytes = 8192 
        print(f"\n1. Основной загрузочный сектор (Boot Sector / $Boot):")
        print(f"   - Описание: Содержит BPB (BIOS Parameter Block) и загрузочный код.")
        print(f"   - Абсолютное начальное смещение: 0x{self.partition_offset:08X}")
        print(f"   - Стандартный размер в NTFS: {boot_size_bytes} байт (16 секторов) [HEX: 0x{boot_size_bytes:X}]")

        print(f"\n2. Главная таблица файлов ($MFT):")
        print(f"   - Описание: Реляционная база данных, содержащая записи обо всех файлах тома.")
        print(f"   - Из BPB получено значение стартового кластера LCN для $MFT: {self.mft_cluster} [HEX: 0x{self.mft_cluster:X}]")
        print(f"   - Размер 1 кластера: {self.bpc} байт [HEX: 0x{self.bpc:X}]")
        print(f"   - Математика (Смещение от начала раздела): {self.mft_cluster} * {self.bpc} = {self.mft_cluster * self.bpc} байт [HEX: 0x{self.mft_cluster * self.bpc:X}]")
        print(f"   - Абсолютный адрес: 0x{self.partition_offset:08X} (Начало раздела) + 0x{self.mft_cluster * self.bpc:X} = 0x{self.mft_absolute_offset:08X}")

        mft_zone_bytes = int(self.total_sectors * 0.125 * self.bps)
        print(f"\n3. Резервная зона MFT (MFT Zone):")
        print(f"   - Описание: Зарезервированное пространство вокруг MFT (по умолчанию 12.5% диска) для предотвращения фрагментации.")
        print(f"   - Размер зоны: {mft_zone_bytes} байт ({mft_zone_bytes / (1024**2):.2f} МБ)")
        print(f"   - Конец зоны: Абс. Смещение 0x{self.mft_absolute_offset + mft_zone_bytes:08X}")

        print(f"\n4. Область данных (Data Area):")
        print(f"   - Описание: Начинается сразу после зарезервированных загрузочных секторов.")
        print(f"   - Кластеры адресуются с LCN = 0 (указывает на сам Boot Sector).")
        print(f"   - Всего секторов на диске: {self.total_sectors} [HEX: 0x{self.total_sectors:X}]")
        print(f"   - Всего кластеров для хранения: {self.total_sectors // self.spc} [HEX: 0x{self.total_sectors // self.spc:X}]")
        print(f"   - Все пользовательские файлы размещаются в свободных кластерах этой области через механизм Data Runs.")

        print("\n====================================================================================================")
        print("                 ПУНКТ 4 И 5: ДЕТАЛЬНЫЙ АНАЛИЗ ВСЕХ НАЙДЕННЫХ ФАЙЛОВ И MFT ЗАПИСЕЙ")
        print("====================================================================================================")
        print(f"\nПОИСК И ЧТЕНИЕ ЗАПИСЕЙ MFT ЧЕРЕЗ DATA RUNS НАЧИНАЯ С АДРЕСА 0x{self.mft_absolute_offset:08X}...")
        
        if self.fixup_errors_detected > 0:
            print(f"⚠️  [ФОРЕНЗИКА ALERT] ОБНАРУЖЕНО {self.fixup_errors_detected} ОШИБОК FIXUP В СЕКТОРАХ (Возможно повреждение диска)!")

        # 4.1 СИСТЕМНЫЕ ФАЙЛЫ
        print("\n[ 4.1 СИСТЕМНЫЕ МЕТАФАЙЛЫ И РЕЗЕРВ (Сигнатура MFT: 'FILE' [HEX: 46 49 4C 45]) ]")
        print("════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════")
        print(f"{'MFT#':<5} {'Имя файла':<12} {'Адрес записи (MFT)':<20} {'Размер':<10} {'Размещение (Data Run)':<25} {'Назначение и описание файла'}")
        print("────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
        for mft_id in sorted(self.parsed_records.keys()):
            f = self.parsed_records[mft_id]
            if not f['is_sys'] and mft_id > 23: continue # ДОБАВЛЕНО: Увеличено до 23 для отображения зарезервированных записей
            
            size_str = f"{f['size']} B"
            lcn_str = f"LCN: {f['runs'][0]['lcn']}" if f['runs'] else "Resident (Атрибут 0x80)"
            desc = f['sys_desc'] if f['sys_desc'] else "Внутренний системный файл/поток"
            print(f"{mft_id:<5} {f['name']:<12} 0x{f['abs_addr']:08X}{' '*10} {size_str:<10} {lcn_str:<25} {desc}")

        # 4.2 ПОЛЬЗОВАТЕЛЬСКИЕ ФАЙЛЫ
        print("\n[ 4.2 ПОЛЬЗОВАТЕЛЬСКИЕ ФАЙЛЫ И КАТАЛОГИ (Подробный разбор полей и флагов) ]")
        print("════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════")
        for mft_id in sorted(self.parsed_records.keys()):
            f = self.parsed_records[mft_id]
            if f['is_sys'] or f['name'] == '.': continue
            
            f_type = 'Каталог' if f['is_dir'] else 'Файл'
            if f['is_deleted']: f_type = f"[DELETED] {f_type}"
            
            size_str = f"{f['size']} B [HEX: 0x{f['size']:X}]"
            
            location = "Resident (Данные лежат внутри MFT, Атрибут 0x80)"
            if f['runs']:
                abs_data = self.partition_offset + (f['runs'][0]['lcn'] * self.bpc)
                location = f"Нерезидентный. LCN: {f['runs'][0]['lcn']} (Абс. Смещение Данных: 0x{abs_data:X})"
                
            print(f"MFT ID: {mft_id:<5} [HEX: 0x{mft_id:X}] | Имя: {f['name']:<20} | Тип: {f_type} [Флаги: {f['flags_hex']}]")
            
            # ДОБАВЛЕНО: Индикаторы повреждений/отключенных проверок
            if f['is_corrupted_by_chkdsk']:
                print(f" │  [!] ЗАПИСЬ ПОВРЕЖДЕНА И ПЕРЕЗАПИСАНА CHKDSK (Сигнатура BAAD вместо FILE)")
            if f['seq_num_zero']:
                print(f" │  [!] Sequence Number равен 0 (проверка целостности отключена)")

            print(f" ├─ Заголовок MFT: Seq Number: {f['seq_num']} | Hard Links: {f['hard_links']} | Base Ref: 0x{f['base_ref']:X}")
            print(f" │                 LSN (Журнал): {f['lsn']} | Занято байт MFT-записью: {f['real_mft_size']} из {f['alloc_mft_size']}")
            
            if f['has_attr_list']:
                print(f" │  [!!!] Файл сильно фрагментирован: Присутствует атрибут $ATTRIBUTE_LIST (0x20).")
                for al_ref in f['attr_list_refs']:
                    print(f" │        -> Ссылка на Extension MFT-запись: {al_ref[1]} для атрибута {al_ref[0]}")
            
            if len(f['names_list']) > 0:
                print(f" ├─ Имена файла ($FILE_NAME) [{len(f['names_list'])} шт.]:")
                for n_idx, n_val in enumerate(f['names_list']):
                    # ДОБАВЛЕНО: Вывод расширенной информации из $FILE_NAME
                    print(f" │    {n_idx+1}. {n_val['name']} | Seq Родителя: {n_val['parent_seq']} | Alloc: {n_val['alloc_size']} B | Real: {n_val['real_size']} B")
            
            print(f" ├─ Адрес записи: 0x{f['abs_addr']:08X} (Абсолютное смещение самой MFT-записи на диске)")
            # ДОБАВЛЕНО: Расширенный вывод размеров $DATA
            print(f" ├─ Размер $DATA: Real (Данные): {f['real_size']} B | Allocated (На диске): {f['alloc_data_size']} B | Initialized: {f['init_data_size']} B")
            
            print(f" ├─ C-Time (Создание):    {f['c_time']} [Сырой HEX: {f['c_time_hex']}]")
            print(f" ├─ A-Time (Данные изм):  {f['a_time_altered']} [Сырой HEX: {f['a_time_altered_hex']}]")
            print(f" ├─ M-Time (MFT изм):     {f['m_time_mft']} [Сырой HEX: {f['m_time_mft_hex']}]")
            print(f" ├─ R-Time (Посл. дост):  {f['r_time_read']}")
            
            if f['timestomp_detected']:
                print(f" │  [ФОРЕНЗИКА ALERT] 🚨 ОБНАРУЖЕНА АНОМАЛИЯ ВРЕМЕНИ (TIMESTOMPING)!")
                print(f" │  Время в $STD_INFO старше, чем в $FILE_NAME. Данные могли быть сфальсифицированы.")

            print(f" ├─ Атрибуты DOS: {f['dos_attrs']} [HEX: {f['dos_attrs_hex']}]")
            
            # ДОБАВЛЕНО: Вывод дополнительных параметров $STANDARD_INFORMATION (Версии/Классы)
            ext_std_info = []
            if f['max_versions']: ext_std_info.append(f"Max Ver: {f['max_versions']}")
            if f['version_num']: ext_std_info.append(f"Ver #: {f['version_num']}")
            if f['class_id']: ext_std_info.append(f"Class ID: {f['class_id']}")
            if ext_std_info:
                print(f" │  Доп. STD_INFO: {' | '.join(ext_std_info)}")
            
            if f['owner_id'] != 'N/A':
                print(f" ├─ Безопасность: Owner ID: {f['owner_id']} | Security ID: {f['security_id']}")
                print(f" │                Занятая квота: {f['quota_charged']} байт | Журнал USN: {f['usn']}")
                
            if f['obj_id']:
                print(f" ├─ Трекинг (0x40): Object ID: {f['obj_id']}")
                print(f" │                  Birth Vol: {f['birth_vol_id']} | Birth Obj: {f['birth_obj_id']}")
                
            # ДОБАВЛЕНО: Индикатор B+ дерева (Важно для поиска INDX slack)
            if f['has_index_root']:
                print(f" ├─ Дерево INDX:  Присутствует B+ Дерево каталога ($INDEX_ROOT). Доступен для Slack-анализа.")

            print(f" └─ Расположение: {location}")
            
            if f['runs']:
                for run_line in f['runs_detail'].strip().split('\n'):
                    print(f"      {run_line.strip()}")
            
            if f['alt_streams']:
                print(f" ✦ Альтернативные потоки данных (ADS) - Обнаружены скрытые/мета данные:")
                for ads in f['alt_streams']:
                    print(f"      - '{ads['name']}' (Real: {ads['size']} B | Alloc: {ads.get('alloc_size', 'N/A')} B)")
                    
            print("────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")

        print("\n====================================================================================================")
        print("                               ПУНКТ 7: ПОЛНОЕ ДЕРЕВО КАТАЛОГОВ")
        print("====================================================================================================")
        print("📁 / (корневой каталог NTFS - MFT #5)")
        self.print_tree(5, "", 0)

        total_obj = self.total_dirs + self.total_files + self.total_sys + self.total_deleted
        print(f"\n📊 ВСЕГО ПРОАНАЛИЗИРОВАНО ЗАПИСЕЙ: {total_obj} (Из них удалено: {self.total_deleted})")

    def print_tree(self, parent_id, prefix, depth):
        children = [r for r in self.parsed_records.values() if r['parent'] == parent_id and r['id'] != parent_id and not r['is_sys']]
        children.sort(key=lambda x: (not x['is_dir'], x['name']))
        
        for i, child in enumerate(children):
            is_last = (i == len(children) - 1)
            connector = "└── " if is_last else "├── "
            icon = "📁" if child['is_dir'] else "📄"
            
            del_marker = " [DELETED]" if child['is_deleted'] else ""
            
            size_str = f"({(child['size']/1024):.1f} KB)" if child['size'] >= 1024 else f"({child['size']} B)"
            print(f"{prefix}{connector}{icon} {child['name']}{del_marker} {size_str} | Изменён: {child['m_time_mft']}")
            
            if child['is_dir']:
                new_prefix = prefix + ("    " if is_last else "│   ")
                self.print_tree(child['id'], new_prefix, depth + 1)


if __name__ == '__main__':
    if not os.path.exists(FILENAME):
        print(f"[-] ОШИБКА: Файл '{FILENAME}' не найден.")
        sys.exit(1)
        
    offset = find_ntfs_partition(FILENAME)
    if offset is not None:
        base_name = os.path.splitext(os.path.basename(FILENAME))[0]
        report_name = f"LR4_{base_name}_report.txt"
        
        print(f"[+] Раздел NTFS найден по смещению: 0x{offset:08X}")
        
        original_stdout = sys.stdout
        try:
            with open(report_name, 'w', encoding='utf-8') as report_file:
                sys.stdout = report_file
                print("====================================================================================================")
                print("                                       ЛАБОРАТОРНАЯ РАБОТА №4")
                print("                               Глубокое исследование файловой системы NTFS")
                print("====================================================================================================\n")
                
                analyzer = NTFSDetailedAnalyzer(FILENAME, offset)
                
                analyzer.print_final_report()
                analyzer.recover_files()
                
        finally:
            sys.stdout = original_stdout
            
        print(f"[+] Отчет сохранен в: {os.path.abspath(report_name)}")
        print(f"[+] Файлы успешно извлечены в папку: {os.path.abspath('Recovered_Files')}")
    else:
        print("[-] ОШИБКА: Загрузочный сектор NTFS не найден в образе.")