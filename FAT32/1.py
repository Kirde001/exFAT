import struct
import math
import os
import sys

FILENAME = "disk_1.vhd"   
VHD_OFFSET = 0x10000        

def decode_dos_time(val):
    sec = (val & 0x1F) * 2
    min_ = (val >> 5) & 0x3F
    hour = (val >> 11) & 0x1F
    return f"{hour:02}:{min_:02}:{sec:02}"

def decode_dos_date(val):
    day = (val & 0x1F)
    month = (val >> 5) & 0x0F
    year = ((val >> 9) & 0x7F) + 1980
    return f"{day:02}.{month:02}.{year}"

def get_attr_str(attr):
    res = []
    if attr & 0x01: res.append("R")
    if attr & 0x02: res.append("H")
    if attr & 0x04: res.append("S")
    if attr & 0x08: res.append("V")
    if attr & 0x10: res.append("D")
    if attr & 0x20: res.append("A")
    return ",".join(res)

class FATAnalyzer:
    def __init__(self, filepath, offset):
        if not os.path.exists(filepath):
            print(f"ОШИБКА: Файл '{filepath}' не найден. Положите скрипт в одну папку с файлом.")
            sys.exit(1)
            
        self.f = open(filepath, 'rb')
        self.offset = offset
        self.f.seek(self.offset)
        
        bs = self.f.read(512)
        
        self.raw_bs = bs 
        
        self.bs_oem = bs[3:11].decode('ascii', errors='ignore').strip()
        self.bps = struct.unpack('<H', bs[11:13])[0]       
        self.spc = bs[13]                                  
        self.res_sec = struct.unpack('<H', bs[14:16])[0]   
        self.n_fats = bs[16]                               
        self.root_cnt = struct.unpack('<H', bs[17:19])[0]  
        self.tot_sec16 = struct.unpack('<H', bs[19:21])[0] 
        self.media = bs[21]
        self.fat_sz16 = struct.unpack('<H', bs[22:24])[0]
        self.tot_sec32 = struct.unpack('<I', bs[32:36])[0] 
        
        if self.fat_sz16 == 0:
            self.fat_sz32 = struct.unpack('<I', bs[36:40])[0]
            self.root_clus = struct.unpack('<I', bs[44:48])[0]
            self.vol_lab_bs = bs[71:82].decode('cp866', errors='replace').strip()
        else:
            self.fat_sz32 = 0
            self.root_clus = 0
            self.vol_lab_bs = bs[43:54].decode('cp866', errors='replace').strip()
        
        self.total_sectors = self.tot_sec16 if self.tot_sec16 != 0 else self.tot_sec32
        self.active_fat_sz = self.fat_sz32 if self.fat_sz16 == 0 else self.fat_sz16
        self.clus_sz = self.bps * self.spc
        self.addr_fat1 = self.offset + (self.res_sec * self.bps)
        self.fat_size_bytes = self.active_fat_sz * self.bps
        self.addr_root = self.addr_fat1 + (self.n_fats * self.fat_size_bytes)
        
        root_sectors = ((self.root_cnt * 32) + (self.bps - 1)) // self.bps
        self.addr_data = self.addr_root + (root_sectors * self.bps)
        data_sectors = self.total_sectors - (self.res_sec + (self.n_fats * self.active_fat_sz) + root_sectors)
        self.clusters_cnt = data_sectors // self.spc
        
        if self.clusters_cnt < 4085: self.fat_type = "FAT12"
        elif self.clusters_cnt < 65525: self.fat_type = "FAT16"
        else: self.fat_type = "FAT32"
        self.f.seek(self.addr_fat1)
        self.fat_table = self.f.read(self.fat_size_bytes)
        
        self.tree_items = []  
        self.found_dirs = []
        self.real_vol_label = self.vol_lab_bs 

    def get_fat_val(self, n):
        if self.fat_type == "FAT32":
            off = n * 4
            return struct.unpack('<I', self.fat_table[off:off+4])[0] & 0x0FFFFFFF
        elif self.fat_type == "FAT16":
            off = n * 2
            return struct.unpack('<H', self.fat_table[off:off+2])[0]
        else: 
            off = int(n * 1.5)
            v1 = self.fat_table[off]
            v2 = self.fat_table[off+1]
            if n % 2 == 0: return ((v2 & 0x0F) << 8) | v1
            else: return (v2 << 4) | ((v1 & 0xF0) >> 4)

    def read_cluster_data(self, n, size=None):
        if size is None: size = self.clus_sz
        if n < 2: return b""
        addr = self.addr_data + (n - 2) * self.clus_sz
        self.f.seek(addr)
        return self.f.read(min(size, self.clus_sz))

    def get_fat_chain(self, start_cluster):
        chain = []
        curr = start_cluster
        if self.fat_type == "FAT32": limit = 0x0FFFFFF8
        elif self.fat_type == "FAT16": limit = 0xFFF8
        else: limit = 0xFF8
        
        while 2 <= curr < limit and len(chain) < 100000:
            chain.append(curr)
            next_clus = self.get_fat_val(curr)
            if next_clus == curr or next_clus == 0: break 
            curr = next_clus
        return chain

    def scan_dir(self, start_clus, parent_path, is_root_fat16=False):
        if is_root_fat16:
            self.f.seek(self.addr_root)
            raw = self.f.read(self.root_cnt * 32)
        else:
            raw = b""
            chain = self.get_fat_chain(start_clus)
            for c in chain:
                raw += self.read_cluster_data(c)

        for i in range(0, len(raw), 32):
            rec = raw[i:i+32]
            if not rec or rec[0] == 0: break 
            if rec[0] == 0xE5: continue      
            
            attr = rec[11]
            if attr == 0x0F: continue      
            
            name = rec[:8].decode('cp866', errors='replace').strip()
            ext = rec[8:11].decode('cp866', errors='replace').strip()
            if rec[0] == 0x05: name = "\xE5" + name[1:]
            
            if name in ['.', '..']: continue

            full_name = f"{name}.{ext}" if ext else name
            
            if attr & 0x08:
                if self.real_vol_label == self.vol_lab_bs or not self.real_vol_label:
                    self.real_vol_label = name
                self.tree_items.append({
                    'path': parent_path, 'name': name, 'attr': 'VOL', 
                    'size': 0, 'clus': 0, 'date': '-', 'preview_hex': b'', 'preview_txt': '[METKA]',
                    'raw_time': 0, 'raw_date': 0
                })
                continue

            fst_hi = struct.unpack('<H', rec[20:22])[0]
            fst_lo = struct.unpack('<H', rec[26:28])[0]
            fst = (fst_hi << 16) | fst_lo
            
            size = struct.unpack('<I', rec[28:32])[0]
            
            raw_time = struct.unpack('<H', rec[14:16])[0]
            raw_date = struct.unpack('<H', rec[16:18])[0]
            
            d_str = decode_dos_date(raw_date)
            t_str = decode_dos_time(raw_time)
            attr_str = get_attr_str(attr)

            preview_hex = b""
            preview_txt = ""
            
            if not (attr & 0x10) and size > 0:
                data = self.read_cluster_data(fst, 32)
                preview_hex = data
                preview_txt = data.decode('cp866', errors='replace').replace('\n', ' ').replace('\r', '')
            elif attr & 0x10:
                preview_txt = "[DIR]"

            self.tree_items.append({
                'path': parent_path,
                'name': full_name,
                'attr': attr_str,
                'size': size,
                'clus': fst,
                'date': f"{d_str} {t_str}",
                'preview_hex': preview_hex,
                'preview_txt': preview_txt,
                'raw_time': raw_time,
                'raw_date': raw_date
            })

            if attr & 0x10:
                self.found_dirs.append(full_name)
                if fst >= 2:
                    self.scan_dir(fst, parent_path + full_name + "/", False)

    def print_full_report(self):
        print(f"============================================================")
        print(f" АНАЛИЗАТОР ФАЙЛОВОЙ СИСТЕМЫ: {FILENAME}")
        print(f"============================================================")
        
        print("\n[1] ТЕХНИЧЕСКИЕ ПАРАМЕТРЫ (BPB)")
        print(f"Тип ФС: {self.fat_type} | Кластеров: {self.clusters_cnt}")
        print(f"OEM Name: {self.bs_oem} | Метка в заголовке: {self.vol_lab_bs}")
        print(f"Bytes Per Sector: {self.bps}")
        print(f"Reserved Sectors: {self.res_sec}")
        print(f"Sectors Per FAT : {self.active_fat_sz}")
        print(f"Root Entries    : {self.root_cnt} (Всегда 0 для FAT32)")
        print(f"Total Sectors 16: {self.tot_sec16}")
        print(f"Total Sectors 32: {self.tot_sec32}")
        print(f"--> Итого секторов (расчетное): {self.total_sectors}")
        print("-" * 60)
        print(f"Адрес FAT1: {hex(self.addr_fat1)}")
        print(f"Адрес Root: {hex(self.addr_root) if self.fat_type != 'FAT32' else 'Динамичный (Кластер ' + str(self.root_clus) + ')'}")
        print(f"Адрес Data: {hex(self.addr_data)}")

        if self.fat_type == "FAT32":
            self.scan_dir(self.root_clus, "/")
        else:
            self.scan_dir(0, "/", is_root_fat16=True)

        print("\n[2] ПОЛНАЯ ФАЙЛОВАЯ СТРУКТУРА")
        print(f"{'ПУТЬ/ИМЯ':<45} | {'АТР':<6} | {'РАЗМЕР':<8} | {'КЛСТ':<5} | {'ПРЕВЬЮ'}")
        print("-" * 100)
        
        for item in self.tree_items:
            full_p = item['path'] + item['name']
            if len(full_p) > 44: full_p = full_p[:41] + "..."
            prev_short = item['preview_txt'][:20]
            print(f"{full_p:<45} | {item['attr']:<6} | {item['size']:<8} | {item['clus']:<5} | {prev_short}")

        bad_clus = 0x0FFFFFF7 if self.fat_type == "FAT32" else (0xFFF7 if self.fat_type == "FAT16" else 0xFF7)
        alloc = 0
        total_recs = int(self.fat_size_bytes / (4 if self.fat_type == "FAT32" else (2 if self.fat_type == "FAT16" else 1.5)))
        
        for i in range(2, self.clusters_cnt + 2):
            v = self.get_fat_val(i)
            if v != 0 and v != bad_clus: alloc += 1
            
        files_only = [x for x in self.tree_items if 'D' not in x['attr'] and 'VOL' not in x['attr']]
        total_bytes = sum(f['size'] for f in files_only)
        total_clus_files = sum(math.ceil(f['size']/self.clus_sz) if f['size']>0 else 0 for f in files_only)

        dir_count = len(self.found_dirs)
        dirs_answer = f"{dir_count},{','.join(self.found_dirs)}"

        print("\n" + "="*60)
        print("[3] ГОТОВЫЕ ОТВЕТЫ НА ВОПРОСЫ")
        print("="*60)
        print(f"1. Метка тома (реальная):     {self.real_vol_label}")
        print(f"2. Всего директорий (С КОРНЕМ): {dir_count + 1}")
        print(f"   ОТВЕТ ДЛЯ ЗАДАНИЯ (маска): {dirs_answer}")
        print(f"3. Записей в FAT всего:       {total_recs}")
        print(f"4. Реально занято (Allocated):{alloc}")
        print(f"5. Вес всех файлов (байт):    {total_bytes}")
        print(f"6. Занимают кластеров (файлы):{total_clus_files}")
        print(f"7. Зарезервировано секторов:  {self.res_sec}")
        print(f"8. OEM название:              {self.bs_oem}")

        print("\n" + "="*60)
        print("[4] СОДЕРЖИМОЕ КАЖДОГО ФАЙЛА (HEX + TEXT)")
        print("="*60)
        
        if not files_only:
            print("Файлов не найдено.")
        
        for f in files_only:
            print(f"ФАЙЛ: {f['name']}")
            print(f"Расположение: {f['path']} | Кластер: {f['clus']} | Размер: {f['size']}")
            if f['size'] > 0:
                hex_s = " ".join(f"{b:02X}" for b in f['preview_hex'][:16])
                txt_s = "".join((chr(b) if 32 <= b <= 126 else '.') for b in f['preview_hex'][:16])
                print(f"HEX: {hex_s}")
                print(f"TXT: {txt_s}")
            else:
                print("(Пустой файл)")
            print("-" * 40)

        print("\n" + "="*60)
        print("[5] ШПАРГАЛКА ДЛЯ ЗАЩИТЫ (BPB & ТЕОРИЯ)")
        print("="*60)
        
        print(">>> ПАРАМЕТРЫ BPB (Как просит преподаватель: Offset, Size)")
        print(f"BPB_BytsPerSec (Off 11, Size 2): {self.bps} (0x{self.bps:04X})")
        print(f"BPB_SecPerClus (Off 13, Size 1): {self.spc} (0x{self.spc:02X})")
        print(f"BPB_RsvdSecCnt (Off 14, Size 2): {self.res_sec} (0x{self.res_sec:04X})")
        print(f"BPB_NumFATs    (Off 16, Size 1): {self.n_fats} (0x{self.n_fats:02X})")
        
        if self.fat_type == "FAT32":
            print(f"BPB_TotSec32   (Off 32, Size 4): {self.tot_sec32} (0x{self.tot_sec32:08X})")
            print(f"BPB_FATSz32    (Off 36, Size 4): {self.fat_sz32} (0x{self.fat_sz32:08X})")
            print(f"BPB_RootClus   (Off 44, Size 4): {self.root_clus} (0x{self.root_clus:08X})")
            print(f"BPB_VolLab     (Off 71, Size 11): '{self.vol_lab_bs}'")
        else:
            print(f"BPB_RootEntCnt (Off 17, Size 2): {self.root_cnt} (0x{self.root_cnt:04X})")
            print(f"BPB_TotSec16   (Off 19, Size 2): {self.tot_sec16} (0x{self.tot_sec16:04X})")
            print(f"BPB_FATSz16    (Off 22, Size 2): {self.fat_sz16} (0x{self.fat_sz16:04X})")
            print(f"BPB_VolLab     (Off 43, Size 11): '{self.vol_lab_bs}'")
            if self.tot_sec16 == 0:
                print(f"BPB_TotSec32   (Off 32, Size 4): {self.tot_sec32} (0x{self.tot_sec32:08X}) <- Используется этот!")
        print("-" * 40)
        
        print(">>> КАК ИСКАТЬ МЕТКУ ТОМА (ТЕОРИЯ)")
        if self.fat_type == "FAT32":
            print("1. В BPB (Boot Sector): Смещение 0x47 (71), длина 11 байт.")
        else:
            print("1. В BPB (Boot Sector): Смещение 0x2B (43), длина 11 байт.")
        print("2. В Root Directory: Искать запись с атрибутом 0x08 (Volume Label).")
        print(f"   В данном образе реальная метка: {self.real_vol_label}")
        print("-" * 40)
        
        print(">>> КАК ИСКАТЬ ВРЕМЯ/ДАТУ (ТЕОРИЯ)")
        if files_only:
            ex_file = files_only[0]
            print(f"Пример на файле: {ex_file['name']}")
            print(f"Время (HEX): 0x{ex_file['raw_time']:04X} | Дата (HEX): 0x{ex_file['raw_date']:04X}")
            t_val = ex_file['raw_time']
            print(f"Время в битах (16 бит): {t_val:016b}")
            print(f"   Часы (5 бит,  11-15): {(t_val >> 11) & 0x1F} (dec)")
            print(f"   Мин  (6 бит,  5-10):  {(t_val >> 5) & 0x3F} (dec)")
            print(f"   Сек/2 (5 бит, 0-4):   {t_val & 0x1F} (dec) * 2 = {(t_val & 0x1F) * 2}")
            d_val = ex_file['raw_date']
            print(f"Дата в битах (16 бит):  {d_val:016b}")
            print(f"   Год  (7 бит, 9-15):   {(d_val >> 9) & 0x7F} (+1980) = {((d_val >> 9) & 0x7F) + 1980}")
            print(f"   Мес  (4 бита, 5-8):   {(d_val >> 5) & 0x0F}")
            print(f"   День (5 бит,  0-4):   {d_val & 0x1F}")
        else:
            print("(Файлов нет для примера, но учите структуру бит: H-5, M-6, S-5 | Y-7, M-4, D-5)")

        print("\n" + "="*60)
        print("[6] ЦЕПОЧКИ КЛАСТЕРОВ (ЕСЛИ ФРАГМЕНТАЦИЯ)")
        print("="*60)
        if not files_only:
            print("Нет файлов для анализа.")
        for f in files_only:
            if f['size'] == 0:
                print(f"Файл: {f['name']} (Пустой, кластеров нет)")
                continue
            chain = self.get_fat_chain(f['clus'])
            chain_str = " -> ".join(map(str, chain)) + " -> EOF"
            print(f"Файл: {f['name']}")
            print(f"   Начальный кластер: {f['clus']}")
            print(f"   Цепочка FAT: {chain_str}")
            if len(chain) > 1:
                is_frag = False
                for k in range(len(chain)-1):
                    if chain[k+1] != chain[k] + 1:
                        is_frag = True
                        break
                if is_frag:
                    print("   !!! ВНИМАНИЕ: ФАЙЛ ФРАГМЕНТИРОВАН !!!")
                else:
                    print("   (Файл записан подряд)")
            print("-" * 20)

        print("\n" + "="*60)
        print("[7] ДЕТАЛЬНАЯ РАСШИФРОВКА ДАТЫ И ВРЕМЕНИ")
        print("="*60)
        for item in self.tree_items:
            if item['attr'] == 'VOL': continue
            name = item['name']
            d_val = item['raw_date']
            t_val = item['raw_time']
            year = ((d_val >> 9) & 0x7F) + 1980
            month = (d_val >> 5) & 0x0F
            day = d_val & 0x1F
            hour = (t_val >> 11) & 0x1F
            minute = (t_val >> 5) & 0x3F
            sec = (t_val & 0x1F) * 2
            
            print(f"ОБЪЕКТ: {name} ({'ПАПКА' if 'D' in item['attr'] else 'ФАЙЛ'})")
            print(f"  > ДАТА (HEX: 0x{d_val:04X}) --> BIN: {d_val:016b}")
            print(f"    Год (7 бит): {d_val >> 9:03d} (dec) + 1980 = {year}")
            print(f"    Мес (4 бита):  {month:02d} (dec)")
            print(f"    Ден (5 бит):   {day:02d} (dec)")
            print(f"  > ВРЕМЯ (HEX: 0x{t_val:04X}) --> BIN: {t_val:016b}")
            print(f"    Час (5 бит):   {hour:02d} (dec)")
            print(f"    Мин (6 бит):   {minute:02d} (dec)")
            print(f"    Сек (5 бит):   {t_val & 0x1F:02d} (dec) * 2    = {sec:02d}")
            print(f"  = РЕЗУЛЬТАТ: {day:02d}.{month:02d}.{year} {hour:02d}:{minute:02d}:{sec:02d}")
            print("-" * 40)

if __name__ == "__main__":
    analyzer = FATAnalyzer(FILENAME, VHD_OFFSET)
    analyzer.print_full_report()