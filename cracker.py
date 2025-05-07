import hashlib
import itertools
import time
import sys
import multiprocessing
import ipaddress

# Öncelikli IP aralıkları (CIDR formatında)
PRIORITY_NETS = [
    "192.168.0.0/16",    # Yerel ağ
    "172.16.0.0/12",     # Yerel ağ
    "10.0.0.0/8",        # Yerel ağ
]

def generate_all_ips():
    """Tüm IPv4 adreslerini üretir (0.0.0.0 - 255.255.255.255)"""
    for a, b, c, d in itertools.product(range(256), repeat=4):
        yield f"{a}.{b}.{c}.{d}"

def generate_priority_ips():
    """Öncelikli IP'leri üretir (daha hızlı erişim için)"""
    for network in PRIORITY_NETS:
        net = ipaddress.ip_network(network)
        for ip in net.hosts():
            yield str(ip)

def check_ip(ip, target_md5):
    """IP'nin hash'ini kontrol eder"""
    return hashlib.md5(ip.encode()).hexdigest() == target_md5

def worker(batch, target_md5, result_queue):
    """İş parçacığı fonksiyonu"""
    found = None
    for ip in batch:
        if check_ip(ip, target_md5):
            found = ip
            break
    result_queue.put((len(batch), found))

def crack_md5_hash(target_md5):
    """Ana hash kırma fonksiyonu"""
    start_time = time.time()
    total_ips = 256**4
    processed_ips = 0
    
    # Sonuç kuyruğu
    result_queue = multiprocessing.Queue()
    
    # İşlemci sayısı
    num_processes = multiprocessing.cpu_count()
    
    # Batch boyutu
    batch_size = 50000
    
    # 1. ÖNCELİKLİ AĞLARI TARA
    print("[+] Öncelikli ağlar taranıyor...")
    priority_ips = generate_priority_ips()
    
    while True:
        # İşlem havuzu oluştur
        processes = []
        for _ in range(num_processes):
            batch = list(itertools.islice(priority_ips, batch_size))
            if not batch:
                break
            p = multiprocessing.Process(
                target=worker,
                args=(batch, target_md5, result_queue)
            )
            p.start()
            processes.append(p)
        
        if not processes:
            break  # Öncelikli IP'ler bitti
        
        # Sonuçları dinle
        while processes:
            try:
                count, found = result_queue.get(timeout=0.1)
                processed_ips += count
                
                # İlerlemeyi göster
                elapsed = time.time() - start_time
                ips_per_sec = processed_ips / elapsed
                progress = processed_ips / total_ips
                
                sys.stdout.write(
                    f"\rDenenen IP: {processed_ips:,} | "
                    f"Ilerleme: {progress:.6%} | "
                    f"Hız: {ips_per_sec:,.0f} IP/s | "
                    f"ETA: {time.strftime('%H:%M:%S', time.gmtime((total_ips-processed_ips)/ips_per_sec))}"
                )
                sys.stdout.flush()
                
                if found:
                    for p in processes:
                        p.terminate()
                    print(f"\n\n[+] BAŞARILI! Hash eşleşmesi bulundu: {found}")
                    print(f"Toplam süre: {elapsed:.2f} saniye")
                    return found
                    
            except multiprocessing.queues.Empty:
                # Zaman aşımı - process'leri kontrol et
                processes = [p for p in processes if p.is_alive()]
    
    # 2. TÜM DİĞER IP'LERİ TARA
    print("\n[+] Tüm IPv4 aralığı taranıyor...")
    all_ips = generate_all_ips()
    
    while True:
        # İşlem havuzu oluştur
        processes = []
        for _ in range(num_processes):
            batch = list(itertools.islice(all_ips, batch_size))
            if not batch:
                break
            p = multiprocessing.Process(
                target=worker,
                args=(batch, target_md5, result_queue)
            )
            p.start()
            processes.append(p)
        
        if not processes:
            break  # Tüm IP'ler bitti
        
        # Sonuçları dinle
        while processes:
            try:
                count, found = result_queue.get(timeout=0.1)
                processed_ips += count
                
                # İlerlemeyi göster
                elapsed = time.time() - start_time
                ips_per_sec = processed_ips / elapsed
                progress = processed_ips / total_ips
                
                sys.stdout.write(
                    f"\rDenenen IP: {processed_ips:,} | "
                    f"Ilerleme: {progress:.6%} | "
                    f"Hız: {ips_per_sec:,.0f} IP/s | "
                    f"ETA: {time.strftime('%H:%M:%S', time.gmtime((total_ips-processed_ips)/ips_per_sec))}"
                )
                sys.stdout.flush()
                
                if found:
                    for p in processes:
                        p.terminate()
                    print(f"\n\n[+] BAŞARILI! Hash eşleşmesi bulundu: {found}")
                    print(f"Toplam süre: {elapsed:.2f} saniye")
                    return found
                    
            except multiprocessing.queues.Empty:
                # Zaman aşımı - process'leri kontrol et
                processes = [p for p in processes if p.is_alive()]
    
    print("\n\n[-] Eşleşme bulunamadı. Tüm IPv4 aralığı tarandı.")
    return None

if __name__ == "__main__":
    target_hash = "fc4d88b57d57592a256c636634a10c6a" # Hedeflenen hash adresini buraya yazınız
    print(f"[+] MD5 IP kırıcı başlatıldı | Hedef hash: {target_hash}")
    crack_md5_hash(target_hash)
