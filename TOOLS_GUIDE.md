# 📖 الدليل الشامل لتشغيل وشرح أدوات Scapy Network Toolkit

هذا الدليل يقدّم شرحاً تفصيلياً لكل أداة موجودة في المشروع، كيفية عملها برمجياً تحت الغطاء (Under the Hood)، أوامر تشغيلها المباشرة من الطرفية (Terminal)، وطريقة استخدامها عبر القائمة التفاعلية.

---

## 📑 فهرس الأدوات

1. [الأداة التفاعلية الشاملة (main.py)](#1-الأداة-التفاعلية-الشاملة-mainpy)
2. [فاحص الأجهزة عبر ARP (arp_scanner.py)](#2-فاحص-الأجهزة-عبر-arp-arp_scannerpy)
3. [فاحص المنافذ والـ Ping (port_scanner.py)](#3-فاحص-المنافذ-والـ-ping-port_scannerpy)
4. [ملتقط الحزم المباشر ومصدر الـ PCAP (sniffer.py)](#4-ملتقط-الحزم-المباشر-ومصدر-الـ-pcap-snifferpy)
5. [قارئ ومحلل ملفات الـ PCAP (pcap_analyzer.py)](#5-قارئ-ومحلل-ملفات-الـ-pcap-pcap_analyzerpy)
6. [صانع ومُرسل الحزم المخصصة (packet_crafter.py)](#6-صانع-ومرسل-الحزم-المخصصة-packet_crafterpy)
7. [مدير شبكات الواي فاي واسترجاع كلمات المرور (wifi_manager.py)](#7-مدير-شبكات-الواي-فاي-واسترجاع-كلمات-المرور-wifi_managerpy)
8. [مكتشف الراوتر وفاحص منافذه وخدماته (gateway_scanner.py)](#8-مكتشف-الراوتر-وفاحص-منافذه-وخدماته-gateway_scannerpy)
9. [فاحص حزم الـ 802.11 Beacons وتحليل التشفير (wifi_sniffer.py)](#9-فاحص-حزم-الـ-80211-beacons-وتحليل-التشفير-wifi_snifferpy)
10. [أداة استكشاف الويب والـ APIs عبر Requests (http_recon.py)](#10-أداة-استكشاف-الويب-والـ-apis-عبر-requests-http_reconpy)
11. [أداة إدارة السيرفرات والتحكم عن بعد عبر SSH و SFTP (ssh_manager.py)](#11-أداة-إدارة-السيرفرات-والتحكم-عن-بعد-عبر-ssh-و-sftp-ssh_managerpy)
12. [فاحص بورتات الشبكة واختبار الخدمات الشامل (network_tester.py)](#12-فاحص-بورتات-الشبكة-واختبار-الخدمات-الشامل-network_testerpy)
13. [واجهة المستخدم الرسومية الشاملة بـ Tkinter (gui.py)](#13-واجهة-المستخدم-الرسومية-الشاملة-بـ-tkinter-guipy)

---

## 1. الأداة التفاعلية الشاملة (`main.py`)

### 📌 الوصف:
هي لوحة التحكم الرئيسية للمشروع، تجمع كل الأدوات في قائمة رقمية ملونة وسهلة، وتفحص تلقائياً ما إذا كان المستخدم يمتلك صلاحيات الـ Root / Sudo المطلوبة للتعامل مع بطاقات الشبكة والـ Raw Sockets.

### ⚙️ كيف تعمل برمجياً؟
- تقوم باستيراد كافة الوحدات من مجلد `modules/`.
- تفحص معرف المستخدم `os.geteuid()` للتأكد من وجود صلاحية الجذر `0`.
- تعرض قائمة من 1 إلى 9 وتستقبل مدخلات المستخدم لتشغيل الوظيفة المطلوبة مع معالجة الأخطاء.

### 💻 أمر التشغيل:
```bash
sudo ./venv/bin/python main.py
```

---

## 2. فاحص الأجهزة عبر ARP (`arp_scanner.py`)

### 📌 الوصف:
أداة لاكتشاف جميع الحواسيب والهواتف والراوترات المتصلة على نفس الشبكة المحلية (Local Subnet)، وتحديد عناوين الـ IP وعناوين الـ MAC الفيزيائية الخاصة بكل جهاز.

### ⚙️ كيف تعمل برمجياً؟
1. تنشئ إطار بث عام على Layer 2: `Ether(dst="ff:ff:ff:ff:ff:ff")`.
2. تنشئ طلب ARP لعنوان الشبكة: `ARP(pdst="192.168.1.0/24")`.
3. تدمج الطبقتين عبر عامل الربط `/`: `packet = broadcast / arp_request`.
4. ترسل الحزم وتستقبل الردود عبر دالة `srp()` الخاصة بالطبقة الثانية (Layer 2 Send/Receive).
5. تقرأ من كل رد عنوان الـ IP من `received.psrc` وعنوان الـ MAC من `received.hwsrc`.

### 💻 أمر التشغيل المباشر:
```bash
# فحص الشبكة الافتراضية
sudo ./venv/bin/python modules/arp_scanner.py

# فحص نطاق شبكة محدد (مثال)
sudo ./venv/bin/python modules/arp_scanner.py 192.168.1.0/24
```

### 📋 مخرجات نموذجية:
```text
[*] Sending ARP broadcast to 192.168.1.0/24 ...
==================================================
IP Address           | MAC Address         
==================================================
192.168.1.1          | c4:a3:66:5e:ff:48   
192.168.1.4          | 48:51:c5:da:31:02   
192.168.1.15         | 70:85:c2:d9:1a:4b   
==================================================
Total discovered hosts: 3
```

---

## 3. فاحص المنافذ والـ Ping (`port_scanner.py`)

### 📌 الوصف:
أداة تشخيص شبكات متقدمة تقوم بوظيفتين أساسيتين:
1. **ICMP Ping**: فحص اتصال الهدف والتأكد من أنه قيد التشغيل.
2. **TCP Stealth SYN Scan**: فحص المنافذ المفتوحة بطريقة التخفي دون إكمال مصافحة الاتصال الثلاثية (Half-Open Scan).

### ⚙️ كيف تعمل برمجياً؟
- **Ping**: تبني `IP(dst=target)/ICMP()` وترسلها عبر `sr1()`. إذا كان الرد يحمل `type=0` (Echo Reply)، فالهدف نشط.
- **SYN Scan**: ترسل حزمة `IP(dst=target)/TCP(dport=port, flags="S")` عبر `sr1()`:
  - إذا رد الهدف بـ `flags="SA"` (SYN-ACK): المنفذ **مفتوح (Open)**، وتقوم الأداة فوراً بإرسال حزمة `RST` لإلغاء الاتصال بهدوء.
  - إذا رد بـ `flags="RA"` (RST-ACK): المنفذ **مغلق (Closed)**.
  - إذا لم يرد أو رد بـ ICMP Unreachable: المنفذ **محجوب بجدار ناري (Filtered)**.

### 💻 أمر التشغيل المباشر:
```bash
# فحص الجهاز المحلي
sudo ./venv/bin/python modules/port_scanner.py 127.0.0.1

# فحص خادم أو راوتر محدد
sudo ./venv/bin/python modules/port_scanner.py 192.168.1.1
```

---

## 4. ملتقط الحزم المباشر ومصدر الـ PCAP (`sniffer.py`)

### 📌 الوصف:
أداة مراقبة ترافيك الشبكة اللحظي، تدعم فلاتر BPF القوية، وتتيح عرض التشريح الكامل لكل حزمة عبر `.show()`، مع إمكانية حفظ الحزم الملتقطة إلى ملف `.pcap` لفتحها لاحقاً في برنامج **Wireshark**.

### ⚙️ كيف تعمل برمجياً؟
- تستدعي دالة `sniff()` في Scapy وتقوم بفتح Raw Socket على كارت الشبكة.
- تطبق فلاتر Berkeley Packet Filter (BPF) مثل `tcp`, `port 80`, `icmp`.
- تقوم بتمرير كل حزمة ملتقطة لدالة `packet_callback` لتنسيق معلومات الـ IP والـ Ports والبروتوكول.
- عند الانتهاء، تستدعي دالة `wrpcap(filename, packets)` لكتابة كافة الحزم على القرص بصيغة الـ PCAP القياسية.

### 💻 أمر التشغيل المباشر:
```bash
# التقاط كافة الحزم
sudo ./venv/bin/python modules/sniffer.py

# التقاط حزم الـ ICMP (الـ Ping) فقط
sudo ./venv/bin/python modules/sniffer.py "icmp"

# التقاط ترافيك الويب (HTTP & HTTPS)
sudo ./venv/bin/python modules/sniffer.py "tcp port 80 or tcp port 443"
```

---

## 5. قارئ ومحلل ملفات الـ PCAP (`pcap_analyzer.py`)

### 📌 الوصف:
أداة لتحليل وتفكيك ملفات الحزم المحفوظة مسبقاً (سواء تم التقاطها من Scapy أو تم تصديرها من برنامج Wireshark أو tcpdump)، وتوليد إحصائيات دقيقة عنها.

### ⚙️ كيف تعمل برمجياً؟
- تقرأ الملف باستخدام دالة `rdpcap(filepath)` التي تعيد كائن `PacketList`.
- تحلل توزيع البروتوكولات (TCP, UDP, ICMP, ARP) باستخدام `collections.Counter`.
- تستخرج أكثر عناوين الـ IP نشاطاً (Top Talkers).
- تتيح اختيار رقم أي حزمة واستدعاء دالة `packet.show()` لعرض تشريح تفصيلي لجميع الهيدرز والحقول وقيمها.

### 💻 أمر التشغيل المباشر:
*(ملاحظة: لا تتطلب صلاحيات sudo لأنها تقرأ ملفاً محلياً)*
```bash
./venv/bin/python modules/pcap_analyzer.py captures/sample_test.pcap
```

---

## 6. صانع ومُرسل الحزم المخصصة (`packet_crafter.py`)

### 📌 الوصف:
أداة لتصميم حزم مخصصة بالكامل على أي طبقة (Layer 2 أو Layer 3)، وتحديد المنافذ والـ Flags وعناوين الـ IP وحمولة البيانات (Payload)، مع إمكانية تزييف عنوان المصدر (IP Spoofing) ومعاينة الحزمة عبر `.show()` قبل إطلاقها إلى الشبكة.

### ⚙️ كيف تعمل برمجياً؟
- **Layer 3**: تبني طبقة الـ IP `IP(src=..., dst=...)` وتدمج معها `TCP` أو `UDP` أو `ICMP` و `Raw(load=...)`، ثم ترسلها عبر دالة `send()`.
- **Layer 2**: تبني إطار إيثرنت `Ether(dst="ff:ff:ff:ff:ff:ff")` وتضع بداخله حزمة الـ IP، ثم ترسلها عبر دالة `sendp()`.
- تستخدم دالة `.show()` لمعاينة الـ Checksum والـ Length وبنية الهيدر بالكامل قبل الضغط على زر الإرسال.

### 💻 أمر التشغيل المباشر:
```bash
sudo ./venv/bin/python modules/packet_crafter.py
```

---

## 7. مدير شبكات الواي فاي واسترجاع كلمات المرور (`wifi_manager.py`)

### 📌 الوصف:
أداة شاملة للتحكم في بطاقة الواي فاي وإدارتها على نظام لينكس:
1. فحص جميع شبكات الواي فاي المحيطة وعرض قوة الإشارة ونوع التشفير.
2. استخراج وعرض جميع كلمات المرور المخزنة في النظام لشبكات الواي فاي المحفوظة.
3. الاتصال المباشر بأي شبكة لاسلكية والتحقق من نيل عنوان IP عبر DHCP.
4. تدقيق أمان وقوة كلمة المرور وحساب الـ Entropy.

### ⚙️ كيف تعمل برمجياً؟
- تستخدم واجهة `nmcli dev wifi list` لجمع بيانات الشبكات الهوائية وعرض نسبة الإشارة بهيئة أعمدة بيانية `▂▄▆█`.
- تستخرج كلمات المرور المخزنة في NetworkManager عبر `nmcli -s -g 802-11-wireless-security.psk connection show <name>` ومن مجلد اتصالات النظام `/etc/NetworkManager/system-connections/`.
- تجري فحص أمان لكلمة المرور عبر فحص القواميس الشائعة (Dictionary Check)، حساب طول الكلمة، وتنوع الأحرف، وقياس عشوائية Shannon Entropy.

### 💻 أمر التشغيل المباشر:
```bash
# فحص الشبكات واستعراض كلمات المرور المحفوظة فوراً
sudo ./venv/bin/python modules/wifi_manager.py
```

---

## 8. مكتشف الراوتر وفاحص منافذه وخدماته (`gateway_scanner.py`)

### 📌 الوصف:
أداة ذكية تحدد عنوان الـ Default Gateway للراوتر تلقائياً عبر الكارت النشط، وتفحص كافة المنافذ الحساسة والخدمات المفتوحة على جهاز التوجيه (الراوتر) فور الاتصال به.

### ⚙️ كيف تعمل برمجياً؟
1. تكتشف الراوتر باستخدام دالة توجيه الحزم في Scapy: `conf.route.route("0.0.0.0")` التي تعيد `(Interface, Local_IP, Gateway_IP)`.
2. تفحص استجابة الراوتر عبر `icmp_ping()`.
3. تجري مسح TCP SYN على أشهر منافذ الراوتر:
   - لوحات التحكم (Web Admin): `80, 443, 8080, 8443`
   - بروتوكولات الإدارة عن بُعد: `SSH (22), Telnet (23)`
   - خوادم الأسماء ومشاركة الملفات: `DNS (53), SMB/NetBIOS (139, 445)`
   - بروتوكولات التوجيه والمزود: `UPnP (1900), TR-069 (7547)`
4. تحلل النتائج وتقدم تنبيهات أمنية (مثل التحذير في حال كان Telnet مفتوحاً وغير مشفر).

### 💻 أمر التشغيل المباشر:
```bash
sudo ./venv/bin/python modules/gateway_scanner.py
```

### 📋 مخرجات نموذجية:
```text
[+] Detected Default Gateway (Router) : 192.168.1.1
    Local Assigned IP                 : 192.168.1.4
    Active Interface                  : wlo1

[*] Testing router reachability (Ping)...
[+] Router 192.168.1.1 is UP and responding to Ping!

[*] Scanning Router Gateway: 192.168.1.1
Port     | Status       | Service      | Description / Security Notes
--------------------------------------------------------------------------------
53       | Open         | DNS          | Router Domain Name Service cache/resolver
80       | Open         | HTTP         | Router Web Admin GUI (Standard)
443      | Open         | HTTPS        | Router Secure Web Admin GUI (SSL/TLS)
1900     | Filtered     | UPnP         | Universal Plug and Play (Auto Port Mapping)
7547     | Open         | TR-069       | CWMP Remote Management (Used by ISPs)
================================================================================
[+] Scan Complete: Found 4 open port(s) on the router.
💡 Web Administration is available! You can access the router via browser.
ℹ️  TR-069 is open (Used by your Internet Service Provider for remote provisioning).
```

---

## 9. فاحص حزم الـ 802.11 Beacons وتحليل التشفير (`wifi_sniffer.py`)

### 📌 الوصف:
أداة تفكيك وتحليل حزم الـ 802.11 Management Frames (Beacons) الصادرة من نقاط الوصول (Access Points) لتحديد نوع التشفير اللاسلكي بدقة متناهية وفحص معايير الأمان.

### ⚙️ كيف تعمل برمجياً؟
- تستخدم طبقات Scapy اللاسلكية: `Dot11`, `Dot11Beacon`, و `Dot11Elt`.
- تبحث داخل Information Elements (IEs):
  - **ID 0**: اسم الشبكة (SSID).
  - **ID 3**: قناة البث (Channel).
  - **ID 48**: حقل الـ RSN (Robust Security Network) لكشف WPA2 (AES/CCMP) و WPA3 (SAE Suite 8) و 802.1X Enterprise.
  - **ID 221**: كشف Microsoft WPA1 القديم.
  - **Capability Privacy Bit**: لكشف شبكات WEP أو الشبكات المفتوحة Open.
- تتيح فحص ملفات `.pcap` اللاسلكية أو الالتقاط المباشر في حال تفعيل وضع الـ Monitor Mode.

### 💻 أمر التشغيل المباشر:
```bash
# التقاط حزم الـ Beacons الحية (يحتاج بطاقة تدعم Monitor Mode)
sudo ./venv/bin/python modules/wifi_sniffer.py

# فحص ملف التقاط لاسلكي مسجل مسبقاً
./venv/bin/python modules/wifi_sniffer.py captures/wireless_sample.pcap
```

---

## 10. أداة استكشاف الويب والـ APIs عبر Requests (`http_recon.py`)

### 📌 الوصف:
أداة مخصصة لبروتوكول HTTP/HTTPS والتفاعل مع خوادم الويب وخدمات الـ REST APIs السحابية، وفحص حالة المواقع، وسحب الـ Server Banners، وتحليل ترويسات الأمان (Security Headers)، وجمع معلومات الـ OSINT والـ Threat Intelligence لعناوين الـ IP.

### ⚙️ كيف تعمل برمجياً؟
- **`requests.get(url)`**: ترسل طلب HTTP GET، تحسب زمن الاستجابة بالميلي ثانية (Latency)، وتتأكد ما إذا كان السيرفر يعمل.
- **`response.status_code`**: تفحص كود الاستجابة بالألوان (200 OK، 301 Redirect، 403 Forbidden، 404 Not Found، 500 Server Error).
- **`response.headers`**: تستخرج خادم الويب (`Server` / `X-Powered-By`) وتفحص ترويسات الأمان الحرجة:
  - `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options` (الحماية من Clickjacking)
  - `X-Content-Type-Options` (الحماية من MIME-sniffing)
- **`response.json()`**: تتواصل مع واجهات برمجة التطبيقات (APIs) وتقوم بتحويل نصوص الرد إلى كائنات بايثون (Dictionaries)، مثل الاستعلام عن Geolocation والـ ASN ومزود الخدمة (ISP) لعنوان الـ IP.
- **`requests.post(url, data/json)`**: ترسل بيانات ونماذج إلى الخادم مثل تسجيل الدخول أو إرسال payloads.
- **`requests.Session()`**: تنشئ جلسة اتصال دائمة تحتفظ بالـ Cookies والترويسات المخصصة عبر عدة طلبات متتالية.

### 💻 أمر التشغيل المباشر:
*(ملاحظة: لا تتطلب صلاحيات sudo لأنها تعمل على طبقة التطبيقات عبر اتصالات المستخدم العادية)*
```bash
# تشغيل القائمة التفاعلية لأداة Requests
./venv/bin/python modules/http_recon.py

# فحص موقع مباشرة من سطر الأوامر (مثال)
./venv/bin/python modules/http_recon.py google.com
```

### 📋 مخرجات نموذجية:
```text
[*] Sending GET request to: https://github.com ...
=================================================================
             HTTP GET INSPECTION RESULT
=================================================================
Target URL       : https://github.com/
Status Code      : 200 OK
Response Time    : 184.2 ms
Content Length   : 577121 bytes
Server Banner    : github.com
=================================================================

======================================================================
             HTTP RESPONSE HEADERS & SECURITY AUDIT
======================================================================
Header                       | Status       | Description
----------------------------------------------------------------------
Strict-Transport-Security    | Present     | HSTS - Enforces HTTPS communication
Content-Security-Policy      | Present     | CSP - Mitigates XSS and data injection attacks
X-Frame-Options              | Present     | Prevents Clickjacking attacks in iframes
X-Content-Type-Options       | Present     | Prevents MIME-sniffing vulnerabilities
Referrer-Policy              | Present     | Controls referrer information passed
Permissions-Policy           | Missing     | Controls browser features allowed
======================================================================
Security Headers Score: 5/6 (83.3%)
```

---

## 11. أداة إدارة السيرفرات والتحكم عن بعد عبر SSH و SFTP (`ssh_manager.py`)

### 📌 الوصف:
أداة مخصصة لإدارة السيرفرات والأجهزة البعيدة عبر بروتوكول SSH المشفّر باستخدام مكتبة **Paramiko**، وتنفيذ الأوامر عن بُعد، وسحب ملفات الـ Logs، ونقل الملفات بأمان عبر SFTP، وإجراء فحوصات أمنية تلقائية على السيرفر البعيد.

### ⚙️ كيف تعمل برمجياً؟
- **`SSHClient()`**: تنشئ كائن عميل SSH جديد وتضبط سياسة قبول مفاتيح الخوادم (`paramiko.AutoAddPolicy()`).
- **`client.connect(hostname, port, username, password/key)`**: تؤسس نفق اتصال مشفّر وآمن بالخادم البعيد باستخدام كلمة المرور أو مفتاح SSH الخاص (`id_rsa`).
- **`client.exec_command(cmd)`**: تنفذ أي أمر shell على الخادم البعيد وتسترجع قنوات الإدخال والإخراج القياسي ورموز الخروج (`exit_status`, `stdout`, `stderr`).
- **`client.open_sftp()` / `SFTPClient`**:
  - `sftp.get(remote_path, local_path)`: سحب ملفات اللوجات أو النسخ الاحتياطية من السيرفر لجهازك المحلي بشكل آمن.
  - `sftp.put(local_path, remote_path)`: رفع الملفات أو السكربتات من جهازك إلى السيرفر البعيد.
- **`run_system_audit()`**: سكربت تدقيق أمني مدمج ينفذ تلقائياً استعلامات عن حالة النظام والمنافذ المفتوحة (`ss -tuln`) والمستخدمين المتصلين (`who`) ومحاولات تسجيل الدخول الفاشلة (`auth.log`).
- **`client.close()`**: إنهاء وإغلاق جلسة الاتصال بأمان بعد الانتهاء.

### 💻 أمر التشغيل المباشر:
*(ملاحظة: لا تتطلب صلاحيات sudo لأنها بروتوكول اتصال طرفي عادي)*
```bash
# تشغيل القائمة التفاعلية لأداة SSH
./venv/bin/python modules/ssh_manager.py
```

### 📋 مخرجات نموذجية:
```text
[*] Connecting to SSH server: 192.168.1.50:22 as 'root' ...
[+] Successfully connected to root@192.168.1.50:22!

=================================================================
       REMOTE SYSTEM AUDIT: root@192.168.1.50
=================================================================
[+] Operating System & Kernel
Linux 6.8.0-45-generic x86_64 GNU/Linux

[+] Host Uptime & System Load
 03:40:15 up 12 days,  4:12,  2 users,  load average: 0.15, 0.08, 0.02

[+] Currently Logged In Users
root     pts/0        2026-09-13 03:39 (192.168.1.4)

[+] Listening Network Ports
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    
tcp   LISTEN 0      4096       127.0.0.1:3306       0.0.0.0:*    
tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*    
=================================================================
```

---

## 12. فاحص بورتات الشبكة واختبار الخدمات الشامل (`network_tester.py`)

### 📌 الوصف:
أداة استطلاع وفحص متطورة وشاملة للمحيط الشبكي (Network-Wide Port Scanner & Service Tester):
1. **التعرف التلقائي على بيئة الشبكة (Auto Subnet & Gateway Discovery)**: استخراج كارت الشبكة النشط، عنوان الـ IP المحلي، عنوان وماك الراوتر (Default Gateway)، ونطاق الشبكة (Subnet CIDR مثل `192.168.1.0/24`).
2. **مسح واكتشاف الأجهزة الحية (Active Hosts Sweep)**: اكتشاف كافة الأجهزة المتصلة على نفس الشبكة المحيطة عبر ARP Broadcast (بصلاحيات الـ Root) أو عبر Ping Sweep المتوازي وقراءة جدول الجيران (بدون Root).
3. **فحص المنافذ المتوازي (Multithreaded Port Scanner)**: فحص منافذ كافة الأجهزة المكتشفة في نفس الوقت بسرعات فائقة عبر الـ ThreadPoolExecutor.
4. **اختبار الخدمات وسحب البانر (Active Service Testing & Banner Grabbing)**:
   - قياس زمن الاستجابة (Latency بالملي ثانية) لكل منفذ.
   - اختبار خوادم الويب (HTTP / HTTPS): إرسال طلب وقراءة كود الاستجابة (Status Code)، نوع الخادم (Server Header)، وعنوان الصفحة (`<title>`).
   - اختبار خدمات الـ SSH / FTP / SMTP / MySQL وقراءة البانر الأولي للتعرف على الإصدار.
   - تقييم المخاطر الأمنية (مثل كشف منافذ Telnet 23 غير المشفرة أو منافذ TR-069).

### ⚙️ كيف تعمل برمجياً؟
- يتم استدعاء `detect_local_network_context()` لقراءة الـ Route Table و `ip addr` لتحديد النطاق.
- تستدعي `discover_active_hosts()` لعمل مسح للأجهزة.
- تنفذ دالة `scan_and_test_host()` لاختبار منافذ كل جهاز وسحب البانر.
- تصدر تقريراً تفاعلياً شاملاً وجدولاً نهائياً يلخص كل جهاز، عناوينه، منافذه المفتوحة، وملاحظاته الأمنية.

### 💻 أوامر التشغيل:
```bash
# تشغيل الفاحص عبر القائمة التفاعلية (الخيار 11):
sudo ./venv/bin/python main.py

# أو اختباره برمجياً مباشرة عبر بايثون:
./venv/bin/python -c "from modules.network_tester import run_interactive_network_tester; run_interactive_network_tester()"
```

---

## 13. واجهة المستخدم الرسومية الشاملة بـ Tkinter (`gui.py`)

### 📌 الوصف:
واجهة سطح مكتب تفاعلية حديثة مبنية بمكتبة **Tkinter** و **ttk**، تغطي جميع وظائف الأدوات السابقة من خلال واجهة بصرية داكنة (Dark Theme) منظمة في 10 ألسنة تبويب (Tabs)، مع دعم الخيوط المتعددة (Multithreading) لمنع تجمد النافذة، وشاشة تشريح الحزم العميقة.

### ⚙️ كيف تعمل برمجياً؟
1. **تصميم التبويبات (Notebook Tabs)**: يتم تقسيم الأدوات إلى 10 تبويبات مستقلة:
   - `📡 Sniffer`: التقاط الترافيك المباشر مع فلتر BPF وعرض الحزم في جدول Treeview تفاعلي، وزر تصدير PCAP.
   - `📁 PCAP`: اختيار وقراءة ملفات `.pcap`، حساب الإحصائيات، وتصفح الحزم.
   - `🔍 ARP`: فحص شبكة محلية واكتشاف أجهزة الـ IP والـ MAC.
   - `🎯 Ports/Ping`: فحص اتصال Ping وفحص منافذ TCP SYN وعرض الحالة (Open/Closed/Filtered) بألوان واضحة.
   - `🛠️ Crafter`: بناء حزم IP, TCP, UDP, ICMP مخصصة مع إمكانية تزييف الـ IP ومعاينة الحزمة بـ `.show()` وإرسالها.
   - `📶 Wi-Fi`: مسح شبكات الواي فاي القريبة، استرجاع كلمات المرور المحفوظة، والاتصال بالشبكة وتدقيق أمان كلمات السر.
   - `🌐 Gateway`: الاكتشاف التلقائي لراوتر الشبكة وفحص كافة منافذه الحساسة وإظهار تنبيهات أمنية.
   - `🛡️ Beacons`: تشريح حزم الـ 802.11 Beacons وتحليل التشفير (WPA2/WPA3).
   - `🌍 Requests`: اختبار مواقع الويب، استخراج الترويسات، فحص درجات الأمان، واستعلام الـ Threat Intel عبر الـ APIs.
   - `🔐 SSH/SFTP`: الاتصال المشفر بالسيرفرات، تنفيذ الأوامر، إجراء فحص أمني تلقائي، ورفع وسحب الملفات بـ SFTP.
2. **عدم حظر الواجهة (Multithreading)**: يتم تشغيل كافة العمليات الثقيلة (مثل التقاط الشبكة والاتصالات البعيدة) داخل `threading.Thread(daemon=True)`.
3. **تحديث الواجهة بأمان (Thread-Safe UI)**: يتم تحديث عناصر Tkinter وجداول الـ Treeview وسجل الـ Log عبر `root.after()` لمنع أي تصادمات برمجية.
4. **شاشة تشريح الحزمة العميقة (Popup Deep Inspector)**: عند النقر المزدوج على أي حزمة في جدول الحزم، تفتح نافذة منبثقة تستدعي مخرجات `.show()` وتنسقها داخل محرر نصوص بألوان زاهية.

### 💻 أوامر التشغيل:
```bash
# تثبيت حزمة Tkinter على نظام Ubuntu/Debian (إذا لم تكن مثبتة):
sudo apt update && sudo apt install -y python3-tk

# تشغيل الواجهة بصلاحيات الـ Root (موصى به للـ Sniffer والـ Raw Packets):
sudo ./venv/bin/python gui.py

# أو تشغيلها في وضع المستخدم العادي:
./venv/bin/python gui.py
```

---

## 💡 نصائح وحلول المشاكل الشائعة

| المشكلة | السبب | الحل |
| :--- | :--- | :--- |
| `PermissionError: [Errno 1] Operation not permitted` | تشغيل أدوات التقاط الترافيك بدون صلاحيات الجذر | استخدم `sudo` قبل الأمر: `sudo ./venv/bin/python main.py` أو `sudo ./venv/bin/python gui.py` |
| `ModuleNotFoundError: No module named 'scapy'` | محاولة التشغيل خارج البيئة الافتراضية | تأكد من تفعيل البيئة `source venv/bin/activate` أو كتابة المسار الكامل `./venv/bin/python` |
| `ModuleNotFoundError: No module named 'tkinter'` | عدم تثبيت حزمة Tkinter لنظام بايثون في النظام | قم بتثبيتها عبر: `sudo apt update && sudo apt install -y python3-tk` |
| `No active devices found` في فاحص الـ ARP | إدخال Subnet غير متطابق مع كارت الشبكة | تأكد من نطاق شبكتك عبر أمر `ip addr show` (غالباً `192.168.1.0/24`) |
| `Could not automatically detect Default Gateway` | الجهاز غير متصل بأي شبكة حالياً | اتصل بشبكة واي فاي أولاً عبر الخيار `6` أو عبر `nmcli` |

